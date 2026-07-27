"""Fingerprint a repository: languages, build systems, version pins, and any
existing build recipe (Dockerfile / devcontainer / CI). Pure and offline —
reads names and small manifests only; never executes anything."""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from vash.lang.hints import EXT_TO_LANG

# build-system id -> marker filenames that prove it (checked at repo root and,
# for a few, anywhere in the tree). A repo can have several.
BUILD_SYSTEM_MARKERS: dict[str, list[str]] = {
    "npm": ["package.json"],
    "yarn": ["yarn.lock"],
    "pnpm": ["pnpm-lock.yaml"],
    "maven": ["pom.xml"],
    "gradle": ["build.gradle", "build.gradle.kts", "settings.gradle"],
    "go-modules": ["go.mod"],
    # A bare `pyproject.toml` is PEP-621, not poetry. Mapping it to poetry built
    # `poetry install` images for setuptools/hatch/uv projects with no
    # `[tool.poetry]` table at all — the install failed, `|| true` swallowed it,
    # and the image came out with none of the target's dependencies. Each python
    # packaging tool is now claimed by its own lockfile, and pyproject.toml falls
    # to pip, which handles PEP-621 correctly with `pip install -e .`.
    "pip": ["requirements.txt", "setup.py", "setup.cfg", "pyproject.toml"],
    "poetry": ["poetry.lock"],
    "uv": ["uv.lock"],
    "cargo": ["Cargo.toml"],
    "bundler": ["Gemfile"],
    "composer": ["composer.json"],
    "dotnet": ["*.csproj", "*.sln"],
}

# repo-relative globs that indicate a ready-made build recipe.
_RECIPE_GLOBS = [
    "Dockerfile", "*/Dockerfile",
    ".devcontainer/devcontainer.json", ".devcontainer.json",
    ".github/workflows/*.yml", ".github/workflows/*.yaml",
    ".gitlab-ci.yml",
]

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build",
              "__pycache__", ".tox", "target", "vendor", ".gradle"}


@dataclass
class ProjectFingerprint:
    languages: list[str] = field(default_factory=list)
    build_systems: list[str] = field(default_factory=list)
    version_pins: dict[str, str] = field(default_factory=dict)
    # Minimum versions (from a range spec such as `">= 16.0.0"`). The renderer
    # takes max(floor, its own default) — a floor must never downgrade a
    # modern default, which is how a `>=16` repo got built on node:16.
    version_floors: dict[str, str] = field(default_factory=dict)
    existing_recipes: list[str] = field(default_factory=list)
    primary_language: str | None = None


def _iter_files(repo_path: Path):
    """Every file under the repo, minus build/VCS noise.

    Permission-guarded per entry (the macOS Claude Code sandbox denies reads of
    `.envrc`, submodule `.git` internals, ...): a single unreadable entry skips
    cleanly instead of aborting the whole fingerprint. This runs on the pipeline's
    critical path (orchestrator Stage 0), so it must not raise. Exclusion is
    checked on the path RELATIVE to the repo, so a repo that merely lives under
    a directory named e.g. `build/` is not silently emptied."""
    try:
        candidates = repo_path.rglob("*")
    except OSError:
        return
    for p in candidates:
        try:
            if not p.is_file():
                continue
            rel_parts = p.relative_to(repo_path).parts
        except (OSError, ValueError):
            continue
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        yield p


def _detect_languages(files: list[Path]) -> tuple[list[str], str | None]:
    counts: Counter[str] = Counter()
    for p in files:
        lang = EXT_TO_LANG.get(p.suffix.lower())
        if lang and lang != "web-template":
            counts[lang] += 1
    if not counts:
        return [], None
    # sort by count desc, then name asc for determinism
    langs = sorted(counts, key=lambda l: (-counts[l], l))
    return langs, langs[0]


def _detect_build_systems(files: list[Path]) -> list[str]:
    present = set(p.name for p in files)
    found: list[str] = []
    for bs, markers in BUILD_SYSTEM_MARKERS.items():
        for m in markers:
            if m.startswith("*."):
                if any(n.endswith(m[1:]) for n in present):
                    found.append(bs)
                    break
            elif m in present:
                found.append(bs)
                break
    return sorted(found)


def _detect_recipes(repo_path: Path) -> list[str]:
    found: list[str] = []
    for glob in _RECIPE_GLOBS:
        for p in repo_path.glob(glob):
            if p.is_file():
                found.append(str(p.relative_to(repo_path)))
    return sorted(set(found))


# A range operator means the version is a FLOOR, not a pin. `engines: {"node":
# ">= 16.0.0"}` says "16 or newer" — pinning the image to node:16 because of it
# is how a repo whose .nvmrc says 24 and whose CI runs 20/22/24 ends up built on
# an eight-year-old runtime (observed on graphql-code-generator).
_RANGE_OPS = (">", "<", "^", "~", "*", "x", "||", " - ")


def _spec_is_a_floor(spec: str) -> bool:
    return any(op in spec for op in _RANGE_OPS)


def _detect_version_pins(repo_path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Returns (exact_pins, floors).

    Exact pins are honoured verbatim. Floors are minimums — the renderer takes
    max(floor, its own default) so a modern default is never downgraded to a
    project's stated minimum.
    """
    pins: dict[str, str] = {}
    floors: dict[str, str] = {}

    # .nvmrc is an EXACT statement of the node version the project develops on,
    # so it outranks the engines range.
    nvmrc = repo_path / ".nvmrc"
    if nvmrc.is_file():
        try:
            m = re.search(r"(\d+(?:\.\d+)*)",
                          nvmrc.read_text(encoding="utf-8", errors="replace"))
            if m:
                pins["node"] = m.group(1)
        except OSError:
            pass

    pkg = repo_path / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            node = (data.get("engines") or {}).get("node")
            if node:
                spec = str(node)
                m = re.search(r"(\d+)", spec)
                if m:
                    if _spec_is_a_floor(spec):
                        floors.setdefault("node", m.group(1))
                    else:
                        pins.setdefault("node", m.group(1))
        except (ValueError, OSError):
            pass
    gomod = repo_path / "go.mod"
    if gomod.is_file():
        try:
            m = re.search(r"^go\s+(\d+\.\d+)",
                          gomod.read_text(encoding="utf-8", errors="replace"), re.M)
            if m:
                pins["go"] = m.group(1)
        except OSError:
            pass
    for fn in (".python-version",):
        fp = repo_path / fn
        if fp.is_file():
            try:
                m = re.search(r"(\d+\.\d+)",
                              fp.read_text(encoding="utf-8", errors="replace"))
                if m:
                    pins["python"] = m.group(1)
            except OSError:
                pass
    return pins, floors


def fingerprint(repo_path: Path) -> ProjectFingerprint:
    repo_path = Path(repo_path)
    # ONE walk shared by both detectors — this is on the pipeline's critical
    # path (Stage 0), and a large target should not be traversed twice.
    files = list(_iter_files(repo_path))
    languages, primary = _detect_languages(files)
    pins, floors = _detect_version_pins(repo_path)
    return ProjectFingerprint(
        languages=languages,
        build_systems=_detect_build_systems(files),
        version_pins=pins,
        version_floors=floors,
        existing_recipes=_detect_recipes(repo_path),
        primary_language=primary,
    )
