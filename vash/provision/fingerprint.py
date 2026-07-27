"""Fingerprint a repository: languages, build systems, version pins, and any
existing build recipe (Dockerfile / devcontainer / CI). Pure and offline —
reads names and small manifests only; never executes anything."""
from __future__ import annotations

import json
import re
import tomllib
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
    "pipenv": ["Pipfile"],
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

# Read for tool evidence but NOT treated as a build recipe: a run script or a
# Makefile says which tool the project uses without being something to build
# from.
_TOOL_EVIDENCE_GLOBS = [
    "Makefile", "makefile", "*.sh", "tox.ini", "noxfile.py", "Taskfile.yml",
]

# What the repo's OWN recipe says it runs. A CI workflow, devcontainer or
# Dockerfile is the highest-signal evidence available — the project stating, in
# its own words, how it installs itself — and it used to be detected and then
# discarded (`render_dockerfile` reused only a literal `Dockerfile` and ignored
# every other recipe it had found).
#
# Only the tool NAME is taken from it. The recipe's commands are never copied or
# executed: CI runs against a runner with secrets, network, services and caches
# this container does not have, so transplanting its script would fail in ways
# that look like the target's fault.
_RECIPE_TOOL_PATTERNS: dict[str, str] = {
    "uv": r"\buv\s+(?:sync|pip|export|build|run|lock|venv)\b",
    "poetry": r"\bpoetry\s+(?:install|lock|build|run|export)\b",
    "pipenv": r"\bpipenv\s+(?:install|sync|requirements)\b",
    "pnpm": r"\bpnpm\s+(?:install|i|ci)\b",
    "yarn": r"\byarn\s+(?:install|--immutable)\b",
    "npm": r"\bnpm\s+(?:ci|install)\b",
    "pip": r"\bpip\s+install\b",
    "maven": r"\bmvn\s+\w",
    "gradle": r"\b(?:\./)?gradlew?\s+\w",
    "go-modules": r"\bgo\s+(?:mod|build|test)\b",
    "dotnet": r"\bdotnet\s+(?:restore|build|test|publish)\b",
}

# A recipe is read for evidence, not parsed in full — cap the read so a
# generated multi-megabyte workflow cannot stall Stage 0.
_MAX_RECIPE_BYTES = 64 * 1024

# Runtime versions a CI recipe states outright. Taken as FLOORS, never pins: a
# matrix legitimately lists several, and pinning to the lowest is exactly the
# mistake `_spec_is_a_floor` already exists to prevent.
_RECIPE_VERSION_PATTERNS: dict[str, str] = {
    "python": r"python-version[\"']?\s*:\s*\[?\s*[\"']?(\d+\.\d+)",
    "node": r"node-version[\"']?\s*:\s*\[?\s*[\"']?(\d+)",
    "go": r"go-version[\"']?\s*:\s*\[?\s*[\"']?(\d+\.\d+)",
}

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
    # Tools the repo's own recipe/run scripts actually invoke. Evidence, not
    # instructions — the renderer prefers a candidate this corroborates, and
    # will trust it for a tool whose marker file is missing entirely.
    recipe_tools: list[str] = field(default_factory=list)


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


def _version_key(v: str) -> tuple:
    """Comparable form of a version string ("3.11" -> (3, 11)). Shared with the
    renderer so "which version is newer" is answered the same way everywhere."""
    return tuple(int(p) for p in re.findall(r"\d+", v)[:3]) or (0,)


def _python_tool_from_pyproject(repo_path: Path) -> str | None:
    """Which python packaging tool a `pyproject.toml` actually declares.

    The filename cannot answer this — setuptools, hatch, flit, pdm, poetry and
    uv all ship the same `pyproject.toml` — and guessing wrong is not cosmetic.
    A poetry 1.x project keeps its dependencies under `[tool.poetry.dependencies]`,
    which `pip install -e .` cannot see, so calling it pip yields an image with
    no dependencies; calling a PEP-621 project poetry fails the other way, since
    `poetry install` refuses a project with no `[tool.poetry]` table at all.

    Returns an id this module has a template for. pdm/hatch/flit/setuptools all
    collapse to ``pip``: they are PEP-621, and `pip install -e .` installs them
    correctly, so a separate template would be ceremony without a difference.
    Returns None when the file is absent or unparseable — the caller then keeps
    whatever the filename markers found, which is the pre-existing behaviour.
    """
    p = repo_path / "pyproject.toml"
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    tool = data.get("tool")
    if isinstance(tool, dict):
        if "uv" in tool:
            return "uv"
        if "poetry" in tool:
            return "poetry"

    build_system = data.get("build-system")
    backend = ""
    if isinstance(build_system, dict):
        backend = str(build_system.get("build-backend") or "")
    if "poetry" in backend:
        return "poetry"
    if backend or isinstance(data.get("project"), dict):
        return "pip"
    return None


def _detect_build_systems(files: list[Path], repo_path: Path) -> list[str]:
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
    # The filename pass maps every `pyproject.toml` to pip. Ask the file itself
    # which tool it belongs to, so a poetry project that never committed its
    # lockfile is still built with poetry rather than a pip install that cannot
    # read its dependency table.
    declared = _python_tool_from_pyproject(repo_path)
    if declared is not None and declared not in found:
        found.append(declared)
    return sorted(found)


def _read_capped(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:_MAX_RECIPE_BYTES]
    except OSError:
        return ""


def _tool_evidence_files(repo_path: Path, recipes: list[str]) -> list[Path]:
    """The recipes already detected, plus root-level run scripts / Makefiles."""
    paths = [repo_path / rel for rel in recipes]
    for glob in _TOOL_EVIDENCE_GLOBS:
        for p in repo_path.glob(glob):
            if p.is_file():
                paths.append(p)
    return paths


def _detect_recipe_tools(repo_path: Path, recipes: list[str]) -> list[str]:
    """Build tools the repo's own recipes and run scripts actually invoke."""
    found: list[str] = []
    for path in _tool_evidence_files(repo_path, recipes):
        text = _read_capped(path)
        if not text:
            continue
        for tool, pattern in _RECIPE_TOOL_PATTERNS.items():
            if tool not in found and re.search(pattern, text):
                found.append(tool)
    return sorted(found)


def _detect_recipe_version_floors(repo_path: Path, recipes: list[str]) -> dict[str, str]:
    """Runtime versions the repo's recipes state, as floors.

    The MAX stated version is used: a CI matrix listing 3.11/3.12/3.13 proves
    the project runs on 3.13, and taking the minimum would build it on the
    oldest runtime it merely tolerates.
    """
    floors: dict[str, str] = {}
    for path in _tool_evidence_files(repo_path, recipes):
        text = _read_capped(path)
        if not text:
            continue
        for key, pattern in _RECIPE_VERSION_PATTERNS.items():
            for m in re.findall(pattern, text):
                if key not in floors or _version_key(m) > _version_key(floors[key]):
                    floors[key] = m
    return floors


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

    # `requires-python = ">=3.12"` is a floor in exactly the sense the machinery
    # above already models. Without it a project needing 3.12 was built on the
    # 3.11 default and failed at install with a version-conflict that reads like
    # a broken dependency.
    pyproject = repo_path / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
            spec = str(((data.get("project") or {}) if isinstance(data.get("project"), dict)
                        else {}).get("requires-python") or "")
            m = re.search(r"(\d+\.\d+)", spec)
            if m:
                if _spec_is_a_floor(spec):
                    floors.setdefault("python", m.group(1))
                else:
                    pins.setdefault("python", m.group(1))
        except (OSError, ValueError, TypeError):
            pass
    return pins, floors


def fingerprint(repo_path: Path) -> ProjectFingerprint:
    repo_path = Path(repo_path)
    # ONE walk shared by both detectors — this is on the pipeline's critical
    # path (Stage 0), and a large target should not be traversed twice.
    files = list(_iter_files(repo_path))
    languages, primary = _detect_languages(files)
    pins, floors = _detect_version_pins(repo_path)
    recipes = _detect_recipes(repo_path)

    # A version the repo's own CI states outranks our default, but never an
    # exact pin the repo declared elsewhere (.nvmrc, .python-version, go.mod).
    for key, ver in _detect_recipe_version_floors(repo_path, recipes).items():
        if key in pins:
            continue
        if key not in floors or _version_key(ver) > _version_key(floors[key]):
            floors[key] = ver

    return ProjectFingerprint(
        languages=languages,
        build_systems=_detect_build_systems(files, repo_path),
        version_pins=pins,
        version_floors=floors,
        existing_recipes=recipes,
        primary_language=primary,
        recipe_tools=_detect_recipe_tools(repo_path, recipes),
    )
