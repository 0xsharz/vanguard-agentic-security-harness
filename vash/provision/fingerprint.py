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
    "pip": ["requirements.txt", "setup.py", "setup.cfg"],
    "poetry": ["pyproject.toml"],
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
    existing_recipes: list[str] = field(default_factory=list)
    primary_language: str | None = None


def _iter_files(repo_path: Path):
    for p in repo_path.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(repo_path).parts):
            continue
        yield p


def _detect_languages(repo_path: Path) -> tuple[list[str], str | None]:
    counts: Counter[str] = Counter()
    for p in _iter_files(repo_path):
        lang = EXT_TO_LANG.get(p.suffix.lower())
        if lang and lang != "web-template":
            counts[lang] += 1
    if not counts:
        return [], None
    # sort by count desc, then name asc for determinism
    langs = sorted(counts, key=lambda l: (-counts[l], l))
    return langs, langs[0]


def _detect_build_systems(repo_path: Path) -> list[str]:
    present = set(p.name for p in _iter_files(repo_path))
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


def _detect_version_pins(repo_path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    pkg = repo_path / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            node = (data.get("engines") or {}).get("node")
            if node:
                m = re.search(r"(\d+)", str(node))
                if m:
                    pins["node"] = m.group(1)
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
    return pins


def fingerprint(repo_path: Path) -> ProjectFingerprint:
    repo_path = Path(repo_path)
    languages, primary = _detect_languages(repo_path)
    return ProjectFingerprint(
        languages=languages,
        build_systems=_detect_build_systems(repo_path),
        version_pins=_detect_version_pins(repo_path),
        existing_recipes=_detect_recipes(repo_path),
        primary_language=primary,
    )
