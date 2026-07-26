"""Render a Dockerfile for a fingerprinted repo. Prefers an existing repo
recipe; otherwise emits a per-ecosystem template STRING. Text only — this
module never runs `docker build` (`build.py` owns build/verify/repair)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vash.provision.fingerprint import ProjectFingerprint

# Dependency-presence probe for the ecosystems whose `build` command cannot
# fail on missing dependencies (python's `python -c ...` and npm's
# `--if-present` are both no-ops on a bare image, so "built" would otherwise
# hide an environment with none of the target's dependencies installed).
# POSIX sh, offline, read-only. Go/Maven/Gradle/dotnet need no probe: their
# build command already fails hard when dependencies are missing.
_PIP_DEPS_PROBE = (
    "[ -f requirements.txt ] || exit 0; "
    "pip freeze 2>/dev/null | sed -e 's/[[:space:]]*@.*//' -e 's/[=<>].*//' "
    "| tr 'A-Z_' 'a-z-' | sort -u > /tmp/have; "
    "sed -e 's/#.*//' -e 's/\\[.*\\]//' -e 's/[<>=!~;].*//' -e 's/[[:space:]]//g' "
    "requirements.txt | grep -v '^$' | grep -v '^-' | tr 'A-Z_' 'a-z-' | sort -u > /tmp/want; "
    "missing=$(comm -23 /tmp/want /tmp/have); "
    "[ -z \"$missing\" ] || { echo \"MISSING DEPENDENCIES: $missing\"; exit 1; }"
)
_NPM_DEPS_PROBE = (
    "[ -f package.json ] || exit 0; "
    # A package.json that declares NO dependencies legitimately has no
    # node_modules — demanding one there is a false alarm (observed against a
    # dependency-free target). Only require the directory when the manifest
    # actually asks for something. If `node` is somehow absent, fall through to
    # exit 0 rather than inventing a failure.
    "node -e \"const p=require('./package.json');"
    "process.exit(Object.keys({...(p.dependencies||{}),...(p.devDependencies||{})}).length?0:1)\" "
    "2>/dev/null || exit 0; "
    "[ -d node_modules ] || { echo 'MISSING DEPENDENCIES: node_modules absent'; exit 1; }"
)

# build-system -> template pieces. {ver} is filled from version_pins when present.
ECOSYSTEM_TEMPLATES: dict[str, dict] = {
    "npm": {
        "base": "node:{ver}",
        "default_ver": "20",
        "ver_key": "node",
        "install": "RUN npm ci || npm install",
        "build": "npm run build --if-present",
        "test": "npm test --if-present",
        "deps": _NPM_DEPS_PROBE,
    },
    "maven": {
        "base": "maven:3.9-eclipse-temurin-{ver}",
        "default_ver": "21",
        "ver_key": "java",
        "install": "RUN mvn -q -B dependency:go-offline || true",
        "build": "mvn -q -B -DskipTests package",
        "test": "mvn -q -B test",
    },
    "gradle": {
        "base": "gradle:8-jdk{ver}",
        "default_ver": "21",
        "ver_key": "java",
        "install": "RUN gradle --no-daemon dependencies || true",
        "build": "gradle --no-daemon assemble",
        "test": "gradle --no-daemon test",
    },
    "go-modules": {
        "base": "golang:{ver}",
        "default_ver": "1.22",
        "ver_key": "go",
        "install": "RUN go mod download",
        "build": "go build ./...",
        "test": "go test ./...",
    },
    "dotnet": {
        "base": "mcr.microsoft.com/dotnet/sdk:{ver}",
        "default_ver": "8.0",
        "ver_key": "dotnet",
        "install": "RUN dotnet restore || true",
        "build": "dotnet build -c Release --no-restore",
        "test": "dotnet test --no-build",
    },
    "pip": {
        "base": "python:{ver}-slim",
        "default_ver": "3.11",
        "ver_key": "python",
        # Both steps run, independently: a succeeding `pip install -e .` used to
        # short-circuit the `||` chain and leave requirements.txt uninstalled —
        # an image that builds but has none of the target's dependencies.
        "install": (
            "RUN if [ -f requirements.txt ]; then pip install -r requirements.txt || true; fi \\\n"
            "    && if [ -f setup.py ] || [ -f pyproject.toml ]; then pip install -e . || true; fi"
        ),
        "build": "python -c \"import sys; print(sys.version)\"",
        "test": "pytest -q || true",
        "deps": _PIP_DEPS_PROBE,
    },
    "poetry": {
        "base": "python:{ver}-slim",
        "default_ver": "3.11",
        "ver_key": "python",
        "install": "RUN pip install poetry && poetry install --no-root || true",
        "build": "python -c \"import sys; print(sys.version)\"",
        "test": "poetry run pytest -q || true",
        "deps": _PIP_DEPS_PROBE,
    },
}

# preference order when a repo declares several ecosystems.
_PRIORITY = ["maven", "gradle", "npm", "go-modules", "dotnet", "pip", "poetry"]

# ecosystem -> language it belongs to, so _pick_ecosystem can prefer the
# ecosystem matching the repo's dominant language over one from a vendored
# manifest (e.g. a Python repo with a vendored frontend/package.json).
_ECOSYSTEM_LANG = {
    "npm": "javascript", "yarn": "javascript", "pnpm": "javascript",
    "maven": "java", "gradle": "java", "go-modules": "go",
    "dotnet": "csharp", "pip": "python", "poetry": "python",
}


@dataclass
class RenderedRecipe:
    source: str = "none"            # "existing" | "template" | "none"
    path: str | None = None
    dockerfile: str | None = None
    build_cmd: str | None = None
    test_cmd: str | None = None
    # Optional dependency-presence probe run by the Phase 2 verify step for
    # ecosystems whose build command cannot itself fail on missing deps.
    deps_cmd: str | None = None
    notes: list[str] = field(default_factory=list)


def _pick_ecosystem(fp: ProjectFingerprint) -> str | None:
    present = [bs for bs in _PRIORITY if bs in fp.build_systems]
    if not present:
        return None
    if fp.primary_language:
        for bs in present:
            if _ECOSYSTEM_LANG.get(bs) == fp.primary_language:
                return bs
    return present[0]


def render_dockerfile(fp: ProjectFingerprint, repo_path: Path) -> RenderedRecipe:
    # 1. Prefer an existing repo recipe (highest signal).
    for rel in fp.existing_recipes:
        if Path(rel).name == "Dockerfile":
            return RenderedRecipe(source="existing", path=rel,
                                  notes=["reused existing repo Dockerfile"])

    # 2. Otherwise template the highest-priority known ecosystem.
    eco = _pick_ecosystem(fp)
    if eco is None:
        return RenderedRecipe(source="none",
                              notes=["no known build system detected"])
    t = ECOSYSTEM_TEMPLATES[eco]
    ver = fp.version_pins.get(t["ver_key"], t["default_ver"])
    base = t["base"].format(ver=ver)
    dockerfile = "\n".join([
        f"FROM {base}",
        "WORKDIR /target",
        "COPY . /target",
        t["install"],
        "# build/test are run by the Phase 2 provisioning stage, not at build time",
    ]) + "\n"
    return RenderedRecipe(
        source="template", path=None, dockerfile=dockerfile,
        build_cmd=t["build"], test_cmd=t["test"], deps_cmd=t.get("deps"),
        notes=[f"templated {eco} (base={base})"],
    )
