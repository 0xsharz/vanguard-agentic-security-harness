"""Render a Dockerfile for a fingerprinted repo. Prefers an existing repo
recipe; otherwise emits a per-ecosystem template STRING. Text only — this
module never runs `docker build` (Phase 2 owns build/verify/repair)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vash.provision.fingerprint import ProjectFingerprint

# build-system -> template pieces. {ver} is filled from version_pins when present.
ECOSYSTEM_TEMPLATES: dict[str, dict] = {
    "npm": {
        "base": "node:{ver}",
        "default_ver": "20",
        "ver_key": "node",
        "install": "RUN npm ci || npm install",
        "build": "npm run build --if-present",
        "test": "npm test --if-present",
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
    "pip": {
        "base": "python:{ver}-slim",
        "default_ver": "3.11",
        "ver_key": "python",
        "install": "RUN pip install -e . || pip install -r requirements.txt || true",
        "build": "python -c \"import sys; print(sys.version)\"",
        "test": "pytest -q || true",
    },
}

# preference order when a repo declares several ecosystems.
_PRIORITY = ["maven", "gradle", "npm", "go-modules", "pip"]


@dataclass
class RenderedRecipe:
    source: str = "none"            # "existing" | "template" | "none"
    path: str | None = None
    dockerfile: str | None = None
    build_cmd: str | None = None
    test_cmd: str | None = None
    notes: list[str] = field(default_factory=list)


def _pick_ecosystem(fp: ProjectFingerprint) -> str | None:
    for bs in _PRIORITY:
        if bs in fp.build_systems:
            return bs
    return None


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
        build_cmd=t["build"], test_cmd=t["test"],
        notes=[f"templated {eco} (base={base})"],
    )
