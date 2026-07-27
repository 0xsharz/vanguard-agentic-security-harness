import shutil
import subprocess
from pathlib import Path

import pytest
from vash.provision.fingerprint import fingerprint
from vash.provision.dockerfile import render_dockerfile, RenderedRecipe


def _mk(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def test_reuses_existing_dockerfile(tmp_path):
    repo = _mk(tmp_path, {"Dockerfile": "FROM node:20\n", "package.json": "{}"})
    r = render_dockerfile(fingerprint(repo), repo)
    assert isinstance(r, RenderedRecipe)
    assert r.source == "existing"
    assert r.path == "Dockerfile"


def test_templates_node_when_no_recipe(tmp_path):
    repo = _mk(tmp_path, {"app.js": "1\n",
                          "package.json": '{"engines":{"node":"20"}}'})
    r = render_dockerfile(fingerprint(repo), repo)
    assert r.source == "template"
    assert r.dockerfile is not None
    assert "FROM node:20" in r.dockerfile
    assert "npm" in r.dockerfile.lower()
    assert r.build_cmd and "npm" in r.build_cmd


def test_templates_maven_when_no_recipe(tmp_path):
    repo = _mk(tmp_path, {"Main.java": "class Main{}\n", "pom.xml": "<project/>"})
    r = render_dockerfile(fingerprint(repo), repo)
    assert r.source == "template"
    assert "maven" in r.dockerfile.lower() or "mvn" in (r.build_cmd or "")


def test_templates_go_when_no_recipe(tmp_path):
    repo = _mk(tmp_path, {"main.go": "package main\n", "go.mod": "module x\ngo 1.22\n"})
    r = render_dockerfile(fingerprint(repo), repo)
    assert r.source == "template"
    assert "FROM golang:1.22" in r.dockerfile


def test_templates_dotnet_when_no_recipe(tmp_path):
    repo = _mk(tmp_path, {"Program.cs": "class P{}\n", "App.csproj": "<Project/>"})
    r = render_dockerfile(fingerprint(repo), repo)
    assert r.source == "template"
    assert "dotnet" in r.dockerfile.lower()
    assert r.build_cmd and "dotnet build" in r.build_cmd


def test_no_known_ecosystem_returns_none(tmp_path):
    repo = _mk(tmp_path, {"README.md": "hi\n"})
    r = render_dockerfile(fingerprint(repo), repo)
    assert r.source == "none"
    assert r.dockerfile is None


def test_templates_poetry_pyproject_python(tmp_path):
    repo = _mk(tmp_path, {"app.py": "x=1\n", "pyproject.toml": "[tool.poetry]\nname='x'\n",
                          "poetry.lock": "# lock\n"})
    r = render_dockerfile(fingerprint(repo), repo)
    assert r.source == "template"
    assert "python:" in r.dockerfile
    assert "poetry install" in r.dockerfile


def test_uv_lock_picks_uv_not_poetry(tmp_path):
    """uv.lock is proof of the tool. Before this, `pyproject.toml` alone meant
    poetry, so a uv project got `poetry install` — which fails outright on a
    PEP-621 project with no [tool.poetry] table (observed on
    worldbank/data360-mcp, whose CI and startup.sh both say `uv`)."""
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "pyproject.toml": "[project]\nname='x'\ndependencies=['requests']\n",
        "uv.lock": "version = 1\n",
    })
    fp = fingerprint(repo)
    assert "uv" in fp.build_systems
    r = render_dockerfile(fp, repo)
    assert "uv pip install --system" in r.dockerfile
    assert "poetry" not in r.dockerfile
    # deps must land on the SYSTEM interpreter: a PoC runs `python3 poc.py`,
    # which would never see a project-local .venv.
    assert "--system" in r.dockerfile
    # and the lock is exported so the existing pip deps probe can check it
    assert "uv export" in r.dockerfile


def test_bare_pep621_pyproject_is_pip_not_poetry(tmp_path):
    """The general case behind the same bug: setuptools/hatch/flit projects all
    ship a pyproject.toml and none of them are poetry. pip handles PEP-621."""
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "pyproject.toml": ("[project]\nname='x'\n\n[build-system]\n"
                           "requires=['setuptools']\n"),
    })
    fp = fingerprint(repo)
    assert "pip" in fp.build_systems and "poetry" not in fp.build_systems
    r = render_dockerfile(fp, repo)
    assert "pip install -e ." in r.dockerfile
    assert "poetry" not in r.dockerfile


def test_primary_language_wins_over_vendored_manifest(tmp_path):
    # python repo (2 .py) with a vendored frontend/package.json (1 .js): must pick python, not node
    repo = _mk(tmp_path, {
        "a.py": "1\n", "b.py": "2\n", "pyproject.toml": "[tool.poetry]\nname='x'\n",
        "frontend/app.js": "1\n", "frontend/package.json": "{}",
    })
    fp = fingerprint(repo)
    assert fp.primary_language == "python"
    r = render_dockerfile(fp, repo)
    assert "python:" in r.dockerfile        # NOT node


# --- dependency-presence probe (Phase 2 verify) -----------------------------

def test_npm_deps_probe_is_conditional_on_declared_dependencies():
    """A package.json with no dependencies legitimately has no node_modules —
    the probe must not report MISSING for it (observed against a real
    dependency-free target, which the first version of this probe failed)."""
    from vash.provision.dockerfile import ECOSYSTEM_TEMPLATES
    probe = ECOSYSTEM_TEMPLATES["npm"]["deps"]
    assert "dependencies" in probe and "devDependencies" in probe
    assert "node_modules" in probe


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node on PATH")
@pytest.mark.parametrize("pkg,expect_ok", [
    ('{"name":"x"}', True),                                  # no deps -> OK
    ('{"name":"x","dependencies":{}}', True),                # empty deps -> OK
    ('{"name":"x","dependencies":{"left-pad":"1.0.0"}}', False),   # deps, no node_modules -> MISSING
])
def test_npm_deps_probe_behaviour(tmp_path, pkg, expect_ok):
    """Run the probe shell for real (no docker, no network) to prove the
    conditional actually behaves as intended."""
    from vash.provision.dockerfile import ECOSYSTEM_TEMPLATES
    (tmp_path / "package.json").write_text(pkg)
    p = subprocess.run(["sh", "-c", ECOSYSTEM_TEMPLATES["npm"]["deps"]],
                       cwd=tmp_path, capture_output=True, text=True)
    assert (p.returncode == 0) is expect_ok, p.stdout + p.stderr


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node on PATH")
def test_npm_deps_probe_passes_when_node_modules_exists(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"x","dependencies":{"left-pad":"1.0.0"}}')
    (tmp_path / "node_modules").mkdir()
    p = subprocess.run(["sh", "-c", ECOSYSTEM_TEMPLATES_DEPS()],
                       cwd=tmp_path, capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr


def ECOSYSTEM_TEMPLATES_DEPS():
    from vash.provision.dockerfile import ECOSYSTEM_TEMPLATES
    return ECOSYSTEM_TEMPLATES["npm"]["deps"]


# --- real-world monorepo shapes (found on graphql-code-generator) ------------

def test_pnpm_workspace_is_not_templated_as_npm(tmp_path):
    """`npm install` cannot resolve pnpm's `workspace:^` protocol, so a pnpm
    monorepo templated as npm installs nothing at all."""
    repo = _mk(tmp_path, {
        "app.ts": "export const x = 1\n",
        "package.json": '{"name":"root","packageManager":"pnpm@11.1.1"}',
        "pnpm-lock.yaml": "lockfileVersion: 9\n",
        "pnpm-workspace.yaml": "packages:\n  - packages/*\n",
    })
    fp = fingerprint(repo)
    assert "pnpm" in fp.build_systems
    r = render_dockerfile(fp, repo)
    assert "pnpm install" in r.dockerfile
    assert "corepack enable" in r.dockerfile      # honours packageManager
    assert "npm ci" not in r.dockerfile


def test_engines_range_is_a_floor_not_a_pin(tmp_path):
    """`engines: {"node": ">= 16.0.0"}` means 16-or-newer. Pinning to 16 builds
    the project on its oldest supported runtime."""
    repo = _mk(tmp_path, {
        "app.js": "1\n",
        "package.json": '{"name":"x","engines":{"node":">= 16.0.0"}}',
    })
    fp = fingerprint(repo)
    assert fp.version_floors.get("node") == "16"
    assert "node" not in fp.version_pins
    r = render_dockerfile(fp, repo)
    assert "FROM node:20" in r.dockerfile        # the default, not the floor


def test_a_floor_above_the_default_is_honoured(tmp_path):
    repo = _mk(tmp_path, {
        "app.js": "1\n",
        "package.json": '{"name":"x","engines":{"node":">=22"}}',
    })
    r = render_dockerfile(fingerprint(repo), repo)
    assert "FROM node:22" in r.dockerfile


def test_nvmrc_is_an_exact_pin_and_outranks_the_engines_range(tmp_path):
    repo = _mk(tmp_path, {
        "app.js": "1\n",
        ".nvmrc": "24\n",
        "package.json": '{"name":"x","engines":{"node":">= 16.0.0"}}',
    })
    fp = fingerprint(repo)
    assert fp.version_pins.get("node") == "24"
    assert "FROM node:24" in render_dockerfile(fp, repo).dockerfile


def test_typescript_repo_matches_the_javascript_ecosystem(tmp_path):
    repo = _mk(tmp_path, {
        "a.ts": "1\n", "b.ts": "2\n",
        "package.json": "{}", "pnpm-lock.yaml": "lockfileVersion: 9\n",
    })
    fp = fingerprint(repo)
    assert fp.primary_language == "typescript"
    assert render_dockerfile(fp, repo).dockerfile.count("pnpm") >= 1


def test_js_ecosystems_build_the_workspace_during_provisioning(tmp_path):
    """A TS package resolves to dist/, which does not exist until something
    builds it — so a PoC doing require('@scope/pkg') hits MODULE_NOT_FOUND and
    never reaches the code it is attacking (observed on graphql-code-generator).
    The build is non-fatal: verify still reports a real failure."""
    for marker, tool in (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn")):
        repo = _mk(tmp_path / tool, {"a.ts": "1\n", "package.json": "{}", marker: "x\n"})
        df = render_dockerfile(fingerprint(repo), repo).dockerfile
        assert "run build" in df, tool
        assert "|| true" in df, tool


# --- which python tool: the manifest and the repo's own recipe ---------------
#
# Filename matching cannot tell setuptools, hatch, flit, pdm, poetry and uv
# apart — they all ship a pyproject.toml — and guessing wrong produces an image
# that builds with NONE of the target's dependencies, which silently degrades
# executed-PoC confirmation to proving that a hello-world ran.

def test_poetry_without_a_committed_lockfile_is_still_poetry(tmp_path):
    """The regression guard for the lockfile rule: poetry 1.x keeps deps under
    [tool.poetry.dependencies], where `pip install -e .` cannot see them. A
    project that never committed poetry.lock must still be built with poetry."""
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "pyproject.toml": ("[tool.poetry]\nname='x'\n\n"
                           "[tool.poetry.dependencies]\nrequests='*'\n"),
    })
    fp = fingerprint(repo)
    assert "poetry" in fp.build_systems
    r = render_dockerfile(fp, repo)
    assert "poetry install" in r.dockerfile


def test_tool_uv_table_without_a_lockfile_is_uv(tmp_path):
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "pyproject.toml": "[project]\nname='x'\n\n[tool.uv]\ndev-dependencies=[]\n",
    })
    fp = fingerprint(repo)
    assert "uv" in fp.build_systems
    assert "uv pip install --system" in render_dockerfile(fp, repo).dockerfile


def test_ci_naming_a_tool_beats_a_missing_marker_file(tmp_path):
    """The repo's own workflow is a STATEMENT of how it builds; a marker file is
    only an inference. A uv project that never committed uv.lock still gets uv."""
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "pyproject.toml": "[project]\nname='x'\n\n[build-system]\nrequires=['setuptools']\n",
        ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: uv sync --frozen\n",
    })
    fp = fingerprint(repo)
    assert "uv" in fp.recipe_tools
    assert "uv" not in fp.build_systems          # no uv.lock, no [tool.uv]
    assert "uv pip install --system" in render_dockerfile(fp, repo).dockerfile


def test_recipe_commands_are_evidence_not_a_script_to_transplant(tmp_path):
    """Only the tool NAME is taken. CI runs against a runner with secrets,
    services and caches this container does not have, so copying its commands
    would fail in ways that look like the target's fault."""
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "pyproject.toml": "[project]\nname='x'\n",
        ".github/workflows/ci.yml": (
            "jobs:\n  t:\n    steps:\n"
            "      - run: uv sync --extra dev --index-url $SECRET_INDEX\n"
            "      - run: ./scripts/needs-a-database.sh\n"
        ),
    })
    r = render_dockerfile(fingerprint(repo), repo)
    assert "uv pip install --system" in r.dockerfile      # our template
    assert "SECRET_INDEX" not in r.dockerfile
    assert "needs-a-database" not in r.dockerfile


def test_pipfile_only_repo_gets_a_python_ecosystem(tmp_path):
    """A Pipfile's dependencies live nowhere pip can read, and a Pipfile-only
    repo previously matched no python ecosystem at all."""
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "Pipfile": "[packages]\nrequests = '*'\n",
    })
    fp = fingerprint(repo)
    assert "pipenv" in fp.build_systems
    r = render_dockerfile(fp, repo)
    assert "pipenv install --system" in r.dockerfile


def test_requires_python_floor_raises_the_base_image(tmp_path):
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "pyproject.toml": "[project]\nname='x'\nrequires-python='>=3.12'\n",
    })
    fp = fingerprint(repo)
    assert fp.version_floors.get("python") == "3.12"
    assert "python:3.12-slim" in render_dockerfile(fp, repo).dockerfile


def test_an_exact_python_pin_outranks_a_ci_matrix(tmp_path):
    """A CI matrix lists what the project TESTS on; .python-version states what
    it develops on. The pin wins, and the matrix must not silently override it."""
    repo = _mk(tmp_path, {
        "app.py": "x=1\n",
        "pyproject.toml": "[project]\nname='x'\n",
        ".python-version": "3.11\n",
        ".github/workflows/ci.yml": (
            "jobs:\n  t:\n    strategy:\n      matrix:\n"
            "        python-version: ['3.11', '3.12', '3.13']\n"
        ),
    })
    fp = fingerprint(repo)
    assert fp.version_pins.get("python") == "3.11"
    assert "python:3.11-slim" in render_dockerfile(fp, repo).dockerfile


# --- the pip dependency probe, run for real ---------------------------------
#
# This probe is the honesty mechanism: it is what stops "the image built" from
# being reported as "the environment is ready". It reported MISSING against a
# real target (worldbank/data360-mcp) whose every dependency imported fine, so
# these run the actual shell rather than asserting on its text.

def _pip_available() -> bool:
    """Is there a pip that can list installed packages? A uv-created venv has
    none, and the probe's own fallback then (correctly) declines to judge —
    which is a different behaviour from the one these tests are pinning."""
    for cmd in (["pip", "freeze"], ["python3", "-m", "pip", "freeze"]):
        try:
            if subprocess.run(cmd, capture_output=True, timeout=30).returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


_HAS_PIP = _pip_available()


def _run_pip_probe(tmp_path, requirements: str):
    from vash.provision.dockerfile import ECOSYSTEM_TEMPLATES
    (tmp_path / "requirements.txt").write_text(requirements)
    return subprocess.run(["sh", "-c", ECOSYSTEM_TEMPLATES["pip"]["deps"]],
                          cwd=tmp_path, capture_output=True, text=True)


@pytest.mark.skipif(not _HAS_PIP, reason="no pip available to list packages")
def test_pip_probe_skips_platform_markered_requirements(tmp_path):
    """`pywin32 ; sys_platform == "win32"` can never install on the linux image.
    Demanding it made the probe fail permanently for any project depending on
    keyring/colorama — and a check that always fails gets ignored."""
    p = _run_pip_probe(tmp_path,
                       'pywin32==306 ; sys_platform == "win32"\n'
                       'colorama==0.4.6 ; platform_system == "Windows"\n')
    assert p.returncode == 0, p.stdout + p.stderr


@pytest.mark.skipif(not _HAS_PIP, reason="no pip available to list packages")
def test_pip_probe_matches_a_direct_url_requirement_by_name(tmp_path):
    """`name @ git+https://...` is one name and one URL. pip freeze already
    dropped the URL; the wanted side did not, so no git dependency could ever
    match. pytest is installed in the environment running this test."""
    p = _run_pip_probe(tmp_path, "pytest @ git+https://example.invalid/pytest.git\n")
    assert p.returncode == 0, p.stdout + p.stderr


@pytest.mark.skipif(not _HAS_PIP, reason="no pip available to list packages")
def test_pip_probe_still_reports_a_genuinely_absent_package(tmp_path):
    """The point of the two fixes above is to remove false alarms, not the
    alarm."""
    p = _run_pip_probe(tmp_path, "vash-definitely-not-installed-xyz==1.0\n")
    assert p.returncode == 1
    assert "MISSING DEPENDENCIES" in p.stdout
    assert "vash-definitely-not-installed-xyz" in p.stdout


@pytest.mark.skipif(not _HAS_PIP, reason="no pip available to list packages")
def test_pip_probe_normalises_names_per_pep503(tmp_path):
    """`_` and `.` and case all fold to `-`, so a requirement and the installed
    distribution are compared as the same package."""
    p = _run_pip_probe(tmp_path, "PyTest\n")
    assert p.returncode == 0, p.stdout + p.stderr


def test_pip_probe_declines_to_judge_when_it_cannot_list_packages():
    """The quietest failure produced the loudest false alarm: `pip freeze` on an
    image without pip printed nothing, the wanted set was compared against an
    empty set, and EVERY dependency was reported missing. The probe now tries
    several ways to list packages and, failing all of them, says so."""
    from vash.provision.dockerfile import DEPS_UNKNOWN_MARKER, ECOSYSTEM_TEMPLATES
    probe = ECOSYSTEM_TEMPLATES["pip"]["deps"]
    assert DEPS_UNKNOWN_MARKER in probe
    for candidate in ("pip3", "python3 -m pip", "uv pip"):
        assert candidate in probe
