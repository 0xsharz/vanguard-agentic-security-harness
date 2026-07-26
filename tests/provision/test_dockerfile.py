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
    repo = _mk(tmp_path, {"app.py": "x=1\n", "pyproject.toml": "[tool.poetry]\nname='x'\n"})
    r = render_dockerfile(fingerprint(repo), repo)
    assert r.source == "template"
    assert "python:" in r.dockerfile


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
