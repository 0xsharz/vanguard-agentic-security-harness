from pathlib import Path
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


def test_no_known_ecosystem_returns_none(tmp_path):
    repo = _mk(tmp_path, {"README.md": "hi\n"})
    r = render_dockerfile(fingerprint(repo), repo)
    assert r.source == "none"
    assert r.dockerfile is None
