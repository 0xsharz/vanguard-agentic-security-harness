from pathlib import Path
from vash.provision.fingerprint import fingerprint, ProjectFingerprint


def _mk(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def test_detects_node_maven_go_and_primary_language(tmp_path):
    repo = _mk(tmp_path, {
        "pkg/app.js": "console.log(1)\n",
        "pkg/util.js": "module.exports = {}\n",
        "svc/Main.java": "class Main {}\n",
        "cmd/main.go": "package main\n",
        "package.json": '{"name":"x","engines":{"node":"20"}}',
        "pom.xml": "<project></project>",
        "go.mod": "module x\n\ngo 1.22\n",
        ".github/workflows/ci.yml": "on: push\n",
    })
    fp = fingerprint(repo)
    assert isinstance(fp, ProjectFingerprint)
    assert "javascript" in fp.languages
    assert "java" in fp.languages
    assert "go" in fp.languages
    assert fp.primary_language == "javascript"          # 2 js files > 1 java/go
    assert set(fp.build_systems) >= {"npm", "maven", "go-modules"}
    assert ".github/workflows/ci.yml" in fp.existing_recipes
    assert fp.version_pins.get("node") == "20"
    assert fp.version_pins.get("go") == "1.22"


def test_empty_repo_is_safe(tmp_path):
    fp = fingerprint(tmp_path)
    assert fp.languages == []
    assert fp.primary_language is None
    assert fp.build_systems == []


def test_repo_under_a_directory_named_build_is_not_emptied(tmp_path):
    """Skip-dirs are matched on the path RELATIVE to the repo — a repo that
    merely lives under `.../build/` must still fingerprint."""
    repo = _mk(tmp_path / "build" / "proj", {"a.py": "1\n", "requirements.txt": "x\n"})
    fp = fingerprint(repo)
    assert fp.primary_language == "python"
    assert "pip" in fp.build_systems


def test_broken_symlink_does_not_abort_the_walk(tmp_path):
    repo = _mk(tmp_path, {"a.py": "1\n"})
    (repo / "dangling").symlink_to(repo / "nope-does-not-exist")
    fp = fingerprint(repo)
    assert fp.primary_language == "python"
