"""The disposable workspace, the diff git computes from it, and the post-gate.

These use real files and real git — the point of the design is that git produces
the diff, so mocking git would test nothing that matters.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from vash.remediation import (
    capture_diff,
    changed_paths,
    enforce,
    safe_relative_path,
    workspace_for,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "notes.py").write_text("def read(p):\n    return open(p).read()\n")
    (repo / "app" / "other.py").write_text("X = 1\n")
    (repo / "README.md").write_text("hi\n")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "junk.js").write_text("//" + "x" * 1000)
    return repo


def _hash_tree(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


# ---- workspace -------------------------------------------------------------

def test_workspace_copies_the_source_and_skips_noise(tmp_path):
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        assert ws is not None
        assert (ws / "app" / "notes.py").read_text().startswith("def read")
        assert (ws / "README.md").is_file()
        assert not (ws / "node_modules").exists()      # noise not duplicated
        assert (ws / ".git").is_dir()                  # fresh baseline for diffing


def test_workspace_is_removed_afterwards(tmp_path):
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        captured = ws
    assert not captured.exists()


def test_workspace_is_removed_even_when_the_caller_raises(tmp_path):
    """Cleanup must not depend on the happy path — a disposable copy that
    survives an exception is a copy of the user's source left in /tmp."""
    repo = _repo(tmp_path)
    captured = None
    with pytest.raises(RuntimeError):
        with workspace_for(repo) as ws:
            captured = ws
            raise RuntimeError("boom")
    assert captured is not None and not captured.exists()


def test_editing_the_workspace_never_touches_the_target(tmp_path):
    repo = _repo(tmp_path)
    before = _hash_tree(repo)
    with workspace_for(repo) as ws:
        (ws / "app" / "notes.py").write_text("TOTALLY DIFFERENT\n")
        (ws / "app" / "brand_new.py").write_text("x = 1\n")
        (ws / "README.md").unlink()
    assert _hash_tree(repo) == before


def test_oversized_repo_is_refused_rather_than_copied(tmp_path):
    repo = _repo(tmp_path)
    (repo / "big.bin").write_bytes(b"x" * 20_000)
    with workspace_for(repo, max_bytes=1_000) as ws:
        assert ws is None                              # caller must degrade


def test_missing_target_yields_none(tmp_path):
    with workspace_for(tmp_path / "nope") as ws:
        assert ws is None


# ---- diff capture ----------------------------------------------------------

def test_diff_of_a_real_edit_applies_cleanly(tmp_path):
    """The whole point: a diff produced by git is valid by construction, so the
    'corrupt patch' failures of hand-written diffs cannot occur."""
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        (ws / "app" / "notes.py").write_text(
            "def read(p):\n"
            "    if '..' in p:\n"
            "        raise ValueError('nope')\n"
            "    return open(p).read()\n"
        )
        diff = capture_diff(ws, ["app/notes.py"])
        assert diff and "raise ValueError" in diff
        # and it really applies to the ORIGINAL tree
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        r = subprocess.run(["git", "-C", str(repo), "apply", "--check", "-"],
                           input=diff, text=True, capture_output=True)
        assert r.returncode == 0, r.stderr


def test_diff_includes_a_newly_created_file(tmp_path):
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        (ws / "app" / "sanitize.py").write_text("def clean(s):\n    return s\n")
        diff = capture_diff(ws, ["app/sanitize.py"])
        assert diff and "def clean" in diff


def test_no_edit_yields_no_diff(tmp_path):
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        assert capture_diff(ws, ["app/notes.py"]) is None


def test_diff_is_scoped_to_the_findings_own_files(tmp_path):
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        (ws / "app" / "notes.py").write_text("EDITED\n")
        (ws / "app" / "other.py").write_text("ALSO EDITED\n")
        diff = capture_diff(ws, ["app/notes.py"])
        assert "notes.py" in diff and "other.py" not in diff


@pytest.mark.parametrize("bad", [
    "/etc/passwd", "../../escape.py", r"\\attacker\share\x", "C:/Windows/hosts",
])
def test_paths_escaping_the_workspace_are_rejected(tmp_path, bad):
    """An absolute/UNC/drive ref reaching a git pathspec is not just a stray
    write: on a Windows runner it opens an outbound SMB connection and leaks the
    runner's credential hash."""
    assert safe_relative_path(tmp_path, bad) is None


def test_a_location_suffix_is_stripped(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("1")
    assert safe_relative_path(tmp_path, "app/x.py:14-20") == "app/x.py"


# ---- post-gate -------------------------------------------------------------

def test_out_of_scope_edits_are_detected_and_reverted(tmp_path):
    """The agent reports what it edited; git is asked what it ACTUALLY edited.
    An unreported change would otherwise ride along in the patch."""
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        (ws / "app" / "notes.py").write_text("legitimate fix\n")
        (ws / "app" / "other.py").write_text("SNEAKY\n")       # not this finding's file
        (ws / "evil_new.py").write_text("also sneaky\n")
        res = enforce(ws, ["app/notes.py"])
        assert res.allowed == ["app/notes.py"]
        assert set(res.reverted) == {"app/other.py", "evil_new.py"}
        assert not res.clean
        assert (ws / "app" / "other.py").read_text() == "X = 1\n"   # restored
        assert not (ws / "evil_new.py").exists()                    # removed
        assert (ws / "app" / "notes.py").read_text() == "legitimate fix\n"


def test_a_clean_run_reports_nothing_reverted(tmp_path):
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        (ws / "app" / "notes.py").write_text("fix\n")
        res = enforce(ws, ["app/notes.py"])
        assert res.clean and res.reverted == []


def test_scope_matching_tolerates_a_location_suffix(tmp_path):
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        (ws / "app" / "notes.py").write_text("fix\n")
        res = enforce(ws, ["app/notes.py:7-11"])
        assert res.reverted == []


def test_changed_paths_parses_a_rename_whose_original_has_a_space(tmp_path):
    """A rename record is followed by a bare token holding the original path.
    Stripping the 3-char status prefix from that token mangles a name whose
    third character is a space — and the mangled name would slip past scope."""
    repo = tmp_path / "t"
    (repo / "ab cde").mkdir(parents=True)
    (repo / "ab cde" / "x.py").write_text("1\n")
    with workspace_for(repo) as ws:
        subprocess.run(["git", "-C", str(ws), "mv", "ab cde/x.py", "moved.py"],
                       capture_output=True)
        paths = changed_paths(ws)
        assert "ab cde/x.py" in paths, paths      # original, unmangled
        assert "moved.py" in paths


def test_postgate_never_raises_on_a_non_git_directory(tmp_path):
    res = enforce(tmp_path, ["a.py"])
    assert res.changed == [] and res.clean


def test_the_generated_test_file_is_reverted_without_crying_wolf(tmp_path, caplog):
    """The agent is asked for a security test and often writes it to disk too.
    Reverting it is right — it must not end up inside the patch — but reporting
    it as an out-of-scope edit would fire a warning on nearly every finding, and
    a warning that always fires is one nobody reads when it finally matters."""
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        (ws / "app" / "notes.py").write_text("fix\n")
        (ws / "tests").mkdir()
        (ws / "tests" / "test_traversal.py").write_text("def test(): ...\n")
        (ws / "app" / "other.py").write_text("GENUINELY SNEAKY\n")
        with caplog.at_level("WARNING"):
            res = enforce(ws, ["app/notes.py"],
                          expected_extra=["tests/test_traversal.py"])

    assert res.expected == ["tests/test_traversal.py"]
    assert res.reverted == ["app/other.py"]          # the real one still shouts
    assert "test_traversal" not in caplog.text       # and the benign one does not
    assert "other.py" in caplog.text


def test_an_expected_path_is_still_kept_out_of_the_patch(tmp_path):
    repo = _repo(tmp_path)
    with workspace_for(repo) as ws:
        (ws / "gen_test.py").write_text("def test(): ...\n")
        enforce(ws, ["app/notes.py"], expected_extra=["gen_test.py"])
        assert not (ws / "gen_test.py").exists()     # reverted, not merely excused


# ---- symlinks: the escape the copy would otherwise carry with it -----------

def test_a_symlink_pointing_into_the_target_cannot_be_written_through(tmp_path):
    """The target repo is untrusted. A repo containing an absolute symlink to
    its own file gives the agent something that looks local but writes straight
    into the real repository — defeating every other control, because the agent
    never has to learn where the target is: the target came to it."""
    repo = _repo(tmp_path)
    real = repo / "app" / "notes.py"
    (repo / "shortcut.py").symlink_to(real)
    before = _hash_tree(repo)

    with workspace_for(repo) as ws:
        assert not (ws / "shortcut.py").is_symlink()   # not carried into the copy
        (ws / "shortcut.py").write_text("PWNED\n")     # now just a local file

    assert _hash_tree(repo) == before


def test_a_symlink_pointing_anywhere_outside_is_removed(tmp_path):
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("safe\n")
    repo = _repo(tmp_path)
    (repo / "out.txt").symlink_to(outside)
    with workspace_for(repo) as ws:
        assert not (ws / "out.txt").is_symlink()
        (ws / "out.txt").write_text("PWNED\n")
    assert outside.read_text() == "safe\n"


def test_a_symlinked_directory_escaping_the_repo_is_removed(tmp_path):
    """A link to a DIRECTORY is the wider hole: every file under it becomes
    writable, not just one."""
    outside = tmp_path / "secrets"
    outside.mkdir()
    (outside / "key.txt").write_text("safe\n")
    repo = _repo(tmp_path)
    (repo / "cfg").symlink_to(outside, target_is_directory=True)
    with workspace_for(repo) as ws:
        assert not (ws / "cfg").exists()
    assert (outside / "key.txt").read_text() == "safe\n"


def test_a_symlink_that_stays_inside_the_repo_is_preserved(tmp_path):
    """Only escapes are removed — an in-repo link is legitimate and its removal
    would silently change the code under review."""
    repo = _repo(tmp_path)
    (repo / "alias.py").symlink_to(Path("app") / "notes.py")   # relative, inside
    with workspace_for(repo) as ws:
        assert (ws / "alias.py").is_symlink()
        assert (ws / "alias.py").read_text().startswith("def read")
