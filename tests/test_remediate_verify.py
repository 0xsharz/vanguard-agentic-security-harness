"""Tests for `vash/remediation/verify.py` — the `--verify` RED/GREEN pass.

These tests DO execute code, unlike the rest of the remediation suite. What
they execute is written here, by us, into a temporary directory: a two-line
module and a two-line test. No target repository is involved and nothing
touches the network, so the suite stays offline and hermetic.

The contract under test is not "does the test pass" — it is **what VASH is
willing to claim**:

  - RED without the patch, GREEN with it            -> ``verified``
  - passes without the patch (test misses the bug)  -> ``not_verified``
  - still fails with the patch                      -> ``not_verified``
  - could not run at all (missing dependency, ...)  -> ``not_attempted``

The fourth row is the one that matters most. The workspace is copied WITHOUT
`node_modules` / `.venv`, so an import error is the expected failure on any
dependency-carrying target — and an import error misread as a failing test
would report the vulnerable state as *proven* for all of them. Absence of
verification must never read as success.

The runner is pinned per test (`_has_pytest` monkeypatched) so a verdict never
depends on whether pytest happens to be importable by whichever `python3` is
first on PATH.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vash.remediation import verify as verify_mod
from vash.remediation.verify import (
    NOT_ATTEMPTED,
    NOT_VERIFIED,
    VERIFIED,
    runner_for,
    verify_patch,
)

# app.py before the fix: hands the string back unchanged.
VULNERABLE = "def clean(s):\n    return s\n"
# app.py after the fix: strips the character the test cares about.
PATCHED = "def clean(s):\n    return s.replace(';', '')\n"

# A security test that is RED against VULNERABLE and GREEN against PATCHED.
# Written as a plain script (not a pytest function) so it behaves identically
# under either python runner.
RED_GREEN_TEST = "from app import clean\nassert ';' not in clean('a;b')\n"


def _git(ws: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(ws), *args],
                   capture_output=True, text=True, check=False, timeout=60)


def _workspace(tmp_path: Path, *, baseline: str = VULNERABLE,
               patched: str = PATCHED) -> Path:
    """A workspace shaped like the real one: a baseline commit holding the
    vulnerable code, and a working tree holding the agent's patch."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text(baseline)
    _git(ws, "init", "-q")
    _git(ws, "config", "user.email", "t@vash.local")
    _git(ws, "config", "user.name", "t")
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "baseline")
    (ws / "app.py").write_text(patched)          # the "patch"
    return ws


@pytest.fixture(autouse=True)
def _plain_python_runner(monkeypatch):
    """Pin the python runner to `python3 <file>`.

    Whether `python3 -m pytest` is available depends on which interpreter is
    first on PATH in the environment running this suite, and the two runners
    report a module-level assertion differently. The pytest path has its own
    test below, which skips when pytest genuinely is not reachable.
    """
    monkeypatch.setattr(verify_mod, "_has_pytest", lambda: False)


# ─────────────────────────────────────────────────────────────────────────────
# The four verdicts
# ─────────────────────────────────────────────────────────────────────────────

def test_red_then_green_is_verified(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    out = verify_patch(ws, test_path="tests/test_sec.py",
                       test_source=RED_GREEN_TEST, finding_files=["app.py"])
    assert out["verdict"] == VERIFIED
    assert (out["pre_patch"], out["post_patch"]) == ("fail", "pass")
    assert "RED→GREEN" in out["reason"] or "RED" in out["reason"]


def test_test_that_passes_without_the_patch_is_not_verified(tmp_path: Path) -> None:
    """The test does not exercise the bug — it would be GREEN on the vulnerable
    code too, so it proves nothing about the patch."""
    ws = _workspace(tmp_path)
    always_true = "from app import clean\nassert clean('ab') == 'ab'\n"
    out = verify_patch(ws, test_path="tests/test_sec.py",
                       test_source=always_true, finding_files=["app.py"])
    assert out["verdict"] == NOT_VERIFIED
    assert out["pre_patch"] == "pass"
    assert "without the patch" in out["reason"]


def test_test_that_still_fails_with_the_patch_is_not_verified(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    impossible = "from app import clean\nassert clean('a;b') == 'nope'\n"
    out = verify_patch(ws, test_path="tests/test_sec.py",
                       test_source=impossible, finding_files=["app.py"])
    assert out["verdict"] == NOT_VERIFIED
    assert out["post_patch"] == "fail"
    assert "still FAILS" in out["reason"]


def test_missing_dependency_is_not_attempted_not_a_failing_test(tmp_path: Path) -> None:
    """THE load-bearing case. The workspace has the target's source but not its
    installed dependencies, so an import error is the *expected* failure on a
    real target. Reading it as RED would report every such target as proven
    vulnerable — and, on the patched side, as proven unfixed."""
    ws = _workspace(tmp_path)
    needs_dep = "import vash_definitely_not_a_real_package_xyz\nassert True\n"
    out = verify_patch(ws, test_path="tests/test_sec.py",
                       test_source=needs_dep, finding_files=["app.py"])
    assert out["verdict"] == NOT_ATTEMPTED
    assert "dependency" in out["reason"]
    assert out.get("pre_patch") is None       # never got as far as the RED half


def test_unsupported_language_is_not_attempted(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    out = verify_patch(ws, test_path="src/PoCTest.java",
                       test_source="class PoCTest {}", finding_files=["app.py"])
    assert out["verdict"] == NOT_ATTEMPTED
    assert ".java" in out["reason"]


def test_no_security_test_is_not_attempted(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    out = verify_patch(ws, test_path="tests/test_sec.py", test_source="   ",
                       finding_files=["app.py"])
    assert out["verdict"] == NOT_ATTEMPTED
    assert "no security test" in out["reason"]


def test_finding_with_no_workspace_relative_file_is_not_attempted(tmp_path: Path) -> None:
    """Without a file to restore, there is no unpatched state to compare
    against — so there is no verdict to give."""
    ws = _workspace(tmp_path)
    out = verify_patch(ws, test_path="tests/test_sec.py",
                       test_source=RED_GREEN_TEST,
                       finding_files=["/etc/passwd", "../escape.py"])
    assert out["verdict"] == NOT_ATTEMPTED
    assert "no file inside the workspace" in out["reason"]


# ─────────────────────────────────────────────────────────────────────────────
# Where the test file lands
# ─────────────────────────────────────────────────────────────────────────────

def test_test_path_colliding_with_a_patched_file_falls_back(tmp_path: Path) -> None:
    """A test written to one of the finding's own files would be wiped by the
    `git checkout` that restores the baseline, and the RED run would then be
    measuring the target's original file instead of the test. It goes to a
    fallback path at the workspace root instead."""
    ws = _workspace(tmp_path)
    out = verify_patch(ws, test_path="app.py", test_source=RED_GREEN_TEST,
                       finding_files=["app.py"])
    assert out["test_path"] == "vash_security_test.py"
    assert out["verdict"] == VERIFIED          # and the comparison still works


def test_escaping_test_path_falls_back_inside_the_workspace(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    ws = _workspace(tmp_path)
    out = verify_patch(ws, test_path="../outside.py", test_source=RED_GREEN_TEST,
                       finding_files=["app.py"])
    assert out["test_path"] == "vash_security_test.py"
    assert not outside.exists()                # nothing was written out of the tree


def test_verification_writes_only_inside_the_workspace(tmp_path: Path) -> None:
    """Everything the pass creates is disposable with the workspace."""
    before = {p for p in tmp_path.rglob("*") if "ws" not in p.parts}
    ws = _workspace(tmp_path)
    verify_patch(ws, test_path="tests/test_sec.py", test_source=RED_GREEN_TEST,
                 finding_files=["app.py"])
    after = {p for p in tmp_path.rglob("*") if "ws" not in p.parts}
    assert before == after


# ─────────────────────────────────────────────────────────────────────────────
# Runner selection
# ─────────────────────────────────────────────────────────────────────────────

def test_runner_for_known_and_unknown_suffixes(monkeypatch) -> None:
    monkeypatch.setattr(verify_mod, "_has_pytest", lambda: False)
    assert runner_for(".py").language == "python"
    assert runner_for(".js").language == "javascript"
    assert runner_for(".mjs").language == "javascript"
    # Deliberately unclaimed: these need a compiler, a framework on the
    # classpath, or module context this module does not set up.
    for suffix in (".java", ".go", ".cs", ".ts", ".rb", ""):
        assert runner_for(suffix) is None


def test_pytest_runner_is_used_when_pytest_is_available(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(verify_mod, "_has_pytest", lambda: True)
    probe = subprocess.run(["python3", "-c", "import pytest"],
                           capture_output=True, timeout=30)
    if probe.returncode != 0:
        pytest.skip("the python3 on PATH cannot import pytest")
    ws = _workspace(tmp_path)
    pytest_style = ("from app import clean\n\n\n"
                    "def test_semicolon_stripped():\n"
                    "    assert ';' not in clean('a;b')\n")
    out = verify_patch(ws, test_path="tests/test_sec.py",
                       test_source=pytest_style, finding_files=["app.py"])
    assert "pytest" in out["runner"]
    assert out["verdict"] == VERIFIED


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_javascript_security_test_runs_under_node(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.js").write_text("module.exports.clean = (s) => s;\n")
    _git(ws, "init", "-q")
    _git(ws, "config", "user.email", "t@vash.local")
    _git(ws, "config", "user.name", "t")
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "baseline")
    (ws / "app.js").write_text(
        "module.exports.clean = (s) => s.split(';').join('');\n")
    js_test = ("const { clean } = require('./app.js');\n"
               "if (clean('a;b').includes(';')) { throw new Error('semicolon survived'); }\n")
    out = verify_patch(ws, test_path="test_sec.js", test_source=js_test,
                       finding_files=["app.js"])
    assert out["verdict"] == VERIFIED
    assert out["language"] == "javascript"
