"""Run the generated security test against the patched and the unpatched copy.

This is the ONLY part of remediation that executes anything. Everything else —
the patch agent, the post-gate, the diff — reads and writes files. Because this
runs code that came out of the target repository, the caller MUST have passed
:func:`vash.sandbox.require` before calling in here; this module does not decide
permission, it assumes it was already granted.

**The trap this module exists to avoid.** The workspace deliberately excludes
``node_modules``, ``.venv``, ``build`` and friends — that exclusion is what keeps
a per-finding copy cheap. It also means the workspace holds the target's
*source* and none of its *dependencies*. Run `pytest` in it and the first import
fails, and a failed import looks exactly like a failing security test. A
verification pass that cannot tell

    "the test failed because the bug is present"          (evidence)

from

    "the test failed because `requests` is not installed"  (noise)

is worse than no verification at all: it would report the vulnerable state as
*proven* for every dependency-carrying target. So the two are separated at the
runner level — a missing dependency surfaces as an import/module-resolution
error, a real RED as an assertion failure — and anything that is not clearly one
of the two is reported as ``not_attempted``.

That asymmetry is deliberate and is the same honesty rule the Phase 3 observers
follow: **absence of verification must never read as success.** When in doubt
this module says it did not verify, never that it did.

The comparison itself is cheap because the workspace already has a baseline
commit: run the test against the patched tree, `git checkout` the finding's
files back to the baseline, run it again. RED→GREEN is the only outcome that
earns ``verified``.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path

from vash.remediation.diffcapture import safe_relative_path

log = logging.getLogger(__name__)

# --- verdicts (what goes on the record) -------------------------------------
VERIFIED = "verified"            # RED without the patch, GREEN with it
NOT_VERIFIED = "not_verified"    # the test ran, and did not demonstrate a fix
NOT_ATTEMPTED = "not_attempted"  # nothing was proven either way — say so

# --- per-run outcomes (internal) --------------------------------------------
PASS, FAIL, ERROR = "pass", "fail", "error"

DEFAULT_TIMEOUT = 120            # seconds per run; two runs per finding
_MAX_LOG = 4000                  # tail of the combined output kept on the record

# A test file the agent named unsafely (or one that collides with a file the
# patch touches) is written here instead — repo root, so that `import app` and
# `require('./app')` resolve the way they would from the project's own tests.
_FALLBACK_STEM = "vash_security_test"

# Shell/OS-level "this could not run at all" signals, independent of language.
_UNMET_GENERIC: tuple[str, ...] = (
    "command not found",
    "No such file or directory",
)


@dataclass(frozen=True)
class TestRunner:
    """How to run one security test, and how to recognise that the environment
    — not the code under test — is what failed.

    `unmet` holds the substrings that mean "a dependency or module could not be
    resolved". They are checked BEFORE a non-zero exit is read as a failing
    test, because misreading this direction is the one error that manufactures
    false evidence.
    """

    language: str
    argv: tuple[str, ...]
    unmet: tuple[str, ...]

    @property
    def label(self) -> str:
        return " ".join(self.argv)


_PYTEST = TestRunner(
    language="python",
    # -p no:cacheprovider: never write .pytest_cache into the tree being diffed.
    argv=("python3", "-m", "pytest", "-q", "-p", "no:cacheprovider"),
    unmet=(
        "ModuleNotFoundError",
        "ImportError",
        "No module named",
        "ImportError while importing test module",
        "error while loading conftest",
    ),
)

_PYTHON = TestRunner(
    language="python",
    argv=("python3",),
    unmet=("ModuleNotFoundError", "ImportError", "No module named"),
)

_NODE = TestRunner(
    language="javascript",
    argv=("node",),
    unmet=(
        "Cannot find module",
        "ERR_MODULE_NOT_FOUND",
        "MODULE_NOT_FOUND",
        "ERR_REQUIRE_ESM",
    ),
)

# Only languages whose single-file test actually runs with no build step are
# claimed. Java/Go/C#/TypeScript tests need a compiler, a test framework on the
# classpath, or module context this module does not set up — claiming them would
# produce `not_attempted` with a confusing reason instead of an honest one.
_SUFFIX_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".cjs": "javascript",
    ".mjs": "javascript",
}


def _has_pytest() -> bool:
    """Is pytest importable by the interpreter that would run the test?

    Cheap, runs no target code, and decides between `python3 -m pytest test.py`
    and `python3 test.py` — generated security tests are written in both shapes.
    """
    try:
        proc = subprocess.run(
            ["python3", "-c", "import pytest"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def runner_for(suffix: str) -> TestRunner | None:
    """The runner for a test file suffix, or None when that language is not
    executable here. None is a normal outcome, not an error."""
    lang = _SUFFIX_LANGUAGE.get((suffix or "").lower())
    if lang == "python":
        return _PYTEST if _has_pytest() else _PYTHON
    if lang == "javascript":
        return _NODE
    return None


def _not_attempted(reason: str, **extra) -> dict:
    log.info("[remediate] verify: not attempted — %s", reason)
    return {"verdict": NOT_ATTEMPTED, "reason": reason, **extra}


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the whole process group. A security test may spawn children (that
    is often the vulnerability), and killing only the direct child would leave
    them running after the workspace is destroyed."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):       # pragma: no cover - race
        try:
            proc.kill()
        except OSError:
            pass


def _run_once(runner: TestRunner, workspace: Path, rel: str,
              timeout: int) -> tuple[str, str]:
    """Run the test once. Returns (outcome, combined output).

    `start_new_session=True` puts the test in its own process group so a hung
    test and everything it spawned can be killed together.
    """
    argv = [*runner.argv, rel]
    # The workspace root goes on PYTHONPATH because a generated test usually
    # lands in `tests/` and imports the package from the repo root. Python puts
    # the SCRIPT's own directory on sys.path, not the cwd, so `python3
    # tests/test_x.py` cannot see `app/` — and the resulting ModuleNotFoundError
    # is indistinguishable from a genuinely missing dependency, so every test
    # would come back `not_attempted`. This is what pytest's rootdir insertion
    # does for the project's own suite; the same courtesy is owed here.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (f"{workspace}{os.pathsep}{existing}" if existing
                         else str(workspace))
    try:
        proc = subprocess.Popen(
            argv, cwd=str(workspace), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )
    except OSError as e:
        # The runner binary itself is missing — an environment problem.
        return ERROR, f"{type(e).__name__}: {e}"

    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            out, _ = proc.communicate(timeout=15)
        except subprocess.SubprocessError:      # pragma: no cover - defensive
            out = ""
        return ERROR, f"{out or ''}\n[vash] timed out after {timeout}s"

    out = out or ""
    if proc.returncode == 0:
        return PASS, out
    if proc.returncode == 127 or any(m in out for m in runner.unmet + _UNMET_GENERIC):
        # Unresolved dependency / missing interpreter — NOT a failing test.
        return ERROR, out
    return FAIL, out


def _restore_baseline(workspace: Path, paths: list[str]) -> bool:
    """Put the finding's files back to the pre-patch baseline commit.

    The patch has already been captured by this point, so discarding it here
    costs nothing and gives the RED half of the comparison.
    """
    if not paths:
        return False
    try:
        proc = subprocess.run(
            ["git", "-C", str(workspace), "checkout", "--", *paths],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("[remediate] verify: could not restore baseline: %s", e)
        return False
    if proc.returncode != 0:
        log.warning("[remediate] verify: git checkout failed: %s",
                    (proc.stderr or "").strip()[:200])
        return False
    return True


def _tail(text: str) -> str:
    text = text or ""
    return text if len(text) <= _MAX_LOG else "…(truncated)\n" + text[-_MAX_LOG:]


def _test_destination(workspace: Path, test_path: str | None,
                      finding_paths: list[str]) -> tuple[str, str]:
    """Where to write the security test inside the workspace, and its suffix.

    The agent's own `test_path` is used when it is safe AND does not collide
    with a file the patch touches. That second condition is not hypothetical:
    the baseline restore below runs `git checkout` over the finding's files, so
    a test written to one of them would be silently replaced by the target's
    original content and the "RED" run would be measuring the wrong file.
    """
    suffix = Path(test_path).suffix if test_path else ""
    rel = safe_relative_path(workspace, test_path or "")
    if rel and rel not in finding_paths:
        return rel, suffix or Path(rel).suffix
    suffix = suffix or ".py"
    return f"{_FALLBACK_STEM}{suffix}", suffix


def verify_patch(workspace: Path, *, test_path: str | None, test_source: str,
                 finding_files: list[str],
                 timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run the security test with and without the patch; return a verdict dict.

    Executes target code — the caller must have cleared :func:`vash.sandbox.require`.
    Never raises: every failure path returns ``not_attempted`` with a reason,
    because the alternative (an exception, or a guess) would either abort a batch
    or invent evidence.

    | observed                                    | verdict          |
    |---------------------------------------------|------------------|
    | fails without the patch, passes with it      | ``verified``     |
    | passes without the patch                     | ``not_verified`` |
    | still fails with the patch                   | ``not_verified`` |
    | import/resolution error on either run        | ``not_attempted``|
    """
    workspace = Path(workspace)
    if not (test_source or "").strip():
        return _not_attempted("the agent produced no security test to run")

    finding_paths = [
        p for p in (safe_relative_path(workspace, f) for f in (finding_files or []))
        if p
    ]
    if not finding_paths:
        return _not_attempted("this finding names no file inside the workspace, "
                              "so the unpatched state cannot be restored")

    rel, suffix = _test_destination(workspace, test_path, finding_paths)
    runner = runner_for(suffix)
    if runner is None:
        return _not_attempted(
            f"no test runner for '{suffix or 'unknown'}' files — VASH runs "
            "python and javascript security tests only; this one was not run",
            test_path=rel,
        )

    dest = workspace / rel
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(test_source, encoding="utf-8")
    except OSError as e:
        return _not_attempted(f"could not write the security test into the "
                              f"workspace: {type(e).__name__}: {e}",
                              test_path=rel)

    common = {"runner": runner.label, "test_path": rel, "language": runner.language}

    # 1. PATCHED (the workspace as the agent left it). The diff was already
    #    captured, so whatever happens to the tree from here is free.
    post, post_out = _run_once(runner, workspace, rel, timeout)
    if post == ERROR:
        return _not_attempted(
            "the security test could not run against the patched code "
            "(missing dependency, interpreter, or timeout) — the workspace "
            "carries the target's source but not its installed dependencies",
            post_patch=post, log=_tail(post_out), **common)

    # 2. UNPATCHED. Same test, baseline code.
    if not _restore_baseline(workspace, finding_paths):
        return _not_attempted("could not restore the unpatched state to "
                              "compare against", post_patch=post,
                              log=_tail(post_out), **common)
    pre, pre_out = _run_once(runner, workspace, rel, timeout)

    combined = _tail(f"--- with the patch ---\n{post_out}\n"
                     f"--- without the patch ---\n{pre_out}")
    if pre == ERROR:
        return _not_attempted(
            "the security test could not run against the unpatched code "
            "(missing dependency, interpreter, or timeout), so there is "
            "nothing to compare the patched run against",
            pre_patch=pre, post_patch=post, log=combined, **common)

    result = {"pre_patch": pre, "post_patch": post, "log": combined, **common}
    if pre == PASS:
        return {
            "verdict": NOT_VERIFIED,
            "reason": ("the security test PASSES without the patch, so it does "
                       "not exercise the vulnerability — the patch is unproven"),
            **result,
        }
    if post == FAIL:
        return {
            "verdict": NOT_VERIFIED,
            "reason": ("the security test still FAILS with the patch applied — "
                       "the patch does not fix what the test checks"),
            **result,
        }
    log.info("[remediate] verify: RED without the patch, GREEN with it (%s)", rel)
    return {
        "verdict": VERIFIED,
        "reason": ("the security test fails without the patch and passes with "
                   "it (RED→GREEN)"),
        **result,
    }
