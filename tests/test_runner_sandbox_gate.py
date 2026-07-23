"""Tests for the sandbox gate in `runner.run_agent()` (R1).

R1 restores audit's Hunt PoC execution (compiling/running proof-of-concept
code against the target), which requires Bash. That is only safe inside an
active isolation sandbox (a container — `/.dockerenv` present, or
`VASH_SANDBOX=1`). This file pins the central, stage-agnostic safety
invariant that makes it safe: `run_agent()` strips `Bash` out of
`allowed_tools` whenever `vash.sandbox.is_sandboxed()` is False, no matter
what `config/stages.yaml` grants a given stage. Inside a sandbox, Bash
passes through unchanged.

All tests here are OFFLINE and hermetic. The real `run_agent()` runs (so the
gate itself is genuinely exercised), but `_run_agent_once` — the function
that actually opens a `ClaudeSDKClient` session — is monkeypatched to a fake
that just records the `allowed_tools` it was called with and returns a
canned `AgentResult`. Nothing is ever executed, no network, no SDK. The
sandbox signal itself is monkeypatched too (mirrors tests/test_sandbox.py) —
never depend on the ambient host/CI environment.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from vash import runner, sandbox
from vash.runner import AgentResult, run_agent


@pytest.fixture(autouse=True)
def _hermetic_sandbox_signals(monkeypatch, tmp_path):
    """Known "definitely not sandboxed" baseline for every test in this
    file; individual tests override one or both signals as needed. See
    tests/test_sandbox.py for why both signals must be repointed rather
    than relying on the host actually running the suite."""
    monkeypatch.delenv("VASH_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "_DOCKERENV", tmp_path / "no-such-dockerenv")


def _capture_allowed_tools(monkeypatch, captured: list[list[str]]):
    async def fake_run_agent_once(*, allowed_tools, artifact_dir, artifact_name,
                                   **_kw) -> AgentResult:
        captured.append(list(allowed_tools))
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload={"ok": True}, cost_usd=0.0, input_tokens=0, output_tokens=0,
            cache_read_tokens=0, cache_creation_tokens=0, num_turns=1,
            duration_ms=1, session_id="stub", artifact_path=ap, repair_used=False,
            raw_result_message={},
        )
    monkeypatch.setattr(runner, "_run_agent_once", fake_run_agent_once)


async def _run(tmp_path: Path, *, stage: str, allowed_tools: list[str]) -> None:
    await run_agent(
        stage=stage,
        prompt_file=tmp_path / "p.md",
        user_input={},
        schema_file=tmp_path / "s.json",
        allowed_tools=allowed_tools,
        model="claude-sonnet-5",
        cwd=tmp_path / "cwd",
        artifact_dir=tmp_path / "art",
        artifact_name="task1",
    )


# ─────────────────────────────────────────────────────────────────────────
# The safety invariant: no sandbox -> Bash stripped, regardless of stage.
# ─────────────────────────────────────────────────────────────────────────

async def test_bash_stripped_when_not_sandboxed(tmp_path: Path, monkeypatch) -> None:
    captured: list[list[str]] = []
    _capture_allowed_tools(monkeypatch, captured)

    await _run(tmp_path, stage="hunt", allowed_tools=["Read", "Grep", "Glob", "Bash"])

    assert captured == [["Read", "Grep", "Glob"]]


async def test_bash_stripped_when_not_sandboxed_regardless_of_stage(
    tmp_path: Path, monkeypatch
) -> None:
    """The gate is stage-agnostic by design — it protects Recon/Trace's Bash
    just as much as Hunt's, since none of them may execute on a bare host."""
    captured: list[list[str]] = []
    _capture_allowed_tools(monkeypatch, captured)

    await _run(tmp_path, stage="trace", allowed_tools=["Read", "Grep", "Glob", "Bash"])

    assert captured == [["Read", "Grep", "Glob"]]


# ─────────────────────────────────────────────────────────────────────────
# Sandboxed -> Bash retained.
# ─────────────────────────────────────────────────────────────────────────

async def test_bash_retained_when_sandboxed_via_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VASH_SANDBOX", "1")
    captured: list[list[str]] = []
    _capture_allowed_tools(monkeypatch, captured)

    await _run(tmp_path, stage="hunt", allowed_tools=["Read", "Grep", "Glob", "Bash"])

    assert captured == [["Read", "Grep", "Glob", "Bash"]]


async def test_bash_retained_when_sandboxed_via_dockerenv(tmp_path: Path, monkeypatch) -> None:
    marker = tmp_path / "dockerenv-present"
    marker.write_text("")
    monkeypatch.setattr(sandbox, "_DOCKERENV", marker)
    captured: list[list[str]] = []
    _capture_allowed_tools(monkeypatch, captured)

    await _run(tmp_path, stage="hunt", allowed_tools=["Read", "Grep", "Glob", "Bash"])

    assert captured == [["Read", "Grep", "Glob", "Bash"]]


# ─────────────────────────────────────────────────────────────────────────
# Stages that never request Bash are untouched either way.
# ─────────────────────────────────────────────────────────────────────────

async def test_no_bash_requested_is_unaffected_when_not_sandboxed(
    tmp_path: Path, monkeypatch
) -> None:
    captured: list[list[str]] = []
    _capture_allowed_tools(monkeypatch, captured)

    await _run(tmp_path, stage="validate", allowed_tools=["Read", "Grep", "Glob"])

    assert captured == [["Read", "Grep", "Glob"]]


async def test_no_bash_requested_is_unaffected_when_sandboxed(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("VASH_SANDBOX", "1")
    captured: list[list[str]] = []
    _capture_allowed_tools(monkeypatch, captured)

    await _run(tmp_path, stage="validate", allowed_tools=["Read", "Grep", "Glob"])

    assert captured == [["Read", "Grep", "Glob"]]


# ─────────────────────────────────────────────────────────────────────────
# Static-only-mode notice is logged exactly when the gate actually fires.
# ─────────────────────────────────────────────────────────────────────────

async def test_bash_stripped_logs_static_only_notice(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    _capture_allowed_tools(monkeypatch, [])

    with caplog.at_level(logging.INFO, logger="vash.runner"):
        await _run(tmp_path, stage="hunt", allowed_tools=["Read", "Grep", "Glob", "Bash"])

    assert "Bash stripped" in caplog.text
    assert "hunt" in caplog.text
    assert "VASH_SANDBOX" in caplog.text


async def test_bash_retained_logs_no_static_only_notice(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    monkeypatch.setenv("VASH_SANDBOX", "1")
    _capture_allowed_tools(monkeypatch, [])

    with caplog.at_level(logging.INFO, logger="vash.runner"):
        await _run(tmp_path, stage="hunt", allowed_tools=["Read", "Grep", "Glob", "Bash"])

    assert "Bash stripped" not in caplog.text
