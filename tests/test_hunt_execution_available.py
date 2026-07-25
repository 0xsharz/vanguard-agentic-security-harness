"""Tests for R1: Hunt's `execution_available` input flag (vash/stages/hunt.py).

Hunt's restored PoC-execution method (prompts/02-hunt.md) needs to know,
per task, whether Bash/PoC execution is actually available for this run.
That decision is resolved ONCE per run by `sandbox.resolve_execution()` in
the orchestrator (F1) and threaded down as `StageContext.execution_enabled`
— the same value `runner.run_agent()` is called with to gate Bash (see
tests/test_runner_sandbox_gate.py). `run_hunt` mirrors `ctx.execution_enabled`
verbatim into every task's `user_input` (rather than re-deriving its own
signal via `vash.sandbox.is_sandboxed()`, which can diverge from the actual
gate) so the model follows the execution-availability rule (attempt +
drop/downgrade vs. reason statically + `needs_poc: true`) instead of
guessing which mode it's in.

Offline + hermetic: `run_agent` is stubbed at `vash.stages.hunt.run_agent`
(the established pattern — see tests/test_validate_cvss.py), results/work
dirs are redirected into tmp_path (mirrors test_pipeline_e2e.py). The
ambient VASH_SANDBOX/.dockerenv signals are set in the "enabled" cases only
to mirror what a realistic sandboxed + dynamic-validation call site looks
like upstream (`sandbox.resolve_execution()` would see them and return
True) — it is `ctx.execution_enabled`, passed explicitly below, that
actually drives the hint, never an ambient signal read directly by this
stage.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import vash.stages._common as common_mod
import vash.stages.hunt as hunt_mod
from vash import sandbox
from vash.config import load_config
from vash.runner import AgentResult
from vash.stages._common import StageContext
from vash.stages.hunt import run_hunt
from vash.state import StateDB

RUN_ID = "r1"
TASK_ID = "t_1"


@pytest.fixture(autouse=True)
def _hermetic_sandbox_signals(monkeypatch, tmp_path):
    monkeypatch.delenv("VASH_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "_DOCKERENV", tmp_path / "no-such-dockerenv")


@pytest.fixture(autouse=True)
def _redirect_results_and_work(monkeypatch, tmp_path):
    # Mirrors tests/test_validate_cvss.py / test_pipeline_e2e.py: never let
    # a stage write into the real repo's results/ or work/ during a test.
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")


def _seed_task(db: StateDB) -> None:
    db.create_run("/repo", RUN_ID)
    db.add_task(RUN_ID, {
        "task_id": TASK_ID, "attack_class": "sql_injection", "scope_hint": "app.py",
        "target_files": ["app.py"], "rationale": "x", "priority": 1,
    })


def _stub_run_agent(monkeypatch, captured: list[dict]):
    async def fake_run_agent(*, user_input, artifact_dir, artifact_name, **_kw) -> AgentResult:
        captured.append(user_input)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload={"task_id": user_input["task_id"], "findings": [], "gaps_observed": []},
            cost_usd=0.0, input_tokens=0, output_tokens=0,
            cache_read_tokens=0, cache_creation_tokens=0, num_turns=1,
            duration_ms=1, session_id="stub", artifact_path=ap, repair_used=False,
            raw_result_message={"usage": {}, "total_cost_usd": 0.0},
        )
    monkeypatch.setattr(hunt_mod, "run_agent", fake_run_agent)


def _ctx(tmp_path: Path, *, execution_enabled: bool = False) -> StageContext:
    return StageContext(run_id=RUN_ID, repo_path=tmp_path, config=load_config(),
                         execution_enabled=execution_enabled)


async def test_execution_available_false_without_sandbox(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict] = []
    _stub_run_agent(monkeypatch, captured)
    db = StateDB(tmp_path / "state.db")
    try:
        _seed_task(db)
        await run_hunt(_ctx(tmp_path, execution_enabled=False), db)
    finally:
        db.close()

    assert len(captured) == 1
    assert captured[0]["execution_available"] is False


async def test_execution_available_true_with_env_sandbox(tmp_path: Path, monkeypatch) -> None:
    # VASH_SANDBOX=1 mirrors the realistic upstream call site (see module
    # docstring); ctx.execution_enabled=True is what actually drives the hint.
    monkeypatch.setenv("VASH_SANDBOX", "1")
    captured: list[dict] = []
    _stub_run_agent(monkeypatch, captured)
    db = StateDB(tmp_path / "state.db")
    try:
        _seed_task(db)
        await run_hunt(_ctx(tmp_path, execution_enabled=True), db)
    finally:
        db.close()

    assert len(captured) == 1
    assert captured[0]["execution_available"] is True


async def test_execution_available_true_with_dockerenv(tmp_path: Path, monkeypatch) -> None:
    marker = tmp_path / "dockerenv-present"
    marker.write_text("")
    monkeypatch.setattr(sandbox, "_DOCKERENV", marker)
    captured: list[dict] = []
    _stub_run_agent(monkeypatch, captured)
    db = StateDB(tmp_path / "state.db")
    try:
        _seed_task(db)
        await run_hunt(_ctx(tmp_path, execution_enabled=True), db)
    finally:
        db.close()

    assert len(captured) == 1
    assert captured[0]["execution_available"] is True


async def test_execution_available_mirrors_ctx_not_ambient_sandbox_signal(
    tmp_path: Path, monkeypatch
) -> None:
    # Regression guard for the bug this fix addressed: the hint must track
    # ctx.execution_enabled (the same value threaded into run_agent()'s
    # Bash gate), never a locally re-derived vash.sandbox.is_sandboxed()
    # read. An ambient sandbox signal alone must NOT flip the hint to True
    # when ctx.execution_enabled is False (e.g. --dynamic-validation was
    # never passed for this run).
    monkeypatch.setenv("VASH_SANDBOX", "1")
    captured: list[dict] = []
    _stub_run_agent(monkeypatch, captured)
    db = StateDB(tmp_path / "state.db")
    try:
        _seed_task(db)
        await run_hunt(_ctx(tmp_path, execution_enabled=False), db)
    finally:
        db.close()

    assert len(captured) == 1
    assert captured[0]["execution_available"] is False
