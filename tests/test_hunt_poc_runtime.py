"""Phase 3: Hunt threads the per-language PoC recipe into `user_input`.

`vash.lang.poc_runtime` knows HOW to compile/run a PoC per language and how
to observe whether the dangerous behaviour actually fired; this test file
covers the wiring — `vash/stages/hunt.py` picking a runtime for the task,
materializing the observer helper into that task's scratch dir, and handing
the whole recipe to the agent as `user_input["poc_execution"]`.

Two invariants matter more than the happy path:

* **The static-host guarantee.** With `execution_enabled=False` (a bare host,
  where `vash.runner` strips Bash) nothing may be written into the scratch
  dir and the `poc_execution` key must be ABSENT — a static run stays exactly
  as it was before Phase 3.
* **Fail-open.** A bug in the runtime registry must never fail a hunt task;
  the task runs without the recipe, the same as an unsupported language.

Offline + hermetic, following tests/test_hunt_execution_available.py: no
agent is ever run (`run_agent` is stubbed at `vash.stages.hunt.run_agent`),
no PoC is ever executed, results/work are redirected into tmp_path. The
prompt-content tests follow tests/test_hunt_poc_prompt.py's convention —
read the real file, assert distinctive substrings so the prose cannot be
silently dropped later.
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

RUN_ID = "r_poc"
TASK_ID = "t_1"

PROMPTS = Path(__file__).resolve().parent.parent / "prompts"


@pytest.fixture(autouse=True)
def _hermetic_sandbox_signals(monkeypatch, tmp_path):
    monkeypatch.delenv("VASH_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "_DOCKERENV", tmp_path / "no-such-dockerenv")


@pytest.fixture(autouse=True)
def _redirect_results_and_work(monkeypatch, tmp_path):
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")


def _seed_task(db: StateDB, target_files: list[str]) -> None:
    db.create_run("/repo", RUN_ID)
    db.add_task(RUN_ID, {
        "task_id": TASK_ID, "attack_class": "command_injection",
        "scope_hint": target_files[0], "target_files": target_files,
        "rationale": "x", "priority": 1,
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


def _ctx(tmp_path: Path, *, execution_enabled: bool = False,
         project_env: dict | None = None) -> StageContext:
    return StageContext(run_id=RUN_ID, repo_path=tmp_path, config=load_config(),
                        execution_enabled=execution_enabled, project_env=project_env)


def _scratch(tmp_path: Path) -> Path:
    # Mirrors StageContext.work_dir("hunt", TASK_ID) under the redirected WORK.
    return tmp_path / "work" / RUN_ID / "hunt" / TASK_ID


async def _run(tmp_path: Path, monkeypatch, *, target_files: list[str],
               execution_enabled: bool = False,
               project_env: dict | None = None) -> tuple[list[dict], StateDB]:
    captured: list[dict] = []
    _stub_run_agent(monkeypatch, captured)
    db = StateDB(tmp_path / "state.db")
    try:
        _seed_task(db, target_files)
        await run_hunt(_ctx(tmp_path, execution_enabled=execution_enabled,
                            project_env=project_env), db)
        statuses = [t.status for t in db.get_all_tasks(RUN_ID)]
    finally:
        db.close()
    return captured, statuses


# ---- the recipe reaches the agent ------------------------------------------


async def test_java_task_gets_java_poc_execution_block(tmp_path: Path, monkeypatch) -> None:
    captured, statuses = await _run(tmp_path, monkeypatch,
                                    target_files=["src/Foo.java"],
                                    execution_enabled=True)
    assert statuses == ["done"]
    block = captured[0]["poc_execution"]
    assert block["language"] == "java"
    assert block["poc_filename"] == "PoC.java"
    assert block["run_cmd"] == 'java -cp ".:$CP" PoC'
    assert block["observer"]["name"] == "jfr"


async def test_javascript_task_gets_node_block_and_materialized_observer(
    tmp_path: Path, monkeypatch
) -> None:
    captured, _ = await _run(tmp_path, monkeypatch, target_files=["lib/app.js"],
                             execution_enabled=True)
    block = captured[0]["poc_execution"]
    assert block["language"] == "javascript"
    assert block["run_cmd"] == "node poc.js"
    assert block["observer"]["name"] == "node-preload"
    # The preload asset must be on disk in the task's own scratch dir, since
    # the observer's `wrap` references it as $PWD/vash_node_observer.js.
    asset = _scratch(tmp_path) / "vash_node_observer.js"
    assert asset.is_file()
    assert str(asset) in block["observer"]["files"]


async def test_task_file_language_beats_repo_primary_language(
    tmp_path: Path, monkeypatch
) -> None:
    # The sink is in gen.py, so the PoC must be Python even though the repo is
    # majority Go. Letting the repo-wide primary language win handed a task
    # targeting a .java sink in a Python repo `poc.py` + an audit hook that can
    # never see a JVM.
    captured, _ = await _run(tmp_path, monkeypatch, target_files=["tools/gen.py"],
                             execution_enabled=True,
                             project_env={"primary_language": "go"})
    assert captured[0]["poc_execution"]["language"] == "python"


async def test_project_env_is_the_fallback_when_the_task_files_say_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    captured, _ = await _run(tmp_path, monkeypatch,
                             target_files=["templates/page.jinja2"],
                             execution_enabled=True,
                             project_env={"primary_language": "go"})
    assert captured[0]["poc_execution"]["language"] == "go"


# ---- the static-host guarantee ---------------------------------------------


async def test_static_run_omits_poc_execution_and_writes_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    captured, statuses = await _run(tmp_path, monkeypatch,
                                    target_files=["lib/app.js"],
                                    execution_enabled=False)
    assert statuses == ["done"]
    assert "poc_execution" not in captured[0]
    assert list(_scratch(tmp_path).iterdir()) == []


# ---- degradation -----------------------------------------------------------


async def test_unsupported_language_yields_no_block_and_does_not_fail(
    tmp_path: Path, monkeypatch
) -> None:
    captured, statuses = await _run(tmp_path, monkeypatch,
                                    target_files=["batch/PAYROLL.cbl"],
                                    execution_enabled=True)
    assert statuses == ["done"]
    assert "poc_execution" not in captured[0]


async def test_poc_runtime_failure_does_not_fail_the_task(
    tmp_path: Path, monkeypatch
) -> None:
    def boom(*_a, **_kw):
        raise RuntimeError("registry exploded")
    monkeypatch.setattr(hunt_mod, "poc_execution_block", boom)
    captured, statuses = await _run(tmp_path, monkeypatch,
                                    target_files=["src/Foo.java"],
                                    execution_enabled=True)
    assert statuses == ["done"]
    assert "poc_execution" not in captured[0]


# ---- prompt guidance -------------------------------------------------------


def _prompt_text() -> str:
    return (PROMPTS / "02-hunt.md").read_text()


def test_prompt_documents_the_poc_execution_recipe() -> None:
    text = _prompt_text()
    assert "`poc_execution`" in text
    assert "poc_execution.poc_filename" in text
    assert "poc_execution.compile_cmd" in text
    assert "poc_execution.run_cmd" in text
    assert "poc_execution.deps_hint" in text


def test_prompt_documents_the_observer_protocol() -> None:
    text = _prompt_text()
    assert "poc_execution.observer" in text
    assert "available_check" in text
    assert "observer.wrap" in text
    assert "evidence_markers" in text
    assert "positive proof that the dangerous operation actually occurred" in text
    assert "poc.run_output" in text


def test_prompt_states_the_observer_honesty_rule() -> None:
    # The one inference that would turn optional instrumentation into a
    # source of false negatives. If this prose is ever dropped, this fails.
    text = _prompt_text()
    assert "an observer is corroboration, never a verdict" in text
    assert "NOT evidence that the finding is false" in text
    assert "Never drop or downgrade a finding" in text
    assert "because an observer was unavailable" in text


def test_prompt_keeps_the_existing_live_target_and_availability_branches() -> None:
    text = _prompt_text()
    assert "If `live_target` is in input" in text
    assert "Execution availability" in text
    idx_live = text.index("If `live_target` is in input")
    idx_local = text.index("Otherwise (no `live_target`)")
    assert idx_live < idx_local < text.index("`poc_execution`", idx_local)
