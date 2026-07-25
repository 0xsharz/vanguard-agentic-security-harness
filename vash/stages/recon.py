"""Stage 1: Recon — map the repo, emit initial hunt tasks."""

from __future__ import annotations

import logging

from vash.baselines import classify_and_baseline
from vash.runner import run_agent
from vash.state import StateDB
from vash.stages._common import StageContext

log = logging.getLogger(__name__)

DEFAULT_MAX_TASKS = 80


async def run_recon(ctx: StageContext, db: StateDB, max_tasks: int = DEFAULT_MAX_TASKS) -> dict:
    if db.get_recon_output(ctx.run_id) is not None:
        log.info("[%s] recon already complete, skipping", ctx.run_id)
        return db.get_recon_output(ctx.run_id)  # type: ignore[return-value]

    sc = ctx.stage("recon")
    log.info("[%s] recon: model=%s max_tasks=%d", ctx.run_id, sc.model, max_tasks)

    # V10: repo-kind -> OWASP/CWE minimum-baseline checklist. Best-effort —
    # a classification error must never block Recon, so it degrades to an
    # empty baseline rather than propagating.
    try:
        baseline_kinds, baseline_text = classify_and_baseline(ctx.repo_path)
    except Exception as e:
        log.warning("[%s] recon: baseline classification failed, continuing "
                    "with an empty baseline: %s", ctx.run_id, e)
        baseline_kinds, baseline_text = set(), ""
    log.info("[%s] recon: baseline repo_kind=%s", ctx.run_id, sorted(baseline_kinds) or "-")

    result = await run_agent(
        stage="recon",
        prompt_file=ctx.prompt("01-recon"),
        user_input={"repo_path": str(ctx.repo_path), "max_tasks": max_tasks,
                    "baseline": baseline_text,
                    **ctx.extras()},
        schema_file=ctx.schema("recon_output"),
        allowed_tools=sc.tools,
        model=sc.model,
        cwd=ctx.repo_path,
        add_dirs=[ctx.repo_path],
        max_turns=sc.max_turns,
        permission_mode=sc.permission_mode,
        artifact_dir=ctx.results_dir("recon"),
        artifact_name="recon",
        repair_attempts=sc.repair_attempts,
        execution_enabled=ctx.execution_enabled,
    )

    payload = result.payload
    db.save_recon_output(ctx.run_id, payload)
    db.record_cost(ctx.run_id, "recon", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "recon", None, "jsonl", str(result.artifact_path))

    for task in payload.get("initial_tasks", []):
        task.setdefault("source", "recon")
        db.add_task(ctx.run_id, task)

    # Persist the attacker-controllable input inventory. This is the
    # completeness ledger the orchestrator later reconciles: every input must
    # reach a disposition. Guarded per-item so a malformed entry can't lose the
    # rest (and the whole field is optional for pre-F1 recon outputs).
    inputs = payload.get("inputs", []) or []
    for inp in inputs:
        try:
            db.add_input(ctx.run_id, inp)
        except Exception as e:  # pragma: no cover - defensive
            log.warning("[%s] recon: could not persist input %r: %s",
                        ctx.run_id, inp.get("id"), e)

    log.info(
        "[%s] recon done: subsystems=%d entry_points=%d inputs=%d initial_tasks=%d cost=$%.4f",
        ctx.run_id,
        len(payload.get("subsystems", [])),
        len(payload.get("architecture", {}).get("entry_points", [])),
        len(inputs),
        len(payload.get("initial_tasks", [])),
        result.cost_usd or 0.0,
    )
    return payload
