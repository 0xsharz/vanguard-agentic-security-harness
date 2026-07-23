"""Stage 4: Gapfill — re-queue under-covered areas back to Hunt."""

from __future__ import annotations

import logging
from collections import defaultdict

from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.state import StateDB
from vash.stages._common import StageContext, truncated_recon_summary

log = logging.getLogger(__name__)

# Gapfill defaults to a modest number — large counts amplify cost
# quadratically at low concurrency, and most projects don't need 30
# extra Hunt tasks per iteration. Override via CLI if needed.
DEFAULT_MAX_NEW_TASKS = 8


async def run_gapfill(ctx: StageContext, db: StateDB,
                      max_new_tasks: int = DEFAULT_MAX_NEW_TASKS) -> int:
    """Returns count of new tasks added."""
    recon_summary = db.get_recon_output(ctx.run_id) or {}
    all_tasks = db.get_all_tasks(ctx.run_id)
    completed = [t for t in all_tasks if t.status in ("done", "failed")]
    if not completed:
        log.info("[%s] gapfill: nothing to analyze", ctx.run_id)
        return 0

    findings_by_task: dict[str, int] = defaultdict(int)
    gaps_by_task: dict[str, list] = defaultdict(list)
    for f in db.get_findings(ctx.run_id):
        findings_by_task[f.task_id] += 1
    # Reconstruct gaps_observed by reading hunt artifacts via raw_json on task
    # No — gaps_observed lives in the hunt JSONL artifact. For simplicity
    # we pass findings_count only; the gapfill agent re-reads code itself.

    sc = ctx.stage("gapfill")
    completed_payload = [
        {
            "task_id": t.task_id,
            "attack_class": t.attack_class,
            "subsystem": _infer_subsystem(t.target_files, recon_summary),
            "scope_hint": t.scope_hint,
            "findings_count": findings_by_task.get(t.task_id, 0),
            "gaps_observed": gaps_by_task.get(t.task_id, []),
            "status": t.status,
        }
        for t in completed
    ]
    user_input = {
        "recon_summary": truncated_recon_summary(recon_summary),
        "completed_tasks": completed_payload,
        "max_new_tasks": max_new_tasks,
        **ctx.extras(),
    }
    try:
        result = await run_agent(
            stage="gapfill",
            prompt_file=ctx.prompt("04-gapfill"),
            user_input=user_input,
            schema_file=ctx.schema("gapfill_output"),
            allowed_tools=sc.tools,
            model=sc.model,
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("gapfill"),
            artifact_name=f"gapfill_{_iter_tag(ctx.run_id, db)}",
            repair_attempts=sc.repair_attempts,
        )
    except (AgentRunError, TransientAgentError) as e:
        log.warning("[%s] gapfill failed: %s — skipping iteration", ctx.run_id, e)
        return 0

    new_tasks = result.payload.get("new_tasks", []) or []
    added = 0
    for t in new_tasks:
        t.setdefault("source", "gapfill")
        existing = next((x for x in all_tasks if x.task_id == t["task_id"]), None)
        if existing is not None:
            continue  # skip duplicate id
        db.add_task(ctx.run_id, t)
        added += 1
    db.record_cost(ctx.run_id, "gapfill", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "gapfill", None, "jsonl", str(result.artifact_path))
    log.info("[%s] gapfill: added %d new tasks", ctx.run_id, added)
    return added


def _infer_subsystem(target_files: list[str], recon: dict) -> str:
    if not target_files:
        return "unknown"
    f = target_files[0]
    for s in recon.get("subsystems", []):
        p = s.get("path", "")
        if p and f.startswith(p):
            return s.get("name", "unknown")
    return "unknown"


def _iter_tag(run_id: str, db: StateDB) -> str:
    # Simple monotonic tag based on existing gapfill artifacts.
    return f"iter_{int(_artifact_count(db, run_id, 'gapfill')) + 1}"


def _artifact_count(db: StateDB, run_id: str, stage: str) -> int:
    cur = db._conn.execute(  # type: ignore[attr-defined]
        "SELECT COUNT(*) AS c FROM artifacts WHERE run_id = ? AND stage = ?",
        (run_id, stage),
    )
    row = cur.fetchone()
    return int(row["c"]) if row else 0
