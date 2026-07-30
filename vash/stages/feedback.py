"""Stage 7: Feedback — convert reachable traces into new Hunt tasks."""

from __future__ import annotations

import logging

from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.state import StateDB
from vash.stages._common import StageContext, truncated_recon_summary

log = logging.getLogger(__name__)

DEFAULT_MAX_NEW_TASKS = 40


async def run_feedback(ctx: StageContext, db: StateDB,
                       max_new_tasks: int = DEFAULT_MAX_NEW_TASKS) -> int:
    reachable = db.get_reachable_canonical_findings(ctx.run_id)
    if not reachable:
        log.info("[%s] feedback: no reachable findings; nothing to seed", ctx.run_id)
        return 0

    sc = ctx.stage("feedback")
    recon_summary = db.get_recon_output(ctx.run_id) or {}
    payload = [{"finding": f.raw_json, "trace": tr} for f, tr in reachable]

    try:
        result = await run_agent(
            stage="feedback",
            prompt_file=ctx.prompt("07-feedback"),
            user_input={
                "reachable_traces": payload,
                "recon_summary": truncated_recon_summary(recon_summary),
                "max_new_tasks": max_new_tasks,
                **ctx.extras(),
            },
            schema_file=ctx.schema("feedback_output"),
            allowed_tools=sc.tools,
            model=sc.model,
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("feedback"),
            artifact_name="feedback",
            repair_attempts=sc.repair_attempts,
            effort=sc.effort,
            thinking=sc.thinking,
        )
    except (AgentRunError, TransientAgentError) as e:
        log.warning("[%s] feedback failed: %s", ctx.run_id, e)
        return 0

    new_tasks = result.payload.get("new_hunt_tasks", []) or []
    existing_ids = {t.task_id for t in db.get_all_tasks(ctx.run_id)}
    added = 0
    for t in new_tasks:
        t.setdefault("source", "feedback")
        if t["task_id"] in existing_ids:
            continue
        db.add_task(ctx.run_id, t)
        added += 1
    db.record_cost(ctx.run_id, "feedback", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "feedback", None, "jsonl", str(result.artifact_path))
    log.info("[%s] feedback: %d new tasks from %d reachable traces",
             ctx.run_id, added, len(reachable))
    return added
