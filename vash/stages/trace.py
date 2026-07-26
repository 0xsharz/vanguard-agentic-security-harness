"""Stage 6: Trace — reachability from entry point to sink, per canonical finding."""

from __future__ import annotations

import asyncio
import logging

from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.state import Finding, StateDB
from vash.stages._common import StageContext, truncated_recon_summary

log = logging.getLogger(__name__)


async def run_trace(ctx: StageContext, db: StateDB) -> int:
    canonicals = db.get_findings(ctx.run_id, validation_status="confirmed",
                                 canonical_only=True)
    if not canonicals:
        log.info("[%s] trace: no canonical findings to trace", ctx.run_id)
        return 0

    sc = ctx.stage("trace")
    sem = asyncio.Semaphore(sc.concurrency)
    recon_summary = db.get_recon_output(ctx.run_id) or {}

    log.info(
        "[%s] trace: %d canonicals (concurrency=%d, model=%s)",
        ctx.run_id, len(canonicals), sc.concurrency, sc.model,
    )
    counters = {"reachable": 0, "unreachable": 0, "failed": 0}

    async def _one(f: Finding) -> None:
        async with sem:
            if db.get_trace(f.finding_id) is not None:
                return  # already traced (resume)
            user_input = {
                "finding": f.raw_json,
                "recon_summary": truncated_recon_summary(recon_summary),
                "repo_path": str(ctx.repo_path),
                **ctx.extras(),
            }
            try:
                result = await run_agent(
                    stage="trace",
                    prompt_file=ctx.prompt("06-trace"),
                    user_input=user_input,
                    schema_file=ctx.schema("trace"),
                    allowed_tools=sc.tools,
                    model=sc.model,
                    cwd=ctx.repo_path,
                    add_dirs=[ctx.repo_path],
                    max_turns=sc.max_turns,
                    permission_mode=sc.permission_mode,
                    artifact_dir=ctx.results_dir("trace"),
                    artifact_name=f.finding_id,
                    repair_attempts=sc.repair_attempts,
                    execution_enabled=ctx.execution_enabled,
                )
            except (AgentRunError, TransientAgentError) as e:
                log.warning("[%s] trace %s failed: %s", ctx.run_id, f.finding_id, e)
                counters["failed"] += 1
                # Conservative: mark unreachable on failure.
                db.add_trace(f.finding_id, {
                    "finding_id": f.finding_id, "reachable": False,
                    "confidence": 0.0,
                    "rationale": f"tracer failed: {e}",
                    "blockers": [{"kind": "other", "location": "tracer",
                                  "description": "agent failed to emit valid trace"}],
                })
                return

            db.add_trace(f.finding_id, result.payload)
            db.record_cost(ctx.run_id, "trace", f.finding_id, result.raw_result_message)
            db.add_artifact(ctx.run_id, "trace", f.finding_id, "jsonl",
                            str(result.artifact_path))
            if result.payload.get("reachable"):
                counters["reachable"] += 1
            else:
                counters["unreachable"] += 1

    await asyncio.gather(*(_one(f) for f in canonicals))
    log.info(
        "[%s] trace: reachable=%d unreachable=%d failed=%d",
        ctx.run_id, counters["reachable"], counters["unreachable"], counters["failed"],
    )
    return counters["reachable"]
