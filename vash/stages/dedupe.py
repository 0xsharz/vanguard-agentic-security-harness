"""Stage 5: Dedupe — cluster confirmed findings by root cause."""

from __future__ import annotations

import logging

from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.state import StateDB
from vash.stages._common import StageContext

log = logging.getLogger(__name__)


async def run_dedupe(ctx: StageContext, db: StateDB) -> int:
    confirmed = db.get_findings(ctx.run_id, validation_status="confirmed")
    if not confirmed:
        log.info("[%s] dedupe: no confirmed findings to cluster", ctx.run_id)
        return 0

    sc = ctx.stage("dedupe")
    payload = []
    for f in confirmed:
        payload.append({
            **f.raw_json,
            "validation": f.validation_json,
        })

    log.info("[%s] dedupe: clustering %d confirmed findings", ctx.run_id, len(confirmed))
    try:
        result = await run_agent(
            stage="dedupe",
            prompt_file=ctx.prompt("05-dedupe"),
            user_input={"confirmed_findings": payload, **ctx.extras()},
            schema_file=ctx.schema("dedupe_output"),
            allowed_tools=sc.tools,
            model=sc.model,
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("dedupe"),
            artifact_name="dedupe",
            repair_attempts=sc.repair_attempts,
        )
    except (AgentRunError, TransientAgentError) as e:
        log.warning("[%s] dedupe failed: %s — treating each finding as its own group",
                    ctx.run_id, e)
        # Fallback: one group per finding, all canonical.
        for f in confirmed:
            gid = f"g_{f.finding_id[2:]}" if f.finding_id.startswith("f_") else f"g_{f.finding_id}"
            db.add_dedupe_group(ctx.run_id, {
                "group_id": gid,
                "root_cause": f.description[:200],
                "canonical_finding_id": f.finding_id,
                "member_finding_ids": [f.finding_id],
            })
            db.assign_finding_group(f.finding_id, gid, True)
        return len(confirmed)

    groups = result.payload.get("groups", [])
    db.record_cost(ctx.run_id, "dedupe", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "dedupe", None, "jsonl", str(result.artifact_path))
    # D8: the dedupe agent picks ONE canonical per group. When a group spans
    # files, that buries a confirmed match living in a different file than the
    # canonical (it is never traced, never reported). Promote one canonical PER
    # DISTINCT FILE so a co-located confirmed finding survives to trace/report.
    # Deterministic, post-clustering. Safe: every promoted member is already
    # `confirmed`, and trace.py independently re-verifies reachability before
    # report.py includes it — this cannot surface an unconfirmed or dead finding.
    fid_to_file = {f.finding_id: f.file for f in confirmed}
    for g in groups:
        db.add_dedupe_group(ctx.run_id, g)
        canonical = g["canonical_finding_id"]
        files_seen = {fid_to_file.get(canonical)}
        for fid in g["member_finding_ids"]:
            file = fid_to_file.get(fid)
            is_canon = (fid == canonical) or (file is not None and file not in files_seen)
            if is_canon:
                files_seen.add(file)
            db.assign_finding_group(fid, g["group_id"], is_canon)

    log.info("[%s] dedupe: %d findings → %d groups", ctx.run_id, len(confirmed), len(groups))
    return len(groups)
