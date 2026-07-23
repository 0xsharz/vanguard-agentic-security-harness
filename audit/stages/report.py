"""Stage 8: Report — schema-validated final document."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from audit.runner import AgentRunError, TransientAgentError, run_agent
from audit.state import StateDB
from audit.stages._common import StageContext

log = logging.getLogger(__name__)


async def run_report(ctx: StageContext, db: StateDB) -> Path:
    reachable = db.get_reachable_canonical_findings(ctx.run_id)
    ready = []
    for f, trace in reachable:
        ready.append({
            "finding": f.raw_json,
            "validation": f.validation_json,
            "trace": trace,
            "variants": _group_members_excluding(db, ctx.run_id, f.group_id, f.finding_id)
                       if f.group_id else [],
        })

    sc = ctx.stage("report")
    target = {"repo_path": str(ctx.repo_path)}
    user_input = {"run_id": ctx.run_id, "target": target, "ready_findings": ready,
                  **ctx.extras()}

    out_path = ctx.results_dir("report") / "report.json"

    if not ready:
        # No reachable findings — emit a minimal empty report without burning an agent call.
        empty = {
            "run_id": ctx.run_id,
            "target": target,
            "summary": {"total": 0, "by_severity": {}},
            "findings": [],
        }
        _attach_input_inventory(db, ctx.run_id, empty)
        out_path.write_text(json.dumps(empty, indent=2))
        log.info("[%s] report: no reachable findings — wrote empty report to %s",
                 ctx.run_id, out_path)
        return out_path

    try:
        result = await run_agent(
            stage="report",
            prompt_file=ctx.prompt("08-report"),
            user_input=user_input,
            schema_file=ctx.schema("report"),
            allowed_tools=sc.tools,
            model=sc.model,
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("report"),
            artifact_name="report_agent",
            repair_attempts=max(sc.repair_attempts, 2),  # report MUST validate
        )
    except (AgentRunError, TransientAgentError) as e:
        log.error("[%s] report agent failed: %s — emitting fallback report",
                  ctx.run_id, e)
        fallback = _build_fallback_report(ctx, db, reachable, target)
        _attach_input_inventory(db, ctx.run_id, fallback)
        out_path.write_text(json.dumps(fallback, indent=2))
        return out_path

    db.record_cost(ctx.run_id, "report", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "report", None, "jsonl", str(result.artifact_path))
    payload = result.payload
    # The resolved input inventory is a completeness artifact sourced from the
    # run state (the ledger), not the agent's imagination — attach it here so
    # it is authoritative and present on every report, agent-authored or not.
    _attach_input_inventory(db, ctx.run_id, payload)
    out_path.write_text(json.dumps(payload, indent=2))
    log.info("[%s] report: %d findings, %d inputs in inventory, written to %s",
             ctx.run_id, len(payload.get("findings", [])),
             len(payload.get("input_inventory", [])), out_path)
    return out_path


def _attach_input_inventory(db: StateDB, run_id: str, payload: dict) -> None:
    """Attach the resolved input inventory (completeness ledger) to a report
    payload. Sourced from run state so it is authoritative regardless of what
    the report agent produced."""
    inventory = [
        {
            "id": inp["id"],
            "source_type": inp["source_type"],
            "location": inp["location"],
            "variable": inp["variable"],
            "entry_point": inp["entry_point"],
            "trust_level": inp["trust_level"],
            "disposition": inp["disposition"],
            "disposition_evidence": inp["disposition_evidence"],
        }
        for inp in db.get_inputs(run_id)
    ]
    payload["input_inventory"] = inventory


def _group_members_excluding(db: StateDB, run_id: str, group_id: str,
                             exclude: str) -> list[str]:
    rows = db._conn.execute(  # type: ignore[attr-defined]
        "SELECT finding_id FROM findings WHERE run_id = ? AND group_id = ? AND finding_id != ?",
        (run_id, group_id, exclude),
    ).fetchall()
    return [r["finding_id"] for r in rows]


def _build_fallback_report(ctx: StageContext, db: StateDB,
                           reachable, target: dict) -> dict:
    by_sev: dict[str, int] = {}
    findings_out = []
    for f, trace in reachable:
        sev = f.severity
        by_sev[sev] = by_sev.get(sev, 0) + 1
        findings_out.append({
            "finding_id": f.finding_id,
            "title": f"{f.vuln_class} in {f.file}",
            "severity": sev,
            "vuln_class": f.vuln_class,
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "description": f.description,
            "evidence": f.evidence,
            "trace": {
                "entry_points": trace.get("entry_points", []),
                "call_chain": trace.get("call_chain", []),
            },
            "recommendation": "Review the sink and add input validation / use a safe API.",
        })
    return {
        "run_id": ctx.run_id,
        "target": target,
        "summary": {"total": len(findings_out), "by_severity": by_sev},
        "findings": findings_out,
    }
