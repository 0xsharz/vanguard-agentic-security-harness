"""Stage 8: Report — schema-validated final document."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from vash.redact import redact_json
from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.state import StateDB
from vash.stages._common import StageContext

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
    # V11: surface any exploit chains the Chain stage constructed. Read-only
    # pass-through — chains carry their own severity; per-finding severities
    # (CVSS/V4) are untouched.
    chains = (db.get_chain_analysis(ctx.run_id) or {}).get("chains") or []
    user_input = {"run_id": ctx.run_id, "target": target, "ready_findings": ready,
                  "chains": chains, **ctx.extras()}

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
        _attach_coverage(db, ctx.run_id, empty)
        out_path.write_text(json.dumps(redact_json(empty), indent=2))
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
        fallback = _build_fallback_report(ctx, db, reachable, target, chains)
        _attach_input_inventory(db, ctx.run_id, fallback)
        _attach_coverage(db, ctx.run_id, fallback)
        _attach_cwe(db, ctx.run_id, fallback)
        _attach_variants(db, ctx.run_id, fallback)
        out_path.write_text(json.dumps(redact_json(fallback), indent=2))
        return out_path

    db.record_cost(ctx.run_id, "report", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "report", None, "jsonl", str(result.artifact_path))
    payload = result.payload
    # The resolved input inventory is a completeness artifact sourced from the
    # run state (the ledger), not the agent's imagination — attach it here so
    # it is authoritative and present on every report, agent-authored or not.
    _attach_input_inventory(db, ctx.run_id, payload)
    # 4.7: consolidated coverage disclosure — same treatment as the input
    # inventory above: sourced from run state, injected post-hoc, never
    # left to the agent to (mis)represent.
    _attach_coverage(db, ctx.run_id, payload)
    # D4: backfill CWE onto each finding from run state so downstream consumers
    # (SARIF, benchmark scorers that class-match on CWE) don't see a bare finding.
    _attach_cwe(db, ctx.run_id, payload)
    # A2: attach located deduped-sibling references (VVAH "Also at:" parity) —
    # same authoritative post-hoc treatment as CWE/coverage/input-inventory above.
    _attach_variants(db, ctx.run_id, payload)
    out_path.write_text(json.dumps(redact_json(payload), indent=2))
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


# Fallback CWE by vuln class, used only when a finding carries no CWE of its own.
_CLASS_CWE = {
    "code_injection": "CWE-94", "codegen": "CWE-94", "ssti": "CWE-94", "logic_chain": "CWE-94",
    "command_injection": "CWE-78", "ssrf": "CWE-918", "path_traversal": "CWE-22", "zip_slip": "CWE-22",
    "sql_injection": "CWE-89", "xxe": "CWE-611", "deserialization": "CWE-502", "open_redirect": "CWE-601",
    "xss_stored": "CWE-79", "xss_reflected": "CWE-79", "credential_leak": "CWE-200",
    "information_disclosure": "CWE-200", "infoleak": "CWE-200", "header_injection": "CWE-113",
    "race_condition": "CWE-362", "uncontrolled_recursion_resource_exhaustion": "CWE-674",
    "denial_of_service": "CWE-400", "algorithmic_complexity_dos": "CWE-407",
}


def _attach_cwe(db: StateDB, run_id: str, payload: dict) -> None:
    """Backfill a `cwe` onto each report finding (D4). The hunters already emit a
    CWE (stored in the finding's raw_json); report findings were dropping it, so
    CWE-class-matching scorers saw nothing. Prefer the finding's own CWE from run
    state (by finding_id), else map from vuln_class. Fail-soft."""
    try:
        by_id = {f.finding_id: (f.raw_json or {}).get("cwe") for f in db.get_findings(run_id)}
        for f in payload.get("findings", []):
            if not f.get("cwe"):
                cwe = by_id.get(f.get("finding_id")) or _CLASS_CWE.get(f.get("vuln_class"))
                if cwe:
                    f["cwe"] = cwe
    except Exception as e:  # additive disclosure — never break report emission
        log.warning("[%s] cwe backfill failed: %s", run_id, e)


def _attach_variants(db: StateDB, run_id: str, payload: dict) -> None:
    """Attach located deduped-sibling references to each report finding (VVAH
    DupLocation parity). A finding whose dedupe group has other members carries
    them here as {finding_id, file, line_start, line_end, vuln_class} — rendered
    "Also at:" — so co-located confirmed sites are visible WITHOUT inflating the
    top-level findings count. Sourced from run state (authoritative), never left
    to the agent. Fail-soft: variant disclosure must never break report emission."""
    try:
        fid_to_group = {f.finding_id: f.group_id
                        for f in db.get_findings(run_id) if f.group_id}
        for f in payload.get("findings", []):
            gid = fid_to_group.get(f.get("finding_id"))
            if gid:
                f["variants"] = _group_members_excluding(db, run_id, gid, f.get("finding_id"))
    except Exception as e:  # additive disclosure — never break report emission
        log.warning("[%s] variant attach failed: %s", run_id, e)


def _attach_coverage(db: StateDB, run_id: str, payload: dict) -> None:
    """Attach a consolidated `coverage` object (4.7) to a report payload —
    reuses existing data rather than re-running any analysis:
      - inputs enumerated/covered/uncovered from the F1 completeness ledger
        (`db.get_inputs`);
      - tasks_by_source / findings_by_status from the 4.3 `db.run_summary`;
      - source_files/covered_files/catchall_tasks/catchall_dropped from the
        F6 catch-all sweep record `_add_catchall_tasks` persists.
    `coverage_complete` is False whenever the catch-all cap dropped files OR
    any enumerated input never reached a disposition — an operator must never
    be told coverage is complete when it isn't.

    Fail-soft: coverage is purely additive disclosure. Any failure here is
    logged and swallowed so it can never break report emission.
    """
    try:
        inputs = db.get_inputs(run_id)
        summary = db.run_summary(run_id)
        coverage = {
            "inputs_enumerated": len(inputs),
            "inputs_covered": sum(1 for i in inputs if i.get("disposition") == "covered"),
            "inputs_uncovered": sum(1 for i in inputs if i.get("disposition") == "uncovered"),
            "tasks_by_source": summary.get("tasks", {}).get("by_source", {}),
            "findings_by_status": summary.get("findings", {}).get("by_status", {}),
            **(db.get_coverage(run_id) or {}),
        }
        coverage["coverage_complete"] = (
            coverage.get("catchall_dropped", 0) == 0
            and all(i.get("disposition") for i in inputs)
        )
        payload["coverage"] = coverage
    except Exception as e:  # fail-soft — coverage must never break the report
        log.warning("[%s] coverage attach failed (continuing): %s", run_id, e)


def _group_members_excluding(db: StateDB, run_id: str, group_id: str,
                             exclude: str) -> list[dict]:
    # VVAH DupLocation parity (s7_dedup.py::_attach_duplicates): a deduped
    # sibling is demoted to a LOCATED reference, never dropped — carry
    # file/line/class so the report can render "Also at:" and a location-aware
    # consumer sees every co-located confirmed site.
    rows = db._conn.execute(  # type: ignore[attr-defined]
        "SELECT finding_id, file, line_start, line_end, vuln_class "
        "FROM findings WHERE run_id = ? AND group_id = ? AND finding_id != ?",
        (run_id, group_id, exclude),
    ).fetchall()
    return [
        {"finding_id": r["finding_id"], "file": r["file"],
         "line_start": r["line_start"], "line_end": r["line_end"],
         "vuln_class": r["vuln_class"]}
        for r in rows
    ]


def _build_fallback_report(ctx: StageContext, db: StateDB,
                           reachable, target: dict,
                           chains: list | None = None) -> dict:
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
    report = {
        "run_id": ctx.run_id,
        "target": target,
        "summary": {"total": len(findings_out), "by_severity": by_sev},
        "findings": findings_out,
    }
    if chains:
        report["chains"] = chains
    return report
