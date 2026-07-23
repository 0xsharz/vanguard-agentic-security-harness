"""Stage 8.5: Chain — multi-step exploit-chain construction (V11, ported VVAH
s8_chain).

One read-only LLM pass sees ALL confirmed canonical findings together and
constructs multi-step exploit *chains* (combinations more dangerous than any
single bug). Runs after the Feedback loop and before Report.

Contracts (do not deviate):
  - Findings are referenced by stable ``finding_id``, never a 0-based index.
  - Chains carry their OWN severity. This stage does NOT re-rank or write
    per-finding severities — V4's CVSS stays per-finding authoritative.
  - Fail-soft: any failure logs + stores an empty analysis and NEVER aborts the
    run (mirrors Trace's conservative failure handling).
  - Chains need >=2 findings; with fewer than 2 confirmed canonical findings the
    stage skips (returns 0) before calling the agent.
"""

from __future__ import annotations

import logging

from audit.runner import AgentRunError, TransientAgentError, run_agent
from audit.state import Finding, StateDB
from audit.stages._common import StageContext

log = logging.getLogger(__name__)


def _compact_finding(f: Finding, trace: dict | None) -> dict:
    """A compact per-finding view for the chain agent. The chain references
    findings by ``finding_id`` (stable), NOT by list position. CVSS
    vector/rating (V4) and Trace's static ``exploitability`` note (F5) are
    included only when present."""
    vj = f.validation_json or {}
    out: dict = {
        "finding_id": f.finding_id,
        "vuln_class": f.vuln_class,
        "file": f.file,
        "line": f.line_start,
        "severity": f.severity,
        "description": f.description,
    }
    if vj.get("cvss_vector"):
        out["cvss_vector"] = vj["cvss_vector"]
    if vj.get("cvss_rating"):
        out["cvss_rating"] = vj["cvss_rating"]
    if isinstance(trace, dict) and isinstance(trace.get("exploitability"), dict):
        out["exploitability"] = trace["exploitability"]
    return out


async def run_chain(ctx: StageContext, db: StateDB) -> int:
    """Construct multi-step exploit chains across all confirmed, canonical,
    reachable findings. Returns the number of chains constructed (0 when the
    stage skips or fails)."""
    # Reuse Report's finding selection: confirmed + canonical + reachable, each
    # paired with its Trace (for the exploitability note). Chains need >=2.
    reachable = db.get_reachable_canonical_findings(ctx.run_id)
    if len(reachable) < 2:
        log.info("[%s] chain: <2 findings, skipping", ctx.run_id)
        return 0

    findings = [_compact_finding(f, trace) for f, trace in reachable]
    recon = db.get_recon_output(ctx.run_id) or {}
    sc = ctx.stage("chain")
    user_input = {
        "findings": findings,
        "design_controls": recon.get("design_controls", []),
        "repo_path": str(ctx.repo_path),
        **ctx.extras(),
    }

    log.info(
        "[%s] chain: analyzing %d findings (model=%s)",
        ctx.run_id, len(findings), sc.model,
    )

    try:
        result = await run_agent(
            stage="chain",
            prompt_file=ctx.prompt("09-chain"),
            user_input=user_input,
            schema_file=ctx.schema("chain"),
            allowed_tools=sc.tools,
            model=sc.model,
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("chain"),
            artifact_name="chain",
            repair_attempts=sc.repair_attempts,
        )
    except (AgentRunError, TransientAgentError) as e:
        # Fail-soft: a chain-stage failure must NEVER abort the run (mirror
        # Trace). Store a well-formed EMPTY analysis so Report still has an
        # artifact to read, and return 0.
        log.warning(
            "[%s] chain failed: %s — storing empty analysis", ctx.run_id, e
        )
        db.add_chain_analysis(ctx.run_id, {
            "summary": f"chain analysis failed: {e}",
            "chains": [],
        })
        return 0

    payload = result.payload
    db.add_chain_analysis(ctx.run_id, payload)
    db.record_cost(ctx.run_id, "chain", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "chain", None, "jsonl", str(result.artifact_path))
    chains = payload.get("chains") or []
    log.info("[%s] chain: constructed %d chains", ctx.run_id, len(chains))
    return len(chains)
