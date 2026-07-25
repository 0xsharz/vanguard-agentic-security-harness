"""Stage 3: Validate — adversarial review, different model from Hunt."""

from __future__ import annotations

import asyncio
import logging

from vash.cvss import rating as cvss_rating, score as cvss_score
from vash.graph_context import neighbors_for_finding
from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.state import Finding, StateDB
from vash.stages._common import StageContext

log = logging.getLogger(__name__)

# CVSS 3.1 qualitative band -> audit's lowercase finding-severity enum
# (schemas/finding.schema.json). Mirrors VVAH's
# s8_chain._CVSS_BAND_TO_SEV / _sev_from_band. "None"/"Unknown" are
# deliberately absent: they mean "no mapped band" so the caller keeps the
# finding's existing severity instead of overwriting it.
_CVSS_RATING_TO_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _severity_from_cvss_rating(rating: str | None) -> str | None:
    """Map a CVSS 3.1 qualitative rating to audit's severity enum. Returns
    None for "None"/"Unknown"/absent so the caller falls back to (i.e. keeps)
    the finding's existing severity."""
    return _CVSS_RATING_TO_SEVERITY.get((rating or "").strip().lower())


def _apply_cvss(db: StateDB, finding_id: str, payload: dict) -> dict:
    """For a confirmed verdict carrying a `cvss_vector`, compute its CVSS 3.1
    base score/rating, fold both into the stored validation payload, and make
    the CVSS band authoritative for the finding's severity.

    Fail-open: an absent or unparseable vector (`cvss.score()` returns None)
    leaves the payload and the finding's severity untouched — this must never
    break validate."""
    s = cvss_score(payload.get("cvss_vector"))
    if s is None:
        return payload
    r = cvss_rating(s)
    payload = {**payload, "cvss_score": s, "cvss_rating": r}
    sev = _severity_from_cvss_rating(r)
    if sev:
        db.update_finding_severity(finding_id, sev)
    return payload


async def run_validate(ctx: StageContext, db: StateDB) -> int:
    """Validate every finding that hasn't been validated yet. Returns
    count of confirmed findings."""
    unvalidated = db.get_unvalidated_findings(ctx.run_id)
    if not unvalidated:
        log.info("[%s] validate: nothing to validate", ctx.run_id)
        return 0

    sc = ctx.stage("validate")
    sem = asyncio.Semaphore(sc.concurrency)

    log.info(
        "[%s] validate: %d findings (concurrency=%d, model=%s)",
        ctx.run_id, len(unvalidated), sc.concurrency, sc.model,
    )

    tasks_by_id = {t.task_id: t for t in db.get_all_tasks(ctx.run_id)}
    counters = {"confirmed": 0, "rejected": 0, "needs_more_info": 0, "failed": 0}

    # V5: recon's design_controls map (if any), loaded once and injected into
    # every finding's user_input as a verify-empirically hint (never a
    # trusted exclusion) — see prompts/03-validate.md's "Design controls"
    # section and the pre-existing "Verify defenses empirically" rule.
    recon = db.get_recon_output(ctx.run_id) or {}
    design_controls = recon.get("design_controls", [])

    async def _one(f: Finding) -> None:
        async with sem:
            task = tasks_by_id.get(f.task_id)
            ctx_block = {
                "attack_class": task.attack_class if task else f.vuln_class,
                "scope_hint": task.scope_hint if task else "",
                "rationale": task.rationale if task else "",
            }
            user_input = {
                "finding": f.raw_json,
                "task_context": ctx_block,
                "repo_path": str(ctx.repo_path),
                **({"design_controls": design_controls} if design_controls else {}),
                **ctx.extras(),
            }
            gq = ctx.graph()
            gc = neighbors_for_finding(gq, f.file, f.line_start) if gq else {}
            if gc:
                user_input["graph_context"] = gc
            try:
                result = await run_agent(
                    stage="validate",
                    prompt_file=ctx.prompt("03-validate"),
                    user_input=user_input,
                    schema_file=ctx.schema("validation"),
                    allowed_tools=sc.tools,
                    model=sc.model,
                    cwd=ctx.repo_path,
                    add_dirs=[ctx.repo_path],
                    max_turns=sc.max_turns,
                    permission_mode=sc.permission_mode,
                    artifact_dir=ctx.results_dir("validate"),
                    artifact_name=f.finding_id,
                    repair_attempts=sc.repair_attempts,
                    execution_enabled=ctx.execution_enabled,
                )
            except (AgentRunError, TransientAgentError) as e:
                log.warning("[%s] validate %s failed: %s", ctx.run_id, f.finding_id, e)
                counters["failed"] += 1
                # Treat unparseable validation as needs_more_info to avoid
                # silently confirming.
                db.set_finding_validation(
                    f.finding_id, "needs_more_info",
                    {"finding_id": f.finding_id, "verdict": "needs_more_info",
                     "rationale": f"validator failed to produce schema-valid output: {e}",
                     "validator_confidence": 0.0},
                )
                return

            verdict = result.payload.get("verdict", "needs_more_info")
            payload = result.payload
            if verdict == "confirmed":
                payload = _apply_cvss(db, f.finding_id, payload)
            db.set_finding_validation(f.finding_id, verdict, payload)
            db.record_cost(ctx.run_id, "validate", f.finding_id, result.raw_result_message)
            db.add_artifact(ctx.run_id, "validate", f.finding_id, "jsonl",
                            str(result.artifact_path))
            counters[verdict] = counters.get(verdict, 0) + 1

    await asyncio.gather(*(_one(f) for f in unvalidated))
    log.info(
        "[%s] validate: confirmed=%d rejected=%d needs_more_info=%d failed=%d",
        ctx.run_id,
        counters.get("confirmed", 0),
        counters.get("rejected", 0),
        counters.get("needs_more_info", 0),
        counters["failed"],
    )
    return counters.get("confirmed", 0)
