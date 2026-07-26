"""`vash validate` — decoupled, static-first, independent second-opinion
re-verification.

This is a SEPARATE, opt-in command (NOT part of the scan loop) — the Phase-6
counterpart to Phase 5's ``vash remediate``. It reads the confirmed canonical
findings a prior scan already stored and, for each, spawns a FRESH agent
session that independently RE-VERIFIES the finding from scratch — a genuine
second opinion (optionally on a different model) rather than a re-print of
the scan's own verdict.

Stance (ported from Visa VVAH's ``s6_verify`` second-opinion reviewer):
  * The agent is told to assume the scan's verdict is unproven and to
    ACTIVELY SEARCH FOR THE OPPOSITE verdict before agreeing with it — for
    the normal case (the selector only feeds scan-CONFIRMED findings) that
    means actively trying to prove a false positive.
  * A ``validated`` verdict below the configured ``min_confidence`` (VVAH's
    gate, default 7/10) is downgraded to ``needs_review`` post-hoc — the
    model's own confidence self-report is honored, but a low-confidence
    "yes" is never silently treated as a confirmation.

Method (reused from VASH's own ``prompts/03-validate.md``): the adversarial
disprove method plus the VulnHunter per-class disprove-gates already grafted
there in Phase F5 (downgrade discipline, full-codebase defense search,
no-input elimination, multi-writer rule) — restated for this standalone
re-verification agent in ``prompts/revalidate.md``.

Static-first guardrails (OVERRIDE defaults):
  * READ-ONLY. The agent's tools are Read/Grep/Glob only — no Bash, no
    Write. It never executes the target.
  * DECOUPLED. This stage only READS the scan's findings (``get_findings``)
    and appends its own telemetry (``record_cost`` / ``add_artifact``),
    exactly like every other stage — it never mutates
    ``findings.validation_status`` or any other scan-state table. The scan's
    own verdict is left untouched; revalidate's verdict lives entirely in
    its own output artifacts.
  * ``agrees_with_scan`` is computed DETERMINISTICALLY by this module from
    the (possibly downgraded) verdict — the model's self-reported bool is
    never trusted blindly, mirroring how ``remediate.py`` forces
    ``needs_verification`` rather than trusting the model's own claim.
  * Every written artifact is redacted via :mod:`vash.redact`.
  * Fail-soft per finding — one finding's failure never aborts the batch; it
    becomes a ``needs_review`` record (never a silent validated/failed).

Surfacing DISAGREEMENTS is the whole value of this command: a ``failed``
verdict on a scan-confirmed finding is an OVERTURNED finding — a false
positive the second opinion caught — and the summary/markdown report puts
those front and center.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from vash.redact import redact, redact_json
from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.state import Finding, StateDB
from vash.stages._common import StageContext

log = logging.getLogger(__name__)

# VVAH s6's confidence gate: a "validated" verdict below this is not trusted
# as a confirmation and is downgraded to "needs_review".
DEFAULT_MIN_CONFIDENCE = 7


def _scan_verdict(f: Finding) -> str | None:
    return (f.validation_json or {}).get("verdict")


def _compute_agreement(verdict: str | None, scan_verdict: str | None) -> bool:
    """Deterministic agreement — NEVER trust the model's self-reported bool
    (same discipline as ``remediate.py`` forcing ``needs_verification=True``
    rather than trusting the model's own claim).

    The selector feeds this stage only scan-confirmed findings, so
    ``scan_verdict`` is normally ``"confirmed"``: agreement holds iff the
    FINAL verdict (after any min-confidence downgrade) is ``"validated"`` —
    ``"needs_review"`` is inherently inconclusive and is never counted as
    agreement, and ``"failed"`` is exactly the disagreement (an overturned
    finding) this command exists to surface. The fallback branch is a
    symmetric default for any other ``scan_verdict`` a future caller might
    pass.
    """
    if scan_verdict == "confirmed":
        return verdict == "validated"
    return verdict != "validated"


def _pointer_fields(f: Finding) -> dict:
    """A light, non-sensitive pointer back to the original finding so a
    ``revalidation.json`` record is self-describing without duplicating the
    (potentially sensitive) evidence text."""
    return {
        "file": f.file,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "vuln_class": f.vuln_class,
        "severity": f.severity,
    }


def _below_gate(confidence: object, min_confidence: int) -> bool:
    try:
        return float(confidence) < float(min_confidence)
    except (TypeError, ValueError):
        # Unparseable confidence -> treat conservatively as below-gate.
        return True


def _error_record(f: Finding, scan_verdict: str | None, note: str) -> dict:
    """A fail-soft record emitted when the revalidate agent errors — verdict
    is ``needs_review`` (never a silent validated/failed) so a broken agent
    call can never masquerade as either a re-confirmation or an overturned
    finding."""
    rec = {
        "finding_id": f.finding_id,
        "verdict": "needs_review",
        "confidence": 0,
        "agrees_with_scan": _compute_agreement("needs_review", scan_verdict),
        "rationale": note,
        "alternative_explanation": "",
        "scan_verdict": scan_verdict,
        "downgraded": False,
        "error": True,
    }
    rec.update(_pointer_fields(f))
    return rec


async def _revalidate_one(ctx: StageContext, db: StateDB, f: Finding,
                          out_dir: Path, model: str | None,
                          min_confidence: int) -> dict:
    """Run the independent second-opinion agent for one finding. Raises on
    agent error — the caller turns that into a fail-soft needs_review
    record."""
    sc = ctx.stage("revalidate")
    scan_verdict = _scan_verdict(f)
    user_input = {
        "finding": f.raw_json,
        "scan_verdict": scan_verdict,
        "repo_path": str(ctx.repo_path),
        **ctx.extras(),
    }
    result = await run_agent(
        stage="revalidate",
        prompt_file=ctx.prompt("revalidate"),
        user_input=user_input,
        schema_file=ctx.schema("revalidation"),
        allowed_tools=sc.tools,
        model=model or sc.model,
        cwd=ctx.repo_path,
        add_dirs=[ctx.repo_path],
        max_turns=sc.max_turns,
        permission_mode=sc.permission_mode,
        artifact_dir=out_dir / "agent",
        artifact_name=f.finding_id,
        repair_attempts=sc.repair_attempts,
    )
    db.record_cost(ctx.run_id, "revalidate", f.finding_id, result.raw_result_message)
    db.add_artifact(ctx.run_id, "revalidate", f.finding_id, "jsonl",
                    str(result.artifact_path))

    payload = dict(result.payload)
    payload["finding_id"] = f.finding_id          # authoritative
    payload["scan_verdict"] = scan_verdict
    payload["downgraded"] = False

    verdict = payload.get("verdict")
    confidence = payload.get("confidence")
    # VVAH s6 min-confidence gate: an under-confident "validated" is not a
    # trustworthy confirmation — downgrade it post-hoc rather than trust the
    # raw verdict as-is.
    if verdict == "validated" and _below_gate(confidence, min_confidence):
        payload["original_verdict"] = verdict
        payload["downgrade_reason"] = (
            f"verdict was 'validated' at confidence {confidence}/10, below "
            f"the min-confidence gate ({min_confidence}/10) — downgraded per "
            "the VVAH s6 second-opinion gate")
        verdict = "needs_review"
        payload["verdict"] = verdict
        payload["downgraded"] = True

    # Deterministic — never trust the model's self-reported bool.
    payload["agrees_with_scan"] = _compute_agreement(verdict, scan_verdict)
    payload.update(_pointer_fields(f))
    return payload


def _evidence_preview(f: Finding, limit: int = 1200) -> str:
    ev = f.evidence or ""
    return ev if len(ev) <= limit else ev[:limit] + "\n… (truncated)"


def _render_one(lines: list[str], f: Finding, record: dict) -> None:
    verdict = record["verdict"]
    tag = ""
    if verdict == "failed":
        tag = "  — OVERTURNED (false positive caught by the second opinion)"
    elif record.get("downgraded"):
        tag = "  (downgraded from validated — below confidence gate)"
    lines.append(f"## `{f.finding_id}` — {f.vuln_class} ({verdict}){tag}")
    lines.append(f"- **Location**: `{f.file}:{f.line_start}-{f.line_end}`  ")
    lines.append(f"- **Severity**: {f.severity}")
    lines.append(f"- **Scan verdict**: {record.get('scan_verdict') or '(unknown)'}")
    lines.append(f"- **Second-opinion verdict**: {verdict} "
                 f"(confidence {record.get('confidence', '?')}/10)")
    lines.append(f"- **Agrees with scan**: {record.get('agrees_with_scan')}")
    if record.get("downgraded"):
        lines.append(f"- **Downgrade**: {record.get('downgrade_reason', '')}")
    if record.get("error"):
        lines.append("- **Agent error**: this finding's re-verification failed "
                     "(fail-soft) — treat as unresolved, not as agreement.")
    lines.append("")
    lines.append("**Evidence (as originally scanned):**")
    lines.append("```")
    lines.append(_evidence_preview(f))
    lines.append("```")
    lines.append("")
    if record.get("rationale"):
        lines.append(f"**Rationale**: {record['rationale']}")
        lines.append("")
    if record.get("alternative_explanation"):
        lines.append(f"**Alternative explanation considered**: "
                     f"{record['alternative_explanation']}")
        lines.append("")
    lines.append("---")
    lines.append("")


def _render_markdown(run_id: str, pairs: list[tuple[Finding, dict]],
                     model: str | None, min_confidence: int, counts: dict,
                     overturned: list[str]) -> str:
    lines: list[str] = []
    lines.append(f"# Revalidation — `{run_id}`")
    lines.append("")
    lines.append("_Generated by `vash validate`. A fresh, READ-ONLY, independent "
                 "second opinion on this run's scan-confirmed findings — a "
                 "separate agent session that actively tries to reach the "
                 "OPPOSITE of the scan's verdict before agreeing with it "
                 "(VVAH `s6_verify` stance). It never executes the target and "
                 "never modifies the original scan's records._")
    lines.append("")
    if model:
        lines.append(f"- model override: `{model}`")
    lines.append(f"- min-confidence gate: {min_confidence}/10 (a `validated` "
                 "verdict below this is downgraded to `needs_review`)")
    lines.append(f"- outcomes: **{counts['validated']} re-confirmed** "
                 f"(validated), **{counts['failed']} OVERTURNED** (failed), "
                 f"{counts['needs_review']} needs-review")
    lines.append("")
    if overturned:
        lines.append(f"## OVERTURNED — {len(overturned)} false positive(s) "
                     "the second opinion caught")
        lines.append("")
        lines.append("The scan confirmed these; independent re-verification "
                     "actively pursued and found the opposite (false-positive) "
                     "verdict — review before acting on them:")
        lines.append("")
        for fid in overturned:
            lines.append(f"- `{fid}`")
        lines.append("")
    lines.append("---")
    lines.append("")
    if not pairs:
        lines.append("_No confirmed canonical findings to revalidate._")
        lines.append("")
    for f, record in pairs:
        _render_one(lines, f, record)
    return "\n".join(lines)


async def run_revalidate(ctx: StageContext, db: StateDB, *, out_dir: Path,
                         model: str | None = None,
                         min_confidence: int = DEFAULT_MIN_CONFIDENCE) -> dict:
    """Independently re-verify a prior scan's confirmed canonical findings —
    a fresh second opinion (VVAH s6 stance: actively pursue the OPPOSITE
    verdict), optionally on a different model than the scan's own Validate
    stage.

    Writes ``revalidation.json`` (list of records) and ``REVALIDATION.md``
    under ``out_dir`` (both redacted), and returns a summary dict with
    per-verdict counts and the list of OVERTURNED finding ids (scan-confirmed
    findings this second opinion actively disproved). READ-ONLY: never
    executes the target, never mutates the scan DB (only appends telemetry
    via record_cost/add_artifact, exactly like every other stage). Fail-soft
    per finding."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = db.get_findings(ctx.run_id, validation_status="confirmed",
                               canonical_only=True)
    log.info("[%s] revalidate: %d confirmed canonical finding(s) to "
             "independently re-verify, min_confidence=%d/10%s",
             ctx.run_id, len(findings), min_confidence,
             f", model={model}" if model else "")

    pairs: list[tuple[Finding, dict]] = []
    for f in findings:
        scan_verdict = _scan_verdict(f)
        try:
            record = await _revalidate_one(ctx, db, f, out_dir, model, min_confidence)
        except (AgentRunError, TransientAgentError) as e:
            log.warning("[%s] revalidate %s: agent failed: %s — needs_review "
                        "(fail-soft)", ctx.run_id, f.finding_id, e)
            record = _error_record(f, scan_verdict, f"revalidation agent failed: {e}")
        except Exception as e:  # fail-soft: one finding never aborts the batch
            log.warning("[%s] revalidate %s: unexpected error: %s — needs_review "
                        "(fail-soft)", ctx.run_id, f.finding_id, e)
            record = _error_record(f, scan_verdict, f"unexpected error: {e}")
        pairs.append((f, record))

    counts = {"validated": 0, "failed": 0, "needs_review": 0}
    overturned: list[str] = []
    for _f, record in pairs:
        counts[record["verdict"]] = counts.get(record["verdict"], 0) + 1
        if record["verdict"] == "failed":
            overturned.append(record["finding_id"])

    summary_payload = {
        "run_id": ctx.run_id,
        "generated_by": "vash validate",
        "read_only": True,
        "model": model,
        "min_confidence": min_confidence,
        "counts": counts,
        "overturned_finding_ids": overturned,
        "records": [r for _f, r in pairs],
    }
    (out_dir / "revalidation.json").write_text(
        json.dumps(redact_json(summary_payload), indent=2))

    md = _render_markdown(ctx.run_id, pairs, model, min_confidence, counts, overturned)
    (out_dir / "REVALIDATION.md").write_text(redact(md))

    log.info("[%s] revalidate: validated=%d failed(OVERTURNED)=%d "
             "needs_review=%d -> %s", ctx.run_id, counts["validated"],
             counts["failed"], counts["needs_review"], out_dir)

    return {
        "out_dir": str(out_dir),
        "counts": counts,
        "overturned_finding_ids": overturned,
        "records": [r for _f, r in pairs],
        "total": len(pairs),
    }
