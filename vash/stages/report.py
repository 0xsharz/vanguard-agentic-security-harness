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
        redacted = redact_json(empty)
        out_path.write_text(json.dumps(redacted, indent=2))
        _write_markdown_report(ctx, db, redacted)
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
            effort=sc.effort,
            thinking=sc.thinking,
        )
    except (AgentRunError, TransientAgentError) as e:
        log.error("[%s] report agent failed: %s — emitting fallback report",
                  ctx.run_id, e)
        fallback = _build_fallback_report(ctx, db, reachable, target, chains)
        _attach_input_inventory(db, ctx.run_id, fallback)
        _attach_coverage(db, ctx.run_id, fallback)
        _attach_cwe(db, ctx.run_id, fallback)
        _attach_poc_evidence(db, ctx.run_id, fallback)
        _attach_variants(db, ctx.run_id, fallback)
        # Fix 1 (review): per-finding validation verdict + confidence — same
        # authoritative post-hoc treatment as CWE/variants above.
        _attach_validation(db, ctx.run_id, fallback)
        # Task 3: report enrichment — scan metrics / verification funnel /
        # CVSS baseline, same authoritative post-hoc treatment as CWE/
        # coverage/variants above (metrics+verification are always
        # state-sourced; CVSS only fills a gap the fallback builder left,
        # never overwrites it).
        _attach_scan_metrics(db, ctx.run_id, fallback)
        _attach_verification(db, ctx.run_id, fallback)
        _attach_cvss(db, ctx.run_id, fallback)
        redacted = redact_json(fallback)
        out_path.write_text(json.dumps(redacted, indent=2))
        _write_markdown_report(ctx, db, redacted)
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
    # Preflight: what the run could ACTUALLY do. Belongs beside the findings,
    # because "PoC confirmation was impossible in this container" changes how
    # every finding below should be read — and a log line nobody opens does not
    # convey that.
    _attach_preflight(ctx, payload)
    # D4: backfill CWE onto each finding from run state so downstream consumers
    # (SARIF, benchmark scorers that class-match on CWE) don't see a bare finding.
    _attach_cwe(db, ctx.run_id, payload)
    _attach_poc_evidence(db, ctx.run_id, payload)
    # A2: attach located deduped-sibling references (VVAH "Also at:" parity) —
    # same authoritative post-hoc treatment as CWE/coverage/input-inventory above.
    _attach_variants(db, ctx.run_id, payload)
    # Fix 1 (review): per-finding validation verdict + confidence — same
    # authoritative post-hoc treatment as CWE/coverage/variants above.
    _attach_validation(db, ctx.run_id, payload)
    # Task 3: report enrichment — scan metrics / verification funnel / CVSS
    # baseline, same authoritative post-hoc treatment as CWE/coverage/variants
    # above (metrics+verification are always state-sourced; CVSS only fills a
    # gap the agent left, never overwrites it).
    _attach_scan_metrics(db, ctx.run_id, payload)
    _attach_verification(db, ctx.run_id, payload)
    _attach_cvss(db, ctx.run_id, payload)
    redacted = redact_json(payload)
    out_path.write_text(json.dumps(redacted, indent=2))
    _write_markdown_report(ctx, db, redacted)
    log.info("[%s] report: %d findings, %d inputs in inventory, written to %s",
             ctx.run_id, len(payload.get("findings", [])),
             len(payload.get("input_inventory", [])), out_path)
    return out_path


def _write_markdown_report(ctx: StageContext, db: StateDB, payload: dict) -> None:
    """Task 4: also emit a human-facing VVAH/GHSA-style `report.md` alongside
    `report.json`. Rendered from the ALREADY-REDACTED payload (the same object
    written to report.json) so the Markdown never carries anything the JSON
    doesn't. Fail-soft: any render/write failure is logged and leaves
    report.json — the authoritative machine artifact — completely intact."""
    try:
        from vash.reporting.markdown import render_report
        md = render_report(payload, db, ctx.run_id)
        (ctx.results_dir("report") / "report.md").write_text(md)
    except Exception as e:  # additive artifact — never break report emission
        log.warning("[%s] markdown render failed (report.json intact): %s",
                    ctx.run_id, e)


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


# How much executed-PoC material the report carries per finding. The PoC code
# is the reproduction recipe (worth keeping in full-ish); run_output can be
# megabytes of application noise, so it is tail-bounded — the observer marker
# lines are extracted separately and always kept, because they ARE the proof.
_POC_CODE_CHARS = 4000
_POC_OUTPUT_CHARS = 2000
_OBSERVER_MARKER = "[VASH-OBSERVER]"


def _observer_markers(run_output: str) -> list[str]:
    """The observer evidence lines from a PoC's output — the record that the
    dangerous operation was actually seen to happen (a process spawned, a
    socket opened), as opposed to a PoC that merely exited 0."""
    return [ln.strip() for ln in (run_output or "").splitlines()
            if _OBSERVER_MARKER in ln][:40]


def _attach_poc_evidence(db: StateDB, run_id: str, payload: dict) -> None:
    """Attach each finding's EXECUTED-PoC evidence to the report finding.

    VASH's differentiator is that a confirmed finding was not merely reasoned
    about — a real PoC was written and RUN in the sandbox, and (Phase 3) a
    runtime observer recorded the dangerous operation as it fired. All of that
    lived only in run state: the report agent never emits `poc`, so
    markdown.py's "Proof of Concept" section rendered "Not determined" even for
    findings that had been proven by execution, and `report.json` carried no
    receipt at all. Measured on a live run: 5 delivered findings, every one with
    poc_succeeded=1, and zero observer lines anywhere in the report.

    Same authoritative post-hoc treatment as _attach_cwe/_attach_variants:
    sourced from run state keyed by finding_id, never invented, fail-soft.
    """
    try:
        by_id = {f.finding_id: f for f in db.get_findings(run_id)}
        for rf in payload.get("findings", []):
            finding = by_id.get(rf.get("finding_id"))
            if finding is None:
                continue
            poc = ((finding.raw_json or {}).get("poc") or {})
            if not poc.get("code"):
                continue
            run_output = str(poc.get("run_output") or "")
            block = {
                "language": poc.get("language"),
                "code": str(poc.get("code"))[:_POC_CODE_CHARS],
                "succeeded": bool(finding.poc_succeeded),
            }
            if run_output:
                block["run_output"] = run_output[-_POC_OUTPUT_CHARS:]
            if poc.get("notes"):
                block["notes"] = str(poc["notes"])
            markers = _observer_markers(run_output)
            if markers:
                block["observer_evidence"] = markers
            rf["poc"] = block
            # Executed-PoC status as a first-class, machine-readable field so a
            # consumer can filter the proven subset without parsing prose.
            rf["poc_succeeded"] = bool(finding.poc_succeeded)
    except Exception as e:  # additive disclosure — never break report emission
        log.warning("[%s] poc evidence attach failed: %s", run_id, e)


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


def _attach_validation(db: StateDB, run_id: str, payload: dict) -> None:
    """Attach each finding's adversarial-verification outcome (Validate's
    verdict/rationale/validator_confidence) and the hunter's own confidence
    onto the report finding — same authoritative post-hoc treatment as
    _attach_variants/_attach_cwe above. Neither the report agent nor the
    fallback builder populate `finding["validation"]`/`finding["confidence"]`
    in the report payload, so without this attach markdown.py's "Adversarial
    verification" block and "Confidence" line always render Not-determined.

    Sourced from run state (`Finding.validation_status` / `.validation_json` /
    `.confidence`), keyed by `finding_id`. Only the keys actually present on
    the stored validation payload are copied — never invented; a key Validate
    didn't emit (e.g. a needs_more_info verdict carries no cvss_vector) is
    simply omitted, and the renderer already degrades gracefully for that.
    Fail-soft: validation disclosure must never break report emission."""
    try:
        by_id = {f.finding_id: f for f in db.get_findings(run_id)}
        for rf in payload.get("findings", []):
            finding = by_id.get(rf.get("finding_id"))
            if finding is None:
                continue
            vjson = finding.validation_json or {}
            validation: dict = {}
            verdict = finding.validation_status or vjson.get("verdict")
            if verdict:
                validation["verdict"] = verdict
            if "rationale" in vjson:
                validation["rationale"] = vjson["rationale"]
            if "validator_confidence" in vjson:
                validation["validator_confidence"] = vjson["validator_confidence"]
            if validation:
                rf["validation"] = validation
            if finding.confidence is not None:
                rf["confidence"] = finding.confidence
    except Exception as e:  # additive disclosure — never break report emission
        log.warning("[%s] validation attach failed: %s", run_id, e)


def _attach_preflight(ctx, payload: dict) -> None:
    """Attach what the run could actually do, and a caveat when it could not.

    A scan whose container lacks the target's dependencies still emits findings
    — they are just static guesses that read like executed proof. The
    `coverage.caveats` line is the part that matters: it puts the limitation
    where someone reading the findings will actually meet it.

    Fail-soft and additive: a missing preflight record leaves the report exactly
    as it was.
    """
    try:
        pre = getattr(ctx, "preflight", None)
        if not pre:
            return
        payload["preflight"] = pre
        if pre.get("execution_enabled") and not pre.get("poc_confirmation_available"):
            missing = ", ".join(pre.get("degraded") or []) or "unknown"
            caveat = (
                "Executed-PoC confirmation was requested but NOT fully available "
                f"in this container (missing: {missing}). Findings below may not "
                "have been proven by execution, and a finding that could not be "
                "proven here must NOT be read as disproven."
            )
            coverage = payload.get("coverage")
            if isinstance(coverage, dict):
                coverage.setdefault("caveats", []).append(caveat)
                coverage["coverage_complete"] = False
            else:
                payload["preflight_caveat"] = caveat
    except Exception as e:  # pragma: no cover - additive disclosure only
        log.warning("[report] preflight attach failed (report still emitted): %s", e)


def _attach_coverage(db: StateDB, run_id: str, payload: dict) -> None:
    """Attach a consolidated `coverage` object (4.7) to a report payload —
    reuses existing data rather than re-running any analysis:
      - inputs enumerated/covered/uncovered from the F1 completeness ledger
        (`db.get_inputs`);
      - tasks_by_source / findings_by_status from the 4.3 `db.run_summary`;
      - source_files/covered_files/catchall_tasks/catchall_dropped from the
        F6 catch-all sweep record `_add_catchall_tasks` persists;
      - tasks_failed / tasks_incomplete straight from run state.
    `coverage_complete` is False whenever the catch-all cap dropped files, any
    enumerated input never reached a disposition, OR any hunt task failed or
    never finished — an operator must never be told coverage is complete when
    it isn't.

    The task counts are not cosmetic. On a real scan one hunt task died to a
    repeated API error (`done=54 failed=1`), meaning an entire attack angle on
    the target was never examined — and NOTHING in the delivered report said so.
    The reader saw only "source_files: 161, covered_files: 159" and would
    reasonably conclude the sweep was complete.

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
        # Straight from run state: run_summary's `tasks` block carries only
        # total/by_source, so reading a by_status off it would silently always
        # report zero failures.
        all_tasks = db.get_all_tasks(run_id)
        failed = sum(1 for t in all_tasks if t.status == "failed")
        # anything neither done nor failed never produced a result: a task left
        # pending by a budget abort, or still marked running when the run ended.
        incomplete = sum(1 for t in all_tasks if t.status not in ("done", "failed"))
        coverage["tasks_failed"] = failed
        coverage["tasks_incomplete"] = incomplete
        if failed or incomplete:
            coverage["coverage_caveat"] = (
                f"{failed} hunt task(s) FAILED and {incomplete} never completed — "
                "the attack angles they covered were not examined. Absence of a "
                "finding in those areas is not evidence that none exists."
            )
        coverage["coverage_complete"] = (
            coverage.get("catchall_dropped", 0) == 0
            and all(i.get("disposition") for i in inputs)
            and failed == 0
            and incomplete == 0
        )
        payload["coverage"] = coverage
    except Exception as e:  # fail-soft — coverage must never break the report
        log.warning("[%s] coverage attach failed (continuing): %s", run_id, e)


# Baseline CVSS 3.1 (score, vector) keyed by severity band — used only when a
# report finding carries no cvss of its own (a backfill floor, never an
# override; see _attach_cvss).
_CVSS_BASELINE = {
    "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high":     (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "medium":   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "low":      (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "informational": (0.0, "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
}


def _attach_cvss(db: "StateDB | None", run_id: str, payload: dict) -> None:
    """Backfill a CVSS 3.1 baseline (score/severity/vector) onto each report
    finding that doesn't already carry one — a severity-keyed floor for
    whatever the report agent (or the fallback builder) left unset. NEVER
    overwrites an existing `cvss`: the agent is instructed to prefer the
    real, per-finding vector Validate already computed (prompts/08-report.md)
    when one is available. Pure over `payload` — does not read `db` — so it
    degrades safely even when no DB handle is available (e.g. called from the
    no-agent fallback path with db=None). Fail-soft."""
    try:
        for f in payload.get("findings", []):
            if not f.get("cvss"):
                score, vector = _CVSS_BASELINE.get((f.get("severity") or "").lower(), (0.0, ""))
                f["cvss"] = {"score": score, "severity": f.get("severity"), "vector": vector}
    except Exception as e:  # additive disclosure — never break report emission
        log.warning("[%s] cvss backfill failed: %s", run_id, e)


def _attach_scan_metrics(db: StateDB, run_id: str, payload: dict) -> None:
    """Attach run-level scan metrics (file coverage, cost, duration, per-phase
    tokens) to a report payload. Sourced from run state — the F6 catch-all
    coverage record, the costs table (`db.total_cost` / `db.run_summary`),
    and the run row's started_at/finished_at — so it is authoritative
    regardless of what the report agent produced. A metric that isn't
    knowable yet (report always runs BEFORE `db.finish_run` sets
    finished_at, so `duration_sec` is normally absent at attach time) is
    simply omitted rather than emitted as a misleading zero/null. Fail-soft:
    metrics disclosure must never break report emission."""
    try:
        cov = db.get_coverage(run_id) or {}
        run = db.get_run(run_id)
        stages = db.run_summary(run_id).get("stages", {})
        metrics: dict = {
            "cost_usd": round(db.total_cost(run_id), 4),
            "tokens_by_phase": [
                {
                    "phase": stage,
                    "input_tokens": agg.get("input_tokens", 0),
                    "output_tokens": agg.get("output_tokens", 0),
                    "cost_usd": round(agg.get("usd", 0.0), 4),
                }
                for stage, agg in stages.items()
            ],
        }
        if cov.get("source_files") is not None:
            metrics["files_in_scope"] = cov["source_files"]
        if cov.get("covered_files") is not None:
            metrics["files_analyzed"] = cov["covered_files"]
        if cov.get("source_files"):
            metrics["coverage_pct"] = round(100 * cov["covered_files"] / cov["source_files"], 1)
        if run is not None and run["started_at"] is not None and run["finished_at"] is not None:
            metrics["duration_sec"] = round(run["finished_at"] - run["started_at"], 1)
        payload["scan_metrics"] = metrics
    except Exception as e:  # additive disclosure — never break report emission
        log.warning("[%s] scan_metrics attach failed: %s", run_id, e)


def _attach_verification(db: StateDB, run_id: str, payload: dict) -> None:
    """Attach the raw/TP/FP/needs-info/duplicate/precision verification tally
    to a report payload — computed from EVERY finding this run recorded (not
    just the reachable/canonical ones that made the final `findings` list),
    so it discloses the full validate funnel rather than just the survivors.
    Sourced from run state, authoritative regardless of what the report
    agent produced. Fail-soft: verification disclosure must never break
    report emission."""
    try:
        fs = db.get_findings(run_id)
        raw = len(fs)
        tp = sum(1 for f in fs if f.validation_status == "confirmed")
        fp = sum(1 for f in fs if f.validation_status == "rejected")
        nmi = sum(1 for f in fs if f.validation_status == "needs_more_info")
        dup = sum(1 for f in fs if f.group_id and not f.is_canonical)
        payload["verification"] = {
            "raw_findings": raw, "true_positives": tp, "false_positives": fp,
            "needs_more_info": nmi, "duplicates_collapsed": dup,
            "precision_pct": round(100 * tp / raw, 1) if raw else 0.0,
        }
    except Exception as e:  # additive disclosure — never break report emission
        log.warning("[%s] verification attach failed: %s", run_id, e)


def _group_members_excluding(db: StateDB, run_id: str, group_id: str,
                             exclude: str) -> list[dict]:
    # VVAH DupLocation parity (s7_dedup.py::_attach_duplicates): a deduped
    # sibling is demoted to a LOCATED reference, never dropped — carry
    # file/line/class so the report can render "Also at:" and a location-aware
    # consumer sees every co-located confirmed site.
    #
    # D8 promotes one canonical PER FILE in a cross-file group, so a group can
    # have MULTIPLE headline (canonical) findings. A sibling belongs in
    # `exclude`'s variants only if it is genuinely demoted (is_canonical = 0)
    # AND it is actually `exclude`'s demoted sibling rather than some OTHER
    # canonical's: either it shares `exclude`'s file, or (the single-canonical
    # case) no other canonical in the group claims its file at all. Without
    # this, every headline in a multi-canonical group would list every OTHER
    # headline's demoted duplicates too.
    rows = db._conn.execute(  # type: ignore[attr-defined]
        "SELECT finding_id, file, line_start, line_end, vuln_class, is_canonical "
        "FROM findings WHERE run_id = ? AND group_id = ?",
        (run_id, group_id),
    ).fetchall()
    exclude_file = next((r["file"] for r in rows if r["finding_id"] == exclude), None)
    canonical_files = {r["file"] for r in rows if r["is_canonical"]}
    return [
        {"finding_id": r["finding_id"], "file": r["file"],
         "line_start": r["line_start"], "line_end": r["line_end"],
         "vuln_class": r["vuln_class"]}
        for r in rows
        if r["finding_id"] != exclude
        and not r["is_canonical"]
        and (r["file"] == exclude_file or r["file"] not in canonical_files)
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
