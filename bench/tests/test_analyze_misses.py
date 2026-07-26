"""Offline, deterministic tests for bench/analyze_misses.py's pure core:
extract_identifiers, locate_loss_phase (all 6 audit-stage branches),
analyze_misses (score_corpus-driven end-to-end), and render_report.

No network, no scan, no StateDB -- findings/recon/traces are hand-built
plain dicts, exactly as the loss-phase locator consumes them. The optional
--diagnose layer (invoke_diagnostic / run_diagnose / build_diagnostic_prompt)
is intentionally NOT exercised here -- it shells out to `claude -p` and only
runs under an explicit CLI flag a human passes by hand (see task-3ST-brief.md).
"""

from __future__ import annotations

from bench.analyze_misses import (
    PHASE_TO_PROMPT,
    analyze_misses,
    extract_identifiers,
    locate_loss_phase,
    render_report,
)


def _cve(finding_id="CVE-TEST-1", cwe="CWE-94", cls="codegen", file_hint=None):
    return {
        "finding_id": finding_id,
        "cwe": cwe,
        "class": cls,
        "file_hint": file_hint if file_hint is not None else ["jsonschema"],
        "description": "x" * 30,
        "source_code": "https://github.com/org/repo@1.0.0",
    }


def _finding(finding_id="f_1", file="src/parser/jsonschema.py", cwe="CWE-94",
             validation_status=None, is_canonical=False, validation_json=None, raw_json=None):
    return {
        "finding_id": finding_id,
        "file": file,
        "cwe": cwe,
        "vuln_class": "code-injection",
        "validation_status": validation_status,
        "is_canonical": is_canonical,
        "validation_json": validation_json or {},
        "raw_json": raw_json or {},
    }


# ---------------------------------------------------------------------------
# locate_loss_phase -- five required scenarios (a)-(e) + one bonus (branch 6)
# ---------------------------------------------------------------------------

def test_locate_loss_phase_recon_gap_when_area_never_enumerated():
    # (a) no finding at all, and recon never references the file_hint.
    cve = _cve(file_hint=["jsonschema"])
    recon_output = {
        "subsystems": [{"name": "core", "path": "src/core", "language": "python", "purpose": "x"}],
        "inputs": [{"id": "in_1", "source_type": "cli_arg", "location": "cli.py:10",
                    "variable": "args", "entry_point": "main", "trust_level": "unauthenticated"}],
    }
    phase, evidence = locate_loss_phase(cve, [], recon_output, {})
    assert phase == "recon"
    assert "file_hint" in evidence


def test_locate_loss_phase_hunt_gap_when_recon_enumerated_the_area():
    # (b) no finding, but recon's subsystem path mentions the hint.
    cve = _cve(file_hint=["jsonschema"])
    recon_output = {
        "subsystems": [{"name": "parser", "path": "src/parser/jsonschema.py",
                         "language": "python", "purpose": "parses schemas"}],
        "inputs": [],
    }
    phase, evidence = locate_loss_phase(cve, [], recon_output, {})
    assert phase == "hunt"
    assert "codegen" in evidence


def test_locate_loss_phase_validate_false_reject():
    # (c) a matching finding exists, but validate rejected it.
    cve = _cve(file_hint=["jsonschema"])
    finding = _finding(validation_status="rejected",
                        validation_json={"rationale": "sanitized upstream by pydantic validators"})
    phase, evidence = locate_loss_phase(cve, [finding], {}, {})
    assert phase == "validate"
    assert "sanitized upstream" in evidence


def test_locate_loss_phase_dedupe_over_merge():
    # (d) matching finding confirmed, but not the canonical group member.
    cve = _cve(file_hint=["jsonschema"])
    finding = _finding(validation_status="confirmed", is_canonical=False)
    phase, evidence = locate_loss_phase(cve, [finding], {}, {})
    assert phase == "dedupe"
    assert "merged" in evidence


def test_locate_loss_phase_trace_unreachable():
    # (e) confirmed + canonical, but trace marked it unreachable.
    cve = _cve(file_hint=["jsonschema"])
    finding = _finding(finding_id="f_1", validation_status="confirmed", is_canonical=True)
    traces_by_id = {"f_1": {"reachable": False, "rationale": "guarded behind an internal-only CLI flag"}}
    phase, evidence = locate_loss_phase(cve, [finding], {}, traces_by_id)
    assert phase == "trace"
    assert "internal-only CLI flag" in evidence


def test_locate_loss_phase_scoring_when_everything_actually_survived():
    # Bonus: branch 6 -- confirmed + canonical + reachable, yet the caller
    # still says it's a miss (matcher/report granularity mismatch, not a
    # prompt gap). Exercises the fallback so all six branches are covered.
    cve = _cve(file_hint=["jsonschema"])
    finding = _finding(finding_id="f_1", validation_status="confirmed", is_canonical=True)
    traces_by_id = {"f_1": {"reachable": True, "rationale": "x" * 20}}
    phase, evidence = locate_loss_phase(cve, [finding], {}, traces_by_id)
    assert phase == "scoring"
    assert "granularity" in evidence


# ---------------------------------------------------------------------------
# analyze_misses -- end-to-end via score_corpus (reused, not re-derived).
# ---------------------------------------------------------------------------

def test_analyze_misses_returns_one_analysis_for_the_missed_cve_only():
    expected = [
        _cve("CVE-FOUND", cwe="CWE-94", cls="codegen", file_hint=["jsonschema"]),
        _cve("CVE-MISSED", cwe="CWE-918", cls="ssrf", file_hint=["http"]),
    ]
    found_finding = _finding(finding_id="f_1", file="src/parser/jsonschema.py", cwe="CWE-94",
                              validation_status="confirmed", is_canonical=True)
    confirmed = [found_finding]
    findings_all = [found_finding]
    recon_output = {"subsystems": [], "inputs": []}
    traces_by_id = {"f_1": {"reachable": True, "rationale": "x" * 20}}

    analyses = analyze_misses(confirmed, findings_all, recon_output, traces_by_id, expected)

    assert len(analyses) == 1
    miss = analyses[0]
    assert miss["cve_id"] == "CVE-MISSED"
    assert miss["class"] == "ssrf"
    assert miss["cwe"] == "CWE-918"
    assert miss["loss_phase"] == "recon"
    assert miss["responsible_prompt"] == PHASE_TO_PROMPT["recon"]
    assert "evidence" in miss


# ---------------------------------------------------------------------------
# extract_identifiers
# ---------------------------------------------------------------------------

def test_extract_identifiers_pulls_paths_functions_and_routes_ignores_prose():
    description = (
        "The bug is in src/pkg/jsonschema.py, e.g. inside the parse_schema() function, "
        "reachable via POST /api/v1/generate."
    )
    identifiers = extract_identifiers(description)
    assert "src/pkg/jsonschema.py" in identifiers
    assert "parse_schema" in identifiers
    assert "/api/v1/generate" in identifiers
    assert "e.g" not in identifiers
    assert "e.g." not in identifiers


def test_extract_identifiers_ignores_version_strings():
    identifiers = extract_identifiers("Fixed in version 1.2.3 of the package.")
    assert "1.2.3" not in identifiers


# ---------------------------------------------------------------------------
# render_report
# ---------------------------------------------------------------------------

def test_render_report_contains_cve_id_phase_and_responsible_prompt():
    analyses = [{
        "cve_id": "CVE-2026-99999", "class": "codegen", "cwe": "CWE-94",
        "loss_phase": "hunt", "responsible_prompt": "prompts/02-hunt.md",
        "evidence": "recon enumerated the area but no hunt finding matched class codegen",
    }]
    report = render_report(analyses)
    assert "CVE-2026-99999" in report
    assert "hunt" in report
    assert "prompts/02-hunt.md" in report


def test_render_report_histogram_counts_by_phase():
    analyses = [
        {"cve_id": "CVE-A", "class": "codegen", "cwe": "CWE-94", "loss_phase": "hunt",
         "responsible_prompt": "prompts/02-hunt.md", "evidence": "e1"},
        {"cve_id": "CVE-B", "class": "ssrf", "cwe": "CWE-918", "loss_phase": "hunt",
         "responsible_prompt": "prompts/02-hunt.md", "evidence": "e2"},
        {"cve_id": "CVE-C", "class": "traversal", "cwe": "CWE-22", "loss_phase": "trace",
         "responsible_prompt": "prompts/06-trace.md", "evidence": "e3"},
    ]
    report = render_report(analyses)
    assert "**hunt**: 2" in report
    assert "**trace**: 1" in report
