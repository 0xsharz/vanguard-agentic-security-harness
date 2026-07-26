"""Tests for Task 4 — the VVAH/GHSA-style Markdown renderer
(vash.reporting.markdown.render_report).

The renderer is a PURE function over an enriched report dict (the Task-3
schema shape: top-level threat_model/scan_metrics/verification, per-finding
cvss/impact/exploit_scenario/preconditions/how_to_fix/poc/variants/validation).
It must be deterministic (no timestamps / Date.now — two calls byte-identical),
must render every section header even when the underlying object is absent
(an explicit "_Not determined (static run)._" line rather than a dropped
section or a crash), and must never raise on a minimal payload.

Most tests here are pure over hand-built dicts (no StateDB, no agent/network).
One section (`_attach_validation` integration, below) additionally seeds a
real StateDB in tmp_path to prove `vash.stages.report._attach_validation` —
not a hand-injected fixture — is what actually surfaces a finding's
verdict/confidence onto the report payload the renderer consumes.

All OFFLINE regardless: no agent calls, no network.
"""

from __future__ import annotations

from pathlib import Path

from vash.reporting import render_report as render_report_reexport
from vash.reporting.markdown import render_report
from vash.stages import report as R
from vash.state import StateDB

NOT_DETERMINED = "_Not determined (static run)._"


# ---------------------------------------------------------------------------
# Fixtures — an enriched report matching the Task-3 schema, and a sparse one.
# ---------------------------------------------------------------------------


def _enriched_report() -> dict:
    """A fully-enriched report exercising every renderable field."""
    return {
        "run_id": "run_abc123",
        "target": {"repo_path": "/tmp/targets/acme-webapp", "commit": "deadbeef"},
        "summary": {
            "total": 2,
            "by_severity": {"critical": 1, "medium": 1},
        },
        "threat_model": {
            "system_context": "A Flask web service that ingests user-supplied "
                              "webhook URLs and renders templates server-side.",
            "assets": [
                {"name": "Internal metadata endpoint", "sensitivity": "critical",
                 "description": "Cloud IMDS reachable from the app host."},
                {"name": "Template cache", "sensitivity": "medium",
                 "description": "Rendered fragments stored on disk."},
            ],
            "trust_boundaries": [
                {"name": "HTTP edge", "description": "Untrusted request body enters the app."},
            ],
            "ranked_threats": [
                {"threat": "SSRF to cloud metadata", "rank": 1,
                 "rationale": "Unvalidated webhook URL is fetched server-side."},
                {"threat": "SSTI via user template", "rank": 2,
                 "rationale": "User string flows into a non-sandboxed Jinja env."},
            ],
            "open_questions": [
                "Is the IMDS endpoint blocked at the network layer?",
                "Are webhook URLs restricted to an allowlist upstream?",
            ],
        },
        "scan_metrics": {
            "files_in_scope": 120,
            "files_analyzed": 96,
            "coverage_pct": 80.0,
            "cost_usd": 1.2345,
            "tokens_by_phase": [
                {"phase": "hunt", "input_tokens": 100000, "output_tokens": 40000,
                 "cost_usd": 0.9},
                {"phase": "validate", "input_tokens": 50000, "output_tokens": 10000,
                 "cost_usd": 0.3},
            ],
            # duration_sec deliberately absent — report runs before finish_run.
        },
        "verification": {
            "raw_findings": 12,
            "true_positives": 2,
            "false_positives": 7,
            "needs_more_info": 3,
            "duplicates_collapsed": 4,
            "precision_pct": 16.7,
        },
        "findings": [
            {
                "finding_id": "f_ssrf",
                "title": "SSRF via unvalidated webhook URL reaches cloud metadata",
                "severity": "critical",
                "vuln_class": "ssrf",
                "cwe": "CWE-918",
                "file": "app/webhooks.py",
                "line_start": 42,
                "line_end": 48,
                "description": "The webhook handler fetches a user-controlled URL "
                               "with no allowlist or private-IP guard, so an attacker "
                               "can pivot to the cloud metadata service.",
                "evidence": "requests.get(request.json['callback_url'])",
                "trace": {
                    "entry_points": [
                        {"kind": "http", "location": "POST /webhooks",
                         "controllable_by": "remote_unauth"},
                    ],
                    "call_chain": [
                        {"file": "app/webhooks.py", "function": "register", "line": 42},
                        {"file": "app/net.py", "function": "fetch", "line": 9},
                    ],
                },
                "cvss": {"score": 9.1, "severity": "critical",
                         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"},
                "impact": "An attacker reads temporary IAM credentials from the "
                          "instance metadata endpoint and pivots into the cloud account.",
                "exploit_scenario": "The attacker POSTs a webhook whose callback_url "
                                    "is http://169.254.169.254/latest/meta-data/iam/... "
                                    "and the server fetches it, echoing the credentials.",
                "preconditions": [
                    "The app runs on a cloud host with IMDSv1 reachable",
                    "No egress firewall blocks link-local addresses",
                ],
                "how_to_fix": "Resolve the URL and reject any address in a private / "
                              "link-local CIDR before fetching; enforce an allowlist.",
                "recommendation": "Validate the URL against an allowlist before fetching.",
                "poc": {
                    "language": "bash",
                    "code": "curl -X POST $APP/webhooks -d "
                            "'{\"callback_url\":\"http://169.254.169.254/\"}'",
                    "succeeded": False,
                },
                "validation": {
                    "finding_id": "f_ssrf",
                    "verdict": "confirmed",
                    "rationale": "Traced the callback_url from the request body to "
                                 "requests.get with no intervening validation.",
                    "validator_confidence": 0.82,
                },
                "variants": [
                    {"finding_id": "f_ssrf2", "file": "app/legacy.py",
                     "line_start": 200, "line_end": 205, "vuln_class": "ssrf"},
                ],
            },
            {
                # Sparse finding — most optional fields absent -> Not-determined.
                "finding_id": "f_path",
                "title": "Path traversal in report download endpoint",
                "severity": "medium",
                "vuln_class": "path_traversal",
                "file": "app/files.py",
                "line_start": 7,
                "line_end": 7,
                "description": "A user-supplied filename is joined to a base directory "
                               "without containment, allowing ../ escape.",
                "evidence": "open(os.path.join(BASE, request.args['name']))",
                "trace": {"entry_points": [], "call_chain": []},
                "recommendation": "Canonicalize the path and assert it stays under BASE.",
                # no cvss/impact/exploit_scenario/preconditions/how_to_fix/poc/validation
            },
        ],
        "chains": [
            {
                "title": "Webhook SSRF into metadata credential theft",
                "finding_ids": ["f_ssrf", "f_path"],
                "severity": "critical",
                "narrative": "Chain the SSRF to read IMDS credentials, then use the "
                             "path traversal to plant a persistent web shell.",
                "blocked_by_controls": ["egress firewall on link-local"],
            },
        ],
    }


# ---------------------------------------------------------------------------
# Section headers — every top-level section is always present.
# ---------------------------------------------------------------------------


def test_all_section_headers_present() -> None:
    md = render_report(_enriched_report())
    for header in ("## Summary", "## Scan Metrics", "## Threat Model",
                   "## Verification", "## Findings"):
        assert header in md, f"missing section header: {header}"


def test_title_line_present() -> None:
    md = render_report(_enriched_report())
    assert md.lstrip().startswith("# ")
    assert "acme-webapp" in md  # target name derived from repo_path


# ---------------------------------------------------------------------------
# Per-finding block — severity heading, CVSS vector, CWE link.
# ---------------------------------------------------------------------------


def test_finding_severity_heading() -> None:
    md = render_report(_enriched_report())
    assert "### 1. [CRITICAL] SSRF via unvalidated webhook URL reaches cloud metadata" in md
    assert "### 2. [MEDIUM] Path traversal in report download endpoint" in md


def test_cvss_vector_line() -> None:
    md = render_report(_enriched_report())
    # The exact vector string must appear on the CVSS line.
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N" in md
    assert "9.1" in md


def test_cwe_mitre_link() -> None:
    md = render_report(_enriched_report())
    assert "https://cwe.mitre.org/data/definitions/918.html" in md


def test_confidence_line() -> None:
    md = render_report(_enriched_report())
    assert "0.82" in md  # validator_confidence surfaced as Confidence


# ---------------------------------------------------------------------------
# _attach_validation integration (Fix 1, review): `_enriched_report` above
# hand-injects `validation`/`confidence` onto its fixture dicts, which a real
# report agent/fallback builder never does — report.schema.json documents
# both as post-hoc-only. This proves the actual production path: a
# schema-valid finding with NEITHER field, run through the real
# `vash.stages.report._attach_validation` against a seeded StateDB, ends up
# rendering the verdict + confidence it produced.
# ---------------------------------------------------------------------------


def test_attach_validation_surfaces_verdict_and_confidence(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        run_id = db.create_run("/some/repo", "r1")
        db.add_task(run_id, {
            "task_id": "t_1", "attack_class": "ssrf", "scope_hint": "x",
            "target_files": ["app/webhooks.py"], "rationale": "r", "priority": 1,
            "source": "recon",
        })
        db.add_finding(run_id, "t_1", {
            "finding_id": "f_ssrf", "file": "app/webhooks.py",
            "line_start": 42, "line_end": 48, "vuln_class": "ssrf",
            "severity": "critical", "description": "d", "evidence_snippet": "e",
            "confidence": 0.77,
        })
        db.set_finding_validation("f_ssrf", "confirmed", {
            "finding_id": "f_ssrf", "verdict": "confirmed",
            "rationale": "Traced the callback_url from the request body to "
                         "requests.get with no intervening validation.",
            "validator_confidence": 0.91,
        })

        # A schema-valid report finding exactly as the report agent (or the
        # fallback builder) actually emits it — no validation/confidence key.
        payload = {
            "findings": [{
                "finding_id": "f_ssrf",
                "title": "SSRF via unvalidated webhook URL",
                "severity": "critical",
                "vuln_class": "ssrf",
                "file": "app/webhooks.py",
                "line_start": 42,
                "line_end": 48,
                "description": "The webhook handler fetches a user-controlled "
                               "URL with no allowlist or private-IP guard.",
                "evidence": "requests.get(request.json['callback_url'])",
                "trace": {"entry_points": [], "call_chain": []},
                "recommendation": "Validate the URL against an allowlist before fetching.",
            }],
        }
        assert "validation" not in payload["findings"][0]
        assert "confidence" not in payload["findings"][0]

        R._attach_validation(db, run_id, payload)
    finally:
        db.close()

    finding = payload["findings"][0]
    assert finding["validation"]["verdict"] == "confirmed"
    assert finding["validation"]["validator_confidence"] == 0.91
    assert finding["validation"]["rationale"].startswith("Traced the callback_url")
    assert finding["confidence"] == 0.77  # hunter's own confidence, distinct from validator's

    report = {
        "run_id": run_id, "target": {"repo_path": "/some/repo"},
        "summary": {"total": 1, "by_severity": {"critical": 1}},
        "findings": [finding],
    }
    md = render_report(report)
    assert "TRUE_POSITIVE" in md  # mapped verdict label, sourced from _attach_validation
    assert "0.91" in md  # validator_confidence surfaced as Confidence


# ---------------------------------------------------------------------------
# "Also at:" — only when variants present.
# ---------------------------------------------------------------------------


def test_also_at_line_when_variants_present() -> None:
    md = render_report(_enriched_report())
    assert "Also at:" in md
    assert "app/legacy.py:200" in md


def test_no_also_at_when_no_variants() -> None:
    report = _enriched_report()
    for f in report["findings"]:
        f.pop("variants", None)
    md = render_report(report)
    assert "Also at:" not in md


def test_also_at_string_variant() -> None:
    """Defensive dual-shape handling (_also_at's legacy branch, markdown.py
    ~475): the report agent's OWN output may carry bare finding_id strings
    (schema permits string OR object — see report.schema.json's `variants`
    description) before report.py's post-hoc _attach_variants overwrites the
    field with located dicts. A string variant must still render under
    "Also at:" rather than being dropped or crashing."""
    report = _enriched_report()
    report["findings"][0]["variants"] = ["f_bare_sibling"]
    md = render_report(report)
    assert "Also at:" in md
    assert "f_bare_sibling" in md


# ---------------------------------------------------------------------------
# GHSA advisory sub-block.
# ---------------------------------------------------------------------------


def test_ghsa_subheaders_present() -> None:
    md = render_report(_enriched_report())
    assert "#### Proof of Concept" in md
    assert "#### Weaknesses" in md


def test_ghsa_affected_patched_static() -> None:
    md = render_report(_enriched_report())
    assert "Not determined — static run" in md  # affected/patched versions


def test_poc_code_rendered() -> None:
    md = render_report(_enriched_report())
    assert "169.254.169.254" in md  # poc.code fenced


# ---------------------------------------------------------------------------
# Per-finding sub-headers + missing-field policy.
# ---------------------------------------------------------------------------


def test_finding_subheaders_present() -> None:
    md = render_report(_enriched_report())
    for sub in ("#### Description", "#### Impact", "#### Exploit scenario",
                "#### Preconditions", "#### How to fix",
                "#### Adversarial verification"):
        assert sub in md, f"missing per-finding sub-header: {sub}"


def test_missing_optional_fields_render_not_determined() -> None:
    """The sparse (2nd) finding lacks impact/exploit_scenario/preconditions/
    poc/validation — each must surface an explicit Not-determined line, never
    be silently dropped."""
    md = render_report(_enriched_report())
    assert NOT_DETERMINED in md


def test_how_to_fix_falls_back_to_recommendation() -> None:
    """The sparse finding has no how_to_fix but does have a recommendation —
    the How to fix section must use it rather than Not-determined."""
    report = _enriched_report()
    md = render_report(report)
    assert "Canonicalize the path and assert it stays under BASE." in md


# ---------------------------------------------------------------------------
# Exploit chains.
# ---------------------------------------------------------------------------


def test_exploit_chains_section() -> None:
    md = render_report(_enriched_report())
    assert "## Exploit chains" in md
    assert "Webhook SSRF into metadata credential theft" in md


def test_no_chains_section_when_absent() -> None:
    report = _enriched_report()
    report.pop("chains", None)
    md = render_report(report)
    assert "## Exploit chains" not in md


# ---------------------------------------------------------------------------
# Determinism.
# ---------------------------------------------------------------------------


def test_deterministic_byte_identical() -> None:
    report = _enriched_report()
    assert render_report(report) == render_report(report)


def test_reexport_matches() -> None:
    report = _enriched_report()
    assert render_report_reexport(report) == render_report(report)


# ---------------------------------------------------------------------------
# Robustness — empty findings, minimal payload, never raise.
# ---------------------------------------------------------------------------


def test_empty_findings_payload_renders() -> None:
    report = {
        "run_id": "run_empty",
        "target": {"repo_path": "/tmp/x"},
        "summary": {"total": 0, "by_severity": {}},
        "findings": [],
    }
    md = render_report(report)
    assert "## Findings" in md
    assert isinstance(md, str) and md.strip()


def test_minimal_payload_does_not_raise() -> None:
    md = render_report({"run_id": "r", "target": {"repo_path": "p"}, "findings": []})
    assert isinstance(md, str)
    assert "## Summary" in md  # section scaffold still present


def test_totally_degenerate_payload_does_not_raise() -> None:
    # Even a payload missing target/summary must not crash the renderer.
    md = render_report({"findings": [{"title": "x"}]})
    assert isinstance(md, str)


def test_findings_count_in_header() -> None:
    md = render_report(_enriched_report())
    assert "## Findings (2)" in md


def test_poc_block_renders_the_runtime_observer_evidence() -> None:
    """The observer lines are the receipt that the exploit actually fired — a
    report showing the PoC script without them makes the tool's central claim
    unverifiable to the reader."""
    from vash.reporting.markdown import _poc_block
    md = "\n".join(_poc_block({
        "language": "python",
        "code": "import app; app.build_report('x; id')",
        "succeeded": True,
        "observer_evidence": [
            "[VASH-OBSERVER] audit:subprocess.Popen ('/bin/sh', ['-c', 'echo x; id'])"
            "  <- from /target/app/reports.py:7 in build_report",
        ],
        "notes": "ran under the PEP-578 audit hook",
    }))
    assert "Runtime observer evidence" in md
    assert "audit:subprocess.Popen" in md
    assert "build_report" in md                 # the attribution survives
    assert "ran under the PEP-578 audit hook" in md


def test_poc_block_falls_back_to_raw_output_when_there_is_no_observer() -> None:
    from vash.reporting.markdown import _poc_block
    md = "\n".join(_poc_block({
        "language": "go", "code": "package main", "succeeded": True,
        "run_output": "target says: pwned\n",
    }))
    assert "PoC output" in md and "target says: pwned" in md


def test_poc_block_unchanged_when_there_is_no_poc() -> None:
    from vash.reporting.markdown import _poc_block
    assert _poc_block(None) == [NOT_DETERMINED]
    assert _poc_block({"language": "py"}) == [NOT_DETERMINED]
