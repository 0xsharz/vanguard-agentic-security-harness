"""Tests for Task 3 report enrichment — threat model / scan metrics /
verification / CVSS additions to schemas/report.schema.json and the
matching deterministic post-hoc attaches in vash/stages/report.py
(_attach_cvss, _attach_scan_metrics, _attach_verification).

Mirrors the existing report.py test style (tests/test_report.py,
tests/test_coverage.py): schema validation is pure (no agent/network); the
seeded-DB cases build a real StateDB in tmp_path via the actual db API
(create_run/add_task/add_finding/...) — no conftest.py fixture needed.

All OFFLINE: no agent calls, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from vash.stages import report as R
from vash.state import StateDB

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "report.schema.json"


# ---------------------------------------------------------------------------
# schema: report.schema.json accepts every new field (threat_model,
# scan_metrics, verification, per-finding cvss/impact/exploit_scenario/
# preconditions/how_to_fix) — back-compat, so everything stays optional.
# ---------------------------------------------------------------------------


def test_schema_accepts_new_fields() -> None:
    schema = json.loads(SCHEMA_PATH.read_text())
    payload = {
        "run_id": "r", "target": {"repo_path": "x"},
        "summary": {"total": 1, "by_severity": {"high": 1}},
        "threat_model": {
            "system_context": "c", "assets": [], "trust_boundaries": [],
            "ranked_threats": [], "open_questions": [],
        },
        "scan_metrics": {
            "files_in_scope": 10, "files_analyzed": 8, "coverage_pct": 80.0,
            "duration_sec": 100, "cost_usd": 1.2, "tokens_by_phase": [],
        },
        "verification": {
            "raw_findings": 5, "true_positives": 1, "false_positives": 2,
            "needs_more_info": 1, "duplicates_collapsed": 1, "precision_pct": 33.3,
        },
        "findings": [{
            "finding_id": "f1", "title": "SSRF via unchecked webhook URL",
            "severity": "high", "vuln_class": "ssrf", "cwe": "CWE-918",
            "file": "a.py", "line_start": 1, "line_end": 2,
            "description": "User-controlled URL is fetched by the server without validation.",
            "evidence": "requests.get(user_url)",
            "trace": {"entry_points": [], "call_chain": []},
            "recommendation": "Validate the URL against an allowlist before fetching.",
            "cvss": {"score": 8.1, "severity": "high", "vector": "CVSS:3.1/AV:N/..."},
            "impact": "i", "exploit_scenario": "e", "preconditions": ["p"],
            "how_to_fix": "fix",
        }],
    }
    jsonschema.validate(payload, schema)


# ---------------------------------------------------------------------------
# _attach_cvss: fills a severity-keyed baseline for a finding lacking cvss;
# never overwrites an existing one. Pure over payload — must tolerate
# db=None (the fallback-report path may call this with no live db handle).
# ---------------------------------------------------------------------------


def test_attach_cvss_fallback() -> None:
    payload = {"findings": [{"finding_id": "f", "severity": "critical", "vuln_class": "code_injection"},
                            {"finding_id": "g", "severity": "high", "cvss": {"score": 1.0, "vector": "keep"}}]}
    R._attach_cvss(None, "r", payload)
    assert payload["findings"][0]["cvss"]["score"] >= 9.0
    assert payload["findings"][1]["cvss"]["vector"] == "keep"  # untouched


def test_attach_cvss_fail_soft_on_bad_payload() -> None:
    payload = {"findings": [None]}  # malformed finding entry
    R._attach_cvss(None, "r", payload)  # must not raise
    assert payload == {"findings": [None]}


# ---------------------------------------------------------------------------
# _attach_verification: raw / TP / FP / needs-info / duplicates / precision
# computed from a seeded StateDB.
# ---------------------------------------------------------------------------


def _seed_task(db: StateDB, run_id: str, task_id: str = "t_1") -> None:
    db.add_task(run_id, {
        "task_id": task_id, "attack_class": "ssrf", "scope_hint": "x",
        "target_files": ["a.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })


def _seed_finding(db: StateDB, run_id: str, task_id: str, finding_id: str, line: int) -> None:
    db.add_finding(run_id, task_id, {
        "finding_id": finding_id, "file": "a.py", "line_start": line, "line_end": line + 1,
        "vuln_class": "ssrf", "severity": "high",
        "description": "d", "evidence_snippet": "e", "confidence": 0.9,
    })


def test_attach_verification_seeded_db(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        rid = db.create_run("/some/repo", "r1")
        _seed_task(db, rid)
        for i, fid in enumerate(["f1", "f2", "f3", "f4", "f5"]):
            _seed_finding(db, rid, "t_1", fid, i + 1)
        db.set_finding_validation("f1", "confirmed", {"verdict": "confirmed"})
        db.set_finding_validation("f2", "confirmed", {"verdict": "confirmed"})
        db.set_finding_validation("f3", "rejected", {"verdict": "rejected"})
        db.set_finding_validation("f4", "needs_more_info", {"verdict": "needs_more_info"})
        # f5 left unvalidated (pending) — still counts toward raw_findings.

        # f1 is a demoted duplicate of canonical f2 -> duplicates_collapsed.
        db.add_dedupe_group(rid, {
            "group_id": "g1", "root_cause": "rc",
            "canonical_finding_id": "f2", "member_finding_ids": ["f1", "f2"],
        })
        db.assign_finding_group("f2", "g1", True)
        db.assign_finding_group("f1", "g1", False)

        payload: dict = {}
        R._attach_verification(db, rid, payload)
    finally:
        db.close()

    v = payload["verification"]
    assert v["raw_findings"] == 5
    assert v["true_positives"] == 2
    assert v["false_positives"] == 1
    assert v["needs_more_info"] == 1
    assert v["duplicates_collapsed"] == 1
    assert v["precision_pct"] == 40.0  # 2/5


def test_attach_verification_fail_soft_on_db_error(monkeypatch, tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")

        def boom(_run_id):
            raise RuntimeError("db exploded")

        monkeypatch.setattr(db, "get_findings", boom)
        payload: dict = {}
        R._attach_verification(db, "r1", payload)  # must not raise
    finally:
        db.close()
    assert "verification" not in payload


# ---------------------------------------------------------------------------
# _attach_scan_metrics: coverage/cost/tokens-by-phase computed from a seeded
# StateDB.
# ---------------------------------------------------------------------------


def test_attach_scan_metrics_seeded_db(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        rid = db.create_run("/some/repo", "r1")
        db.set_coverage(rid, {"source_files": 10, "covered_files": 8,
                              "catchall_tasks": 1, "catchall_dropped": 0})
        db.record_cost(rid, "hunt", None, {
            "usage": {"input_tokens": 100, "output_tokens": 50},
            "total_cost_usd": 0.05, "num_turns": 1, "duration_ms": 10,
        })
        payload: dict = {}
        R._attach_scan_metrics(db, rid, payload)
    finally:
        db.close()

    m = payload["scan_metrics"]
    assert m["files_in_scope"] == 10
    assert m["files_analyzed"] == 8
    assert m["coverage_pct"] == 80.0
    assert m["cost_usd"] == pytest.approx(0.05)
    assert m["tokens_by_phase"] == [
        {"phase": "hunt", "input_tokens": 100, "output_tokens": 50,
         "cost_usd": pytest.approx(0.05)}
    ]
    # report always runs before db.finish_run sets finished_at, so it is
    # never knowable yet -> must be omitted rather than emitted as null.
    assert "duration_sec" not in m


def test_attach_scan_metrics_fail_soft_on_db_error(monkeypatch, tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")

        def boom(_run_id):
            raise RuntimeError("db exploded")

        monkeypatch.setattr(db, "get_coverage", boom)
        payload: dict = {}
        R._attach_scan_metrics(db, "r1", payload)  # must not raise
    finally:
        db.close()
    assert "scan_metrics" not in payload
