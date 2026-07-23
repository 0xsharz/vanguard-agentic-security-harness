"""Tests for StateDB.run_summary (4.3 — observability run summary).

run_summary() is a pure read that aggregates the existing `costs` table
(GROUP BY stage, SUM/COUNT, COALESCE nulls to 0) plus findings/tasks
breakdowns already queryable via get_findings/get_all_tasks. No new
instrumentation — just roll-up.
"""

from __future__ import annotations

import json

import pytest

from audit.state import StateDB


def _mk_result(usd: float, in_tok: int, out_tok: int, duration_ms: int,
               cache_read: int = 0, cache_creation: int = 0, num_turns: int = 1) -> dict:
    return {
        "total_cost_usd": usd,
        "usage": {
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_creation,
        },
        "num_turns": num_turns,
        "duration_ms": duration_ms,
    }


def _seed_multi_stage_run(db: StateDB) -> str:
    rid = db.create_run("/some/repo", "run_summary_test")

    # ---- costs across 3 stages (varied usd/tokens/duration/calls) ----
    db.record_cost(rid, "recon", None, _mk_result(0.01, 100, 20, 1000, cache_read=5, cache_creation=2))
    db.record_cost(rid, "hunt", "t_1", _mk_result(0.02, 200, 40, 2000, cache_read=10, cache_creation=4))
    db.record_cost(rid, "hunt", "t_2", _mk_result(0.03, 300, 60, 3000, cache_read=15, cache_creation=6))
    db.record_cost(rid, "validate", "t_1", _mk_result(0.04, 400, 80, 4000))

    # ---- tasks: mixed source ----
    db.add_task(rid, {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "x",
        "target_files": ["a.py"], "rationale": "r", "priority": 1, "source": "recon",
    })
    db.add_task(rid, {
        "task_id": "t_2", "attack_class": "xss", "scope_hint": "y",
        "target_files": ["b.py"], "rationale": "r", "priority": 2, "source": "taint",
    })
    db.add_task(rid, {
        "task_id": "t_3", "attack_class": "xss", "scope_hint": "z",
        "target_files": ["c.py"], "rationale": "r", "priority": 2, "source": "taint",
    })

    # ---- findings: mixed severity/status/canonical ----
    db.add_finding(rid, "t_1", {
        "finding_id": "f_1", "file": "a.py", "line_start": 1, "line_end": 2,
        "vuln_class": "sqli", "severity": "high",
        "description": "d", "evidence_snippet": "e", "confidence": 0.9,
    })
    db.add_finding(rid, "t_2", {
        "finding_id": "f_2", "file": "b.py", "line_start": 1, "line_end": 2,
        "vuln_class": "xss", "severity": "medium",
        "description": "d", "evidence_snippet": "e", "confidence": 0.5,
    })
    db.add_finding(rid, "t_2", {
        "finding_id": "f_3", "file": "b.py", "line_start": 3, "line_end": 4,
        "vuln_class": "xss", "severity": "high",
        "description": "d", "evidence_snippet": "e", "confidence": 0.5,
    })

    db.set_finding_validation("f_1", "confirmed", {"finding_id": "f_1", "verdict": "confirmed",
                                                    "rationale": "ok", "validator_confidence": 0.9})
    db.set_finding_validation("f_2", "rejected", {"finding_id": "f_2", "verdict": "rejected",
                                                   "rationale": "fp", "validator_confidence": 0.9})
    # f_3 deliberately left unvalidated -> validation_status is None

    db.assign_finding_group("f_1", "g_1", True)
    db.assign_finding_group("f_3", "g_2", True)

    return rid


def test_run_summary_per_stage_and_totals(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = _seed_multi_stage_run(db)

    summary = db.run_summary(rid)

    assert summary["run_id"] == rid

    # Deterministic ordering: stage keys sorted.
    assert list(summary["stages"].keys()) == ["hunt", "recon", "validate"]

    hunt = summary["stages"]["hunt"]
    assert hunt["calls"] == 2
    assert hunt["usd"] == pytest.approx(0.05)
    assert hunt["input_tokens"] == 500
    assert hunt["output_tokens"] == 100
    assert hunt["cache_read_tokens"] == 25
    assert hunt["cache_creation_tokens"] == 10
    assert hunt["duration_ms"] == 5000

    recon = summary["stages"]["recon"]
    assert recon["calls"] == 1
    assert recon["usd"] == pytest.approx(0.01)
    assert recon["duration_ms"] == 1000

    validate = summary["stages"]["validate"]
    assert validate["calls"] == 1
    assert validate["usd"] == pytest.approx(0.04)
    # validate's record_cost call had no cache fields -> COALESCE to 0
    assert validate["cache_read_tokens"] == 0
    assert validate["cache_creation_tokens"] == 0

    totals = summary["totals"]
    assert totals["calls"] == 4
    assert totals["usd"] == pytest.approx(0.01 + 0.02 + 0.03 + 0.04)
    assert totals["input_tokens"] == 100 + 200 + 300 + 400
    assert totals["output_tokens"] == 20 + 40 + 60 + 80
    assert totals["duration_ms"] == 1000 + 2000 + 3000 + 4000

    # totals must equal both total_cost(run_id) and the sum of per-stage usd.
    assert totals["usd"] == pytest.approx(db.total_cost(rid))
    assert totals["usd"] == pytest.approx(sum(s["usd"] for s in summary["stages"].values()))
    assert totals["calls"] == sum(s["calls"] for s in summary["stages"].values())
    assert totals["duration_ms"] == sum(s["duration_ms"] for s in summary["stages"].values())

    db.close()


def test_run_summary_findings_breakdown(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = _seed_multi_stage_run(db)

    findings = db.run_summary(rid)["findings"]
    assert findings["total"] == 3
    assert findings["by_severity"] == {"high": 2, "medium": 1}
    assert findings["by_status"] == {"confirmed": 1, "rejected": 1, None: 1}
    assert findings["canonical"] == 2  # f_1 and f_3 both assigned canonical

    db.close()


def test_run_summary_tasks_breakdown(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = _seed_multi_stage_run(db)

    tasks = db.run_summary(rid)["tasks"]
    assert tasks["total"] == 3
    assert tasks["by_source"] == {"recon": 1, "taint": 2}

    db.close()


def test_run_summary_is_json_serializable(tmp_path) -> None:
    """The dict (including a None key in by_status) must serialize cleanly
    since it is written verbatim to run_summary.json."""
    db = StateDB(tmp_path / "state.db")
    rid = _seed_multi_stage_run(db)

    summary = db.run_summary(rid)
    encoded = json.dumps(summary)
    assert json.loads(encoded)["findings"]["total"] == 3

    db.close()


def test_run_summary_empty_run_is_zeroed_not_crashed(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "run_summary_empty")

    summary = db.run_summary(rid)

    assert summary["run_id"] == rid
    assert summary["stages"] == {}
    assert summary["totals"] == {
        "calls": 0, "usd": 0.0, "input_tokens": 0, "output_tokens": 0,
        "cache_read_tokens": 0, "cache_creation_tokens": 0, "duration_ms": 0,
    }
    assert summary["findings"] == {
        "total": 0, "by_severity": {}, "by_status": {}, "canonical": 0,
    }
    assert summary["tasks"] == {"total": 0, "by_source": {}}

    db.close()
