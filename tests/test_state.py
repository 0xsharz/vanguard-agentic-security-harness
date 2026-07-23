"""StateDB roundtrip tests."""

from __future__ import annotations

from pathlib import Path

from vash.state import StateDB


def test_run_and_task_lifecycle(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    assert db.get_run(rid)["status"] == "running"

    db.add_task(rid, {
        "task_id": "t_1",
        "attack_class": "sqli",
        "scope_hint": "lookup name parameter",
        "target_files": ["app.py"],
        "rationale": "raw string formatting",
        "priority": 1,
        "source": "recon",
    })
    pending = db.get_pending_tasks(rid)
    assert len(pending) == 1
    assert pending[0].task_id == "t_1"

    db.update_task_status("t_1", "done")
    assert db.get_pending_tasks(rid) == []
    assert any(t.status == "done" for t in db.get_all_tasks(rid))

    db.finish_run(rid)
    assert db.get_run(rid)["status"] == "completed"
    db.close()


def test_reset_incomplete_tasks(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    for tid, status in [("t_done", "done"), ("t_run", "running"),
                        ("t_fail", "failed"), ("t_pend", "pending")]:
        db.add_task(rid, {
            "task_id": tid, "attack_class": "sqli", "scope_hint": "x",
            "target_files": ["a.py"], "rationale": "r", "priority": 1,
            "source": "recon",
        })
        db.update_task_status(tid, status)

    n = db.reset_incomplete_tasks(rid)
    assert n == 2  # only running + failed are re-queued
    by_status = {t.task_id: t.status for t in db.get_all_tasks(rid)}
    assert by_status == {
        "t_done": "done", "t_run": "pending",
        "t_fail": "pending", "t_pend": "pending",
    }
    assert {t.task_id for t in db.get_pending_tasks(rid)} == {"t_run", "t_fail", "t_pend"}
    db.close()


def test_finding_validation_and_dedupe(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    db.add_task(rid, {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "x",
        "target_files": ["a.py"], "rationale": "r", "priority": 1, "source": "recon",
    })
    db.add_finding(rid, "t_1", {
        "finding_id": "f_1", "file": "a.py", "line_start": 1, "line_end": 2,
        "vuln_class": "sqli", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    assert len(db.get_unvalidated_findings(rid)) == 1

    db.set_finding_validation("f_1", "confirmed", {
        "finding_id": "f_1", "verdict": "confirmed",
        "rationale": "ok", "validator_confidence": 0.9,
    })
    assert len(db.get_findings(rid, validation_status="confirmed")) == 1

    db.add_dedupe_group(rid, {
        "group_id": "g_1", "root_cause": "rc",
        "canonical_finding_id": "f_1", "member_finding_ids": ["f_1"],
    })
    db.assign_finding_group("f_1", "g_1", True)
    assert len(db.get_findings(rid, canonical_only=True)) == 1

    db.add_trace("f_1", {
        "finding_id": "f_1", "reachable": True, "confidence": 0.9,
        "rationale": "trivial", "entry_points": [], "call_chain": [],
    })
    reachable = db.get_reachable_canonical_findings(rid)
    assert len(reachable) == 1
    db.close()


def test_cost_aggregation(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/r", "test_run")
    db.record_cost(rid, "hunt", "t_1", {"total_cost_usd": 0.01, "usage": {
        "input_tokens": 100, "output_tokens": 50,
    }, "num_turns": 3, "duration_ms": 1234})
    db.record_cost(rid, "hunt", "t_2", {"total_cost_usd": 0.02, "usage": {
        "input_tokens": 200, "output_tokens": 100,
    }, "num_turns": 5, "duration_ms": 4321})
    assert abs(db.total_cost(rid) - 0.03) < 1e-9
    db.close()
