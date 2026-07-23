"""Tests for feature 4.7 — coverage honesty: a disclosed `coverage` block in
the report.

Scene: coverage data mostly already exists — the report already carries F1's
`input_inventory` (inputs + covered/uncovered dispositions) and 4.3's
`run_summary` has tasks-by-source + findings-by-status. The ONE missing
honesty datum is F6's catch-all `dropped`-by-cap count (previously only
logged). This suite covers:
  - state.set_coverage / get_coverage round-trip (mirrors the `chains` table).
  - orchestrator._add_catchall_tasks persists the catch-all honesty numbers,
    fail-open like the rest of the function.
  - report.py's consolidated `coverage` object: inputs enumerated/covered/
    uncovered (F1), tasks_by_source/findings_by_status (4.3 run_summary),
    merged with the persisted catch-all record (F6), plus the
    `coverage_complete` honesty flag — and that its own failure is fail-soft
    (never breaks the report).
  - schemas/report.schema.json accepts a report with and without `coverage`.

All OFFLINE: no agent calls, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import vash.orchestrator as orch
import vash.stages._common as common_mod
import vash.stages.report as report_mod
from vash.config import load_config
from vash.json_utils import validate_schema
from vash.orchestrator import _add_catchall_tasks
from vash.runner import AgentRunError
from vash.state import StateDB
from vash.stages._common import StageContext

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"

REPORT_BASE = {
    "run_id": "r1",
    "target": {"repo_path": "/tmp/some_repo"},
    "summary": {"total": 0, "by_severity": {}},
    "findings": [],
}


# ---------------------------------------------------------------------------
# state: coverage table round-trip (mirrors add_chain_analysis/get_chain_analysis)
# ---------------------------------------------------------------------------


def test_set_and_get_coverage_round_trip(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")
        assert db.get_coverage("r1") is None
        payload = {"source_files": 10, "covered_files": 8,
                   "catchall_tasks": 2, "catchall_dropped": 0}
        db.set_coverage("r1", payload)
        assert db.get_coverage("r1") == payload
    finally:
        db.close()


def test_set_coverage_replaces(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")
        db.set_coverage("r1", {"source_files": 1, "covered_files": 1,
                                "catchall_tasks": 0, "catchall_dropped": 0})
        db.set_coverage("r1", {"source_files": 10, "covered_files": 3,
                                "catchall_tasks": 2, "catchall_dropped": 5})
        got = db.get_coverage("r1")
        assert got == {"source_files": 10, "covered_files": 3,
                        "catchall_tasks": 2, "catchall_dropped": 5}  # INSERT OR REPLACE
    finally:
        db.close()


def test_get_coverage_missing_run_returns_none(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        assert db.get_coverage("never_ran") is None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# orchestrator: _add_catchall_tasks persists the honesty numbers (fail-open)
# ---------------------------------------------------------------------------


@pytest.fixture
def isolate_work(monkeypatch, tmp_path):
    """Keep StageContext.work_dir out of the real checkout."""
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")


def _ctx_no_graph(tmp_path: Path) -> StageContext:
    ctx = StageContext(run_id="r1", repo_path=tmp_path, config=load_config())
    ctx._graph = None          # catchall is graph-independent by design
    ctx._graph_loaded = True   # short-circuit ctx.graph() -> None, no rebuild
    return ctx


def _write(tmp_path: Path, rel: str, content: str = "x = 1\n") -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def _db(tmp_path: Path) -> StateDB:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "r1")
    return db


def test_add_catchall_tasks_persists_coverage_numbers(tmp_path: Path, isolate_work) -> None:
    _write(tmp_path, "a.py")
    _write(tmp_path, "b.py")
    db = _db(tmp_path)
    db.add_task("r1", {
        "task_id": "t1", "source": "recon", "attack_class": "sql_injection",
        "scope_hint": "x" * 12, "target_files": ["a.py"],
        "rationale": "y" * 12, "priority": 1,
    })
    _add_catchall_tasks(_ctx_no_graph(tmp_path), db)
    cov = db.get_coverage("r1")
    # a.py covered by t1, b.py swept by one catchall task -> matches
    # test_catchall.py's happy-path fixture (2 source, 1 covered, 1 task).
    assert cov == {"source_files": 2, "covered_files": 1,
                    "catchall_tasks": 1, "catchall_dropped": 0}
    db.close()


def test_add_catchall_tasks_persists_nonzero_dropped_count(
    monkeypatch, tmp_path: Path, isolate_work
) -> None:
    # Persistence just needs to reflect whatever build_catchall_tasks returns
    # — the cap/dropped arithmetic itself is exercised in test_catchall.py.
    db = _db(tmp_path)
    monkeypatch.setattr(orch, "build_catchall_tasks", lambda *a, **k: ([], 3))
    _add_catchall_tasks(_ctx_no_graph(tmp_path), db)
    cov = db.get_coverage("r1")
    assert cov == {"source_files": 0, "covered_files": 0,
                    "catchall_tasks": 0, "catchall_dropped": 3}
    db.close()


def test_add_catchall_tasks_fail_open_leaves_no_coverage_row(
    monkeypatch, tmp_path: Path, isolate_work
) -> None:
    db = _db(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("catchall blew up")

    monkeypatch.setattr(orch, "build_catchall_tasks", boom)
    _add_catchall_tasks(_ctx_no_graph(tmp_path), db)  # must not raise
    assert db.get_coverage("r1") is None
    db.close()


# ---------------------------------------------------------------------------
# report.py: consolidated `coverage` object (whitebox on _attach_coverage)
# ---------------------------------------------------------------------------


def _seed_input(db: StateDB, run_id: str, input_id: str, *, disposition: str | None) -> None:
    stored_id = db.add_input(run_id, {
        "id": input_id, "source_type": "HTTP query param", "location": "app.py:1",
        "variable": "x", "entry_point": "GET /x", "trust_level": "unauthenticated",
    })
    if disposition is not None:
        db.set_input_disposition(stored_id, disposition, "seen")


def test_attach_coverage_counts_inputs_and_merges_catchall(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")
        _seed_input(db, "r1", "in_a", disposition="covered")
        _seed_input(db, "r1", "in_b", disposition="covered")
        _seed_input(db, "r1", "in_c", disposition="uncovered")
        db.set_coverage("r1", {"source_files": 12, "covered_files": 9,
                                "catchall_tasks": 2, "catchall_dropped": 3})
        payload = dict(REPORT_BASE)
        report_mod._attach_coverage(db, "r1", payload)
    finally:
        db.close()
    cov = payload["coverage"]
    assert cov["inputs_enumerated"] == 3
    assert cov["inputs_covered"] == 2
    assert cov["inputs_uncovered"] == 1
    assert cov["source_files"] == 12
    assert cov["covered_files"] == 9
    assert cov["catchall_tasks"] == 2
    assert cov["catchall_dropped"] == 3
    assert "tasks_by_source" in cov
    assert "findings_by_status" in cov
    assert cov["coverage_complete"] is False  # dropped > 0 -> INCOMPLETE


def test_attach_coverage_complete_when_all_covered_and_no_drops(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")
        _seed_input(db, "r1", "in_a", disposition="covered")
        _seed_input(db, "r1", "in_b", disposition="covered")
        db.set_coverage("r1", {"source_files": 5, "covered_files": 5,
                                "catchall_tasks": 0, "catchall_dropped": 0})
        payload = dict(REPORT_BASE)
        report_mod._attach_coverage(db, "r1", payload)
    finally:
        db.close()
    assert payload["coverage"]["coverage_complete"] is True


def test_attach_coverage_incomplete_when_input_unreconciled(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")
        _seed_input(db, "r1", "in_a", disposition="covered")
        _seed_input(db, "r1", "in_b", disposition=None)  # never reconciled
        db.set_coverage("r1", {"source_files": 5, "covered_files": 5,
                                "catchall_tasks": 0, "catchall_dropped": 0})
        payload = dict(REPORT_BASE)
        report_mod._attach_coverage(db, "r1", payload)
    finally:
        db.close()
    assert payload["coverage"]["coverage_complete"] is False


def test_attach_coverage_without_catchall_record_still_builds(tmp_path: Path) -> None:
    # _add_catchall_tasks may not have run yet (or may have failed open) —
    # the consolidated object must still build from inputs/run_summary alone,
    # and an absent record must not poison coverage_complete.
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")
        _seed_input(db, "r1", "in_a", disposition="covered")
        payload = dict(REPORT_BASE)
        report_mod._attach_coverage(db, "r1", payload)
    finally:
        db.close()
    cov = payload["coverage"]
    assert cov["inputs_enumerated"] == 1
    assert "catchall_dropped" not in cov
    assert cov["coverage_complete"] is True


def test_attach_coverage_fail_soft_on_db_error(monkeypatch, tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")

        def boom(_run_id):
            raise RuntimeError("db exploded")

        monkeypatch.setattr(db, "run_summary", boom)
        payload = dict(REPORT_BASE)
        report_mod._attach_coverage(db, "r1", payload)  # must not raise
    finally:
        db.close()
    assert "coverage" not in payload  # additive: failure must not break the report


# ---------------------------------------------------------------------------
# schema: report.schema.json accepts a report with and without `coverage`
# ---------------------------------------------------------------------------


def test_schema_accepts_report_without_coverage() -> None:
    errors = validate_schema(REPORT_BASE, SCHEMAS / "report.schema.json")
    assert errors == [], errors


def test_schema_accepts_report_with_coverage() -> None:
    report = {
        **REPORT_BASE,
        "coverage": {
            "inputs_enumerated": 3, "inputs_covered": 2, "inputs_uncovered": 1,
            "tasks_by_source": {"recon": 2, "catchall": 1},
            "findings_by_status": {"confirmed": 1, "false_positive": 1},
            "source_files": 12, "covered_files": 9,
            "catchall_tasks": 2, "catchall_dropped": 3,
            "coverage_complete": False,
        },
    }
    errors = validate_schema(report, SCHEMAS / "report.schema.json")
    assert errors == [], errors


def test_schema_accepts_coverage_without_catchall_fields() -> None:
    # Permissive: a coverage object missing the (not-yet-persisted) catchall
    # fields must still validate.
    report = {
        **REPORT_BASE,
        "coverage": {
            "inputs_enumerated": 0, "inputs_covered": 0, "inputs_uncovered": 0,
            "tasks_by_source": {}, "findings_by_status": {},
            "coverage_complete": True,
        },
    }
    errors = validate_schema(report, SCHEMAS / "report.schema.json")
    assert errors == [], errors


# ---------------------------------------------------------------------------
# integration: run_report wires `coverage` into every write path
# ---------------------------------------------------------------------------


def _ctx(tmp_path: Path) -> StageContext:
    return StageContext(run_id="r1", repo_path=tmp_path, config=load_config())


def _seed_confirmed_reachable(db: StateDB, run_id: str, fid: str) -> None:
    tid = f"t_{fid}"
    db.add_task(run_id, {
        "task_id": tid, "attack_class": "ssrf", "scope_hint": "app.py",
        "target_files": ["app.py"], "rationale": "x", "priority": 1,
    })
    db.add_finding(run_id, tid, {
        "finding_id": fid, "file": "app.py", "line_start": 10, "line_end": 12,
        "vuln_class": "ssrf", "severity": "medium", "description": "d",
        "evidence_snippet": "e", "confidence": 0.9,
    })
    db.set_finding_validation(fid, "confirmed", {
        "finding_id": fid, "verdict": "confirmed", "rationale": "ok",
        "validator_confidence": 0.9,
    })
    db.assign_finding_group(fid, f"g_{fid}", True)
    db.add_trace(fid, {
        "finding_id": fid, "reachable": True, "confidence": 0.9,
        "rationale": "reachable", "entry_points": [], "call_chain": [],
    })


async def test_run_report_empty_path_includes_coverage(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        db.set_coverage("r1", {"source_files": 1, "covered_files": 0,
                                "catchall_tasks": 1, "catchall_dropped": 1})
        # No confirmed+canonical+reachable findings -> the no-agent-call
        # empty-report fast path.
        out_path = await report_mod.run_report(_ctx(tmp_path), db)
    finally:
        db.close()
    report = json.loads(out_path.read_text())
    assert report["coverage"]["catchall_dropped"] == 1
    assert report["coverage"]["coverage_complete"] is False


async def test_run_report_fallback_path_includes_coverage(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")

    async def failing(**_kwargs):
        raise AgentRunError("report agent produced junk")

    monkeypatch.setattr(report_mod, "run_agent", failing)
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_reachable(db, "r1", "f_leak_1")
        db.set_coverage("r1", {"source_files": 4, "covered_files": 4,
                                "catchall_tasks": 0, "catchall_dropped": 0})
        out_path = await report_mod.run_report(_ctx(tmp_path), db)
    finally:
        db.close()
    report = json.loads(out_path.read_text())
    assert report["coverage"]["coverage_complete"] is True
    assert report["coverage"]["inputs_enumerated"] == 0
