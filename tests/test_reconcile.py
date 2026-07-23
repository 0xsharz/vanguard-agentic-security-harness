"""Reconciliation completeness pass (feature F1).

Covers the pure classification/synthesis helpers and the full
`_reconcile_inputs` flow (with Hunt/Validate stubbed to no-ops) — no network,
no Claude call.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import audit.orchestrator as orch
from audit.config import load_config
from audit.orchestrator import (
    RECONCILE_CAP,
    _classify_input,
    _default_attack_class,
    _location_file,
    _reconcile_inputs,
    _reconcile_pass,
    _synthesize_reconcile_task,
)
from audit.state import StateDB, Task
from audit.stages._common import StageContext


def _task(task_id: str, scope_hint: str, target_files: list[str]) -> Task:
    return Task(
        task_id=task_id, run_id="r1", source="recon", attack_class="x",
        scope_hint=scope_hint, target_files=target_files, rationale="",
        priority=3, status="done", raw_json={},
    )


def _inp(iid: str, **over) -> dict:
    base = {
        "input_id": f"r1:{iid}", "id": iid,
        "source_type": "HTTP query param", "location": "app.py:14",
        "variable": "q", "entry_point": "GET /search",
        "trust_level": "unauthenticated",
    }
    base.update(over)
    return base


# ---- pure helpers --------------------------------------------------------

def test_location_file_strips_line_and_dir() -> None:
    assert _location_file("src/handlers/search.py:14") == "search.py"
    assert _location_file("app.py:12:5") == "app.py"
    assert _location_file("app.py") == "app.py"
    assert _location_file("") == ""


def test_default_attack_class_by_source() -> None:
    assert _default_attack_class("file upload") == "path_traversal"
    assert _default_attack_class("SQS queue message") == "deserialization_pickle"
    assert _default_attack_class("CLI arg") == "command_injection"
    assert _default_attack_class("HTTP header") == "header_injection"
    assert _default_attack_class("weird thing") == "injection"
    assert _default_attack_class(None) == "injection"


def test_classify_covered_by_finding_file() -> None:
    disp, ev = _classify_input(_inp("in_1", location="app.py:14"),
                               {"app.py"}, [])
    assert disp == "covered"
    assert "app.py" in ev


def test_classify_covered_by_task_scope() -> None:
    tasks = [_task("t1", "GET /search reads q into cur.execute()", ["other.py"])]
    disp, ev = _classify_input(_inp("in_1", location="nope.py:1",
                                    entry_point="GET /search"),
                               set(), tasks)
    assert disp == "covered"
    assert "t1" in ev


def test_classify_uncovered() -> None:
    disp, ev = _classify_input(_inp("in_1", location="ghost.py:9",
                                    entry_point="GET /never"),
                               {"app.py"},
                               [_task("t1", "unrelated", ["app.py"])])
    assert disp == "uncovered"


def test_synthesize_reconcile_task_shape() -> None:
    t = _synthesize_reconcile_task(
        _inp("in_2", location="cli.py:3", source_type="CLI arg",
             entry_point="import command"), 2)
    assert t["task_id"] == "t_rc_2"
    assert t["source"] == "reconcile"
    assert t["attack_class"] == "command_injection"
    assert t["target_files"] == ["cli.py"]
    assert "in_2" in t["scope_hint"]
    assert "import command" in t["scope_hint"]


# ---- _reconcile_pass over a real DB --------------------------------------

def test_reconcile_pass_marks_dispositions(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/repo", "r1")
    # Input A lives in app.py; input B in ghost.py with an unmatched entry point.
    db.add_input(rid, {"id": "in_a", "source_type": "HTTP param",
                       "location": "app.py:14", "variable": "q",
                       "entry_point": "GET /search", "trust_level": "unauthenticated"})
    db.add_input(rid, {"id": "in_b", "source_type": "HTTP param",
                       "location": "ghost.py:9", "variable": "z",
                       "entry_point": "GET /ghost", "trust_level": "unauthenticated"})
    # A task + a finding both anchored on app.py cover input A.
    db.add_task(rid, {"task_id": "t_web_1", "attack_class": "sql_injection",
                      "scope_hint": "app.py handler", "target_files": ["app.py"],
                      "rationale": "r", "priority": 1, "source": "recon"})
    db.add_finding(rid, "t_web_1", {
        "finding_id": "f1", "file": "app.py", "line_start": 1, "line_end": 2,
        "vuln_class": "sqli", "severity": "high", "description": "x",
        "evidence_snippet": "y", "confidence": 0.9})

    covered, uncovered = _reconcile_pass(db, rid)
    assert {c["id"] for c in covered} == {"in_a"}
    assert {u["id"] for u in uncovered} == {"in_b"}
    # Dispositions persisted.
    by_id = {i["id"]: i for i in db.get_inputs(rid)}
    assert by_id["in_a"]["disposition"] == "covered"
    assert by_id["in_b"]["disposition"] == "uncovered"
    assert db.get_unresolved_inputs(rid) == []  # all now have a disposition
    db.close()


# ---- full _reconcile_inputs flow (Hunt/Validate stubbed) -----------------

@pytest.fixture
def ctx(tmp_path) -> StageContext:
    return StageContext(run_id="r1", repo_path=tmp_path, config=load_config())


async def test_reconcile_inputs_requeues_uncovered(monkeypatch, tmp_path, ctx) -> None:
    """Uncovered inputs produce reconcile Hunt tasks; after a (no-op) re-hunt
    the pass re-runs so the ledger is final."""
    db = StateDB(tmp_path / "state.db")
    db.create_run("/repo", "r1")
    db.add_input("r1", {"id": "in_a", "source_type": "HTTP param",
                        "location": "app.py:14", "variable": "q",
                        "entry_point": "GET /search", "trust_level": "unauthenticated"})
    db.add_input("r1", {"id": "in_b", "source_type": "CLI arg",
                        "location": "cli.py:3", "variable": "--f",
                        "entry_point": "import command", "trust_level": "privileged"})
    # A finding on app.py covers in_a; in_b is uncovered.
    db.add_task("r1", {"task_id": "t_web_1", "attack_class": "sql_injection",
                       "scope_hint": "app.py", "target_files": ["app.py"],
                       "rationale": "r", "priority": 1, "source": "recon"})
    db.add_finding("r1", "t_web_1", {
        "finding_id": "f1", "file": "app.py", "line_start": 1, "line_end": 2,
        "vuln_class": "sqli", "severity": "high", "description": "x",
        "evidence_snippet": "y", "confidence": 0.9})

    hunt_calls = {"n": 0}

    async def fake_hunt(c, d, **kw):
        hunt_calls["n"] += 1
        return 0

    async def fake_validate(c, d, **kw):
        return 0

    monkeypatch.setattr(orch.stages, "run_hunt", fake_hunt)
    monkeypatch.setattr(orch.stages, "run_validate", fake_validate)

    await _reconcile_inputs(ctx, db)

    # A reconcile Hunt task was synthesized for the uncovered CLI input.
    rc = [t for t in db.get_all_tasks("r1") if t.source == "reconcile"]
    assert len(rc) == 1
    assert rc[0].task_id == "t_rc_1"
    assert rc[0].attack_class == "command_injection"
    # Hunt+Validate re-ran exactly once.
    assert hunt_calls["n"] == 1
    # After re-reconcile every input has a disposition; in_b is now covered
    # because its entry_point appears in the reconcile task's scope.
    by_id = {i["id"]: i for i in db.get_inputs("r1")}
    assert by_id["in_a"]["disposition"] == "covered"
    assert by_id["in_b"]["disposition"] == "covered"
    assert db.get_unresolved_inputs("r1") == []
    db.close()


async def test_reconcile_requeue_capped(monkeypatch, tmp_path, ctx) -> None:
    """No more than RECONCILE_CAP uncovered inputs are re-queued."""
    db = StateDB(tmp_path / "state.db")
    db.create_run("/repo", "r1")
    # 25 uncovered inputs, none matching any finding/task.
    for i in range(25):
        db.add_input("r1", {"id": f"in_{i}", "source_type": "HTTP param",
                            "location": f"mod{i}.py:1", "variable": "q",
                            "entry_point": f"GET /r{i}", "trust_level": "unauthenticated"})

    async def fake_hunt(c, d, **kw):
        return 0

    async def fake_validate(c, d, **kw):
        return 0

    monkeypatch.setattr(orch.stages, "run_hunt", fake_hunt)
    monkeypatch.setattr(orch.stages, "run_validate", fake_validate)

    await _reconcile_inputs(ctx, db)

    rc = [t for t in db.get_all_tasks("r1") if t.source == "reconcile"]
    assert len(rc) == RECONCILE_CAP == 20
    # The 5 beyond the cap remain uncovered in the final ledger.
    uncovered = [i for i in db.get_inputs("r1") if i["disposition"] == "uncovered"]
    assert len(uncovered) == 5
    db.close()


async def test_reconcile_fail_open(monkeypatch, tmp_path, ctx) -> None:
    """A Hunt error inside reconciliation must not propagate."""
    db = StateDB(tmp_path / "state.db")
    db.create_run("/repo", "r1")
    db.add_input("r1", {"id": "in_a", "source_type": "HTTP param",
                        "location": "ghost.py:1", "variable": "q",
                        "entry_point": "GET /x", "trust_level": "unauthenticated"})

    async def boom_hunt(c, d, **kw):
        raise RuntimeError("hunt blew up")

    async def fake_validate(c, d, **kw):
        return 0

    monkeypatch.setattr(orch.stages, "run_hunt", boom_hunt)
    monkeypatch.setattr(orch.stages, "run_validate", fake_validate)

    # Must not raise.
    await _reconcile_inputs(ctx, db)
    # First-pass disposition still persisted before the failure.
    assert db.get_inputs("r1")[0]["disposition"] == "uncovered"
    db.close()


async def test_reconcile_no_inputs_noop(monkeypatch, tmp_path, ctx) -> None:
    """No inputs enumerated (pre-F1 recon) → pass is a no-op, no Hunt re-run."""
    db = StateDB(tmp_path / "state.db")
    db.create_run("/repo", "r1")

    called = {"hunt": False}

    async def fake_hunt(c, d, **kw):
        called["hunt"] = True
        return 0

    monkeypatch.setattr(orch.stages, "run_hunt", fake_hunt)
    await _reconcile_inputs(ctx, db)
    assert called["hunt"] is False
    db.close()
