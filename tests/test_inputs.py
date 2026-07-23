"""StateDB `inputs` table + input-inventory schema tests (feature F1)."""

from __future__ import annotations

from pathlib import Path

from vash.json_utils import validate_schema
from vash.state import StateDB

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


def _mk_input(iid: str, **over) -> dict:
    base = {
        "id": iid,
        "source_type": "HTTP query param",
        "location": "app.py:14",
        "variable": "q",
        "entry_point": "GET /search",
        "trust_level": "unauthenticated",
    }
    base.update(over)
    return base


def test_add_and_get_inputs(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "r1")

    db.add_input(rid, _mk_input("in_1"))
    db.add_input(rid, _mk_input("in_2", location="cli.py:3", source_type="CLI arg",
                                variable="--file", entry_point="import command",
                                trust_level="privileged"))

    inputs = db.get_inputs(rid)
    assert len(inputs) == 2
    by_id = {i["id"]: i for i in inputs}
    assert by_id["in_1"]["source_type"] == "HTTP query param"
    assert by_id["in_1"]["trust_level"] == "unauthenticated"
    assert by_id["in_2"]["variable"] == "--file"
    # Fresh inputs have no disposition yet.
    assert all(i["disposition"] is None for i in inputs)
    db.close()


def test_add_input_idempotent(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "r1")
    db.add_input(rid, _mk_input("in_1"))
    db.add_input(rid, _mk_input("in_1", variable="changed"))  # same id -> ignored
    inputs = db.get_inputs(rid)
    assert len(inputs) == 1
    assert inputs[0]["variable"] == "q"  # first write wins
    db.close()


def test_input_id_namespaced_no_cross_run_collision(tmp_path: Path) -> None:
    """Two runs sharing one DB can both emit id 'in_1' without clobbering."""
    db = StateDB(tmp_path / "state.db")
    db.create_run("/some/repo", "r1")
    db.create_run("/some/repo", "r2")
    db.add_input("r1", _mk_input("in_1", variable="run1_var"))
    db.add_input("r2", _mk_input("in_1", variable="run2_var"))
    assert len(db.get_inputs("r1")) == 1
    assert len(db.get_inputs("r2")) == 1
    assert db.get_inputs("r1")[0]["variable"] == "run1_var"
    assert db.get_inputs("r2")[0]["variable"] == "run2_var"
    db.close()


def test_set_disposition_and_unresolved(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "r1")
    id1 = db.add_input(rid, _mk_input("in_1"))
    db.add_input(rid, _mk_input("in_2"))

    # Both unresolved initially.
    assert {i["id"] for i in db.get_unresolved_inputs(rid)} == {"in_1", "in_2"}

    db.set_input_disposition(id1, "covered", "finding touches app.py")
    unresolved = db.get_unresolved_inputs(rid)
    assert {i["id"] for i in unresolved} == {"in_2"}

    resolved = {i["id"]: i for i in db.get_inputs(rid)}["in_1"]
    assert resolved["disposition"] == "covered"
    assert resolved["disposition_evidence"] == "finding touches app.py"
    db.close()


def test_recon_schema_accepts_inputs_array() -> None:
    """The optional `inputs` array validates against recon_output.schema.json."""
    payload = {
        "subsystems": [{"name": "web", "path": "app.py", "language": "python",
                        "purpose": "Flask HTTP handlers"}],
        "architecture": {
            "build_commands": [],
            "entry_points": [{"kind": "http_route", "location": "app.py:lookup"}],
            "trust_boundaries": [],
        },
        "inputs": [
            {"id": "in_1", "source_type": "HTTP query param", "location": "app.py:14",
             "variable": "q", "entry_point": "GET /search", "trust_level": "unauthenticated"},
            {"id": "in_2", "source_type": "CLI arg", "location": "cli.py:3",
             "variable": "--file", "entry_point": "import command", "trust_level": "privileged"},
        ],
        "initial_tasks": [{
            "task_id": "t_web_sqli_1", "attack_class": "sql_injection",
            "scope_hint": "GET /search reads q into cur.execute() at app.py:14",
            "target_files": ["app.py"], "rationale": "raw string formatting",
            "priority": 1, "source": "recon",
        }],
    }
    errors = validate_schema(payload, SCHEMAS / "recon_output.schema.json")
    assert errors == [], errors


def test_recon_schema_still_valid_without_inputs() -> None:
    """Back-compat: recon output with no `inputs` key still validates."""
    payload = {
        "subsystems": [{"name": "web", "path": "app.py", "language": "python",
                        "purpose": "Flask HTTP handlers"}],
        "architecture": {
            "build_commands": [],
            "entry_points": [{"kind": "http_route", "location": "app.py:lookup"}],
            "trust_boundaries": [],
        },
        "initial_tasks": [{
            "task_id": "t_web_sqli_1", "attack_class": "sql_injection",
            "scope_hint": "GET /search reads q into cur.execute() at app.py:14",
            "target_files": ["app.py"], "rationale": "raw string formatting",
            "priority": 1, "source": "recon",
        }],
    }
    errors = validate_schema(payload, SCHEMAS / "recon_output.schema.json")
    assert errors == [], errors


def test_recon_schema_rejects_bad_trust_level() -> None:
    payload = {
        "subsystems": [{"name": "web", "path": "app.py", "language": "python",
                        "purpose": "x"}],
        "architecture": {"build_commands": [], "entry_points": [], "trust_boundaries": []},
        "inputs": [{"id": "in_1", "source_type": "HTTP", "location": "a.py:1",
                    "variable": "q", "entry_point": "GET /", "trust_level": "superuser"}],
        "initial_tasks": [{
            "task_id": "t1", "attack_class": "sql_injection", "scope_hint": "x",
            "target_files": ["app.py"], "rationale": "r", "priority": 1, "source": "recon",
        }],
    }
    errors = validate_schema(payload, SCHEMAS / "recon_output.schema.json")
    assert errors, "expected trust_level enum violation"
