"""Offline tests for feature V12 — gated repo-wide specialist Hunt sweeps.

Covers the ported VVAH gate (`audit.specialists`: `_scan_any` + the crypto/
deserialization/batch-etl regexes, `_has_authz_surface`, `_has_batch_surface`,
`active_specialists`), task synthesis (`build_specialist_tasks`, validated
against `schemas/hunt_task.schema.json`), the specialist-flows-to-the-V9-lens
wiring (the one-line `audit.stages.hunt` change), and the fail-open/gated
orchestrator wireup (`orchestrator._add_specialist_tasks`).

All tests are OFFLINE: files are written to `tmp_path` and only read
statically (utf-8, errors="replace"). NEVER executes target code, NO network.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import audit.orchestrator as orch
import audit.stages._common as common_mod
import audit.stages.hunt as hunt_mod
from audit.config import load_config
from audit.json_utils import validate_schema
from audit.lang.hints import SPECIALIST_HINTS, hints_for, is_iac_file
from audit.orchestrator import _add_specialist_tasks
from audit.specialists import (
    _BATCH_ETL_RX,
    _CRYPTO_RX,
    _DESER_RX,
    _has_authz_surface,
    _has_batch_surface,
    _scan_any,
    active_specialists,
    build_specialist_tasks,
)
from audit.state import StateDB, Task
from audit.stages._common import StageContext

REPO_ROOT = Path(__file__).resolve().parents[1]
HUNT_TASK_SCHEMA = REPO_ROOT / "schemas" / "hunt_task.schema.json"


def _write(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


# ---------------------------------------------------------------------------
# Ported regex gate: _scan_any + _CRYPTO_RX / _DESER_RX (verbatim from VVAH).
# ---------------------------------------------------------------------------


def test_crypto_gate_on_with_hashlib_md5(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "import hashlib\nhashlib.md5(b'x').hexdigest()\n")
    assert _scan_any(tmp_path, ["a.py"], _CRYPTO_RX) is True


def test_crypto_gate_on_with_aes(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "from Crypto.Cipher import AES\n")
    assert _scan_any(tmp_path, ["a.py"], _CRYPTO_RX) is True


def test_crypto_gate_off_when_absent(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "def add(a, b):\n    return a + b\n")
    assert _scan_any(tmp_path, ["a.py"], _CRYPTO_RX) is False


def test_deserialization_gate_on_with_pickle_loads(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "import pickle\npickle.loads(data)\n")
    assert _scan_any(tmp_path, ["a.py"], _DESER_RX) is True


def test_deserialization_gate_off_when_absent(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "x = 1\n")
    assert _scan_any(tmp_path, ["a.py"], _DESER_RX) is False


def test_scan_any_survives_unreadable_file(tmp_path: Path) -> None:
    # Nonexistent file must not raise — _scan_any swallows OSError per file.
    assert _scan_any(tmp_path, ["does_not_exist.py"], _CRYPTO_RX) is False


# ---------------------------------------------------------------------------
# access-control gate: _has_authz_surface — ADAPTED from VVAH's ContextPackage
# to audit's recon_output dict + F1 inputs list.
# ---------------------------------------------------------------------------


def test_authz_surface_on_http_route_entry_point() -> None:
    recon = {"architecture": {"entry_points": [{"kind": "http_route", "location": "a.py:1"}],
                               "trust_boundaries": []}}
    assert _has_authz_surface(recon, []) is True


def test_authz_surface_on_auth_required_present() -> None:
    recon = {"architecture": {"entry_points": [{"kind": "library_api", "location": "a.py:1",
                                                  "auth_required": False}],
                               "trust_boundaries": []}}
    assert _has_authz_surface(recon, []) is True


def test_authz_surface_on_unauthenticated_input() -> None:
    recon = {"architecture": {"entry_points": [], "trust_boundaries": []}}
    inputs = [{"id": "in_1", "trust_level": "unauthenticated"}]
    assert _has_authz_surface(recon, inputs) is True


def test_authz_surface_on_trust_boundary_present() -> None:
    recon = {"architecture": {"entry_points": [],
                               "trust_boundaries": [{"name": "b", "description": "d"}]}}
    assert _has_authz_surface(recon, []) is True


def test_authz_surface_off_for_pure_library_recon() -> None:
    recon = {"architecture": {"entry_points": [{"kind": "library_api", "location": "a.py:1"}],
                               "trust_boundaries": []}}
    inputs = [{"id": "in_1", "trust_level": "internal"}]
    assert _has_authz_surface(recon, inputs) is False


def test_authz_surface_tolerates_string_entry_points() -> None:
    # Malformed/lenient recon shapes (entry_points as bare strings, no "kind")
    # must never raise — the gate degrades to "no signal", not a crash.
    recon = {"architecture": {"entry_points": ["app.py"], "trust_boundaries": []}}
    assert _has_authz_surface(recon, []) is False


def test_authz_surface_tolerates_missing_architecture() -> None:
    assert _has_authz_surface({}, []) is False
    assert _has_authz_surface(None, None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# batch-etl gate: _has_batch_surface
# ---------------------------------------------------------------------------


def test_batch_surface_on_cli_entry_point(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "x = 1\n")
    recon = {"architecture": {"entry_points": [{"kind": "cli", "location": "a.py:1"}]}}
    assert _has_batch_surface(recon, tmp_path, ["a.py"]) is True


def test_batch_surface_on_file_input_entry_point(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "x = 1\n")
    recon = {"architecture": {"entry_points": [{"kind": "file_input", "location": "a.py:1"}]}}
    assert _has_batch_surface(recon, tmp_path, ["a.py"]) is True


def test_batch_surface_on_csv_writer_content(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "import csv\ncsv.writer(f)\n")
    recon = {"architecture": {"entry_points": []}}
    assert _has_batch_surface(recon, tmp_path, ["a.py"]) is True


def test_batch_surface_off_when_absent(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "def add(a, b):\n    return a + b\n")
    recon = {"architecture": {"entry_points": [{"kind": "http_route", "location": "a.py:1"}]}}
    assert _has_batch_surface(recon, tmp_path, ["a.py"]) is False


# ---------------------------------------------------------------------------
# iac gate: is_iac_file (reused from audit.lang.hints — not re-authored here)
# ---------------------------------------------------------------------------


def test_iac_gate_on_dockerfile() -> None:
    assert any(is_iac_file(f) for f in ["Dockerfile", "app.py"]) is True


def test_iac_gate_on_tf_file() -> None:
    assert any(is_iac_file(f) for f in ["infra/main.tf"]) is True


def test_iac_gate_off_without_iac_files() -> None:
    assert any(is_iac_file(f) for f in ["app.py", "lib/util.py"]) is False


# ---------------------------------------------------------------------------
# active_specialists — the aggregate gate. logic-bug is unconditional; every
# other specialist is dropped unless its surface predicate is true.
# ---------------------------------------------------------------------------


def test_active_specialists_logic_bug_always_on_pure_library(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "def add(a, b):\n    return a + b\n")
    recon = {"architecture": {"entry_points": [{"kind": "library_api", "location": "a.py:1"}],
                               "trust_boundaries": []}}
    active = active_specialists(recon, [], tmp_path, ["a.py"])
    assert active == ["logic-bug"]


def test_active_specialists_all_gate_on_when_surface_present(tmp_path: Path) -> None:
    _write(tmp_path, "a.py",
           "import hashlib, pickle\nhashlib.md5(b'x')\npickle.loads(b'y')\n")
    recon = {"architecture": {
        "entry_points": [{"kind": "http_route", "location": "a.py:1"},
                          {"kind": "cli", "location": "a.py:2"}],
        "trust_boundaries": [],
    }}
    source_files = ["a.py", "Dockerfile"]
    active = active_specialists(recon, [], tmp_path, source_files)
    assert set(active) == {
        "crypto", "logic-bug", "access-control", "deserialization", "batch-etl", "iac",
    }


def test_active_specialists_returns_known_keys_only(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "x = 1\n")
    active = active_specialists({}, [], tmp_path, ["a.py"])
    assert set(active) <= set(SPECIALIST_HINTS)
    assert "logic-bug" in active


# ---------------------------------------------------------------------------
# build_specialist_tasks — task synthesis, schema-validated.
# ---------------------------------------------------------------------------


def test_build_specialist_tasks_emits_valid_hunt_tasks(tmp_path: Path) -> None:
    tasks = build_specialist_tasks(["crypto", "logic-bug"], ["a.py", "b.py"], tmp_path)
    assert len(tasks) == 2
    by_name = {t["specialist"]: t for t in tasks}
    for name, t in by_name.items():
        errors = validate_schema(t, HUNT_TASK_SCHEMA)
        assert errors == [], errors
        assert t["source"] == "specialist"
        assert t["priority"] == 3
        assert t["target_files"]
        assert len(t["scope_hint"]) >= 10
        assert len(t["rationale"]) >= 10
    assert by_name["crypto"]["task_id"] == "t_spec_crypto"
    assert by_name["logic-bug"]["task_id"] == "t_spec_logic_bug"


def test_build_specialist_tasks_task_id_for_hyphenated_names(tmp_path: Path) -> None:
    tasks = build_specialist_tasks(["access-control", "batch-etl", "iac"], ["a.py"], tmp_path)
    ids = {t["specialist"]: t["task_id"] for t in tasks}
    assert ids["access-control"] == "t_spec_access_control"
    assert ids["batch-etl"] == "t_spec_batch_etl"
    assert ids["iac"] == "t_spec_iac"
    for t in tasks:  # task_id must satisfy the schema's ^[a-z0-9_-]{1,64}$ pattern
        assert validate_schema(t, HUNT_TASK_SCHEMA) == []


def test_build_specialist_tasks_skips_when_no_source_files(tmp_path: Path) -> None:
    tasks = build_specialist_tasks(["crypto", "logic-bug"], [], tmp_path)
    assert tasks == []


def test_build_specialist_tasks_caps_at_max_files(tmp_path: Path) -> None:
    files = [f"f{i}.py" for i in range(50)]
    tasks = build_specialist_tasks(["logic-bug"], files, tmp_path, max_files=40)
    assert len(tasks[0]["target_files"]) == 40


def test_build_specialist_tasks_empty_active_yields_no_tasks(tmp_path: Path) -> None:
    assert build_specialist_tasks([], ["a.py"], tmp_path) == []


# ---------------------------------------------------------------------------
# Wiring: the specialist key flows from task.raw_json into the V9 lens.
# This is Hunt's ENTIRE V12 change — one line: specialist=None ->
# specialist=task.raw_json.get("specialist"). Proven in two parts per the
# brief: (1) the raw_json round-trip, (2) hints_for really returns the
# specialist's lens body for that key. A source-inspection check pins the
# actual line so a future revert of the one-line change fails loudly.
# ---------------------------------------------------------------------------


def test_specialist_key_flows_from_task_raw_json_to_lens() -> None:
    task = Task(task_id="t_spec_crypto", run_id="r1", source="specialist",
                attack_class="weak_crypto", scope_hint="x" * 12,
                target_files=["a.py"], rationale="y" * 12, priority=3,
                status="pending", raw_json={"specialist": "crypto"})
    # Exactly what hunt.py's one-line change extracts and passes to hints_for.
    specialist = task.raw_json.get("specialist")
    assert specialist == "crypto"
    assert hints_for(["python"], specialist, None) == SPECIALIST_HINTS["crypto"]


def test_specialist_absent_key_falls_back_to_none() -> None:
    task = Task(task_id="t1", run_id="r1", source="recon", attack_class="sql_injection",
                scope_hint="x" * 12, target_files=["a.py"], rationale="y" * 12,
                priority=1, status="pending", raw_json={})
    assert task.raw_json.get("specialist") is None
    assert hints_for(["python"], task.raw_json.get("specialist"), None) != SPECIALIST_HINTS["crypto"]


def test_hunt_module_wires_task_specialist_into_hints_for() -> None:
    """Pins the literal one-line change in audit/stages/hunt.py so an
    accidental revert to specialist=None fails this test immediately."""
    src = inspect.getsource(hunt_mod.run_hunt)
    assert 'hints_for(languages, specialist=task.raw_json.get("specialist")' in src


# ---------------------------------------------------------------------------
# Orchestrator wireup: _add_specialist_tasks — fail-open, graph-independent.
# ---------------------------------------------------------------------------


@pytest.fixture
def isolate_work(monkeypatch, tmp_path):
    """Keep StageContext.work_dir out of the real checkout."""
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")


def _ctx_no_graph(tmp_path: Path) -> StageContext:
    ctx = StageContext(run_id="r1", repo_path=tmp_path, config=load_config())
    ctx._graph = None          # specialists are graph-independent by design
    ctx._graph_loaded = True   # short-circuit ctx.graph() -> None, no rebuild
    return ctx


def _db(tmp_path: Path) -> StateDB:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "r1")
    return db


def _specialist_tasks(db: StateDB):
    return [t for t in db.get_all_tasks("r1") if t.source == "specialist"]


def test_add_specialist_tasks_happy_path(tmp_path: Path, isolate_work) -> None:
    _write(tmp_path, "a.py", "def f(x):\n    return x\n")
    db = _db(tmp_path)
    _add_specialist_tasks(_ctx_no_graph(tmp_path), db)
    tasks = _specialist_tasks(db)
    names = {t.raw_json.get("specialist") for t in tasks}
    assert names == {"logic-bug"}  # no crypto/deser/authz/batch/iac surface
    for t in tasks:
        assert t.priority == 3
        assert t.target_files == ["a.py"]
        assert validate_schema(t.raw_json, HUNT_TASK_SCHEMA) == []
    db.close()


def test_add_specialist_tasks_gates_off_absent_surfaces(tmp_path: Path, isolate_work) -> None:
    _write(tmp_path, "a.py", "import hashlib\nhashlib.sha256(b'x')\n")
    db = _db(tmp_path)
    db.save_recon_output("r1", {"architecture": {
        "entry_points": [{"kind": "http_route", "location": "a.py:1"}],
        "trust_boundaries": [],
    }})
    _add_specialist_tasks(_ctx_no_graph(tmp_path), db)
    names = {t.raw_json.get("specialist") for t in _specialist_tasks(db)}
    assert names == {"logic-bug", "crypto", "access-control"}
    assert "deserialization" not in names
    assert "batch-etl" not in names
    assert "iac" not in names
    db.close()


def test_add_specialist_tasks_fail_open(monkeypatch, tmp_path: Path, isolate_work) -> None:
    db = _db(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("specialists blew up")

    monkeypatch.setattr(orch, "active_specialists", boom)
    _add_specialist_tasks(_ctx_no_graph(tmp_path), db)  # must not raise
    assert _specialist_tasks(db) == []
    db.close()


def test_add_specialist_tasks_fail_open_on_build_tasks(monkeypatch, tmp_path: Path, isolate_work) -> None:
    db = _db(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("task synthesis blew up")

    monkeypatch.setattr(orch, "build_specialist_tasks", boom)
    _add_specialist_tasks(_ctx_no_graph(tmp_path), db)  # must not raise
    assert _specialist_tasks(db) == []
    db.close()


def test_add_specialist_tasks_no_source_files_yields_no_tasks(tmp_path: Path, isolate_work) -> None:
    # Empty repo (no .py files at all) — logic-bug gates on but has nothing to
    # scope, so build_specialist_tasks skips it. Must not raise either way.
    db = _db(tmp_path)
    _add_specialist_tasks(_ctx_no_graph(tmp_path), db)
    assert _specialist_tasks(db) == []
    db.close()
