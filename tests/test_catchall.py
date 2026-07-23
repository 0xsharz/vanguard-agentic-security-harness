"""Offline tests for feature F6 — terminal whole-repo coverage sweep.

Covers the ported VVAH catch-all eligibility filter (``audit.catchall``:
``_CATCHALL_SKIP_EXTS`` / ``_CATCHALL_SKIP_NAMES`` / ``_CATCHALL_SKIP_DIR_PARTS``
+ ``_catchall_eligible``, ported verbatim from VVAH's ``s3_decompose.py``), the
authored task synthesis (``build_catchall_tasks``, validated against
``schemas/hunt_task.schema.json``), and the fail-open / graph-independent
orchestrator wireup (``orchestrator._add_catchall_tasks``), which runs LAST —
after recon + taint (V8) + sink-backward (F3) + specialist (V12) — so its
covered set reflects every targeted task already queued in a run.

All tests are OFFLINE: files are written to `tmp_path` and only read
statically (name/extension checks, never executed). NO network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import vash.orchestrator as orch
import vash.stages._common as common_mod
from vash.catchall import _catchall_eligible, build_catchall_tasks
from vash.config import load_config
from vash.json_utils import validate_schema
from vash.orchestrator import _add_catchall_tasks
from vash.state import StateDB
from vash.stages._common import StageContext

REPO_ROOT = Path(__file__).resolve().parents[1]
HUNT_TASK_SCHEMA = REPO_ROOT / "schemas" / "hunt_task.schema.json"


def _write(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


# ---------------------------------------------------------------------------
# _catchall_eligible — ported verbatim from VVAH (constants + function).
# ---------------------------------------------------------------------------


def test_eligible_python_file() -> None:
    assert _catchall_eligible("app.py") is True


def test_skips_readme() -> None:
    assert _catchall_eligible("README.md") is False


def test_skips_poetry_lock() -> None:
    assert _catchall_eligible("poetry.lock") is False


def test_skips_minified_multi_suffix_js() -> None:
    # foo.min.js: p.suffix alone is only ".js" (not in the skip set) — the
    # multi-suffix TAIL check (name.endswith(".min.js")) is what catches it.
    assert _catchall_eligible("static/foo.min.js") is False


def test_skips_image() -> None:
    assert _catchall_eligible("assets/icon.png") is False


def test_skips_file_under_snapshots_dir() -> None:
    assert _catchall_eligible("src/__snapshots__/a.py") is False


def test_skips_file_under_fixtures_dir() -> None:
    assert _catchall_eligible("tests/fixtures/sample.py") is False


def test_keeps_dotenv_credential_prone() -> None:
    # .env is intentionally KEPT — credential-prone configs stay in scope.
    assert _catchall_eligible(".env") is True


# ---------------------------------------------------------------------------
# build_catchall_tasks — authored task synthesis (grouping + cap + dropped).
# ---------------------------------------------------------------------------


def test_build_tasks_emits_valid_hunt_tasks_for_uncovered_files() -> None:
    tasks, dropped = build_catchall_tasks(["a.py", "b.py"], covered_files=[])
    assert dropped == 0
    assert len(tasks) == 1
    t = tasks[0]
    assert validate_schema(t, HUNT_TASK_SCHEMA) == []
    assert t["source"] == "catchall"
    assert t["priority"] == 5
    assert set(t["target_files"]) == {"a.py", "b.py"}
    assert t["task_id"] == "t_catchall_01"


def test_covered_file_produces_no_task() -> None:
    tasks, dropped = build_catchall_tasks(["a.py", "b.py"], covered_files=["b.py"])
    assert dropped == 0
    all_files = [f for t in tasks for f in t["target_files"]]
    assert all_files == ["a.py"]


def test_grouping_caps_files_per_task() -> None:
    files = [f"pkg/f{i}.py" for i in range(30)]
    tasks, dropped = build_catchall_tasks(files, covered_files=[], max_files_per_task=25)
    assert dropped == 0
    assert len(tasks) == 2
    assert len(tasks[0]["target_files"]) == 25
    assert len(tasks[1]["target_files"]) == 5
    # every file accounted for exactly once across the two shards
    assert sorted(tasks[0]["target_files"] + tasks[1]["target_files"]) == sorted(files)


def test_dropped_count_nonzero_when_max_tasks_exceeded() -> None:
    # Three distinct top-level directories -> three groups -> three buckets
    # (one file each), but max_tasks=2 caps emission at 2 tasks.
    files = ["a/x.py", "b/y.py", "c/z.py"]
    tasks, dropped = build_catchall_tasks(files, covered_files=[], max_tasks=2)
    assert len(tasks) == 2
    assert dropped == 1


def test_empty_input_returns_no_tasks() -> None:
    assert build_catchall_tasks([], covered_files=[]) == ([], 0)


def test_all_covered_returns_no_tasks() -> None:
    assert build_catchall_tasks(["a.py"], covered_files=["a.py"]) == ([], 0)


def test_ineligible_uncovered_files_yield_no_tasks() -> None:
    tasks, dropped = build_catchall_tasks(["README.md", "x.min.js"], covered_files=[])
    assert (tasks, dropped) == ([], 0)


# ---------------------------------------------------------------------------
# Orchestrator wireup: _add_catchall_tasks — fail-open, graph-independent.
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


def _db(tmp_path: Path) -> StateDB:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "r1")
    return db


def _catchall_tasks(db: StateDB):
    return [t for t in db.get_all_tasks("r1") if t.source == "catchall"]


def test_add_catchall_tasks_happy_path(tmp_path: Path, isolate_work) -> None:
    _write(tmp_path, "a.py", "x = 1\n")
    _write(tmp_path, "b.py", "y = 2\n")
    db = _db(tmp_path)
    db.add_task("r1", {
        "task_id": "t1", "source": "recon", "attack_class": "sql_injection",
        "scope_hint": "x" * 12, "target_files": ["a.py"],
        "rationale": "y" * 12, "priority": 1,
    })
    _add_catchall_tasks(_ctx_no_graph(tmp_path), db)
    tasks = _catchall_tasks(db)
    assert len(tasks) == 1
    assert tasks[0].target_files == ["b.py"]  # a.py already covered by t1
    assert tasks[0].priority == 5
    assert validate_schema(tasks[0].raw_json, HUNT_TASK_SCHEMA) == []
    db.close()


def test_add_catchall_tasks_fail_open(monkeypatch, tmp_path: Path, isolate_work) -> None:
    db = _db(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("catchall blew up")

    monkeypatch.setattr(orch, "build_catchall_tasks", boom)
    _add_catchall_tasks(_ctx_no_graph(tmp_path), db)  # must not raise
    assert _catchall_tasks(db) == []
    db.close()


def test_add_catchall_tasks_no_source_files_yields_no_tasks(tmp_path: Path, isolate_work) -> None:
    # Empty repo (no .py files at all) — must not raise either way.
    db = _db(tmp_path)
    _add_catchall_tasks(_ctx_no_graph(tmp_path), db)
    assert _catchall_tasks(db) == []
    db.close()
