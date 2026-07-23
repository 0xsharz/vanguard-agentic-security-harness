"""Offline tests for feature V8 — deterministic entry→sink taint chunking.

Covers the ported multi-source BFS (`GraphQuery.taint_paths`), the authored
Python sink table + glue (`audit.taint`), and the fail-open / gated orchestrator
wireup (`orchestrator._add_taint_tasks`).

All tests are OFFLINE: GraphDocument/GraphQuery are hand-built from dicts, tmp
repos are written and only read statically. NEVER calls graphify, NEVER executes
target code, NO network.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

import audit.orchestrator as orch
import audit.stages._common as common_mod
from audit.config import load_config
from audit.graph.query import GraphQuery
from audit.graph.schema import SCHEMA_VERSION, Edge, GraphDocument, Node
from audit.json_utils import validate_schema
from audit.orchestrator import _add_taint_tasks
from audit.state import StateDB
from audit.stages._common import StageContext
from audit.taint import (
    PYTHON_SINKS,
    build_taint_tasks,
    find_sinks,
    _split_location,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HUNT_TASK_SCHEMA = REPO_ROOT / "schemas" / "hunt_task.schema.json"


# ---- hand-built graph helpers ---------------------------------------------


def _n(nid: str, name: str, file: str, line: int, lang: str = "python") -> Node:
    return Node(id=nid, kind="function", name=name, file=file, line=line,
                qualified_name=f"{file}:{name}", language=lang)


def _doc(nodes, edges, *, confidence: str = "high", backend: str = "ast") -> GraphDocument:
    return GraphDocument(
        schema_version=SCHEMA_VERSION, graphify_version="0.8.51", generated_at="",
        backend=backend, confidence=confidence, content_hash="", root_dir="/repo",
        nodes={n.id: n for n in nodes}, edges=edges,
    )


def _flow_doc(confidence: str = "high") -> GraphDocument:
    """handler → service → run_cmd, over `calls` edges (a real forward flow)."""
    return _doc(
        [
            _n("h", "handler", "handlers.py", 1),
            _n("s", "service", "service.py", 1),
            _n("k", "run_cmd", "sink.py", 1),
        ],
        [
            Edge(src="h", dst="s", kind="calls"),
            Edge(src="s", dst="k", kind="calls"),
        ],
        confidence=confidence,
    )


def _write_flow_repo(root: Path) -> None:
    (root / "handlers.py").write_text("def handler(x):\n    return service(x)\n")
    (root / "service.py").write_text("def service(x):\n    return run_cmd(x)\n")
    (root / "sink.py").write_text("def run_cmd(x):\n    subprocess.Popen(x, shell=True)\n")


def _inp(iid: str, location: str, trust: str = "unauthenticated") -> dict:
    return {
        "id": iid, "source_type": "HTTP query param", "location": location,
        "variable": "x", "entry_point": "GET /", "trust_level": trust,
    }


# ---- find_sinks: right class per representative sink -----------------------


def test_find_sinks_detects_and_classifies(tmp_path: Path) -> None:
    (tmp_path / "sinks.py").write_text(
        "import subprocess\n"                       # 1
        "def run_cmd(x):\n"                          # 2
        "    subprocess.Popen(x, shell=True)\n"      # 3 -> command_injection
        "def load(x):\n"                             # 4
        "    return pickle.loads(x)\n"               # 5 -> deserialization
        "def read(x):\n"                             # 6
        "    f = open(x)\n"                          # 7 -> path_traversal
        "    return os.path.join('/base', x)\n"      # 8 -> path_traversal
        "def fetch(x):\n"                            # 9
        "    return requests.get(x)\n"               # 10 -> ssrf
        "def query(x):\n"                            # 11
        "    cursor.execute(x)\n"                    # 12 -> sql_injection
        "def ev(x):\n"                               # 13
        "    return eval(x)\n"                       # 14 -> code_injection
    )
    doc = _doc(
        [
            _n("n_run", "run_cmd", "sinks.py", 2),
            _n("n_load", "load", "sinks.py", 4),
            _n("n_read", "read", "sinks.py", 6),
            _n("n_fetch", "fetch", "sinks.py", 9),
            _n("n_query", "query", "sinks.py", 11),
            _n("n_ev", "ev", "sinks.py", 13),
        ],
        [],
    )
    gq = GraphQuery(doc, tmp_path)
    sinks = find_sinks(tmp_path, gq)

    name_of = {n.id: n.name for n in doc.nodes.values()}
    by_symbol: dict[str, set[str]] = defaultdict(set)
    for s in sinks:
        by_symbol[name_of[s.symbol_id]].add(s.attack_class)

    assert by_symbol["run_cmd"] == {"command_injection"}
    assert by_symbol["load"] == {"deserialization"}
    assert by_symbol["read"] == {"path_traversal"}
    assert by_symbol["fetch"] == {"ssrf"}
    assert by_symbol["query"] == {"sql_injection"}
    assert by_symbol["ev"] == {"code_injection"}


def test_find_sinks_skips_unresolved_symbol(tmp_path: Path) -> None:
    """A dangerous line whose enclosing symbol does not resolve is skipped."""
    (tmp_path / "m.py").write_text("os.system(x)\n")  # line 1, no def precedes
    doc = _doc([_n("late", "late", "m.py", 5)], [])   # only symbol is at line 5
    gq = GraphQuery(doc, tmp_path)
    assert find_sinks(tmp_path, gq) == []


def test_python_sinks_table_covers_expected_classes() -> None:
    for cls in ("command_injection", "code_injection", "deserialization",
                "path_traversal", "ssrf", "sql_injection", "xxe", "ssti",
                "open_redirect", "log_injection"):
        assert cls in PYTHON_SINKS and PYTHON_SINKS[cls]


# ---- taint_paths (ported BFS) ---------------------------------------------


def test_taint_paths_reaches_sink() -> None:
    gq = GraphQuery(_flow_doc())
    paths = gq.taint_paths(["h"], ["k"])
    assert paths == [("k", ["h", "s", "k"])]


def test_taint_paths_unreachable_sink_yields_nothing() -> None:
    doc = _doc(
        [_n("h", "handler", "a.py", 1), _n("o", "orphan", "o.py", 1),
         _n("i", "imp", "i.py", 1)],
        [Edge(src="h", dst="i", kind="imports")],  # only a non-calls edge
    )
    gq = GraphQuery(doc)
    assert gq.taint_paths(["h"], ["o"]) == []       # no edge at all
    assert gq.taint_paths(["h"], ["i"]) == []       # reachable only via imports


def test_taint_paths_max_hops_truncates() -> None:
    doc = _doc(
        [_n("h", "handler", "a.py", 1), _n("a", "a", "a.py", 2),
         _n("b", "b", "a.py", 3), _n("c", "c", "a.py", 4),
         _n("z", "sink", "a.py", 5)],
        [Edge(src="h", dst="a", kind="calls"), Edge(src="a", dst="b", kind="calls"),
         Edge(src="b", dst="c", kind="calls"), Edge(src="c", dst="z", kind="calls")],
    )
    gq = GraphQuery(doc)
    assert gq.taint_paths(["h"], ["z"], max_hops=8) == [("z", ["h", "a", "b", "c", "z"])]
    assert gq.taint_paths(["h"], ["z"], max_hops=2) == []  # too deep -> truncated


def test_taint_paths_multi_source_shortest_wins() -> None:
    """Two entries reach the same sink; the shared visited set records the
    shortest (nearest-entry) path exactly once."""
    doc = _doc(
        [_n("e1", "e1", "a.py", 1), _n("e2", "e2", "b.py", 1),
         _n("m", "m", "c.py", 1), _n("k", "sink", "d.py", 1)],
        [Edge(src="e1", dst="m", kind="calls"), Edge(src="m", dst="k", kind="calls"),
         Edge(src="e2", dst="k", kind="calls")],
    )
    gq = GraphQuery(doc)
    paths = gq.taint_paths(["e1", "e2"], ["k"])
    assert paths == [("k", ["e2", "k"])]  # e2 is one hop; recorded once


def test_taint_paths_empty_inputs() -> None:
    gq = GraphQuery(_flow_doc())
    assert gq.taint_paths([], ["k"]) == []
    assert gq.taint_paths(["h"], []) == []


# ---- build_taint_tasks ----------------------------------------------------


def test_build_taint_tasks_emits_valid_hunt_task(tmp_path: Path) -> None:
    _write_flow_repo(tmp_path)
    gq = GraphQuery(_flow_doc(), tmp_path)
    tasks = build_taint_tasks(gq, [_inp("in_1", "handlers.py:1")], tmp_path)

    assert len(tasks) == 1
    t = tasks[0]
    assert validate_schema(t, HUNT_TASK_SCHEMA) == []   # passes the real schema
    assert t["task_id"] == "t_taint_01"
    assert t["source"] == "taint"
    assert t["attack_class"] == "command_injection"
    assert t["priority"] == 1
    assert t["target_files"] == ["handlers.py", "service.py", "sink.py"]
    assert "handler" in t["scope_hint"] and "run_cmd" in t["scope_hint"]
    assert "in_1" in t["rationale"]


def test_build_taint_tasks_dedups_same_symbol_sinks(tmp_path: Path) -> None:
    """Two dangerous lines in the SAME sink symbol collapse to one task."""
    (tmp_path / "handlers.py").write_text("def handler(x):\n    return run_cmd(x)\n")
    (tmp_path / "sink.py").write_text(
        "def run_cmd(x):\n    subprocess.Popen(x, shell=True)\n    os.system(x)\n"
    )
    doc = _doc(
        [_n("h", "handler", "handlers.py", 1), _n("k", "run_cmd", "sink.py", 1)],
        [Edge(src="h", dst="k", kind="calls")],
    )
    gq = GraphQuery(doc, tmp_path)
    tasks = build_taint_tasks(gq, [_inp("in_1", "handlers.py:1")], tmp_path)
    assert len(tasks) == 1


def test_build_taint_tasks_caps_at_max_tasks(tmp_path: Path) -> None:
    (tmp_path / "handlers.py").write_text("def handler(x):\n    return service(x)\n")
    (tmp_path / "service.py").write_text(
        "def service(x):\n    run_cmd(x)\n    do_sql(x)\n"
    )
    (tmp_path / "sink.py").write_text(
        "def run_cmd(x):\n    subprocess.Popen(x, shell=True)\n"
        "def do_sql(x):\n    cursor.execute(x)\n"
    )
    doc = _doc(
        [_n("h", "handler", "handlers.py", 1), _n("s", "service", "service.py", 1),
         _n("k1", "run_cmd", "sink.py", 1), _n("k2", "do_sql", "sink.py", 3)],
        [Edge(src="h", dst="s", kind="calls"),
         Edge(src="s", dst="k1", kind="calls"), Edge(src="s", dst="k2", kind="calls")],
    )
    gq = GraphQuery(doc, tmp_path)
    inputs = [_inp("in_1", "handlers.py:1")]
    assert len(build_taint_tasks(gq, inputs, tmp_path)) == 2            # both sinks
    assert len(build_taint_tasks(gq, inputs, tmp_path, max_tasks=1)) == 1  # capped


def test_build_taint_tasks_empty_when_no_inputs(tmp_path: Path) -> None:
    _write_flow_repo(tmp_path)
    gq = GraphQuery(_flow_doc(), tmp_path)
    assert build_taint_tasks(gq, [], tmp_path) == []


def test_build_taint_tasks_empty_when_no_sinks(tmp_path: Path) -> None:
    (tmp_path / "handlers.py").write_text("def handler(x):\n    return x\n")
    doc = _doc([_n("h", "handler", "handlers.py", 1)], [])
    gq = GraphQuery(doc, tmp_path)
    assert build_taint_tasks(gq, [_inp("in_1", "handlers.py:1")], tmp_path) == []


def test_build_taint_tasks_empty_when_graph_empty(tmp_path: Path) -> None:
    _write_flow_repo(tmp_path)
    gq = GraphQuery(_doc([], []), tmp_path)  # no nodes -> no entries resolve
    assert build_taint_tasks(gq, [_inp("in_1", "handlers.py:1")], tmp_path) == []


def test_split_location() -> None:
    assert _split_location("app.py:1") == ("app.py", 1)
    assert _split_location("a/b.py:10:3") == ("a/b.py", 10)
    assert _split_location("app.py") == ("app.py", 0)
    assert _split_location("") == ("", 0)


# ---- orchestrator wireup: fail-open + gated -------------------------------


@pytest.fixture
def isolate_work(monkeypatch, tmp_path):
    """Keep StageContext.work_dir out of the real checkout."""
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")


def _db_with_input(tmp_path: Path) -> StateDB:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "r1")
    db.add_input("r1", _inp("in_1", "handlers.py:1"))
    return db


def _ctx(tmp_path: Path) -> StageContext:
    return StageContext(run_id="r1", repo_path=tmp_path, config=load_config())


def test_add_taint_tasks_happy_path(monkeypatch, tmp_path, isolate_work) -> None:
    _write_flow_repo(tmp_path)
    monkeypatch.setattr(orch, "build_or_load", lambda root, cache: _flow_doc())
    db = _db_with_input(tmp_path)
    _add_taint_tasks(_ctx(tmp_path), db)
    taint = [t for t in db.get_all_tasks("r1") if t.source == "taint"]
    assert len(taint) == 1
    assert taint[0].attack_class == "command_injection"
    assert taint[0].priority == 1
    db.close()


def test_add_taint_tasks_fail_open_on_build_error(monkeypatch, tmp_path, isolate_work) -> None:
    def boom(root, cache):
        raise RuntimeError("graph build blew up")

    monkeypatch.setattr(orch, "build_or_load", boom)
    db = _db_with_input(tmp_path)
    _add_taint_tasks(_ctx(tmp_path), db)  # must NOT raise
    assert [t for t in db.get_all_tasks("r1") if t.source == "taint"] == []
    db.close()


def test_add_taint_tasks_skips_low_confidence(monkeypatch, tmp_path, isolate_work) -> None:
    """Grep-fallback (low-confidence) graph → unreliable reachability → skip."""
    _write_flow_repo(tmp_path)
    monkeypatch.setattr(orch, "build_or_load",
                        lambda root, cache: _flow_doc(confidence="low"))
    db = _db_with_input(tmp_path)
    _add_taint_tasks(_ctx(tmp_path), db)
    assert [t for t in db.get_all_tasks("r1") if t.source == "taint"] == []
    db.close()


def test_add_taint_tasks_skips_when_no_calls_edges(monkeypatch, tmp_path, isolate_work) -> None:
    """High-confidence graph but zero `calls` edges → no forward path → skip.
    This is the gate that keeps the e2e stub green (its fixture graph has only
    imports/defines edges)."""
    _write_flow_repo(tmp_path)
    no_calls = _doc(
        [_n("h", "handler", "handlers.py", 1), _n("k", "run_cmd", "sink.py", 1)],
        [Edge(src="h", dst="k", kind="imports")],  # not a calls edge
    )
    monkeypatch.setattr(orch, "build_or_load", lambda root, cache: no_calls)
    db = _db_with_input(tmp_path)
    _add_taint_tasks(_ctx(tmp_path), db)
    assert [t for t in db.get_all_tasks("r1") if t.source == "taint"] == []
    db.close()
