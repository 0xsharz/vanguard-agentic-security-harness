"""Offline tests for feature F3 — sink-backward hunting modality.

Covers the backward reach primitive (`GraphQuery.callers_within`), the
orphan-sink task builder (`audit.taint.build_sink_backward_tasks`, which reuses
V8's `find_sinks`/`PYTHON_SINKS` + `taint_paths`), and the fail-open / gated
orchestrator wireup (`orchestrator._add_sink_backward_tasks`).

F3 emits tasks ONLY for **orphan sinks** — dangerous sinks that NO enumerated
input reaches forward (``all_sinks − forward_reached``). This makes F3 disjoint
from V8's forward (input→sink) tasks by construction; ``test_disjoint_from_forward``
pins that property.

All tests are OFFLINE: GraphDocument/GraphQuery are hand-built from dicts, tmp
repos are written and only read statically. NEVER calls graphify, NEVER executes
target code, NO network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import audit.orchestrator as orch
import audit.stages._common as common_mod
from audit.config import load_config
from audit.graph.query import GraphQuery
from audit.graph.schema import SCHEMA_VERSION, Edge, GraphDocument, Node
from audit.json_utils import validate_schema
from audit.orchestrator import _add_sink_backward_tasks
from audit.state import StateDB
from audit.stages._common import StageContext
from audit.taint import (
    build_sink_backward_tasks,
    build_taint_tasks,
    _entry_ids,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HUNT_TASK_SCHEMA = REPO_ROOT / "schemas" / "hunt_task.schema.json"


# ---- hand-built graph helpers (mirrors test_taint.py) ---------------------


def _n(nid: str, name: str, file: str, line: int, lang: str = "python") -> Node:
    return Node(id=nid, kind="function", name=name, file=file, line=line,
                qualified_name=f"{file}:{name}", language=lang)


def _doc(nodes, edges, *, confidence: str = "high", backend: str = "ast") -> GraphDocument:
    return GraphDocument(
        schema_version=SCHEMA_VERSION, graphify_version="0.8.51", generated_at="",
        backend=backend, confidence=confidence, content_hash="", root_dir="/repo",
        nodes={n.id: n for n in nodes}, edges=edges,
    )


def _inp(iid: str, location: str, trust: str = "unauthenticated") -> dict:
    return {
        "id": iid, "source_type": "HTTP query param", "location": location,
        "variable": "x", "entry_point": "GET /", "trust_level": trust,
    }


def _split_repo(root: Path) -> GraphDocument:
    """One forward flow (handler→service→run_cmd) PLUS a disconnected orphan
    (orphan_caller→load). ``load`` is reachable by NO input → an orphan sink;
    ``run_cmd`` IS reachable from the handler → NOT an orphan."""
    (root / "handlers.py").write_text("def handler(x):\n    return service(x)\n")
    (root / "service.py").write_text("def service(x):\n    return run_cmd(x)\n")
    (root / "sink.py").write_text("def run_cmd(x):\n    subprocess.Popen(x, shell=True)\n")
    (root / "orphan.py").write_text("def orphan_caller():\n    return load(read())\n")
    (root / "orphan_sink.py").write_text("def load(x):\n    return pickle.loads(x)\n")
    return _doc(
        [
            _n("h", "handler", "handlers.py", 1),
            _n("s", "service", "service.py", 1),
            _n("k", "run_cmd", "sink.py", 1),
            _n("oc", "orphan_caller", "orphan.py", 1),
            _n("ld", "load", "orphan_sink.py", 1),
        ],
        [
            Edge(src="h", dst="s", kind="calls"),
            Edge(src="s", dst="k", kind="calls"),
            Edge(src="oc", dst="ld", kind="calls"),
        ],
    )


# ---- callers_within: reverse BFS over calls edges -------------------------


def test_callers_within_reverse_bfs() -> None:
    """a→b→c→k over `calls`; x→k over `imports`. Backward reach excludes the
    seed and the imports-only caller, and respects max_hops."""
    doc = _doc(
        [_n("a", "a", "a.py", 1), _n("b", "b", "b.py", 1), _n("c", "c", "c.py", 1),
         _n("k", "sink", "k.py", 1), _n("x", "x", "x.py", 1)],
        [Edge(src="a", dst="b", kind="calls"), Edge(src="b", dst="c", kind="calls"),
         Edge(src="c", dst="k", kind="calls"), Edge(src="x", dst="k", kind="imports")],
    )
    gq = GraphQuery(doc)
    assert gq.callers_within(["k"], max_hops=3) == {"a", "b", "c"}  # x excluded (imports)
    assert gq.callers_within(["k"], max_hops=1) == {"c"}            # 1 hop
    assert gq.callers_within(["k"], max_hops=2) == {"b", "c"}       # 2 hops
    assert "k" not in gq.callers_within(["k"], max_hops=3)          # seed excluded
    assert gq.callers_within([], max_hops=3) == set()              # no seeds


def test_callers_within_multi_seed_excludes_all_seeds() -> None:
    doc = _doc(
        [_n("a", "a", "a.py", 1), _n("b", "b", "b.py", 1), _n("c", "c", "c.py", 1),
         _n("k", "sink", "k.py", 1)],
        [Edge(src="a", dst="b", kind="calls"), Edge(src="b", dst="c", kind="calls"),
         Edge(src="c", dst="k", kind="calls")],
    )
    gq = GraphQuery(doc)
    # seeds {k, c}: direct caller of k is c (a seed → excluded); of c is b.
    assert gq.callers_within(["k", "c"], max_hops=1) == {"b"}


# ---- build_sink_backward_tasks --------------------------------------------


def test_build_sink_backward_emits_valid_task(tmp_path: Path) -> None:
    doc = _split_repo(tmp_path)
    gq = GraphQuery(doc, tmp_path)
    tasks = build_sink_backward_tasks(gq, [_inp("in_1", "handlers.py:1")], tmp_path)

    assert len(tasks) == 1                       # only the orphan (load), not run_cmd
    t = tasks[0]
    assert validate_schema(t, HUNT_TASK_SCHEMA) == []   # passes the real schema
    assert t["task_id"] == "t_sinkback_01"
    assert t["source"] == "sink_backward"
    assert t["attack_class"] == "deserialization"
    assert t["priority"] == 2
    # sink file first, then backward-reachable caller files.
    assert t["target_files"] == ["orphan_sink.py", "orphan.py"]
    assert "load" in t["scope_hint"] and "backward" in t["scope_hint"].lower()
    assert "orphan sink" in t["rationale"].lower()


def test_disjoint_from_forward(tmp_path: Path) -> None:
    """Correctness property: F3 tasks are for orphan sinks ONLY — never a sink
    V8 already covered forward. The forward-reached sink (run_cmd) appears in a
    build_taint_tasks task and in NO build_sink_backward_tasks task."""
    doc = _split_repo(tmp_path)
    gq = GraphQuery(doc, tmp_path)
    inputs = [_inp("in_1", "handlers.py:1")]

    forward = build_taint_tasks(gq, inputs, tmp_path)
    backward = build_sink_backward_tasks(gq, inputs, tmp_path)

    # Forward covers run_cmd (reachable from the input).
    assert any(t["attack_class"] == "command_injection"
               and "run_cmd" in t["scope_hint"] for t in forward)
    # Backward covers ONLY the orphan (load) — run_cmd never appears in F3.
    assert all("run_cmd" not in t["scope_hint"] for t in backward)
    assert all(t["attack_class"] != "command_injection" for t in backward)
    assert [t["attack_class"] for t in backward] == ["deserialization"]


def test_build_sink_backward_orphan_with_no_callers(tmp_path: Path) -> None:
    """An orphan sink whose symbol has no callers still yields one task, with
    target_files == just the sink file."""
    (tmp_path / "s.py").write_text("def load(x):\n    return pickle.loads(x)\n")
    doc = _doc([_n("ld", "load", "s.py", 1)], [])
    gq = GraphQuery(doc, tmp_path)
    tasks = build_sink_backward_tasks(gq, [], tmp_path)
    assert len(tasks) == 1
    assert tasks[0]["target_files"] == ["s.py"]
    assert tasks[0]["source"] == "sink_backward"


def test_build_sink_backward_caps_at_max_tasks(tmp_path: Path) -> None:
    (tmp_path / "s1.py").write_text("def s1(x):\n    return eval(x)\n")
    (tmp_path / "s2.py").write_text("def s2(x):\n    return pickle.loads(x)\n")
    (tmp_path / "s3.py").write_text("def s3(x):\n    os.system(x)\n")
    doc = _doc(
        [_n("n1", "s1", "s1.py", 1), _n("n2", "s2", "s2.py", 1),
         _n("n3", "s3", "s3.py", 1)],
        [],
    )
    gq = GraphQuery(doc, tmp_path)
    assert len(build_sink_backward_tasks(gq, [], tmp_path)) == 3            # all orphans
    assert len(build_sink_backward_tasks(gq, [], tmp_path, max_tasks=2)) == 2  # capped


def test_build_sink_backward_empty_when_no_orphans(tmp_path: Path) -> None:
    """Every sink is forward-reached by an input → no orphans → no tasks."""
    (tmp_path / "handlers.py").write_text("def handler(x):\n    return run_cmd(x)\n")
    (tmp_path / "sink.py").write_text("def run_cmd(x):\n    subprocess.Popen(x, shell=True)\n")
    doc = _doc(
        [_n("h", "handler", "handlers.py", 1), _n("k", "run_cmd", "sink.py", 1)],
        [Edge(src="h", dst="k", kind="calls")],
    )
    gq = GraphQuery(doc, tmp_path)
    assert build_sink_backward_tasks(gq, [_inp("in_1", "handlers.py:1")], tmp_path) == []


def test_build_sink_backward_empty_when_no_sinks(tmp_path: Path) -> None:
    (tmp_path / "handlers.py").write_text("def handler(x):\n    return x\n")
    doc = _doc([_n("h", "handler", "handlers.py", 1)], [])
    gq = GraphQuery(doc, tmp_path)
    assert build_sink_backward_tasks(gq, [], tmp_path) == []


def test_build_sink_backward_empty_when_graph_empty(tmp_path: Path) -> None:
    gq = GraphQuery(_doc([], []), tmp_path)  # no nodes → no files → no sinks
    assert build_sink_backward_tasks(gq, [_inp("in_1", "handlers.py:1")], tmp_path) == []


def test_entry_ids_shared_helper(tmp_path: Path) -> None:
    """The extracted entry-id derivation resolves input locations to enclosing
    symbols, deduped and order-preserved (shared with build_taint_tasks)."""
    doc = _doc([_n("h", "handler", "handlers.py", 1), _n("s", "svc", "service.py", 1)], [])
    gq = GraphQuery(doc, tmp_path)
    ids = _entry_ids(gq, [_inp("i1", "handlers.py:2"), _inp("i2", "service.py:9"),
                          _inp("i3", "handlers.py:5")])
    assert ids == ["h", "s"]  # h resolved once (dedup), order preserved
    assert _entry_ids(gq, []) == []


# ---- orchestrator wireup: fail-open + gated -------------------------------


@pytest.fixture
def isolate_work(monkeypatch, tmp_path):
    """Keep StageContext.work_dir out of the real checkout."""
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")


def _ctx_with_graph(tmp_path: Path, gq: GraphQuery | None) -> StageContext:
    ctx = StageContext(run_id="r1", repo_path=tmp_path, config=load_config())
    ctx._graph = gq            # inject the memoized graph directly (no rebuild)
    ctx._graph_loaded = True
    return ctx


def _db(tmp_path: Path) -> StateDB:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "r1")
    return db


def _sink_backward(db: StateDB):
    return [t for t in db.get_all_tasks("r1") if t.source == "sink_backward"]


def test_add_sink_backward_happy_path(tmp_path, isolate_work) -> None:
    doc = _split_repo(tmp_path)
    db = _db(tmp_path)
    db.add_input("r1", _inp("in_1", "handlers.py:1"))  # reaches run_cmd → not orphan
    _add_sink_backward_tasks(_ctx_with_graph(tmp_path, GraphQuery(doc, tmp_path)), db)
    tasks = _sink_backward(db)
    assert len(tasks) == 1                       # only the orphan (load)
    assert tasks[0].attack_class == "deserialization"
    assert tasks[0].priority == 2
    db.close()


def test_add_sink_backward_fail_open(monkeypatch, tmp_path, isolate_work) -> None:
    doc = _split_repo(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("sink-backward blew up")

    monkeypatch.setattr(orch, "build_sink_backward_tasks", boom)
    db = _db(tmp_path)
    _add_sink_backward_tasks(_ctx_with_graph(tmp_path, GraphQuery(doc, tmp_path)), db)  # no raise
    assert _sink_backward(db) == []
    db.close()


def test_add_sink_backward_gated_none_graph(tmp_path, isolate_work) -> None:
    db = _db(tmp_path)
    _add_sink_backward_tasks(_ctx_with_graph(tmp_path, None), db)  # ctx.graph() → None
    assert _sink_backward(db) == []
    db.close()


def test_add_sink_backward_gated_low_confidence(tmp_path, isolate_work) -> None:
    doc = _split_repo(tmp_path)
    low = _doc(list(doc.nodes.values()), doc.edges, confidence="low")
    db = _db(tmp_path)
    _add_sink_backward_tasks(_ctx_with_graph(tmp_path, GraphQuery(low, tmp_path)), db)
    assert _sink_backward(db) == []
    db.close()


def test_add_sink_backward_gated_no_calls_edges(tmp_path, isolate_work) -> None:
    """High-confidence graph but zero `calls` edges → no callers to trace
    backward → skip. This is the gate that keeps the e2e stub green (its fixture
    graph is high-confidence with only imports/defines edges)."""
    (tmp_path / "s.py").write_text("def load(x):\n    return pickle.loads(x)\n")
    no_calls = _doc(
        [_n("ld", "load", "s.py", 1), _n("o", "other", "o.py", 1)],
        [Edge(src="o", dst="ld", kind="imports")],  # not a calls edge
    )
    db = _db(tmp_path)
    _add_sink_backward_tasks(_ctx_with_graph(tmp_path, GraphQuery(no_calls, tmp_path)), db)
    assert _sink_backward(db) == []
    db.close()
