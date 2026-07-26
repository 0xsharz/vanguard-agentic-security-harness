"""Offline tests for feature V6 — deterministic graph neighbor-context
injected into Hunt + Validate.

Covers the block-builders (`audit.graph_context.neighbors_for_files` /
`neighbors_for_finding`), the memoized fail-open `StageContext.graph()`
accessor, and a wiring check that `run_hunt`/`run_validate` inject
`graph_context` into `user_input` additively (present when a graph resolves,
absent when it doesn't).

All tests are OFFLINE: GraphDocument/GraphQuery are hand-built from dicts
(same convention as tests/test_taint.py). NEVER calls graphify, NEVER
executes target code, NO network.
"""

from __future__ import annotations

from pathlib import Path

import vash.graph as graph_mod
import vash.stages.hunt as hunt_mod
import vash.stages.validate as validate_mod
from vash.config import load_config
from vash.graph.query import GraphQuery
from vash.graph.schema import SCHEMA_VERSION, Edge, GraphDocument, Node
from vash.graph_context import neighbors_for_files, neighbors_for_finding
from vash.runner import AgentResult
from vash.stages._common import StageContext
from vash.state import StateDB


# ---- hand-built graph helpers (same convention as tests/test_taint.py) ----


def _n(nid: str, name: str, file: str, line: int, lang: str = "python") -> Node:
    return Node(id=nid, kind="function", name=name, file=file, line=line,
                qualified_name=f"{file}:{name}", language=lang)


def _doc(nodes, edges, *, confidence: str = "high", backend: str = "ast") -> GraphDocument:
    return GraphDocument(
        schema_version=SCHEMA_VERSION, graphify_version="0.8.51", generated_at="",
        backend=backend, confidence=confidence, content_hash="", root_dir="/repo",
        nodes={n.id: n for n in nodes}, edges=edges,
    )


def _ab_doc() -> GraphDocument:
    """a.py:A calls b.py:B; a.py also imports b.py."""
    return _doc(
        [_n("a.py:A", "A", "a.py", 1), _n("b.py:B", "B", "b.py", 1)],
        [
            Edge(src="a.py:A", dst="b.py:B", kind="calls"),
            Edge(src="a.py:A", dst="b.py:B", kind="imports"),
        ],
    )


def _many_callers_doc(n: int = 25) -> GraphDocument:
    """n distinct files each define a function that calls b.py:B."""
    nodes = [_n("b.py:B", "B", "b.py", 1)]
    edges = []
    for i in range(n):
        cid = f"c{i}.py:C{i}"
        nodes.append(_n(cid, f"C{i}", f"c{i}.py", 1))
        edges.append(Edge(src=cid, dst="b.py:B", kind="calls"))
    return _doc(nodes, edges)


# ---- neighbors_for_files ----------------------------------------------------


def test_neighbors_for_files_returns_callers_callees_imports_importers() -> None:
    gq = GraphQuery(_ab_doc())
    out = neighbors_for_files(gq, ["a.py", "b.py"])
    assert out["confidence"] == "high"
    a = out["files"]["a.py"]
    b = out["files"]["b.py"]
    assert a["callees"] == ["b.py:B"]
    assert a["imports"] == ["b.py:B"]
    assert a["callers"] == []
    assert b["callers"] == ["a.py:A"]
    assert b["importers"] == ["a.py:A"]
    assert b["callees"] == []


def test_neighbors_for_files_skips_files_with_no_nodes() -> None:
    gq = GraphQuery(_ab_doc())
    assert neighbors_for_files(gq, ["nonexistent.py"]) == {}


def test_neighbors_for_files_empty_when_files_list_empty() -> None:
    gq = GraphQuery(_ab_doc())
    assert neighbors_for_files(gq, []) == {}


def test_neighbors_for_files_returns_empty_for_none_graph() -> None:
    assert neighbors_for_files(None, ["a.py"]) == {}


def test_neighbors_for_files_caps_lists() -> None:
    gq = GraphQuery(_many_callers_doc(25))
    out = neighbors_for_files(gq, ["b.py"], cap=3)
    assert len(out["files"]["b.py"]["callers"]) == 3


def test_neighbors_for_files_default_cap_is_20() -> None:
    gq = GraphQuery(_many_callers_doc(25))
    out = neighbors_for_files(gq, ["b.py"])
    assert len(out["files"]["b.py"]["callers"]) == 20


# ---- neighbors_for_finding ---------------------------------------------------


def test_neighbors_for_finding_resolves_symbol_and_neighbors_at_a() -> None:
    gq = GraphQuery(_ab_doc())
    out = neighbors_for_finding(gq, "a.py", 1)
    assert out["symbol"] == "A"
    assert out["callees"] == ["b.py:B"]
    assert out["callers"] == []
    assert out["reachable_files"] == []  # nothing calls A
    assert out["confidence"] == "high"


def test_neighbors_for_finding_resolves_symbol_and_neighbors_at_b() -> None:
    gq = GraphQuery(_ab_doc())
    out = neighbors_for_finding(gq, "b.py", 1)
    assert out["symbol"] == "B"
    assert out["callers"] == ["a.py:A"]
    assert out["callees"] == []
    assert out["reachable_files"] == ["a.py"]  # a.py:A transitively reaches b.py


def test_neighbors_for_finding_no_symbol_at_line_returns_empty() -> None:
    gq = GraphQuery(_ab_doc())
    assert neighbors_for_finding(gq, "nonexistent.py", 1) == {}


def test_neighbors_for_finding_returns_empty_for_none_graph() -> None:
    assert neighbors_for_finding(None, "a.py", 1) == {}


def test_neighbors_for_finding_caps_callers() -> None:
    gq = GraphQuery(_many_callers_doc(25))
    out = neighbors_for_finding(gq, "b.py", 1, cap=3)
    assert len(out["callers"]) == 3


# ---- StageContext.graph() — memoized, fail-open -----------------------------


def test_stage_context_graph_memoizes(tmp_path: Path, monkeypatch) -> None:
    calls = {"n": 0}

    def fake_build_or_load(root, cache):
        calls["n"] += 1
        return _ab_doc()

    monkeypatch.setattr(graph_mod, "build_or_load", fake_build_or_load)
    ctx = StageContext(run_id="r", repo_path=tmp_path, config=load_config(),
                        graph_cache_path=tmp_path / "graph.json")
    g1 = ctx.graph()
    g2 = ctx.graph()
    assert g1 is not None
    assert g1 is g2
    assert calls["n"] == 1


def test_stage_context_graph_fail_open_on_build_error(tmp_path: Path, monkeypatch) -> None:
    def boom(root, cache):
        raise RuntimeError("graph build blew up")

    monkeypatch.setattr(graph_mod, "build_or_load", boom)
    ctx = StageContext(run_id="r", repo_path=tmp_path, config=load_config(),
                        graph_cache_path=tmp_path / "graph.json")
    assert ctx.graph() is None  # must not raise
    assert ctx.graph() is None  # memoized None on second call, still no raise


def test_stage_context_graph_returns_none_for_empty_graph(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(graph_mod, "build_or_load", lambda root, cache: _doc([], []))
    ctx = StageContext(run_id="r", repo_path=tmp_path, config=load_config(),
                        graph_cache_path=tmp_path / "graph.json")
    assert ctx.graph() is None


def test_stage_context_graph_uses_default_cache_path_when_unset(tmp_path: Path, monkeypatch) -> None:
    """When graph_cache_path is unset, graph() falls back to work_dir('graph')/graph.json
    and stores that path back onto the context."""
    monkeypatch.setattr(graph_mod, "build_or_load", lambda root, cache: _ab_doc())
    import vash.stages._common as common_mod
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")
    ctx = StageContext(run_id="r", repo_path=tmp_path, config=load_config())
    assert ctx.graph_cache_path is None
    g = ctx.graph()
    assert g is not None
    assert ctx.graph_cache_path == tmp_path / "work" / "r" / "graph" / "default" / "graph.json"


# ---- wiring: run_hunt / run_validate inject graph_context additively --------


async def _fake_run_agent_factory(captured: list[dict], payload: dict):
    async def fake_run_agent(*, user_input, artifact_dir, artifact_name, **_kwargs) -> AgentResult:
        captured.append(user_input)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{artifact_name}.jsonl"
        artifact_path.write_text("{}\n")
        return AgentResult(
            payload=payload,
            cost_usd=0.0, input_tokens=0, output_tokens=0,
            cache_read_tokens=0, cache_creation_tokens=0,
            num_turns=1, duration_ms=1, session_id="stub",
            artifact_path=artifact_path, repair_used=False,
            raw_result_message={},
        )
    return fake_run_agent


async def test_run_hunt_injects_graph_context_when_graph_resolves(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(graph_mod, "build_or_load", lambda root, cache: _ab_doc())
    captured: list[dict] = []
    monkeypatch.setattr(
        hunt_mod, "run_agent",
        await _fake_run_agent_factory(captured, {"findings": [], "gaps_observed": []}),
    )

    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        db.add_task("r1", {
            "task_id": "t1", "attack_class": "sql_injection", "scope_hint": "a.py",
            "target_files": ["a.py", "b.py"], "rationale": "x", "priority": 1,
        })
        ctx = StageContext(run_id="r1", repo_path=tmp_path, config=load_config(),
                            graph_cache_path=tmp_path / "graph.json")
        await hunt_mod.run_hunt(ctx, db)
    finally:
        db.close()

    assert len(captured) == 1
    assert "graph_context" in captured[0]
    assert captured[0]["graph_context"]["files"]


async def test_run_hunt_omits_graph_context_when_graph_absent(tmp_path: Path, monkeypatch) -> None:
    def boom(root, cache):
        raise RuntimeError("graph build blew up")

    monkeypatch.setattr(graph_mod, "build_or_load", boom)
    captured: list[dict] = []
    monkeypatch.setattr(
        hunt_mod, "run_agent",
        await _fake_run_agent_factory(captured, {"findings": [], "gaps_observed": []}),
    )

    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        db.add_task("r1", {
            "task_id": "t1", "attack_class": "sql_injection", "scope_hint": "a.py",
            "target_files": ["a.py"], "rationale": "x", "priority": 1,
        })
        ctx = StageContext(run_id="r1", repo_path=tmp_path, config=load_config(),
                            graph_cache_path=tmp_path / "graph.json")
        await hunt_mod.run_hunt(ctx, db)
    finally:
        db.close()

    assert len(captured) == 1
    assert "graph_context" not in captured[0]


async def test_run_validate_injects_graph_context_when_graph_resolves(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(graph_mod, "build_or_load", lambda root, cache: _ab_doc())
    captured: list[dict] = []
    monkeypatch.setattr(
        validate_mod, "run_agent",
        await _fake_run_agent_factory(captured, {"finding_id": "f1", "verdict": "rejected",
                                                  "rationale": "x", "validator_confidence": 0.5,
                                                  "alternative_explanation": "x"}),
    )

    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        db.add_task("r1", {
            "task_id": "t1", "attack_class": "sql_injection", "scope_hint": "b.py",
            "target_files": ["b.py"], "rationale": "x", "priority": 1,
        })
        db.add_finding("r1", "t1", {
            "finding_id": "f1", "file": "b.py", "line_start": 1, "line_end": 1,
            "vuln_class": "sql_injection", "severity": "high", "description": "d",
            "evidence_snippet": "e", "confidence": 0.9,
        })
        ctx = StageContext(run_id="r1", repo_path=tmp_path, config=load_config(),
                            graph_cache_path=tmp_path / "graph.json")
        await validate_mod.run_validate(ctx, db)
    finally:
        db.close()

    assert len(captured) == 1
    assert "graph_context" in captured[0]
    assert captured[0]["graph_context"]["symbol"] == "B"


async def test_run_validate_omits_graph_context_when_graph_absent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(graph_mod, "build_or_load", lambda root, cache: _doc([], []))
    captured: list[dict] = []
    monkeypatch.setattr(
        validate_mod, "run_agent",
        await _fake_run_agent_factory(captured, {"finding_id": "f1", "verdict": "rejected",
                                                  "rationale": "x", "validator_confidence": 0.5,
                                                  "alternative_explanation": "x"}),
    )

    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        db.add_task("r1", {
            "task_id": "t1", "attack_class": "sql_injection", "scope_hint": "b.py",
            "target_files": ["b.py"], "rationale": "x", "priority": 1,
        })
        db.add_finding("r1", "t1", {
            "finding_id": "f1", "file": "b.py", "line_start": 1, "line_end": 1,
            "vuln_class": "sql_injection", "severity": "high", "description": "d",
            "evidence_snippet": "e", "confidence": 0.9,
        })
        ctx = StageContext(run_id="r1", repo_path=tmp_path, config=load_config(),
                            graph_cache_path=tmp_path / "graph.json")
        await validate_mod.run_validate(ctx, db)
    finally:
        db.close()

    assert len(captured) == 1
    assert "graph_context" not in captured[0]
