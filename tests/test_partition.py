"""Offline tests for feature F2 — union-find call-graph partitioning.

Covers `audit.partition.partition_files` (the union-find grouping utility)
and its wiring into `audit.catchall.build_catchall_tasks` via the new
`graph=` parameter.

THE mandatory property under test is the RECALL GUARDRAIL: partitioning only
REORGANIZES files into cohesive groups keyed off call-graph connectivity —
it never drops, duplicates, or invents one. Every test that builds a graph
also asserts this invariant directly; `test_invariant_*` pins it as its own
dedicated test, with and without a graph.

All tests are OFFLINE: GraphDocument/GraphQuery are hand-built from dicts
(mirrors tests/test_sink_backward.py, tests/test_taint.py). No files are
written, no graphify call, no network.
"""

from __future__ import annotations

from vash.catchall import build_catchall_tasks
from vash.graph.query import GraphQuery
from vash.graph.schema import SCHEMA_VERSION, Edge, GraphDocument, Node
from vash.partition import partition_files

# ---- hand-built graph helpers (mirrors test_sink_backward.py) -------------


def _n(nid: str, name: str, file: str, line: int, lang: str = "python") -> Node:
    return Node(id=nid, kind="function", name=name, file=file, line=line,
                qualified_name=f"{file}:{name}", language=lang)


def _doc(nodes, edges, *, confidence: str = "high", backend: str = "ast") -> GraphDocument:
    return GraphDocument(
        schema_version=SCHEMA_VERSION, graphify_version="0.8.51", generated_at="",
        backend=backend, confidence=confidence, content_hash="", root_dir="/repo",
        nodes={n.id: n for n in nodes}, edges=edges,
    )


# ---- connectivity -----------------------------------------------------------


def test_connectivity_calls_join_one_partition_disconnected_stays_separate() -> None:
    """A calls B -> a.py and b.py land in one partition; c.py (no edges) is
    separate from that partition."""
    doc = _doc(
        [_n("a", "func_a", "a.py", 1), _n("b", "func_b", "b.py", 1),
         _n("c", "func_c", "c.py", 1)],
        [Edge(src="a", dst="b", kind="calls")],
    )
    gq = GraphQuery(doc)
    partitions = partition_files(["a.py", "b.py", "c.py"], gq)
    sets = [set(p) for p in partitions]
    assert {"a.py", "b.py"} in sets
    assert not any("c.py" in s and "a.py" in s for s in sets)


def test_connectivity_ignores_non_calls_edges() -> None:
    """An `imports` edge between dira/a.py and dirb/b.py must NOT union
    them — only `calls` edges drive connectivity. Distinct directories so
    the singleton dir-fallback can't coincidentally cluster them together
    and mask a bug (unlike two root-level files, which would always share
    dirkey ".")."""
    doc = _doc(
        [_n("a", "func_a", "dira/a.py", 1), _n("b", "func_b", "dirb/b.py", 1)],
        [Edge(src="a", dst="b", kind="imports")],
    )
    gq = GraphQuery(doc)
    partitions = partition_files(["dira/a.py", "dirb/b.py"], gq)
    sets = [set(p) for p in partitions]
    assert {"dira/a.py", "dirb/b.py"} not in sets
    assert {"dira/a.py"} in sets
    assert {"dirb/b.py"} in sets


# ---- INVARIANT (the mandatory recall guardrail) ----------------------------


def test_invariant_no_drop_no_dup_no_invent_with_graph() -> None:
    """The graph knows about a file (z.py) OUTSIDE the requested `files` --
    partition_files must never invent it into the output, drop a requested
    file, or duplicate one."""
    files = ["a.py", "b.py", "c.py", "d.py", "e.py"]
    doc = _doc(
        [_n("a", "fa", "a.py", 1), _n("b", "fb", "b.py", 1), _n("c", "fc", "c.py", 1),
         _n("d", "fd", "d.py", 1), _n("z", "fz", "z.py", 1)],
        [Edge(src="a", dst="b", kind="calls"), Edge(src="c", dst="d", kind="calls"),
         Edge(src="d", dst="z", kind="calls")],  # z.py reachable but NOT requested
    )
    gq = GraphQuery(doc)
    partitions = partition_files(files, gq)
    flat = [f for p in partitions for f in p]
    assert sorted(flat) == sorted(files)   # no drop, no invention
    assert len(flat) == len(set(flat))     # no duplication
    assert "z.py" not in flat


def test_invariant_no_drop_no_dup_no_invent_without_graph() -> None:
    files = ["pkg/a.py", "pkg/sub/b.py", "other/c.py", "d.py", "pkg/e.py"]
    partitions = partition_files(files, None)
    flat = [f for p in partitions for f in p]
    assert sorted(flat) == sorted(files)
    assert len(flat) == len(set(flat))


def test_invariant_holds_for_empty_input() -> None:
    assert partition_files([], None) == []
    assert partition_files([], GraphQuery(_doc([], []))) == []


# ---- oversize split ---------------------------------------------------------


def test_oversize_component_split_preserves_every_file() -> None:
    n = 30
    files = [f"pkg/mod{i}.py" for i in range(n)]
    nodes = [_n(f"n{i}", f"f{i}", files[i], 1) for i in range(n)]
    # Chain n0->n1->n2->... so the whole set is ONE connected component.
    edges = [Edge(src=f"n{i}", dst=f"n{i + 1}", kind="calls") for i in range(n - 1)]
    gq = GraphQuery(_doc(nodes, edges))

    partitions = partition_files(files, gq, max_partition_size=10)

    assert len(partitions) == 3  # 30 files / 10-per-partition
    assert all(len(p) <= 10 for p in partitions)
    flat = [f for p in partitions for f in p]
    assert sorted(flat) == sorted(files)
    assert len(flat) == len(set(flat))


def test_oversize_dir_fallback_split_preserves_every_file() -> None:
    files = [f"pkg/mod{i}.py" for i in range(12)]
    partitions = partition_files(files, None, max_partition_size=5)
    assert len(partitions) == 3  # 5 + 5 + 2
    assert [len(p) for p in partitions] == [5, 5, 2]
    flat = [f for p in partitions for f in p]
    assert sorted(flat) == sorted(files)


# ---- singleton clustering ----------------------------------------------------


def test_singleton_clustering_graph_none_reproduces_f6_dirkey_grouping() -> None:
    """graph=None: pure top-2-directory grouping, identical to F6's original
    `_dirkey` grouping (alphabetical dirkey order; "other" < "pkg")."""
    files = ["pkg/a.py", "pkg/b.py", "other/c.py"]
    partitions = partition_files(files, None, max_partition_size=25)
    assert partitions == [["other/c.py"], ["pkg/a.py", "pkg/b.py"]]


def test_singleton_clustering_with_graph_but_no_edges_matches_dir_fallback() -> None:
    """A graph is present but has zero `calls` edges among these files -> every
    file is a call-graph singleton -> falls back to the SAME dir-clustering as
    graph=None."""
    files = ["pkg/a.py", "pkg/b.py", "other/c.py"]
    nodes = [_n("a", "fa", "pkg/a.py", 1), _n("b", "fb", "pkg/b.py", 1),
             _n("c", "fc", "other/c.py", 1)]
    gq = GraphQuery(_doc(nodes, []))

    with_graph = partition_files(files, gq, max_partition_size=25)
    without_graph = partition_files(files, None, max_partition_size=25)

    assert with_graph == without_graph == [["other/c.py"], ["pkg/a.py", "pkg/b.py"]]


# ---- coverage-preservation in catchall (grouping differs, coverage doesn't) --


def test_catchall_coverage_preserved_with_and_without_graph() -> None:
    """web/handlers.py -> web/service.py -> db/dao.py forms one call chain
    that crosses top-level directories. With a graph, the catch-all task
    grouping should reflect that cohesion; without one, it falls back to pure
    directory grouping. Either way, EVERY eligible file still gets covered by
    exactly one task — F2 changes grouping, never coverage."""
    files = ["web/handlers.py", "web/service.py", "db/dao.py", "util/helpers.py"]
    nodes = [
        _n("h", "handler", "web/handlers.py", 1),
        _n("s", "service", "web/service.py", 1),
        _n("d", "query", "db/dao.py", 1),
    ]
    edges = [
        Edge(src="h", dst="s", kind="calls"),
        Edge(src="s", dst="d", kind="calls"),  # cross-directory link web -> db
    ]
    gq = GraphQuery(_doc(nodes, edges))

    tasks_g, dropped_g = build_catchall_tasks(files, covered_files=[], graph=gq)
    tasks_none, dropped_none = build_catchall_tasks(files, covered_files=[], graph=None)

    files_g = sorted(f for t in tasks_g for f in t["target_files"])
    files_none = sorted(f for t in tasks_none for f in t["target_files"])
    assert files_g == files_none == sorted(files)
    assert dropped_g == dropped_none == 0

    # Grouping DIFFERS: only with the graph do handlers.py and dao.py (linked
    # transitively through service.py) land in the same task, despite living
    # under different top-level directories.
    def _same_task(tasks) -> bool:
        return any(
            "web/handlers.py" in t["target_files"] and "db/dao.py" in t["target_files"]
            for t in tasks
        )

    assert _same_task(tasks_g) is True
    assert _same_task(tasks_none) is False


def test_build_catchall_tasks_graph_param_defaults_to_none() -> None:
    """No graph= passed at all -> identical to F6's pre-F2 behavior."""
    tasks, dropped = build_catchall_tasks(["a.py", "b.py"], covered_files=[])
    assert dropped == 0
    assert len(tasks) == 1
    assert set(tasks[0]["target_files"]) == {"a.py", "b.py"}
