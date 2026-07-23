"""Union-find call-graph partitioning for cohesive catch-all tasks (feature F2).

F6's catch-all coverage sweep (``audit.catchall``) groups uncovered files by
top-2-directory prefix — arbitrary with respect to how the code actually
calls itself. This module groups by **call-graph connectivity** instead:
files whose functions call each other land in the same partition, so a
catch-all Hunt task sees a coherent slice (source AND sink together) rather
than an arbitrary directory grab-bag. Directory grouping survives as the
fallback for files the graph can't connect (no ``graph`` supplied, or a file
with no ``calls`` edge to any peer in the requested set).

RECALL GUARDRAIL: ``partition_files`` only REORGANIZES ``files`` into
groups — it never drops, duplicates, or invents one. ``tests/test_partition.py``
pins this invariant directly; ``audit.catchall.build_catchall_tasks`` depends
on it to keep F6's completeness guarantee intact when F2 changes its grouping.

Reference: adapted from VVAH's ``_cohesive_groups`` idea
(visa-harness/vvaharness/pipeline/stages/s3_decompose.py L215-259 — call-graph
connected components + directory fallback). Reimplemented here as a clean
union-find over ``audit.graph.query.GraphQuery``'s ``calls`` edges rather than
porting VVAH's DFS-over-global-adjacency; VVAH's donor also has a first pass
over an agentic ``ctx.modules`` grouping that audit has no equivalent of, so
that step is dropped.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cost / any cycle — used only for type hints
    from audit.graph.query import GraphQuery


def _dirkey(rel: str) -> str:
    """Top-2-directory prefix, e.g. "pkg/sub" for "pkg/sub/deep/file.py".

    Replicated (not imported) from ``audit.catchall._dirkey``: importing it
    from here would make ``audit.catchall`` <-> ``audit.partition`` a cycle,
    since ``catchall`` imports ``partition_files`` from this module.
    """
    parts = Path(rel).parts[:-1]
    return "/".join(parts[:2]) if parts else "."


def _find(parent: dict[str, str], x: str) -> str:
    """Union-find `find` with path compression."""
    root = x
    while parent[root] != root:
        root = parent[root]
    while parent[x] != root:
        parent[x], x = root, parent[x]
    return root


def _union(parent: dict[str, str], a: str, b: str) -> None:
    ra, rb = _find(parent, a), _find(parent, b)
    if ra != rb:
        parent[rb] = ra


def _node_file(graph: "GraphQuery", node_id: str) -> str | None:
    node = graph._doc.nodes.get(node_id)
    return node.file if node is not None else None


def _dir_grouped(files: list[str]) -> list[list[str]]:
    """Pure top-2-directory grouping — F6's original algorithm, verbatim.
    Used both as the ``graph=None`` fallback and to cluster call-graph
    singletons so they don't explode into hundreds of 1-file partitions."""
    groups: dict[str, list[str]] = {}
    for f in sorted(files, key=_dirkey):
        groups.setdefault(_dirkey(f), []).append(f)
    return list(groups.values())


def _split_oversize(groups: list[list[str]], max_partition_size: int) -> list[list[str]]:
    """Split any partition with more than ``max_partition_size`` files into
    consecutive, stably-ordered chunks. Every file is preserved."""
    partitions: list[list[str]] = []
    for g in groups:
        for i in range(0, len(g), max_partition_size):
            partitions.append(g[i:i + max_partition_size])
    return partitions


def partition_files(
    files: list[str],
    graph: "GraphQuery | None" = None,
    *,
    max_partition_size: int = 25,
) -> list[list[str]]:
    """Group `files` into cohesive partitions by call-graph connectivity
    (union-find over `calls` edges). Files whose functions call each other
    land together; files with no call relationship to others form their own
    (or dir-clustered) partition. Oversized partitions are split into chunks
    of <= max_partition_size, preserving every file.

    RECALL GUARDRAIL (INVARIANT): the multiset union of all returned
    partitions == set(files) exactly — no file is dropped, duplicated, or
    invented. Assert-tested in tests/test_partition.py.

    When `graph` is None, degrades to pure top-2-directory grouping (F6's
    original, pre-F2 behavior).
    """
    files = list(files)
    if graph is None:
        return _split_oversize(_dir_grouped(files), max_partition_size)

    parent = {f: f for f in files}
    for src_id, edges in graph._out_edges.items():
        fa = _node_file(graph, src_id)
        if fa is None or fa not in parent:
            continue
        for dst_id, kind in edges:
            if kind != "calls":
                continue
            fb = _node_file(graph, dst_id)
            if fb is None or fb not in parent or fb == fa:
                continue
            _union(parent, fa, fb)

    components: dict[str, list[str]] = {}
    for f in files:
        components.setdefault(_find(parent, f), []).append(f)

    real_components: list[list[str]] = []
    singletons: list[str] = []
    for members in components.values():
        if len(members) == 1:
            singletons.append(members[0])
        else:
            real_components.append(sorted(members))

    # Combine call-graph components with dir-clustered singletons, then sort
    # by full sorted content — deterministic regardless of edge-visitation or
    # union-find root-assignment order (neither affects group MEMBERSHIP, but
    # either could affect which file a dict happens to key a component by).
    groups = real_components + _dir_grouped(singletons)
    groups.sort(key=lambda g: sorted(g))

    return _split_oversize(groups, max_partition_size)
