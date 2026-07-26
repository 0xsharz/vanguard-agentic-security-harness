"""Deterministic graph neighbor-context block-builders (feature V6).

Composes the existing `audit.graph.query.GraphQuery` primitives
(`context_for_file`, `callers_of`, `callees_of`, `blast_radius`,
`symbol_at_line`, `status`) into small, bounded JSON blocks that get
injected into the Hunt and Validate stage inputs. This module adds no new
graph logic — it is pure composition/aggregation over primitives that
already exist.

Fail-open by construction: every function here returns `{}` (never raises)
when `gq` is None or nothing resolves, so callers can inject the result
additively without a try/except at the call site:

    gq = ctx.graph()
    gc = neighbors_for_files(gq, task.target_files) if gq else {}
    if gc:
        user_input["graph_context"] = gc

No file reads, no execution — every list returned is deduped, sorted for
determinism, and capped at `cap`.
"""

from __future__ import annotations

from typing import Iterable


def _capped_sorted(items: Iterable[str], cap: int) -> list[str]:
    """Dedup, sort (deterministic order — never raw set iteration order),
    and bound to `cap` entries."""
    return sorted(set(items))[:cap]


def neighbors_for_files(gq, files: Iterable[str], *, cap: int = 20) -> dict:
    """Deterministic caller/callee/import neighbors for a set of target files.

    For each file, gathers the callers and callees of every symbol the graph
    says is defined in that file (from `context_for_file`'s `nodes`), plus
    the file's own `imports`/`importers`. Every list is deduped, sorted, and
    capped at `cap`. Files the graph has no nodes for are skipped.

    Returns ``{"files": {file: {"callers", "callees", "imports",
    "importers"}}, "confidence": ...}``, or ``{}`` when `gq` is None or no
    file resolves anything. Never raises.
    """
    if gq is None:
        return {}
    try:
        out_files: dict[str, dict] = {}
        for file in files:
            try:
                fctx = gq.context_for_file(file)
            except Exception:
                continue
            names = fctx.get("nodes") or []
            if not names:
                continue  # no graph nodes for this file -> nothing to add
            callers: set[str] = set()
            callees: set[str] = set()
            for name in names:
                symbol = f"{file}:{name}"
                callers.update(gq.callers_of(symbol))
                callees.update(gq.callees_of(symbol))
            out_files[file] = {
                "callers": _capped_sorted(callers, cap),
                "callees": _capped_sorted(callees, cap),
                "imports": _capped_sorted(fctx.get("imports") or [], cap),
                "importers": _capped_sorted(fctx.get("importers") or [], cap),
            }
        if not out_files:
            return {}
        return {"files": out_files, "confidence": gq.status()["confidence"]}
    except Exception:
        return {}


def neighbors_for_finding(gq, file: str, line: int, *, cap: int = 20) -> dict:
    """Deterministic callers/callees/blast-radius for the symbol enclosing a
    finding's `file:line` location.

    Callers answer "does an upstream caller sanitize?"; callees answer "does
    the sink escape internally?"; `reachable_files` is the finding's blast
    radius (capped) — the same questions Validate's method already asks,
    minus the manual code-reading step to find candidates.

    Returns ``{"symbol", "callers", "callees", "reachable_files",
    "confidence"}``, or ``{}`` when `gq` is None, the location resolves to no
    symbol, or anything else fails. Never raises.
    """
    if gq is None:
        return {}
    try:
        node_id = gq.symbol_at_line(file, line)
        if not node_id:
            return {}
        node = gq._doc.nodes.get(node_id)
        name = node.name if node else node_id
        callers = gq.callers_of(node_id)
        callees = gq.callees_of(node_id)
        reachable = gq.blast_radius(file).get("reachable_files") or []
        confidence = gq.status()["confidence"]
    except Exception:
        return {}
    return {
        "symbol": name,
        "callers": _capped_sorted(callers, cap),
        "callees": _capped_sorted(callees, cap),
        "reachable_files": _capped_sorted(reachable, cap),
        "confidence": confidence,
    }
