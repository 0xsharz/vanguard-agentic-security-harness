"""Deterministic entry→sink taint chunking (feature V8).

Recon's LLM only hunts what it *thinks* to hunt. This module makes coverage
deterministic: for every attacker-controllable input F1 already enumerated,
walk the real call graph (``audit.graph``) to every dangerous sink and emit ONE
narrowly-scoped Hunt task per reachable ``(input → sink)`` path — so the Hunter
always sees source AND sink together, the precondition for a confirmed
data-flow finding.

Composition:
  - F1 inputs (``db.get_inputs``)                    → taint *entries*
  - ``PYTHON_SINKS`` regex table (curated here)      → dangerous *sinks*
  - ``GraphQuery.taint_paths`` (ported BFS)           → reachability

Everything here is STATIC: files are read (utf-8, ``errors="replace"``) but the
target's code is NEVER executed. The sink table below is the one genuinely new
artifact — no donor ships a portable Python sink table, so it is authored from
real dangerous Python APIs plus the attack classes named in
``schemas/hunt_task.schema.json``. The BFS is ported; the rest is thin glue.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cost / any cycle — used only for type hints
    from audit.graph.query import GraphQuery


# ---------------------------------------------------------------------------
# Curated Python sink table (AUTHORED — the one genuinely new artifact).
#
# A few high-signal patterns per class beats exhaustive noise. Keys are the
# attack_class strings the hunt_task schema documents. Patterns are matched
# line-by-line against statically-read source; first matching class per line
# wins (so one dangerous line yields at most one sink).
# ---------------------------------------------------------------------------
PYTHON_SINKS: dict[str, list[re.Pattern]] = {
    "command_injection": [
        re.compile(p)
        for p in (
            r"subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(",
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"os\.exec[lv]\w*\s*\(",
            r"os\.spawn\w*\s*\(",
            r"commands\.get(?:output|status)\w*\s*\(",
            r"\bshell\s*=\s*True\b",
            r"pty\.spawn\s*\(",
        )
    ],
    "code_injection": [
        re.compile(p)
        for p in (
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
            r"__import__\s*\(",
            r"types\.FunctionType\s*\(",
        )
    ],
    "deserialization": [
        re.compile(p)
        for p in (
            r"(?:c|_)?[pP]ickle\.loads?\s*\(",
            r"yaml\.load\s*\((?![^)]*Loader\s*=)",
            r"marshal\.loads?\s*\(",
            r"dill\.loads?\s*\(",
            r"jsonpickle\.(?:decode|loads)\s*\(",
            r"shelve\.open\s*\(",
        )
    ],
    "path_traversal": [
        re.compile(p)
        for p in (
            r"\bopen\s*\(",
            r"os\.path\.join\s*\(",
            r"shutil\.(?:copy\w*|move|rmtree)\s*\(",
            r"\bsend_file\s*\(",
            r"send_from_directory\s*\(",
            r"os\.(?:remove|unlink)\s*\(",
            r"\bPath\s*\(",
        )
    ],
    "ssrf": [
        re.compile(p)
        for p in (
            r"requests\.(?:get|post|put|delete|head|patch|request)\s*\(",
            r"urllib\.request\.urlopen\s*\(",
            r"\burlopen\s*\(",
            r"httpx\.(?:get|post|put|delete|request|Client|AsyncClient)\s*\(",
            r"aiohttp\.(?:ClientSession|request)\b",
            r"socket\.(?:connect|create_connection)\s*\(",
        )
    ],
    "sql_injection": [
        re.compile(p)
        for p in (
            r"\.execute(?:many|script)?\s*\(",
            r"session\.execute\s*\(",
            r"\btext\s*\(",
            r"\.raw\s*\(",
        )
    ],
    "xxe": [
        re.compile(p)
        for p in (
            r"etree\.(?:parse|fromstring|XML)\s*\(",
            r"\blxml\b",
            r"xml\.dom\.minidom\b",
            r"\bxmlrpc\b",
            r"\bpulldom\b",
            r"sax\.(?:parse|parseString)\s*\(",
        )
    ],
    "ssti": [
        re.compile(p)
        for p in (
            r"\bTemplate\s*\(",
            r"render_template_string\s*\(",
            r"\.from_string\s*\(",
            r"\bEnvironment\s*\(",
        )
    ],
    "open_redirect": [
        re.compile(p)
        for p in (
            r"\bredirect\s*\(",
            r"HttpResponseRedirect\s*\(",
        )
    ],
    "log_injection": [
        re.compile(p)
        for p in (
            r"log(?:ging|ger)?\.(?:info|warning|warn|error|debug|critical|exception)\s*\([^)]*%",
        )
    ],
}


@dataclass(frozen=True)
class Sink:
    file: str
    line: int
    symbol_id: str
    attack_class: str


@dataclass(frozen=True)
class Entry:
    file: str
    line: int
    symbol_id: str
    trust_level: str


def _split_location(location: str | None) -> tuple[str, int]:
    """Split an F1 ``location`` ("file:line" / "file:line:col" / "file") into
    ``(file, line)``. Line defaults to 0 when absent."""
    loc = (location or "").strip()
    if not loc:
        return "", 0
    parts = loc.split(":")
    # Drop a trailing column ("file:line:col") so we key on the line.
    if len(parts) >= 3 and parts[-1].strip().isdigit() and parts[-2].strip().isdigit():
        parts = parts[:-1]
    if len(parts) >= 2 and parts[-1].strip().isdigit():
        return ":".join(parts[:-1]).strip(), int(parts[-1].strip())
    return loc, 0


def _python_files(graph: "GraphQuery") -> list[str]:
    """The graph's known Python source files (by extension or node language)."""
    files: list[str] = []
    for f, nids in graph._by_file.items():
        if f.endswith(".py") or any(
            graph._doc.nodes[nid].language == "python" for nid in nids
        ):
            files.append(f)
    return sorted(files)


def _read_static(repo_path: Path, rel_file: str) -> str | None:
    """Read a source file statically. NEVER executes it. None on any OSError."""
    try:
        return (Path(repo_path) / rel_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def find_sinks(repo_path: Path, graph: "GraphQuery") -> list[Sink]:
    """Scan the graph's Python files for dangerous-API lines, tagging each with
    its attack class and enclosing symbol.

    Deterministic and static-only: reads each file (utf-8, ``errors="replace"``)
    and, for every line matching a ``PYTHON_SINKS`` pattern, resolves the
    enclosing symbol via ``graph.symbol_at_line``. Lines whose symbol does not
    resolve are skipped. First matching class per line wins.
    """
    sinks: list[Sink] = []
    for rel_file in _python_files(graph):
        text = _read_static(repo_path, rel_file)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for attack_class, patterns in PYTHON_SINKS.items():
                if any(pat.search(line) for pat in patterns):
                    symbol_id = graph.symbol_at_line(rel_file, lineno)
                    if symbol_id:
                        sinks.append(Sink(rel_file, lineno, symbol_id, attack_class))
                    break  # one class per line
    return sinks


def _node_file(graph: "GraphQuery", node_id: str) -> str | None:
    node = graph._doc.nodes.get(node_id)
    return node.file if node else None


def _node_label(graph: "GraphQuery", node_id: str) -> str:
    node = graph._doc.nodes.get(node_id)
    return node.name if node else node_id


def _target_files(
    graph: "GraphQuery", path: list[str], entry: Entry, sink: Sink
) -> list[str]:
    """Unique, order-preserved files along the flow (entry → path → sink),
    keeping only files that exist in the graph."""
    files: list[str] = []

    def add(f: str | None) -> None:
        if f and f not in files and f in graph._by_file:
            files.append(f)

    add(entry.file)
    for nid in path:
        add(_node_file(graph, nid))
    add(sink.file)
    return files


def build_taint_tasks(
    graph: "GraphQuery",
    inputs: list[dict],
    repo_path: Path,
    *,
    max_tasks: int = 40,
    max_hops: int = 8,
) -> list[dict]:
    """Emit one ``hunt_task`` dict per reachable ``(input → sink)`` call-graph
    path. Never raises for empty/degenerate input — returns ``[]``.

    Steps (per the V8 brief):
      1. Resolve each F1 input's ``location`` to an entry symbol; keep resolved.
      2. Scan for sinks (``find_sinks``); index by enclosing symbol id.
      3. Multi-source BFS (``graph.taint_paths``) entries → sinks.
      4. Emit a priority-1 ``source="taint"`` hunt_task per (sink, path),
         dedup by ``(entry_symbol, sink_id, frozenset(target_files))``, cap at
         ``max_tasks``.
    """
    # 1. entries
    entry_by_id: dict[str, tuple[dict, Entry]] = {}
    entry_ids: list[str] = []
    for inp in inputs:
        file, line = _split_location(inp.get("location"))
        if not file:
            continue
        symbol_id = graph.symbol_at_line(file, line)
        if not symbol_id:
            continue
        if symbol_id not in entry_by_id:
            entry_by_id[symbol_id] = (
                inp,
                Entry(file, line, symbol_id, inp.get("trust_level") or "unknown"),
            )
            entry_ids.append(symbol_id)
    if not entry_ids:
        return []

    # 2. sinks
    sinks = find_sinks(repo_path, graph)
    if not sinks:
        return []
    sinks_by_id: dict[str, list[Sink]] = defaultdict(list)
    for s in sinks:
        sinks_by_id[s.symbol_id].append(s)

    # 3. reachability (ported BFS)
    paths = graph.taint_paths(entry_ids, list(sinks_by_id.keys()), max_hops)

    # 4. emit
    tasks: list[dict] = []
    seen: set[tuple[str, str, frozenset]] = set()
    for sink_id, path in paths:
        start = path[0]
        entry_pair = entry_by_id.get(start)
        if entry_pair is None:
            continue
        inp, entry = entry_pair
        for sink in sinks_by_id.get(sink_id, []):
            target_files = _target_files(graph, path, entry, sink)
            if not target_files:
                continue
            key = (entry.symbol_id, sink_id, frozenset(target_files))
            if key in seen:
                continue
            seen.add(key)
            tasks.append(
                _emit_task(len(tasks) + 1, graph, inp, entry, sink, path, target_files)
            )
            if len(tasks) >= max_tasks:
                return tasks
    return tasks


def _emit_task(
    n: int,
    graph: "GraphQuery",
    inp: dict,
    entry: Entry,
    sink: Sink,
    path: list[str],
    target_files: list[str],
) -> dict:
    sink_name = _node_label(graph, sink.symbol_id)
    chain = " -> ".join(_node_label(graph, nid) for nid in path)
    iid = inp.get("id") or inp.get("input_id") or "input"
    return {
        "task_id": f"t_taint_{n:02d}",
        "source": "taint",
        "attack_class": sink.attack_class,
        "target_files": target_files,
        "scope_hint": (
            f"{entry.trust_level} input at {entry.file}:{entry.line} reaches "
            f"{sink.attack_class} sink {sink_name}() at {sink.file}:{sink.line} "
            f"via {chain}. Verify every hop for sanitization; if none, exploitable."
        ),
        "rationale": (
            f"Deterministic call-graph path from attacker-controllable input "
            f"{iid} ({entry.file}:{entry.line}) to a {sink.attack_class} sink at "
            f"{sink.file}:{sink.line}. F1 marks this input attacker-controllable; "
            f"this reachable flow is the precondition for a confirmed data-flow finding."
        ),
        "priority": 1,
    }
