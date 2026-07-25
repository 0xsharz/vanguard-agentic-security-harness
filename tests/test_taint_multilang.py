"""Offline tests for the language-parametric taint sink registry (Task 3 of
the 2026-07-26 multilang provisioning plan).

Covers the new JS/TS, Java, and Go sink tables + `SINKS_BY_LANG` registry, and
a `find_sinks` integration test proving the language-parametric file scan
picks the right table per file — including a regression guard that a
Python-only graph's `find_sinks` output is unchanged.

All tests are OFFLINE: GraphDocument/GraphQuery are hand-built from dicts
(mirroring tests/test_taint.py's fixture helpers), tmp repos are written and
only read statically. NEVER calls graphify, NEVER executes target code, NO
network.
"""

from __future__ import annotations

from pathlib import Path

from vash.graph.query import GraphQuery
from vash.graph.schema import SCHEMA_VERSION, GraphDocument, Node
from vash.taint import (
    GO_SINKS,
    JAVA_SINKS,
    JAVASCRIPT_SINKS,
    PYTHON_SINKS,
    SINKS_BY_LANG,
    find_sinks,
)


def _matches(table, cls, line):
    return any(p.search(line) for p in table[cls])


def test_registry_maps_languages():
    assert SINKS_BY_LANG["python"] is PYTHON_SINKS
    assert SINKS_BY_LANG["javascript"] is JAVASCRIPT_SINKS
    assert SINKS_BY_LANG["typescript"] is JAVASCRIPT_SINKS
    assert SINKS_BY_LANG["java"] is JAVA_SINKS
    assert SINKS_BY_LANG["go"] is GO_SINKS


def test_js_sinks():
    assert _matches(JAVASCRIPT_SINKS, "command_injection",
                    "child_process.exec(userInput)")
    assert _matches(JAVASCRIPT_SINKS, "code_injection", "eval(req.body.x)")
    assert _matches(JAVASCRIPT_SINKS, "ssrf", "axios.get(url)")


def test_java_sinks():
    assert _matches(JAVA_SINKS, "command_injection",
                    "Runtime.getRuntime().exec(cmd)")
    assert _matches(JAVA_SINKS, "deserialization",
                    "new ObjectInputStream(in).readObject()")
    assert _matches(JAVA_SINKS, "ssrf",
                    "HttpURLConnection c = (HttpURLConnection) new URL(u).openConnection();")


def test_go_sinks():
    assert _matches(GO_SINKS, "command_injection", 'exec.Command("sh", "-c", x)')
    assert _matches(GO_SINKS, "ssrf", "http.Get(url)")
    assert _matches(GO_SINKS, "sql_injection", 'db.Query(fmt.Sprintf("...%s", x))')


def test_all_class_keys_are_known():
    known = {"command_injection", "code_injection", "sql_injection", "ssrf",
             "path_traversal", "deserialization", "ssti", "xxe",
             "prototype_pollution", "jndi_injection"}
    for table in (JAVASCRIPT_SINKS, JAVA_SINKS, GO_SINKS):
        assert set(table).issubset(known)


# ---- find_sinks integration: language-parametric file scan ----------------
#
# Hand-built graph helpers mirroring tests/test_taint.py's `_n`/`_doc` (kept
# in sync deliberately — see that file for the canonical versions).


def _n(nid: str, name: str, file: str, line: int, lang: str = "python") -> Node:
    return Node(id=nid, kind="function", name=name, file=file, line=line,
                qualified_name=f"{file}:{name}", language=lang)


def _doc(nodes, edges, *, confidence: str = "high", backend: str = "ast") -> GraphDocument:
    return GraphDocument(
        schema_version=SCHEMA_VERSION, graphify_version="0.8.51", generated_at="",
        backend=backend, confidence=confidence, content_hash="", root_dir="/repo",
        nodes={n.id: n for n in nodes}, edges=edges,
    )


def test_find_sinks_matches_java_file(tmp_path: Path) -> None:
    """A Java file with a Runtime.exec() call yields a command_injection Sink,
    proving find_sinks selects JAVA_SINKS for a `lang="java"` graph node."""
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "Main.java").write_text(
        "class Main {\n"
        "    void run(String x) {\n"
        "        Runtime.getRuntime().exec(x);\n"
        "    }\n"
        "}\n"
    )
    doc = _doc(
        [_n("n_run", "run", "svc/Main.java", 2, lang="java")],
        [],
    )
    gq = GraphQuery(doc, tmp_path)
    sinks = find_sinks(tmp_path, gq)

    assert len(sinks) == 1
    sink = sinks[0]
    assert sink.file == "svc/Main.java"
    assert sink.attack_class == "command_injection"
    assert sink.symbol_id == "n_run"


def test_find_sinks_python_only_repo_unchanged(tmp_path: Path) -> None:
    """Regression guard: a Python-only graph's find_sinks output is identical
    to the pre-refactor behavior (subprocess.run -> command_injection)."""
    (tmp_path / "sinks.py").write_text(
        "def run_cmd(x):\n"
        "    subprocess.run(x, shell=True)\n"
    )
    doc = _doc([_n("n_run", "run_cmd", "sinks.py", 1)], [])
    gq = GraphQuery(doc, tmp_path)
    sinks = find_sinks(tmp_path, gq)

    assert len(sinks) == 1
    sink = sinks[0]
    assert sink.file == "sinks.py"
    assert sink.attack_class == "command_injection"
    assert sink.symbol_id == "n_run"
