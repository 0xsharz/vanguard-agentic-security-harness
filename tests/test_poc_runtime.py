"""Phase 3: per-language PoC run recipes + per-runtime observers.

Everything here is OFFLINE and never executes target code. The single
exception is the Python audit-hook observer, which is pure stdlib Python and
IS executed end-to-end (as a subprocess, on a throwaway script this test
writes itself) — it is the one observer we can honestly prove works without a
JVM / Node / strace / docker.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from vash.lang.hints import EXT_TO_LANG
from vash.lang.poc_runtime import (
    OBSERVER_DIR,
    RUNTIMES,
    Observer,
    Runtime,
    materialize_observer,
    poc_execution_block,
    runtime_for,
)

EXPECTED = {"python", "javascript", "typescript", "java", "go", "csharp"}


# ---- registry shape --------------------------------------------------------


def test_every_runtime_key_is_a_real_hints_language() -> None:
    # Guards against key drift: a Runtime keyed "js" or "node" would never be
    # selected, because detect_languages only ever emits EXT_TO_LANG values.
    assert set(RUNTIMES) <= set(EXT_TO_LANG.values())


def test_all_phase3_languages_are_covered() -> None:
    assert EXPECTED <= set(RUNTIMES)


def test_runtimes_are_frozen_dataclasses_with_a_matching_language() -> None:
    for key, rt in RUNTIMES.items():
        assert isinstance(rt, Runtime)
        assert rt.language == key
        assert rt.poc_filename and "/" not in rt.poc_filename
        assert rt.run_cmd.strip()
        assert rt.deps_hint.strip()
        with pytest.raises(Exception):
            rt.language = "nope"  # type: ignore[misc]


# ---- runtime_for -----------------------------------------------------------


@pytest.mark.parametrize("lang", sorted(EXPECTED))
def test_runtime_for_returns_the_matching_runtime(lang: str) -> None:
    rt = runtime_for([lang])
    assert rt is not None and rt.language == lang


def test_runtime_for_unknown_language_returns_none() -> None:
    assert runtime_for(["cobol"]) is None
    assert runtime_for([]) is None
    assert runtime_for(["web-template", "jcl"]) is None


def test_runtime_for_skips_unsupported_and_takes_the_first_supported() -> None:
    assert runtime_for(["web-template", "rust", "go", "python"]).language == "go"


def test_project_env_primary_language_wins_over_file_derived_list() -> None:
    rt = runtime_for(["python"], {"primary_language": "java"})
    assert rt is not None and rt.language == "java"


def test_project_env_without_a_usable_primary_language_falls_back() -> None:
    assert runtime_for(["go"], {"primary_language": "cobol"}).language == "go"
    assert runtime_for(["go"], {"primary_language": None}).language == "go"
    assert runtime_for(["go"], {}).language == "go"


# ---- observer contract -----------------------------------------------------


def _observers() -> list[tuple[str, Observer]]:
    return [(k, rt.observer) for k, rt in RUNTIMES.items() if rt.observer]


def test_every_observer_is_well_formed() -> None:
    seen = _observers()
    assert seen, "phase 3 must ship at least one observer"
    for lang, obs in seen:
        assert obs.name, lang
        assert obs.kind.strip(), lang
        assert "{cmd}" in obs.wrap, lang
        assert obs.evidence_markers, lang
        assert all(m.strip() for m in obs.evidence_markers), lang
        assert obs.available_check.strip(), lang
        assert obs.notes.strip(), lang


def test_every_wrap_is_a_usable_format_template() -> None:
    # The agent substitutes the run command into `wrap`; a stray brace (a JSON
    # literal, a shell ${} ) would raise instead of producing a command line.
    for lang, obs in _observers():
        rt = RUNTIMES[lang]
        line = obs.wrap.format(cmd=rt.run_cmd)
        assert rt.run_cmd in line, lang
        assert "{cmd}" not in line, lang


def test_observer_wraps_read_evidence_back_even_when_the_poc_fails() -> None:
    # A PoC that exits non-zero is still worth a trace, so the readback must
    # not hang off `&&`.
    jfr = RUNTIMES["java"].observer
    assert "; jfr print" in jfr.wrap and "&& jfr" not in jfr.wrap
    assert "; cat vash-strace.log" in RUNTIMES["go"].observer.wrap


def test_observer_assets_exist_on_disk() -> None:
    for lang, obs in _observers():
        if obs.asset:
            assert (OBSERVER_DIR / obs.asset).is_file(), lang


def test_honesty_rule_is_stated_in_every_observer() -> None:
    # Hard requirement: a missing observer must never be read as "the
    # vulnerability did not reproduce".
    for lang, obs in _observers():
        text = (obs.notes + " " + obs.kind).lower()
        assert "optional" in text, lang
        assert "absence of observer evidence is not evidence" in text, lang


def test_csharp_is_honest_about_having_no_observer() -> None:
    rt = RUNTIMES["csharp"]
    assert rt.observer is None
    assert "dotnet-trace" in rt.deps_hint


# ---- deps hints reach the TARGET's own dependencies ------------------------


def test_java_deps_hint_explains_the_classpath() -> None:
    hint = RUNTIMES["java"].deps_hint
    assert "classpath" in hint.lower()
    assert "dependency:build-classpath" in hint
    assert ".m2" in hint


def test_javascript_deps_hint_explains_node_modules_resolution() -> None:
    hint = RUNTIMES["javascript"].deps_hint
    assert "node_modules" in hint
    assert "NODE_PATH" in hint


def test_go_deps_hint_explains_module_context() -> None:
    hint = RUNTIMES["go"].deps_hint
    assert "go.mod" in hint or "module" in hint.lower()


def test_typescript_is_honest_about_the_build_step() -> None:
    rt = RUNTIMES["typescript"]
    assert rt.compile_cmd is not None
    assert "tsx" in (rt.deps_hint + rt.run_cmd + rt.compile_cmd)


def test_python_needs_no_compile_step() -> None:
    assert RUNTIMES["python"].compile_cmd is None


# ---- materialize_observer --------------------------------------------------


def test_materialize_observer_writes_the_asset_and_is_idempotent(tmp_path) -> None:
    scratch = tmp_path / "run" / "scratch"
    rt = RUNTIMES["python"]
    first = materialize_observer(rt, scratch)
    assert first and all(p.is_file() for p in first)
    assert all(p.parent == scratch for p in first)
    body = first[0].read_text()

    second = materialize_observer(rt, scratch)
    assert [str(p) for p in second] == [str(p) for p in first]
    assert first[0].read_text() == body
    assert sorted(p.name for p in scratch.iterdir()) == sorted(p.name for p in first)


def test_materialize_observer_writes_nothing_outside_scratch(tmp_path) -> None:
    scratch = tmp_path / "scratch"
    before = sorted(p.name for p in tmp_path.iterdir())
    materialize_observer(RUNTIMES["javascript"], scratch)
    after = sorted(p.name for p in tmp_path.iterdir())
    assert after == sorted(before + ["scratch"])


def test_materialize_observer_is_a_noop_without_an_observer(tmp_path) -> None:
    assert materialize_observer(RUNTIMES["csharp"], tmp_path) == []
    assert list(tmp_path.iterdir()) == []


def test_materialize_observer_is_a_noop_for_assetless_observers(tmp_path) -> None:
    # java/go observers are pure command recipes — no file to write.
    assert materialize_observer(RUNTIMES["java"], tmp_path) == []
    assert list(tmp_path.iterdir()) == []


# ---- poc_execution_block ---------------------------------------------------


def test_block_shape_matches_the_contract(tmp_path) -> None:
    block = poc_execution_block(["python"], None, tmp_path)
    assert set(block) == {"language", "poc_filename", "compile_cmd", "run_cmd",
                          "deps_hint", "observer"}
    assert block["language"] == "python"
    assert block["poc_filename"] == RUNTIMES["python"].poc_filename
    obs = block["observer"]
    assert set(obs) == {"name", "kind", "wrap", "evidence_markers",
                        "available_check", "notes", "files"}
    assert isinstance(obs["evidence_markers"], list) and obs["evidence_markers"]
    assert isinstance(obs["files"], list)


def test_block_is_none_for_an_unmatched_language(tmp_path) -> None:
    assert poc_execution_block(["cobol"], None, tmp_path) is None
    assert poc_execution_block([], None, tmp_path) is None
    assert list(tmp_path.iterdir()) == []


def test_block_without_materialize_writes_nothing(tmp_path) -> None:
    scratch = tmp_path / "scratch"
    block = poc_execution_block(["javascript"], None, scratch)
    assert block is not None
    assert block["observer"]["files"] == []
    assert not scratch.exists() or list(scratch.iterdir()) == []


def test_block_with_materialize_writes_the_asset(tmp_path) -> None:
    scratch = tmp_path / "scratch"
    block = poc_execution_block(["typescript"], None, scratch, materialize=True)
    files = block["observer"]["files"]
    assert files
    for f in files:
        assert Path(f).is_file()
        assert Path(f).parent == scratch


def test_block_honours_project_env_primary_language(tmp_path) -> None:
    block = poc_execution_block(["python"], {"primary_language": "go"}, tmp_path)
    assert block["language"] == "go"


def test_block_observer_is_none_when_the_runtime_has_none(tmp_path) -> None:
    block = poc_execution_block(["csharp"], None, tmp_path, materialize=True)
    assert block["observer"] is None


# ---- the python audit-hook observer, proven end-to-end ---------------------


_POC = """\
import os
import subprocess
import sys

with open("vash-evidence.txt", "w") as fh:
    fh.write("written by the poc\\n")
subprocess.run([sys.executable, "-c", "pass"], check=False)
print("poc done")
"""

_QUIET_POC = "x = 1 + 1\n"


def _run_hook(scratch: Path, poc_body: str) -> subprocess.CompletedProcess:
    materialize_observer(RUNTIMES["python"], scratch)
    poc = scratch / RUNTIMES["python"].poc_filename
    poc.write_text(poc_body)
    return subprocess.run(
        [sys.executable, str(scratch / "vash_audit_hook.py"),
         sys.executable, str(poc)],
        cwd=scratch, capture_output=True, text=True, timeout=120,
    )


def test_python_audit_hook_records_the_events_that_matter(tmp_path) -> None:
    p = _run_hook(tmp_path, _POC)
    out = p.stdout + p.stderr
    assert p.returncode == 0, out
    assert "poc done" in p.stdout            # the PoC itself still runs normally
    assert "hook-armed" in out               # the observer proves it was active
    assert "[VASH-OBSERVER] audit:open" in out
    assert "vash-evidence.txt" in out
    assert "[VASH-OBSERVER] audit:subprocess.Popen" in out
    assert (tmp_path / "vash-evidence.txt").is_file()


def test_python_audit_hook_emits_declared_evidence_markers(tmp_path) -> None:
    markers = RUNTIMES["python"].observer.evidence_markers
    p = _run_hook(tmp_path, _POC)
    out = p.stdout + p.stderr
    assert any(m in out for m in markers), out


def test_python_audit_hook_stays_quiet_on_an_inert_poc(tmp_path) -> None:
    # No false evidence: the hook must not report its own bootstrap
    # (compiling/exec'ing the PoC, importing runpy) as attacker behaviour.
    p = _run_hook(tmp_path, _QUIET_POC)
    out = p.stdout + p.stderr
    assert p.returncode == 0, out
    assert "hook-armed" in out
    for marker in RUNTIMES["python"].observer.evidence_markers:
        assert marker not in out, out


def test_python_audit_hook_propagates_the_poc_exit_code(tmp_path) -> None:
    p = _run_hook(tmp_path, "import sys\nsys.exit(3)\n")
    assert p.returncode == 3, p.stdout + p.stderr


# ---- the node observer asset (static assertions only — node is not run) ----


def test_node_observer_asset_is_real_and_instruments_the_right_modules() -> None:
    obs = RUNTIMES["javascript"].observer
    body = (OBSERVER_DIR / obs.asset).read_text()
    for mod in ("child_process", "fs", "net", "http"):
        assert f"require('{mod}')" in body, mod
    assert "[VASH-OBSERVER]" in body
    assert obs.wrap.startswith("NODE_OPTIONS=")


def test_javascript_and_typescript_share_the_node_observer() -> None:
    assert RUNTIMES["typescript"].observer is RUNTIMES["javascript"].observer
