"""Phase 3: per-language PoC run recipes + per-runtime observers.

Everything here is OFFLINE and never executes target code. The single
exception is the Python audit-hook observer, which is pure stdlib Python and
IS executed end-to-end (as a subprocess, on a throwaway script this test
writes itself) — it is the one observer we can honestly prove works without a
JVM / Node / strace / docker.
"""

from __future__ import annotations

import os
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


def test_the_tasks_own_language_beats_the_repo_wide_primary_language() -> None:
    """The sink lives in the task's file, so that file's language is what the
    PoC must exploit. Letting the repo-wide primary language win handed a task
    targeting a .java sink in a Python-majority repo `poc.py` + an audit hook
    that can never see a JVM."""
    rt = runtime_for(["java"], {"primary_language": "python"})
    assert rt is not None and rt.language == "java"
    rt = runtime_for(["python"], {"primary_language": "java"})
    assert rt is not None and rt.language == "python"


def test_project_env_is_the_fallback_when_the_task_says_nothing_usable() -> None:
    # e.g. a task scoped to a template or a language Phase 3 does not cover
    assert runtime_for(["web-template"], {"primary_language": "go"}).language == "go"
    assert runtime_for([], {"primary_language": "java"}).language == "java"


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


def test_every_wrap_is_a_usable_format_template(tmp_path) -> None:
    # The agent substitutes the run command into `wrap`; a stray brace (a JSON
    # literal, a shell ${} ) would raise instead of producing a command line.
    # Checked on the RESOLVED wrap poc_execution_block emits, since {observer}
    # is substituted there with the absolute materialized asset path.
    for lang, obs in _observers():
        rt = RUNTIMES[lang]
        block = poc_execution_block([lang], None, tmp_path, materialize=True)
        wrap = block["observer"]["wrap"]
        assert "{observer}" not in wrap, lang
        line = wrap.format(cmd=rt.run_cmd)
        assert rt.run_cmd in line, lang
        assert "{cmd}" not in line, lang


def test_asset_observers_are_wrapped_by_absolute_path(tmp_path) -> None:
    """A relative asset name (or $PWD) breaks the moment the agent follows
    deps_hint and `cd /target` — node/python abort at startup having never run
    the PoC, which reads as 'no evidence'."""
    for lang in ("python", "javascript"):
        block = poc_execution_block([lang], None, tmp_path, materialize=True)
        wrap = block["observer"]["wrap"]
        assert str(tmp_path) in wrap, lang
        assert "$PWD" not in wrap, lang


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


def test_csharp_uses_the_syscall_observer_since_dotnet_trace_is_unavailable() -> None:
    """dotnet-trace is a global tool absent from the SDK image and its install
    needs the network — but the scan image ships strace, and a .NET
    Process.Start sink IS visible at the syscall boundary (verified in the real
    dotnet SDK image). Shipping no observer would have been leaving evidence on
    the table, not honesty."""
    rt = RUNTIMES["csharp"]
    assert rt.observer is not None and rt.observer.name == "strace"
    assert "dotnet-trace" in rt.deps_hint          # still explains WHY not EventPipe


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


def test_block_prefers_the_tasks_language_and_falls_back_to_project_env(tmp_path) -> None:
    block = poc_execution_block(["python"], {"primary_language": "go"}, tmp_path)
    assert block["language"] == "python"
    block = poc_execution_block(["web-template"], {"primary_language": "go"}, tmp_path)
    assert block["language"] == "go"


def test_block_observer_is_none_when_the_runtime_has_none(tmp_path, monkeypatch) -> None:
    """Every shipped runtime now has an observer, so the None path is exercised
    with a synthetic runtime — it must still degrade cleanly rather than crash."""
    from dataclasses import replace
    bare = replace(RUNTIMES["python"], observer=None)
    monkeypatch.setitem(RUNTIMES, "python", bare)
    block = poc_execution_block(["python"], None, tmp_path, materialize=True)
    assert block["observer"] is None
    assert block["run_cmd"]                       # the recipe still works


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


def test_hook_applies_a_leading_env_assignment_and_still_runs_the_poc(tmp_path) -> None:
    """The python deps_hint documents `PYTHONPATH=/target python3 poc.py`. The
    shell only honours NAME=VALUE at the START of a command, so once that command
    is spliced after `python3 <hook>` the assignment arrives as a plain argv
    token. Before the fix the wrapper treated it as the script name and exited 2
    WITHOUT RUNNING THE POC — which downstream reads as 'the observer saw
    nothing', i.e. a real finding quietly loses its proof."""
    libdir = tmp_path / "libdir"
    libdir.mkdir()
    (libdir / "vash_target_mod.py").write_text(
        "def pwn():\n"
        "    import subprocess\n"
        "    subprocess.run(['/bin/echo', 'sink'], capture_output=True)\n"
        "    return 'ok'\n"
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    materialize_observer(RUNTIMES["python"], scratch)
    (scratch / "poc.py").write_text(
        "import vash_target_mod\nprint('RESULT:', vash_target_mod.pwn())\n"
    )
    p = subprocess.run(
        [sys.executable, str(scratch / "vash_audit_hook.py"),
         f"PYTHONPATH={libdir}", sys.executable, str(scratch / "poc.py")],
        cwd=scratch, capture_output=True, text=True, timeout=120,
    )
    out = p.stdout + p.stderr
    assert p.returncode == 0, out
    assert "RESULT: ok" in p.stdout            # the PoC really ran
    assert "hook-armed" in out                 # ...with the hook armed
    assert "audit:subprocess.Popen" in out     # ...and the sink was observed
    assert f"env PYTHONPATH={libdir}" in out   # ...and the assignment was applied


def test_hook_env_assignment_reaches_sys_path_not_just_environ(tmp_path) -> None:
    """os.environ alone is too late — sys.path was already built from the
    inherited environment before the wrapper started."""
    libdir = tmp_path / "lib2"
    libdir.mkdir()
    (libdir / "vash_only_here.py").write_text("VALUE = 'imported-from-pythonpath'\n")
    scratch = tmp_path / "s2"
    scratch.mkdir()
    materialize_observer(RUNTIMES["python"], scratch)
    (scratch / "poc.py").write_text(
        "import vash_only_here\nprint('GOT:', vash_only_here.VALUE)\n"
    )
    p = subprocess.run(
        [sys.executable, str(scratch / "vash_audit_hook.py"),
         f"PYTHONPATH={libdir}", str(scratch / "poc.py")],
        cwd=scratch, capture_output=True, text=True, timeout=120,
    )
    assert "GOT: imported-from-pythonpath" in p.stdout, p.stdout + p.stderr


def test_no_recipe_tells_the_agent_to_write_into_the_read_only_target() -> None:
    """/target is mounted read-only in every documented invocation, so a recipe
    that writes there fails with EROFS before the PoC ever links against the
    target."""
    for lang, rt in RUNTIMES.items():
        for field in (rt.compile_cmd or "", rt.run_cmd, rt.deps_hint):
            for bad in ("mkdir -p /target", "mkdir /target", "cp poc", "> /target/"):
                if bad == "cp poc":
                    assert "cp poc.go /target" not in field, lang
                    assert "cp poc.js /target" not in field, lang
                else:
                    assert bad not in field, f"{lang}: {bad!r} writes to read-only /target"


def test_go_compiles_before_tracing_so_the_toolchain_is_not_the_evidence() -> None:
    """`strace go run` traces the COMPILER: its execve/openat satisfy the
    evidence markers unconditionally, so every Go PoC would 'prove' process
    spawn whether or not the sink fired."""
    go = RUNTIMES["go"]
    assert go.compile_cmd and "go build" in go.compile_cmd
    assert "go run" not in go.run_cmd
    assert go.run_cmd.strip().startswith("./")


def test_markers_attribute_to_the_code_that_caused_the_event(tmp_path) -> None:
    """A marker alone only says "a process spawned" — innocent code does that
    too. The attribution is what ties it to the vulnerability, so it must name
    the TARGET's frame, not the stdlib frame nearest the call."""
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "vash_vulnmod.py").write_text(
        "import subprocess\n"
        "\n"
        "\n"
        "def build_report(name):\n"
        "    return subprocess.run('echo ' + name, shell=True, capture_output=True).stdout\n"
    )
    scratch = tmp_path / "s"
    scratch.mkdir()
    materialize_observer(RUNTIMES["python"], scratch)
    (scratch / "poc.py").write_text(
        "import vash_vulnmod\nprint(vash_vulnmod.build_report('x; echo hi'))\n"
    )
    p = subprocess.run(
        [sys.executable, str(scratch / "vash_audit_hook.py"),
         f"PYTHONPATH={lib}", str(scratch / "poc.py")],
        cwd=scratch, capture_output=True, text=True, timeout=120,
    )
    out = p.stdout + p.stderr
    line = next(ln for ln in out.splitlines() if "audit:subprocess.Popen" in ln)
    assert "<- from" in line, line
    assert "vash_vulnmod.py:5 in build_report" in line, line   # the target's frame
    assert "subprocess.py" not in line.split("<- from")[1], line  # not the stdlib


def test_attribution_names_the_poc_when_the_poc_bypasses_the_target(tmp_path) -> None:
    """If the PoC calls the sink directly it proves nothing about the target —
    the hunter must be able to see that from the evidence."""
    scratch = tmp_path / "s"
    scratch.mkdir()
    materialize_observer(RUNTIMES["python"], scratch)
    (scratch / "poc.py").write_text(
        "import subprocess\nsubprocess.run('echo direct', shell=True, capture_output=True)\n"
    )
    p = subprocess.run(
        [sys.executable, str(scratch / "vash_audit_hook.py"), str(scratch / "poc.py")],
        cwd=scratch, capture_output=True, text=True, timeout=120,
    )
    out = p.stdout + p.stderr
    line = next(ln for ln in out.splitlines() if "audit:subprocess.Popen" in ln)
    assert "poc.py:2" in line, line


def test_typescript_prefers_an_installed_compiler_over_npx(tmp_path) -> None:
    """The scan container is OFFLINE. `npx --yes tsc` would try to fetch and
    fail, so a locally-installed compiler (typescript is nearly always a
    devDependency of a TS project) must win."""
    cmd = RUNTIMES["typescript"].compile_cmd
    assert "command -v tsc" in cmd
    assert "/target/node_modules/.bin/tsc" in cmd
    assert cmd.index("command -v tsc") < cmd.index("npx --yes tsc")   # npx is last

    # ...and the selection shell really picks the local one. PATH is narrowed to
    # the system dirs so a globally-installed tsc (present on CI runners, absent
    # on most laptops) cannot win the `command -v tsc` branch and make this test
    # depend on what happens to be installed.
    binp = tmp_path / "node_modules" / ".bin"
    binp.mkdir(parents=True)
    tsc = binp / "tsc"
    tsc.write_text('#!/bin/sh\necho "LOCAL-TSC $*"\n')
    tsc.chmod(0o755)
    env = {**os.environ, "PATH": "/usr/bin:/bin"}
    proc = subprocess.run(["sh", "-c", cmd], cwd=tmp_path, capture_output=True,
                          text=True, timeout=60, env=env)
    assert "LOCAL-TSC poc.ts" in proc.stdout, proc.stdout + proc.stderr


def test_csharp_has_a_working_observer_not_none() -> None:
    """dotnet-trace is unavailable offline, but the scan image ships strace and
    a .NET Process.Start sink is visible at the syscall boundary — verified in
    the real dotnet SDK image."""
    cs = RUNTIMES["csharp"]
    assert cs.observer is not None
    assert cs.observer.name == "strace"
    assert "bin/Release" in cs.deps_hint          # the refint trap is documented
    assert "BadImageFormatException" in cs.deps_hint
