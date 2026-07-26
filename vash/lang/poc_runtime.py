"""Per-language PoC run recipes + per-runtime observers (Phase 3).

VASH's differentiator is that Hunt does not merely *describe* an exploit — it
writes one and **runs it in the sandbox**, then drops the candidates that do
not reproduce. Until now that path was Python-shaped: the prompt said "run a
local PoC, in the target language" and left the agent to invent the commands.
Phases 1 and 2 taught VASH to *find* bugs in JS/TS, Java, Go and C# and to
*build* an environment for them; this module is what lets VASH **prove** them.

Two static registries, in the spirit of `vash.provision.dockerfile`:

* :data:`RUNTIMES` — how to compile and run a PoC per language, and (the part
  that actually decides whether a PoC is worth anything) how to reach the
  **target's own dependencies**. A Java PoC that cannot see the target's
  classpath, or a Node PoC that cannot resolve the target's `node_modules`,
  proves nothing at all: it only proves that a hello-world compiled.
* :class:`Observer` — optional per-runtime instrumentation that answers the
  question "did the vulnerable behaviour actually *fire*?" rather than "did the
  script exit 0?". A PoC can exit 0 because the sink swallowed an exception; a
  process-spawn event in the trace cannot.

**Honesty rule (load-bearing, not a nicety).** An observer is OPTIONAL. Its
tooling may be absent — no `jfr` in a JRE-only image, no `strace` binary, no
`SYS_PTRACE` under Docker's default seccomp profile. When that happens the PoC
must still run, unwrapped, and **the absence of observer evidence must never be
read as "the vulnerability did not reproduce"**. That is what
:attr:`Observer.available_check` is for: the agent tests for the tooling
first, and treats the observer as corroboration on top of the PoC's own
assertions — never as the verdict. Every observer repeats this in its
``notes`` so the rule survives into the prompt the agent actually reads.

**Safety.** Nothing in this module executes anything. It produces command
*strings* and copies observer helper files into a scratch directory; the agent,
inside the sandbox (where `vash.runner` has granted it Bash), is what runs
them. On a bare host Hunt has no Bash and these recipes are simply unused.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Observer assets live next to this module as real, readable files so they can
# be reviewed (and unit-tested) like any other source, not smuggled in as
# escaped string literals.
OBSERVER_DIR = Path(__file__).resolve().parent / "observers"

# Every marker line an observer prints starts with this, so a single grep
# separates instrumentation output from the PoC's own chatter.
MARKER = "[VASH-OBSERVER]"

# Appended to every Observer.notes. The wording is deliberately blunt: this is
# the one inference that would turn optional instrumentation into a source of
# false negatives.
_HONESTY = (
    "This observer is OPTIONAL instrumentation — run `available_check` first "
    "and, if it fails, run the PoC unwrapped and say so in the finding. "
    "The absence of observer evidence is NOT evidence that the vulnerability "
    "did not reproduce; only the PoC's own assertions decide that."
)


@dataclass(frozen=True)
class Observer:
    """Optional instrumentation that proves the vulnerable behaviour fired.

    `wrap` is a shell template containing ``{cmd}``; the agent substitutes the
    (already compiled) run command into it. Every observer here wraps via an
    environment prefix or a wrapper script rather than by editing the run
    command's internals, so `wrap.format(cmd=run_cmd)` is always a valid
    command line.

    `evidence_markers` are substrings whose *presence* in the combined output
    proves the behaviour fired. Their absence proves nothing (see the module
    docstring) — that asymmetry is the whole design.
    """

    name: str
    kind: str
    asset: str | None
    wrap: str
    evidence_markers: tuple[str, ...]
    available_check: str
    notes: str


@dataclass(frozen=True)
class Runtime:
    """How to build and run a PoC for one language, in the target's own env.

    `deps_hint` is the field that decides whether a PoC is meaningful: it tells
    the agent how to reach the TARGET's dependencies (classpath, node_modules,
    module context, installed package). It is prose because the answer is
    genuinely repo-shaped — the agent has Bash and can run the probe commands
    it names.
    """

    language: str
    poc_filename: str
    compile_cmd: str | None
    run_cmd: str
    observer: Observer | None
    deps_hint: str


# ─────────────────────────────────────────────────────────────────────────────
# Observers
# ─────────────────────────────────────────────────────────────────────────────

# Python: a real PEP-578 audit hook. Audit events are raised by CPython below
# the Python API, so they fire however the sink is reached — including from C
# extensions and pickle gadget chains, which a monkey-patch would miss.
PYTHON_AUDIT_HOOK = Observer(
    name="python-audit-hook",
    kind=("PEP-578 sys.addaudithook: CPython raises audit events for process "
          "spawn, file open, socket connect, exec/compile and pickle/marshal "
          "loads; the wrapper runs the PoC via runpy with the hook armed and "
          "prints one marker line per event. Optional instrumentation."),
    asset="vash_audit_hook.py",
    wrap='python3 vash_audit_hook.py {cmd} 2>&1',
    evidence_markers=(
        MARKER + " audit:subprocess.Popen",
        MARKER + " audit:os.system",
        MARKER + " audit:os.exec",
        MARKER + " audit:os.spawn",
        MARKER + " audit:open",
        MARKER + " audit:socket.connect",
        MARKER + " audit:exec",
        MARKER + " audit:compile",
        MARKER + " audit:pickle.find_class",
        MARKER + " audit:marshal.load",
        MARKER + " audit:ctypes.dlopen",
    ),
    available_check=(
        "python3 -c 'import sys; raise SystemExit(0 if hasattr(sys, \"addaudithook\") "
        "else 1)'"
    ),
    notes=(
        "Run from the scratch dir (the Hunt prompt already `cd $scratch_dir`), "
        "where materialize_observer wrote vash_audit_hook.py. The wrapper "
        "tolerates a leading `python3` in {cmd} and strips it; `-c` and `-m` "
        "forms are NOT observable, use a script file. Markers go to stderr "
        "(the wrap already folds stderr into stdout). A `hook-armed` banner "
        "line proves the hook ran, which is how you tell 'observer saw "
        "nothing' apart from 'observer never ran'. Import-time noise (opening "
        ".py files, compiling the PoC itself) is filtered out on purpose. " +
        _HONESTY
    ),
)

# JavaScript/TypeScript: a --require preload. Node has no audit-hook
# equivalent, so the mechanism is patching the builtin module objects before
# the entry module loads. Shared by both languages (TS runs as JS).
NODE_PRELOAD = Observer(
    name="node-preload",
    kind=("node --require preload that wraps child_process, fs, net, "
          "http/https and vm before the entry module loads, printing one "
          "marker line per call. Optional instrumentation."),
    asset="vash_node_observer.js",
    wrap='NODE_OPTIONS="--require $PWD/vash_node_observer.js" {cmd} 2>&1',
    evidence_markers=(
        MARKER + " node:child_process.",
        MARKER + " node:fs.",
        MARKER + " node:net.",
        MARKER + " node:http.",
        MARKER + " node:https.",
        MARKER + " node:vm.",
    ),
    available_check="command -v node >/dev/null 2>&1",
    notes=(
        "NODE_OPTIONS is used instead of a bare `--require` flag so the wrap "
        "composes with any run command (`node poc.js`, `npx tsx poc.ts`). "
        "$PWD must be the scratch dir where the asset was materialized. "
        "`eval` / `new Function` are language constructs and cannot be "
        "wrapped — only vm.* is visible; a native addon that syscalls "
        "directly is invisible too. Reads of .js/.json/.node are suppressed "
        "because the CommonJS loader itself uses fs.readFileSync. A "
        "`preload-armed` line proves the preload ran. " + _HONESTY
    ),
)

# Java: JDK Flight Recorder. Present in every modern JDK (not a JRE), zero
# install, and its event set maps almost exactly onto the sinks we care about.
JFR_OBSERVER = Observer(
    name="jfr",
    kind=("JDK Flight Recorder: the JVM records jdk.ProcessStart, "
          "jdk.SocketWrite/jdk.SocketRead and jdk.FileWrite/jdk.FileRead "
          "events, and `jfr print` reads them back after the PoC exits. "
          "Optional instrumentation."),
    asset=None,
    wrap=(
        'JDK_JAVA_OPTIONS="-XX:StartFlightRecording=filename=vash-poc.jfr,'
        'settings=profile,dumponexit=true" {cmd}; '
        'jfr summary vash-poc.jfr; '
        'jfr print --events jdk.ProcessStart,jdk.SocketWrite,jdk.SocketRead,'
        'jdk.FileWrite vash-poc.jfr'
    ),
    evidence_markers=(
        "jdk.ProcessStart",
        "jdk.SocketWrite",
        "jdk.SocketRead",
        "jdk.FileWrite",
    ),
    available_check=(
        "command -v jfr >/dev/null 2>&1 && java -XX:+PrintFlagsFinal -version "
        ">/dev/null 2>&1"
    ),
    notes=(
        "JDK_JAVA_OPTIONS (JDK 9+) injects the recording flag without editing "
        "the run command, so the wrap composes with any classpath. `;` not "
        "`&&` between the run and the readback: a PoC that exits non-zero "
        "still leaves a recording worth reading. The recording is dumped on "
        "exit, so a PoC that hangs or is killed produces nothing. A JRE-only "
        "image has no `jfr` binary; jdk.FileWrite/FileRead are sampled under "
        "`settings=profile`, so a single small write can legitimately be "
        "missing from the recording. " + _HONESTY
    ),
)

# Go: no in-process hook worth having for a compiled binary, so observe at the
# syscall boundary. This is the observer most likely to be unavailable.
STRACE_OBSERVER = Observer(
    name="strace",
    kind=("strace on the syscalls that matter (execve, openat, connect) — a "
          "compiled Go binary has no in-process hook, so the evidence is "
          "taken at the kernel boundary. Optional instrumentation."),
    asset=None,
    wrap=(
        'strace -f -s 256 -e trace=execve,openat,connect -o vash-strace.log '
        '{cmd}; cat vash-strace.log'
    ),
    evidence_markers=("execve(", "openat(", "connect("),
    available_check=(
        "command -v strace >/dev/null 2>&1 && "
        "strace -f -e trace=execve /bin/true >/dev/null 2>&1"
    ),
    notes=(
        "REQUIRES CAP_SYS_PTRACE: Docker's default seccomp profile blocks "
        "ptrace(2), so a plain `docker run` cannot strace — the container "
        "needs `--cap-add=SYS_PTRACE` (or `--security-opt seccomp=unconfined`). "
        "The available_check above actually attempts a trace, so it fails for "
        "the permission case and not only for a missing binary. `-f` follows "
        "the goroutine threads and any child process. Expect openat noise from "
        "the Go runtime's own startup. " + _HONESTY
    ),
)


# ─────────────────────────────────────────────────────────────────────────────
# Runtimes
# ─────────────────────────────────────────────────────────────────────────────

RUNTIMES: dict[str, Runtime] = {
    "python": Runtime(
        language="python",
        poc_filename="poc.py",
        compile_cmd=None,
        run_cmd="python3 poc.py",
        observer=PYTHON_AUDIT_HOOK,
        deps_hint=(
            "Phase 2 provisioning pip-installs the target into the image "
            "(`pip install -e .` plus `-r requirements.txt`), so the target "
            "package is importable directly: `import <pkg>` works from any "
            "cwd. Confirm with `python3 -c 'import <pkg>, sys; "
            "print(<pkg>.__file__)'` before trusting a PoC. If the import "
            "fails (provisioning was skipped, or the repo is not installable), "
            "run with `PYTHONPATH=/target python3 poc.py` or `cd /target` "
            "first — and record in the finding that the PoC ran against the "
            "source tree rather than an installed distribution."
        ),
    ),
    "javascript": Runtime(
        language="javascript",
        poc_filename="poc.js",
        compile_cmd=None,
        run_cmd="node poc.js",
        observer=NODE_PRELOAD,
        deps_hint=(
            "Node resolves `require`/`import` by walking up from the "
            "IMPORTING FILE's directory, so a poc.js sitting in the scratch "
            "dir will NOT see /target/node_modules. Three ways to reach the "
            "target's dependencies, best first: (1) `require('/target/<entry>')` "
            "by absolute path and run with "
            "`NODE_PATH=/target/node_modules node poc.js`; (2) write the PoC "
            "inside the target tree (e.g. /target/vash-poc.js) and "
            "`cd /target && node vash-poc.js` — natural resolution, but it "
            "writes into the target; (3) `npm ls <dep>` / "
            "`ls /target/node_modules` first to confirm the dependency is "
            "actually installed. If node_modules is missing, provisioning did "
            "not complete: say so rather than PoC-ing against a stub."
        ),
    ),
    "typescript": Runtime(
        language="typescript",
        poc_filename="poc.ts",
        compile_cmd=(
            "npx --yes tsc poc.ts --outDir . --module commonjs --target es2020 "
            "--skipLibCheck --esModuleInterop"
        ),
        run_cmd="node poc.js",
        observer=NODE_PRELOAD,
        deps_hint=(
            "TypeScript is not run, JavaScript is — be explicit about which "
            "you did. Preferred: compile with the compile_cmd above and run "
            "the emitted poc.js, because the node observer then applies "
            "unchanged. One-step alternative when it is installed: "
            "`npx --yes tsx poc.ts` (or `ts-node`), which needs no build "
            "step; both `npx` forms hit the network on a cold cache, so check "
            "`npx --no-install tsx --version` / `ls /target/node_modules/.bin` "
            "first — in an offline container neither may exist, in which case "
            "write the PoC as plain JavaScript instead. Dependency resolution "
            "is exactly the JavaScript case: NODE_PATH=/target/node_modules, "
            "or run from inside /target. Type errors are irrelevant to a PoC "
            "— `--skipLibCheck` and, if needed, `--noEmitOnError false`."
        ),
    ),
    "java": Runtime(
        language="java",
        poc_filename="PoC.java",
        compile_cmd='javac -cp "$CP" -d . PoC.java',
        run_cmd='java -cp ".:$CP" PoC',
        observer=JFR_OBSERVER,
        deps_hint=(
            "Build $CP first — a Java PoC without the target's classpath "
            "compiles nothing and proves nothing. Maven: "
            "`cd /target && mvn -q -B dependency:build-classpath "
            "-Dmdep.outputFile=/tmp/cp.txt` then "
            "`CP=/target/target/classes:$(cat /tmp/cp.txt)`. Gradle: "
            "`gradle -q dependencies` or point at the build output plus the "
            "cache — `CP=$(find /target -name '*.jar' -o -path '*/build/classes/*' "
            "-type d | tr '\\n' ':')`. Last resort (works surprisingly often): "
            "`CP=$(find /target ~/.m2 ~/.gradle -name '*.jar' 2>/dev/null | "
            "tr '\\n' ':')`. Verify with `javap -cp \"$CP\" "
            "fully.qualified.TargetClass` BEFORE writing the PoC. On JDK 11+ a "
            "single-file PoC can skip javac entirely: `java -cp \"$CP\" "
            "PoC.java`. Keep the class name PoC so the filename matches."
        ),
    ),
    "go": Runtime(
        language="go",
        poc_filename="poc.go",
        compile_cmd=None,
        run_cmd="go run poc.go",
        observer=STRACE_OBSERVER,
        deps_hint=(
            "Module context is everything: `go run` resolves imports against "
            "the go.mod of the directory it runs in, so a poc.go in the "
            "scratch dir cannot import the target's packages. Preferred: put "
            "the PoC INSIDE the target module — `mkdir -p /target/vashpoc && "
            "cp poc.go /target/vashpoc/ && cd /target && go run ./vashpoc` "
            "(package main) — which reuses the module's resolved, already "
            "downloaded dependencies. Alternative that keeps the target tree "
            "clean: `go mod init vashpoc && go mod edit "
            "-replace <target/module>=/target && go mod tidy`, but `tidy` "
            "wants the network, so prefer the in-module form in an offline "
            "container. `go env GOFLAGS GOMODCACHE` and "
            "`head -1 /target/go.mod` tell you the module path to import."
        ),
    ),
    "csharp": Runtime(
        language="csharp",
        poc_filename="Poc.cs",
        compile_cmd=(
            'dotnet new console -o vashpoc --force && cp Poc.cs vashpoc/Program.cs '
            '&& dotnet add vashpoc reference "$TARGET_CSPROJ" '
            '&& dotnet build vashpoc -c Release --nologo'
        ),
        run_cmd="dotnet run --project vashpoc -c Release --no-build --nologo",
        observer=None,
        deps_hint=(
            "Set TARGET_CSPROJ first: "
            "`TARGET_CSPROJ=$(find /target -name '*.csproj' | head -1)`; the "
            "project reference is what puts the target's own types on the "
            "compile path. `dotnet new`/`dotnet add reference` trigger a NuGet "
            "restore, which needs the network on a cold cache — if the "
            "container is offline, skip the scratch project and reference the "
            "assemblies the Phase 2 build already produced "
            "(`find /target -path '*/bin/*' -name '*.dll'`) via an explicit "
            "<Reference><HintPath> in the csproj, or PoC against the target's "
            "own test project with `dotnet test --no-restore --no-build`. "
            "NO OBSERVER IS SHIPPED FOR C#: the EventPipe tooling "
            "(dotnet-trace) is a global tool that is NOT in the SDK image and "
            "installing it needs the network, so VASH would be inventing a "
            "mechanism that does not run. Prove the behaviour inside the PoC "
            "instead — assert on the artefact the sink produced (the file it "
            "wrote, the process it started, the connection it opened) and "
            "print a distinctive marker line yourself."
        ),
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Selection / materialization
# ─────────────────────────────────────────────────────────────────────────────

def runtime_for(languages: list[str],
                project_env: dict | None = None) -> Runtime | None:
    """Pick the Runtime for a Hunt task, or None when nothing matches.

    `project_env` is Phase 2's `ProvisionResult.agent_summary()` (what the
    agent already sees as `project_environment`). Its `primary_language` is
    repo-wide evidence — manifests and file counts across the whole tree — so
    it outranks the per-task, file-extension-derived `languages` list, which
    can name a single incidental `.js` in a Java repo. When it names a
    language with no Runtime we fall through to the task's own list rather
    than giving up.

    Returning None is a normal outcome (COBOL, templates, a language Phase 3
    does not cover). Callers must degrade to a static, unexecuted PoC.
    """
    if project_env:
        primary = project_env.get("primary_language")
        if primary and primary in RUNTIMES:
            return RUNTIMES[primary]
    for lang in languages or ():
        rt = RUNTIMES.get(lang)
        if rt is not None:
            return rt
    return None


def materialize_observer(rt: Runtime, scratch_dir: Path) -> list[Path]:
    """Copy `rt`'s observer asset into `scratch_dir`; return what was written.

    Idempotent (re-running rewrites identical bytes) and confined: the only
    path ever written is ``scratch_dir / <asset basename>``. Runtimes whose
    observer is pure command recipe (JFR, strace) or absent (C#) write
    nothing and return []. This function never executes anything.
    """
    obs = rt.observer
    if obs is None or not obs.asset:
        return []
    name = Path(obs.asset).name          # defensive: assets are never nested
    source = OBSERVER_DIR / name
    body = source.read_text(encoding="utf-8")
    scratch_dir = Path(scratch_dir)
    scratch_dir.mkdir(parents=True, exist_ok=True)
    dest = scratch_dir / name
    if not dest.exists() or dest.read_text(encoding="utf-8") != body:
        dest.write_text(body, encoding="utf-8")
    return [dest]


def poc_execution_block(languages: list[str], project_env: dict | None,
                        scratch_dir: Path, *,
                        materialize: bool = False) -> dict | None:
    """The per-task PoC recipe injected into the Hunt agent's `user_input`.

    Returns None when no Runtime matches — Hunt then falls back to its existing
    generic "run a PoC in the target language" instruction, which is exactly
    the pre-Phase-3 behaviour, so an unknown language degrades instead of
    breaking.

    `materialize=False` (the default) is pure text: nothing is written to disk,
    and `observer["files"]` is empty. Pass `materialize=True` only when the
    scratch dir is real and the agent is actually going to run the PoC — i.e.
    inside the sandbox.
    """
    rt = runtime_for(languages, project_env)
    if rt is None:
        return None

    observer: dict | None = None
    if rt.observer is not None:
        files = materialize_observer(rt, scratch_dir) if materialize else []
        observer = {
            "name": rt.observer.name,
            "kind": rt.observer.kind,
            "wrap": rt.observer.wrap,
            "evidence_markers": list(rt.observer.evidence_markers),
            "available_check": rt.observer.available_check,
            "notes": rt.observer.notes,
            "files": [str(p) for p in files],
        }
    return {
        "language": rt.language,
        "poc_filename": rt.poc_filename,
        "compile_cmd": rt.compile_cmd,
        "run_cmd": rt.run_cmd,
        "deps_hint": rt.deps_hint,
        "observer": observer,
    }
