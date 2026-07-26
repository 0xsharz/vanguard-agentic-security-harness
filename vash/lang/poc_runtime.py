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
    # {observer} is substituted with the ABSOLUTE materialized asset path by
    # poc_execution_block. A relative name (or $PWD) breaks the moment the
    # agent follows deps_hint and `cd /target` — node/python then abort at
    # startup having never run the PoC, which reads as "no evidence".
    wrap='python3 {observer} {cmd} 2>&1',
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
        ".py files, compiling the PoC itself) is filtered out on purpose. "
        "Each marker carries `<- from file:line in func` naming the code that "
        "caused the event (interpreter/stdlib frames are skipped): if it names "
        "the TARGET's file the vulnerable path really ran; if it names your PoC "
        "the PoC hit the sink directly and proves nothing about the target. " +
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
    wrap='NODE_OPTIONS="--require {observer}" {cmd} 2>&1',
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
        "The preload path is absolute, so the wrap keeps working after a "
        "`cd /target`. ESM IS COVERED — verified on node v20: `--require` runs "
        "before any ESM binding is created, and the builtin ESM namespace is "
        "generated from the same exports object this preload patches, so "
        "`import { execSync } from 'node:child_process'`, `import cp from "
        "'node:child_process'` and an ESM module importing another ESM module "
        "are all observed. Blind spots are narrower than the module system: "
        "`eval` / `new Function` are language constructs and cannot be "
        "wrapped — only vm.* is visible; a native addon that syscalls "
        "directly is invisible too. Reads of .js/.json/.node are suppressed "
        "because the CommonJS loader itself uses fs.readFileSync. A "
        "`preload-armed` line proves the preload ran. Each marker carries "
        "`<- from file:line:col` naming the calling code (node internals "
        "skipped): the TARGET's file means the vulnerable path ran; your own "
        "PoC file means the PoC bypassed the target. " + _HONESTY
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
        "VERIFIED end-to-end in the scan image: a Runtime.exec sink produced "
        "one jdk.ProcessStart carrying the full injected command line AND a "
        "stackTrace naming the vulnerable method "
        "(com.example.ReportService.buildReport line 10). That stack trace is "
        "the strongest evidence any observer here produces — it ATTRIBUTES the "
        "dangerous operation to the sink instead of merely showing that "
        "something spawned a process, so quote it into poc.run_output. "
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
        "the goroutine threads and any child process. "
        "VERIFIED in the scan image (which now ships strace, and "
        "run-in-docker.sh grants --cap-add=SYS_PTRACE): tracing the built "
        "binary produced execve(\"/usr/bin/sh\", [\"sh\", \"-c\", "
        "\"...; id; echo INJECTED\"]) — the injected command line itself. "
        "The FIRST execve is always the PoC binary's own launch; that one is "
        "baseline noise, the evidence is the execve that carries attacker "
        "input. "
        "**Trace the BUILT BINARY, never `go run`** — the toolchain's own "
        "execve/openat would satisfy these markers unconditionally, making "
        "every PoC look like it spawned a process. The runtime's compile_cmd "
        "builds first for exactly this reason. Even so, `openat(` fires "
        "during ordinary Go runtime startup, so treat `execve(` and "
        "`connect(` as the load-bearing markers and read the traced path/"
        "argument before calling an openat hit proof. " + _HONESTY
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
            "dir will NOT see /target/node_modules. /target is mounted "
            "READ-ONLY, so you cannot simply drop the PoC inside it. In order: "
            "(1) `require('/target/<entry>')` by absolute path and run with "
            "`NODE_PATH=/target/node_modules node poc.js`; (2) if the target's "
            "own relative imports break under (1), copy the tree out — "
            "`cp -a /target /tmp/vashtgt && cp poc.js /tmp/vashtgt/ && "
            "cd /tmp/vashtgt && node poc.js` — which gives natural resolution "
            "without writing to the read-only mount; (3) `npm ls <dep>` / "
            "`ls /target/node_modules` first to confirm the dependency is "
            "actually installed. If node_modules is missing, provisioning did "
            "not complete: say so rather than PoC-ing against a stub. CommonJS and "
            "ESM PoCs are both observed (verified on node v20), so write "
            "whichever matches the target's module system."
        ),
    ),
    "typescript": Runtime(
        language="typescript",
        poc_filename="poc.ts",
        # Prefer a compiler that is already installed — a TS project almost
        # always has typescript as a devDependency, and the scan container is
        # OFFLINE, where `npx --yes` would try to fetch and fail. npx stays as
        # the last resort rather than the default.
        compile_cmd=(
            'TSC="$(command -v tsc 2>/dev/null)"; '
            '[ -n "$TSC" ] || [ ! -x /target/node_modules/.bin/tsc ] || '
            'TSC=/target/node_modules/.bin/tsc; '
            '[ -n "$TSC" ] || [ ! -x ./node_modules/.bin/tsc ] || '
            'TSC=./node_modules/.bin/tsc; '
            '[ -n "$TSC" ] || TSC="npx --yes tsc"; '
            '$TSC poc.ts --outDir . --module commonjs --target es2020 '
            '--skipLibCheck --esModuleInterop'
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
            "compiles nothing and proves nothing. "
            "VERIFIED RECIPE (works offline inside the scan image, because "
            "provisioning already primed the maven cache): "
            "`cp -a /target /tmp/t && cd /tmp/t && "
            "mvn -q -B -o -DskipTests package` then "
            "`CP=/tmp/t/target/classes`. Copy first: /target is mounted "
            "READ-ONLY and maven writes target/. Add third-party jars with "
            "`mvn -q -B -o dependency:build-classpath "
            "-Dmdep.outputFile=/tmp/cp.txt` and "
            "`CP=/tmp/t/target/classes:$(cat /tmp/cp.txt)`. Use `-o` "
            "(offline) — the container has no network. Gradle: "
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
        # COMPILE FIRST, then run the produced binary. `go run` would compile
        # inside the traced process, and the toolchain's own execve/openat then
        # satisfy the strace evidence markers unconditionally — every Go PoC
        # would "prove" process spawn whether or not the sink ever fired.
        # Building first means the trace covers ONLY the PoC's own behaviour.
        compile_cmd="go build -o vash_poc ./vashpoc",
        run_cmd="./vash_poc",
        observer=STRACE_OBSERVER,
        deps_hint=(
            "Module context is everything: Go resolves imports against the "
            "go.mod of the directory it builds in, so a poc.go in the scratch "
            "dir cannot import the target's packages. /target is mounted "
            "READ-ONLY, so do NOT try to mkdir inside it — copy the module out "
            "first:\n"
            "  cp -a /target /tmp/vashtgt && mkdir -p /tmp/vashtgt/vashpoc && "
            "cp poc.go /tmp/vashtgt/vashpoc/ && cd /tmp/vashtgt && "
            "go build -o vash_poc ./vashpoc && ./vash_poc\n"
            "That reuses the module's already-downloaded dependencies (the "
            "module cache is outside /target) and needs no network. Declare "
            "`package main` in poc.go. `head -1 /target/go.mod` gives the "
            "module path to import; `go env GOMODCACHE GOFLAGS` shows the "
            "cache. Avoid `go mod tidy` — it wants the network. Build and run "
            "as two steps: it keeps the observer's trace clean and it "
            "separates a COMPILE failure (your PoC is wrong) from a RUNTIME "
            "result (the finding is real or not)."
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
        # strace, not dotnet-trace: EventPipe tooling is a global tool absent
        # from the SDK image and its install needs the network, whereas the scan
        # image ships strace. VERIFIED in the dotnet SDK image — a
        # Process.Start sink produced
        # execve("/bin/sh", ["-c", "echo building report for x; id; ..."]).
        observer=STRACE_OBSERVER,
        deps_hint=(
            "/target is mounted READ-ONLY: build the scratch project in the "
            "scratch dir (as compile_cmd does) or under /tmp — never inside "
            "/target, which fails with EROFS. Set TARGET_CSPROJ first: "
            "`TARGET_CSPROJ=$(find /target -name '*.csproj' | head -1)`; the "
            "project reference is what puts the target's own types on the "
            "compile path. `dotnet new`/`dotnet add reference` trigger a NuGet "
            "restore, which needs the network on a cold cache — if the "
            "container is offline, skip the scratch project and reference the "
            "assemblies the Phase 2 build already produced "
            "(`find /target -path '*/bin/*' -name '*.dll'`) via an explicit "
            "<Reference><HintPath> in the csproj, or PoC against the target's "
            "own test project with `dotnet test --no-restore --no-build`. "
            "REFERENCE THE ASSEMBLY UNDER bin/, NOT obj/: "
            "`find /tmp/t -name '<Target>.dll' -path '*bin/Release*'`. The "
            "obj/**/ref and obj/**/refint copies are REFERENCE assemblies and "
            "throw `BadImageFormatException: Cannot load a reference assembly "
            "for execution` at run time — a bare `find -name '*.dll'` walks "
            "straight into this. "
            "The observer is strace (syscall level), not dotnet-trace: "
            "EventPipe tooling is a global tool absent from the SDK image and "
            "installing it needs the network, while the scan image ships "
            "strace. VERIFIED: a Process.Start sink produced "
            "execve(\"/bin/sh\", [\"-c\", \"echo ...; id; ...\"]). Also "
            "assert on the artefact inside the PoC (the file written, the "
            "process started) and print your own marker line — belt and "
            "braces, since strace needs CAP_SYS_PTRACE."
        ),
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Selection / materialization
# ─────────────────────────────────────────────────────────────────────────────

def runtime_for(languages: list[str],
                project_env: dict | None = None) -> Runtime | None:
    """Pick the Runtime for a Hunt task, or None when nothing matches.

    The TASK's own languages win. They come from `detect_languages(
    task.target_files)` — the actual files this hunt is about, and the file the
    sink lives in is the file the PoC must exploit. Letting the repo-wide
    `primary_language` outrank them handed a Hunt task that explicitly targets a
    `.java` sink in a Python-majority polyglot repo the Python recipe: `poc.py`,
    `python3`, and an audit hook that can never see a JVM.

    `project_env` (Phase 2's `ProvisionResult.agent_summary()`, which the agent
    already sees as `project_environment`) is the FALLBACK: repo-wide evidence
    for when the task's own files say nothing useful — a task scoped to a
    template, a config file, or a language Phase 3 does not cover.

    Returning None is a normal outcome (COBOL, templates, a language Phase 3
    does not cover). Callers must degrade to a static, unexecuted PoC.
    """
    for lang in languages or ():
        rt = RUNTIMES.get(lang)
        if rt is not None:
            return rt
    if project_env:
        primary = project_env.get("primary_language")
        if primary and primary in RUNTIMES:
            return RUNTIMES[primary]
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
    # A scratch dir can be reused across resumes. If something left a SYMLINK
    # at the asset path, both the exists() probe and the write would follow it
    # and land outside scratch_dir — so replace a symlink rather than write
    # through it. (`is_symlink` does not follow; `exists` does.)
    if dest.is_symlink():
        dest.unlink()
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
        # Resolve {observer} to the ABSOLUTE materialized path so the wrap
        # survives the `cd /target` that deps_hint often calls for. Un-
        # materialized (the text-only path) falls back to the bare asset name,
        # which is all that can honestly be promised without a real scratch dir.
        wrap = rt.observer.wrap
        if "{observer}" in wrap:
            if files:
                asset_path = str(files[0].resolve())
            elif rt.observer.asset:
                asset_path = str(Path(scratch_dir) / Path(rt.observer.asset).name)
            else:
                asset_path = ""
            wrap = wrap.replace("{observer}", asset_path)
        observer = {
            "name": rt.observer.name,
            "kind": rt.observer.kind,
            "wrap": wrap,
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
