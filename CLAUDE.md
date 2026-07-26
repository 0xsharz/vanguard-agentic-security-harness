# VASH — Vanguard Agentic Security Harness

Production Python vulnerability scanner. **Forked from evilsocket/audit** (MIT, 8-stage LLM pipeline) and
grafted with the best mechanisms from **Capital One VulnHunter** and **Visa VVAH** (both Apache-2.0).
Repo: `~/my_backup/vash` (was `~/audit` → `~/vash`; moved under `my_backup/` in the 2026-07-26 laptop
migration). Branch: `evolve/vulnhunter-imports`. Tests: 717 passing, 1 skipped (offline, no network).
Package + CLI: `vash`. Python 3.11 is provided by `uv` (`~/.local/bin/uv`); rebuild the venv with
`uv venv --python 3.11 && uv pip install -e '.[dev]'`.

## Donor policy (HARD RULE)
Reuse ONLY from **audit (`~/my_backup/audit-orig`), VulnHunter (`~/my_backup/VulnHunter`), VVAH
(`~/my_backup/visa-harness`)**. **ai-proofscan is FORBIDDEN
as a donor** (user directive 2026-07-24) — never port its code/prompts. If a plan step points at ai-proofscan,
re-source from the 3 allowed tools or author fresh. (F5 was rebuilt off VulnHunter after an ai-proofscan slip.)
Attribution: `NOTICE` + `THIRD_PARTY_LICENSES.md` (Task 4.8). Benchmark corpus in `bench/ground_truth/` is
real CVE test-data transcribed from ai-proofscan's benchmark (data, not a technique) — flagged, kept.

## Architecture (the key identity)
**Static recall + sandboxed executed-PoC confirmation.** Broad static hunting for recall; then Hunt
**executes a real PoC per candidate in a sandbox** and drops non-reproducing findings (zero-FP mechanism —
30/31 findings had `poc_succeeded=1` on the dmcg run). **This executed-PoC confirmation is VASH's key
differentiator — VVAH and audit are static-only and cannot do it.** Safety: `vash/runner.py` **strips `Bash`
unless `sandbox.is_sandboxed()`** (container/`VASH_SANDBOX=1`), so on a bare host VASH is fully static and
never executes untrusted code; inside Docker it runs PoCs. Pipeline (9 stages): recon → hunt → validate →
gapfill → dedupe → trace → feedback → chain → report, plus a deterministic **graphify call-graph** feeding
V8 taint + F3 sink-backward. Decoupled commands: `vash run` / `vash remediate` / `vash validate` / `vash provision`.

## Multi-language provisioning (plan `docs/superpowers/plans/2026-07-26-vash-multilang-provisioning-phase1.md`)
- **Phase 1 DONE** (`fac07df..b497d02`): `vash/provision/fingerprint.py` (languages/build-systems/version-pins/
  existing recipes) + `dockerfile.py` (per-ecosystem template, text only) + `SINKS_BY_LANG` in `taint.py`
  (JS/TS, Java, Go, C#; Python byte-for-byte unchanged).
- **Phase 2 DONE**: `provision/build.py` (`docker build` fed on stdin + verify + retry) and
  `provision/repair.py` (deterministic repair ladder, 6 rungs, each fires at most once). Wired as
  **orchestrator Stage 0** (`_provision_environment`, fail-open, pre-recon): always fingerprints+renders
  (free, offline, no Docker); builds ONLY with `vash run --provision`. Environment facts ride to every agent
  via `ctx.project_env` → `extras()["project_environment"]`; full record at
  `results/<run>/provision/provision.json`. Isolation: the target's own build instructions run INSIDE a
  container, never on the host; verify uses `--network none` + `no-new-privileges` + cpu/mem/pid caps.
  Verify probes **dependency presence** — an image that builds but lacks the target's deps is reported
  INCOMPLETE, not success (this caught a real Phase-1 template bug: `pip install -e . || pip install -r
  requirements.txt` short-circuited and left deps uninstalled).
- **Phase 3 IN PROGRESS — Python DONE + PROVEN** (`fdb29f7..c91c086`). USER DIRECTIVE 2026-07-26: language
  support must be **IN THE PIPELINE FLOW — no decoupled command**. A `vash poc` command was built from the
  approved spec and then **reverted at user request** (do not rebuild it; the spec is stale on this point).
  - `vash/lang/poc_runtime.py` — per-language Runtime registry (python/js/ts/java/go/csharp): poc filename,
    compile/run cmds, `deps_hint` (how to reach the TARGET's deps). `vash/lang/observers/` — real assets:
    PEP-578 audit hook (python) + node `--require` preload; JFR/strace are recipes.
  - `hunt.py` injects `poc_execution` + materializes the observer **only when `execution_enabled`** (bare-host
    static path byte-for-byte unchanged). Fail-open.
  - **THE KEY ARCHITECTURAL FIX** (`vash/provision/scan_image.py`, `vash provision --scan-image`): the scan used
    to run in `vash:latest`, which has **no javac/java/mvn/go/dotnet/strace and no docker socket** → every
    non-Python recipe died at `command not found`, and Python only worked by luck (target imports that
    succeeded — yaml, pydantic — are VASH's OWN deps). Fix inverts the layering:
    `vash-scan-<target>` = the Phase 2 provisioned image + VASH. Docker-socket mounting was REJECTED
    (root-equivalent on host, destroys the isolation claim). **LOAD-BEARING: VASH's venv must NEVER be on
    PATH** — with it on PATH `python3` resolves to VASH's interpreter and the target is invisible
    (`import app.reports` → ModuleNotFoundError); VASH is invoked by absolute path.
  - `report.py::_attach_poc_evidence` — the executed-PoC receipt + `[VASH-OBSERVER]` marker lines now reach
    `report.json` (previously: 5 delivered findings, all `poc_succeeded=1`, zero evidence in the report).
  - **LIVE PROOF** (`vulnpy1`, 2026-07-26, $9.17 / 17m14s, in `vash-scan-vuln-py`): found BOTH planted bugs
    (CWE-78 cmd-injection, CWE-502 unsafe yaml) + 3 unplanted real ones (CWE-306 no-auth, CWE-400 DoS proven
    with a 19s block, CWE-674); 5 delivered, **all `poc_succeeded=1`**; 3 exploit chains incl. "missing auth +
    injection = unauthenticated RCE". Targets live in `scratchpad/vulntargets/` (py/node-cjs/node-esm/java/go).
  - **Honesty rules (tested, load-bearing)**: an observer is corroboration NEVER a verdict; and a missing
    **toolchain** is not a failed exploit — the pre-existing "drop the finding" rule would otherwise have
    silently deleted real findings on every Java target.
  - **ALL SIX REVIEW BUGS FIXED** (`0b9efd6`): observer path now absolute (`{observer}` substituted by
    `poc_execution_block`) so a `cd /target` can't break it; `runtime_for` now prefers the TASK's own file
    language (project_env is fallback); the python hook applies leading `NAME=VALUE` argv tokens (its own
    deps_hint documents `PYTHONPATH=/target python3 poc.py`, which used to exit 2 without running the PoC);
    Go compiles first and traces only the built binary (tracing `go run` made the COMPILER satisfy the
    markers → every Go PoC "proved" process spawn); no recipe writes into read-only `/target`;
    `materialize_observer` no longer follows symlinks.
  - **ATTRIBUTION** (`9aee06d`) — the design risk I flagged before building observers: a marker alone only
    says "a process spawned", which innocent code does too; read as proof it yields CONFIDENT false
    positives. Every marker now carries `<- from file:line` (Java gets it free from JFR's stackTrace).
    Interpreter/stdlib frames skipped (the nearest frame to `subprocess.run` is always
    `subprocess.py:_execute_child` — useless); the PoC is deliberately NOT skipped, because attribution to
    the PoC means the PoC hit the sink directly and proves NOTHING about the target. Prompt teaches this.
  - **ALL 4 OBSERVERS VERIFIED against real targets**: python audit-hook; node preload (**ESM works** — my
    and the reviewer's ESM concern was empirically WRONG: `--require` runs before ESM bindings exist);
    java JFR (**best evidence of all** — stackTrace names `ReportService.buildReport line 10`); go strace
    (needed BOTH `strace` installed in the scan image AND `--cap-add=SYS_PTRACE`, now in run-in-docker.sh).
    C# ships no observer, honestly.
  - **LIVE RUNS — every language found its planted bug AND proved it by execution** (targets in
    `scratchpad/vulntargets/`; self-authored, so they validate MACHINERY not recall — never quote as a
    recall number):

    | run | target | planted bug delivered | evidence | cost/time |
    |---|---|---|---|---|
    | `vulnpy1` | python | CWE-78 + CWE-502, both critical | audit-hook `subprocess.Popen`/`os.system` | $9.17 / 17m |
    | `nodecjs1` | node cjs | CWE-78 critical | `child_process.execSync`; one PoC ran end-to-end through the HTTP server | $5.32 / 14m |
    | `java1` | java | CWE-78 critical | **JFR stackTrace naming `ReportService.buildReport line 10`** | $7.41 / 16m |
    | `go1` | go | CWE-78 critical | strace execve chain → `sh -c ...; id` | $5.06 / 12m |
    | `cs1` | csharp | CWE-78 critical (conf 0.99) | strace execve + `uid=0(root)` | ~$5 |

    Each run also surfaced REAL unplanted bugs (no-auth endpoint, single-threaded-server DoS proven with a
    19s stall, terminal-escape injection, never-reaped child processes) and built exploit chains
    ("missing auth + injection = unauthenticated RCE").
  - **Per-language status (all observers VERIFIED by hand in the real scan image):**

    | lang | poc | compile | observer | evidence quality |
    |---|---|---|---|---|
    | python | poc.py | – | PEP-578 audit hook | events + `<- from` attribution |
    | javascript | poc.js | – | node `--require` preload | events + attribution; **ESM covered** |
    | typescript | poc.ts | local `tsc` (npx last resort — container is OFFLINE) | node preload | as JS |
    | java | PoC.java | `javac -cp $CP` | **JFR** | **best: stackTrace names the sink method** |
    | go | poc.go | `go build` (never `go run` — traces the compiler) | strace | execve chain |
    | csharp | Poc.cs | `dotnet build` | strace | execve chain; ref bin/ NOT obj/**/refint |

  - **Gotchas worth remembering**: `/target` is READ-ONLY → Go/C#/JS recipes copy to /tmp first;
    Debian bases (node/golang) have a python3.11 whose `venv` is broken → scan-image probe ATTEMPTS a venv
    then falls back to uv; C# `find -name '*.dll'` hits `obj/**/refint` reference assemblies →
    `BadImageFormatException` at run time.
  - **NEXT after live runs**: consider rebuilding py/node scan images to pick up attribution; a real CVE
    benchmark re-run (dmcg 5/11) has NOT been done since Phase 2 added `project_environment` to prompts —
    unmeasured, and the only open risk to the published recall number.
- C/C++ deferred entirely per user.

## How to run (Docker, the real way)
Auth into the container needs a container-passable token (macOS Keychain can't cross into Linux):
`claude setup-token` → `export CLAUDE_CODE_OAUTH_TOKEN=...`. Then:
`./scripts/run-in-docker.sh .bench-targets/dmcg-src <run-id> --max-concurrency 4`
(or `docker build -t vash:latest .` then `docker run -d ... vash:latest run --repo /target ...`).
Container has Node + the `claude` CLI (the SDK shells out to it) + graphify. Inside a container `/.dockerenv`
makes `is_sandboxed()` true → PoC execution enabled. Model tiers (config/stages.yaml): Opus 4.8 for
recon/validate/trace, Sonnet 5 for the rest.

## Benchmark result (datamodel-code-generator 0.55.0, 11 in-version CVEs) — 2026-07-25 (POST-FIX)
Same target, same models, same scorer (`bench/scorer.py::score_corpus`, class+file-hint, greedy 1:1).
**Fair basis = DELIVERED output**, static (VVAH is 100% static too):

| DELIVERED recall | cost | notes |
|---|---|---|
| **VASH 5/11 (0.455)** 🏆 | ~2.5hr / $103 | AFTER D8+D7 fixes; delivered BOTH template CVEs 54621+54654 + 54653/54690/55389; 5 chains |
| VVAH 4/11 | ~3hr | static; templates (only 54621) + http SSRF; 6 chains |
| audit 2/11 | $48 | cheapest, lean 8-stage LLM |

**VASH now BEATS VVAH.** Decisive edge = **D7 template scanning** (coverage 50→70 files; both `.jinja2` CVEs vs VVAH's one).
Proven progression: old VASH **2/11** → **4/11** (D8 per-file-canonical, re-scored on the same 45 confirmed → recovered
54690+55415) → **5/11** (D8+D7 fresh host-static run `dmcg-outperform`). Caveats: E is host-static (20 extras unfiltered
by executed-PoC; VVAH also static, 16 extras); fresh hunt is stochastic (gained templates+msgspec, missed 54655/55415
that the Docker set had). A **Docker run (D7 + executed-PoC)** would likely reach ~6–7/11 with PoC-filtered precision —
deferred until a container token is minted. ai-proofscan baseline = 6/11. Full write-up: `docs/BENCHMARK-COMPARISON.md`.

## Fix backlog — status (see `docs/superpowers/plans/2026-07-25-vash-outperform.md`)
- **D8 DONE + PROVEN** (`dedupe.py`): per-file canonical promotion (one canonical per (group, distinct file)) +
  dict.fromkeys dup-guard. Re-scored 2→4/11 on the same confirmed set. Also A2 (`report.py::_attach_variants`)
  VVAH "Also at:" located variant evidence.
- **D7 DONE + PROVEN** (`orchestrator.py::_sweepable_source_files`): catch-all now sweeps templates/IaC (EXT_TO_LANG +
  is_iac via hardened `safe_walk_files`), not just `.py`. Coverage 50→70; delivered both `.jinja2` CVEs → 5/11.
- **C1 DONE** (`taint.py`): narrow CWE-200 `information_disclosure` sink + hunt framing (55403 not yet delivered).
- **D1 DEFERRED**: validate PoC-succeeded guardrail — moot on host-static; Docker-PoC-only.
- **D6 (open):** cost still ~$100/run (Opus recon+trace). Cap trace/taint counts if needed. **D3 (open):** subscription
  rate-limits; an API key would remove retry stretch. Background-runtime cap on host → run via detached `--resume`.
- Still open to push past 5/11: **Docker run (D7 + executed-PoC)** for ~6–7/11 + zero-FP precision (needs token);
  hunt robustness for the stochastic 54655/55415 misses.
- Closed: **D1/D2** (graphify emitted package-relative node paths → mismatch with recon → taint produced 0
  tasks; fixed in `vash/graph/build.py::_rebase_to_repo_root` — inputs 0→21/21, sinks 0→62, taint 0→11).
  **D4** (report dropped `cwe` → scorer couldn't class-match; fixed via `report.py::_attach_cwe`).
  **D5** (false alarm — PoCs DO execute; I'd mis-checked the report which strips `poc`).

## Strategic direction (agreed with user)
**Keep VASH as base; treat VVAH as a donor, not a replacement.** VASH's executed-PoC + graph engine +
decoupled commands + owned MIT code are worth protecting. Path: fix D8 → D7 → D6, port VVAH's template
scanning + clean delivery, re-benchmark. VVAH-as-base only makes sense if going static-only + forking Visa's tool.

## Facts about the donors (verified from source)
- **VVAH is 100% static** — agents are deny-by-default Read/Glob/Grep, Bash cannot execute (`backends/agent_sdk.py`);
  no online/CVE-feed lookups (has an optional operator-supplied offline CVE injector, unused here). Its edge:
  it scans template files + delivers cleanly. It writes PoC scripts but never runs them.
- **audit** = lean 8-stage LLM, no graph/templates/execution — cheap baseline.

## Working conventions
- Static-first on a bare host; execution ONLY inside the sandbox via `sandbox.require()`/the runner Bash-gate.
- Build features via subagent-driven-development (fresh implementer per task, review between); ledger at
  `.superpowers/sdd/progress.md` (git-excluded).
- Offline test suite is the gate for every change; live recall measured via a Docker run + `bench` scorer.
- Never execute the target's untrusted code outside the sandbox.
