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
- **Phase 3 (open)**: per-language PoC observers (JFR/async_hooks/strace) + the `vash poc --run-id` command
  (spec: `docs/superpowers/specs/2026-07-26-vash-poc-command-design.md`). C/C++ deferred entirely per user.

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
