# VASH — Vanguard Agentic Security Harness

Production Python vulnerability scanner. **Forked from evilsocket/audit** (MIT, 8-stage LLM pipeline) and
grafted with the best mechanisms from **Capital One VulnHunter** and **Visa VVAH** (both Apache-2.0).
Repo: `/Users/snatarajan14/vash` (was `~/audit`; renamed 2026-07-24). Branch: `evolve/vulnhunter-imports`.
Tests: ~606 passing (offline, no network). Package + CLI: `vash`.

## Donor policy (HARD RULE)
Reuse ONLY from **audit, VulnHunter (`~/VulnHunter`), VVAH (`~/visa-harness`)**. **ai-proofscan is FORBIDDEN
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
V8 taint + F3 sink-backward. Decoupled commands: `vash run` / `vash remediate` / `vash validate`.

## How to run (Docker, the real way)
Auth into the container needs a container-passable token (macOS Keychain can't cross into Linux):
`claude setup-token` → `export CLAUDE_CODE_OAUTH_TOKEN=...`. Then:
`./scripts/run-in-docker.sh .bench-targets/dmcg-src <run-id> --max-concurrency 4`
(or `docker build -t vash:latest .` then `docker run -d ... vash:latest run --repo /target ...`).
Container has Node + the `claude` CLI (the SDK shells out to it) + graphify. Inside a container `/.dockerenv`
makes `is_sandboxed()` true → PoC execution enabled. Model tiers (config/stages.yaml): Opus 4.8 for
recon/validate/trace, Sonnet 5 for the rest.

## Benchmark result (datamodel-code-generator 0.55.0, 11 in-version CVEs) — 2026-07-25
Ran all three tools, same target, same models, same Docker-sandbox, same scorer (class+file-hint, greedy 1:1).
**Fair basis = DELIVERED output** (each tool's report/SARIF after its own dedup):

| DELIVERED recall | cost | notes |
|---|---|---|
| **VVAH 4/11** 🏆 | ~3hr/7.2M tok | scans `.jinja2` TEMPLATES (unique win 54621) + clean http SSRF (54690); 6 chains |
| audit 2/11 | $48 | cheapest, lean 8-stage LLM |
| VASH 2/11 | $96 | confirms 6/11 internally but delivers 2 (D8 bug); 5 chains; 2× cost |

ai-proofscan baseline = 6/11. **VASH lost on delivery, NOT detection** — its pipeline confirmed 6/11
true-positives (54655,54690,54691,55415,55389,55391) but dedup/report (D8) discarded 4 before the report.
Do NOT rank on "pre-dedup confirmed" cross-tool (VVAH's pre-dedup 97-candidate set is unavailable — only its
final 20). Full write-up: `docs/BENCHMARK-COMPARISON.md` (+ .pdf). Per-tool PDFs:
`results/dmcg-fix/VASH-dmcg-fix-report.pdf`, `~/audit-orig/audit-dmcg-report.pdf`, VVAH `.md`/`.sarif` in `~/vul_testing/`.

## Fix backlog (`docs/DISCREPANCIES.md`) — to beat VVAH
- **D8 (TOP, cheap, no re-scan):** report/dedup discards confirmed corpus matches (delivers 2 of 6 detected).
  Fix canonical-selection so the report keeps its real hits. Could move delivered recall 2→~6/11. *Prove by
  re-scoring the fixed report — do not assume.*
- **D7:** scan template files (`.jinja2`/`.mako`/`.j2`) in `find_sinks` — VVAH's unique win (54621) lives there.
- **D6:** cost — deterministic engine doubled hunt tasks (71 vs 27) → $96. Cap taint/sink-backward counts;
  reduce gapfill/feedback iterations (gapfill already 2→1); an API key kills the D3 rate-limit retries.
- **D3:** subscription-token rate-limiting at concurrency 4 → retries/failed tasks, stretched wall-clock.
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
