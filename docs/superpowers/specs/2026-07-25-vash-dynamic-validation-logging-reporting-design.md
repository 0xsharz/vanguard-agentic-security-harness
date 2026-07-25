# VASH — Dynamic Validation, Rich Logging & VVAH/GHSA Reporting — Design

**Status:** approved (design) — 2026-07-25
**Branch:** `evolve/vulnhunter-imports`
**Repo:** `/Users/snatarajan14/my_backup/vash` (moved here 2026-07-25)

## Goal

Three cohesive upgrades to VASH's run → report flow:

1. **`--dynamic-validation`** — an explicit CLI opt-in that enables the executed-PoC (sandboxed) stage. Default is static-only, always (even in Docker).
2. **Rich run logging** — a fail-soft progress reporter: per-stage banners, live counters, per-confirmed-finding lines, and a final summary table; degrades to clean plain lines when detached/non-TTY.
3. **VVAH/GHSA-style report** — a deterministic Markdown renderer producing a detailed report (Summary → Scan Metrics → Threat Model → Verification → per-finding advisory blocks with GHSA sub-sections → Chains), fed by an enriched report payload. The raw `report.json` is kept unchanged.

## Architecture

VASH's 9-stage pipeline and static-first safety invariant are unchanged. Execution of target code stays behind the sandbox gate — the new flag adds an **explicit second precondition** in front of it. Logging adds a presentation layer over existing `StateDB` state (no new data). Reporting extends the existing agent/schema plus a new pure renderer; nothing about how findings are produced changes.

## Tech Stack

Python 3.11, Click (CLI), `rich` (already a dependency, used by `vash/cli.py`'s `console`), the existing `claude_agent_sdk` runner, `StateDB` (SQLite). Tests: pytest, offline (no network/API).

## Global Constraints

- **Static-first safety invariant is inviolable:** no target code executes unless `--dynamic-validation` is set AND (`sandbox.is_sandboxed()` OR `--dangerously-no-sandbox`). Default (no flag) is static-only in every environment, including Docker.
- **Fail-soft everywhere additive:** logging and report-enrichment code must never break a run (wrap in try/except + log, like the existing `_attach_cwe`/`_attach_coverage`/`_attach_variants`).
- **Offline test suite is the gate:** ~619 existing tests must stay green; all new tests run offline (no network, no live API, no Docker).
- **Donor policy:** reuse only from audit / VulnHunter / VVAH. The report format is modeled on VVAH's `s7`/report output (allowed donor). **ai-proofscan is a forbidden donor** — never port its code/prompts.
- **Environment:** the repo was moved to `my_backup`, so `.venv` console-script shebangs are stale. Run tools via the venv interpreter, e.g. `/Users/snatarajan14/my_backup/vash/.venv/bin/python -m pytest` and `... -m vash`. (Optionally repair the venv, but `python -m` is the reliable path.)

---

## Feature 1 — `--dynamic-validation` (explicit executed-PoC opt-in)

### Current behavior
`vash/runner.py` (the R1 gate) strips `Bash` from a stage's tools whenever `sandbox.is_sandboxed()` is false. So execution is decided purely by environment detection: auto-on inside Docker/`VASH_SANDBOX=1`, static on a bare host. There is no explicit operator control and no fail-fast if execution was expected but unavailable.

### New behavior
Execution requires **two** conditions, decided once, centrally:

```
execution_enabled = bool(dynamic_validation and (sandbox.is_sandboxed() or allow_no_sandbox))
```

- **Default (no `--dynamic-validation`):** `execution_enabled = False` → static-only in every environment.
- **`--dynamic-validation` + sandbox (Docker/`VASH_SANDBOX=1`):** execution enabled.
- **`--dynamic-validation` + `--dangerously-no-sandbox`:** execution enabled on a bare host, after a loud warning (trusted-target dev escape; reuses `sandbox.require`'s existing warning).
- **`--dynamic-validation` on a bare host with neither:** **fail fast** — raise `SandboxError` at run startup with the remedy. Never silently downgrade to static (the operator explicitly asked for dynamic).

### Files & interfaces
- `vash/cli.py` — `run()` command: add
  - `--dynamic-validation` (`is_flag`, default `False`): "Enable the executed-PoC (sandboxed) validation stage. Default: static-only. Requires a sandbox (Docker/VASH_SANDBOX=1) or --dangerously-no-sandbox."
  - `--dangerously-no-sandbox` (`is_flag`, dest `no_sandbox`, default `False`): mirrors the existing `remediate` option — bypass the sandbox requirement with a loud warning (unsafe on untrusted targets).
  - Pass both into `run_pipeline(...)`.
- `vash/orchestrator.py` — `run_pipeline(...)` (currently at ~line 442): add params `dynamic_validation: bool = False`, `allow_no_sandbox: bool = False`. At startup, before any stage work:
  - Compute `execution_enabled` as above.
  - If `dynamic_validation and not execution_enabled`: `sandbox.require(allow_no_sandbox=allow_no_sandbox)` (raises `SandboxError` — fail fast). (`require` also emits the dev-escape warning when `allow_no_sandbox`.)
  - Set `ctx.execution_enabled = execution_enabled` on the `StageContext` (created at ~line 454).
  - Log the resolved mode once: `"[<run_id>] mode=<dynamic|static> (execution_enabled=<bool>, sandboxed=<bool>)"`.
- `vash/stages/_common.py` — `StageContext`: add field `execution_enabled: bool = False`.
- `vash/runner.py` — `run_agent(...)`: add param `execution_enabled: bool = False`. Replace the R1 gate's `not sandbox.is_sandboxed()` with `not execution_enabled`. Keep the existing "Bash stripped — static-only mode" log line, reworded to mention the flag. (The orchestrator has already enforced the sandbox precondition + fail-fast; the runner gate is defense-in-depth on the resolved boolean.)
- Stages that request `Bash` (**hunt, validate, trace, recon**) pass `execution_enabled=ctx.execution_enabled` into their `run_agent(...)` calls. Other stages may pass it for uniformity; it is a no-op when Bash isn't in their tools.
- `scripts/run-in-docker.sh` — append `--dynamic-validation` to the `vash run` invocation (Docker's purpose is executed-PoC; the wrapper opts in by default).

### Tests
- Gate matrix (unit, monkeypatching `sandbox.is_sandboxed`): `(dynamic_validation, sandboxed, allow_no_sandbox) → execution_enabled` for all 8 combinations, plus the fail-fast `SandboxError` case (`dynamic_validation=True, sandboxed=False, allow_no_sandbox=False`).
- `run_agent` strips `Bash` when `execution_enabled=False` and keeps it when `True` (assert on the `allowed_tools` actually passed to `_run_agent_once`, or via a seam).
- CLI: `vash run --dynamic-validation` on a non-sandboxed host exits non-zero with the remedy message; without the flag it proceeds (static).

---

## Feature 2 — Rich run logging (`vash/progress.py::RunReporter`)

### Design
A single fail-soft `RunReporter` wrapping a `rich.Console`, owned by the orchestrator for the run and reachable by stages via `ctx.reporter`. It is the **progress surface**; noisy per-task `log.info` lines drop to DEBUG. All counters are read from `StateDB` (authoritative), never recomputed.

TTY vs non-TTY (the operator runs detached to a file):
- **TTY (`console.is_terminal`):** live `rich` progress bars / status for the parallel stages, colored banners, a rendered summary table.
- **Non-TTY (detached/piped):** the same information as **throttled clean plain lines** — a stage banner per stage, a progress line every *K* task completions (not every task), each confirmed finding once, and a plain-text summary table. No ANSI live-refresh spam in the log file.

### Module API — `vash/progress.py`
```python
class RunReporter:
    def __init__(self, console: Console | None = None, run_id: str = "",
                 throttle: int = 5) -> None: ...
    def stage_start(self, name: str, *, model: str | None = None,
                    count: int | None = None) -> None: ...
    def task_done(self, stage: str, *, ok: bool = True,
                  done: int | None = None, total: int | None = None,
                  confirmed: int | None = None, cost: float | None = None) -> None: ...
    def finding_confirmed(self, *, severity: str, vuln_class: str,
                          file: str, line: int | None, confidence: float | None) -> None: ...
    def stage_end(self, name: str, **stats) -> None: ...
    def run_summary(self, db: "StateDB", run_id: str) -> None: ...
```
- Every method is wrapped so an internal error is logged and swallowed — the reporter must never raise into the pipeline.
- `throttle` controls the non-TTY progress-line cadence (print on every `throttle`-th `task_done`, plus always on stage boundaries).
- `run_summary` renders: findings by severity, validation-status counts (confirmed/rejected/needs_info/pending), coverage (files swept / total), total cost, wall-clock duration, and the top findings (file:line + class + severity).

### Wire-up — `vash/orchestrator.py`
- Instantiate `reporter = RunReporter(console, run_id)` in `run_pipeline`; set `ctx.reporter = reporter`.
- Call `reporter.stage_start(...)` / `reporter.stage_end(...)` around each of the 9 stages.
- In the hunt and validate loops, call `reporter.task_done(...)` per task and `reporter.finding_confirmed(...)` when a finding's validation is confirmed.
- At the end of `run_pipeline`, call `reporter.run_summary(db, run_id)`.
- `StageContext` gains `reporter: "RunReporter | None" = None` (typed loosely to avoid an import cycle; import under `TYPE_CHECKING`).

### Tests
- Non-TTY mode: feed a sequence of `stage_start`/`task_done`/`finding_confirmed`/`run_summary` with a `Console(file=StringIO, force_terminal=False)`; assert the expected banners, throttled progress cadence, the confirmed-finding line format, and the summary table content.
- Fail-soft: `run_summary` with a `db` whose call raises does not propagate; a `task_done` with `None`s does not raise.
- Throttle: with `throttle=5`, 12 `task_done` calls emit 2 progress lines (at 5 and 10) plus boundaries.

---

## Feature 3a — Report enrichment (schema + agent + deterministic attaches)

### Schema — `schemas/report.schema.json`
Add **top-level**:
- `threat_model` (object): `system_context` (str), `assets` (array of `{name, sensitivity, description}`), `trust_boundaries` (array of `{name, from, to, description}`), `ranked_threats` (array of `{id, threat, actor, surface, asset, impact, likelihood, controls}`), `open_questions` (array of str).
- `scan_metrics` (object): `files_in_scope`, `files_analyzed`, `coverage_pct`, `duration_sec`, `cost_usd`, `tokens_by_phase` (array of `{phase, calls, total}`). Deterministic — sourced from run state.
- `verification` (object): `raw_findings`, `true_positives`, `false_positives`, `needs_more_info`, `duplicates_collapsed`, `precision_pct`. Deterministic.

Add **per-finding** (`findings[].properties`) — `poc` and `recommendation` already exist:
- `cvss` (object): `score` (number), `severity` (str), `vector` (str, CVSS 3.1 vector).
- `impact` (str), `exploit_scenario` (str), `preconditions` (array of str), `how_to_fix` (str).
All new fields optional (`additionalProperties` already governs); back-compat preserved.

### Agent — `prompts/08-report.md`
Instruct the report agent to emit, per finding: a CVSS 3.1 vector + score consistent with the severity and vuln class, an `exploit_scenario`, `preconditions`, `how_to_fix`, and to reuse/keep `poc`. Add a top-level `threat_model` section (system context, assets, trust boundaries, ranked threats, open questions) synthesized from the recon/finding context already in `user_input`. Keep output strictly schema-valid.

### Deterministic attaches — `vash/stages/report.py`
Mirror the existing fail-soft `_attach_*` pattern (sourced from run state, injected post-hoc, never agent-trusted):
- `_attach_scan_metrics(db, run_id, payload)` — files in scope/analyzed + coverage% (from `db.get_coverage` / inputs), duration (run started/finished), cost (`db` cost records), tokens by phase (cost records' usage).
- `_attach_verification(db, run_id, payload)` — `raw_findings` = all findings; `true_positives` = confirmed; `false_positives` = rejected; `needs_more_info`; `duplicates_collapsed` = grouped non-canonical count; `precision_pct`.
- `_attach_cvss(db, run_id, payload)` — **fallback only**: if a finding lacks `cvss`, compute a baseline vector+score from `(vuln_class, severity)` via a small deterministic map (e.g. code_injection/critical → `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, 10.0). Never overwrites an agent-provided `cvss`.
Call all three in both the success and fallback paths of `run_report` (alongside the existing `_attach_cwe`/`_attach_coverage`/`_attach_variants`).

### Tests
- Schema accepts a payload carrying every new field; still rejects a genuinely malformed one.
- Each `_attach_*` populates correctly from a seeded in-memory `StateDB`; each is fail-soft (a raising `db` leaves the payload emittable).
- `_attach_cvss` fills a baseline for a finding without `cvss` and leaves an agent-provided `cvss` untouched.

---

## Feature 3b — VVAH/GHSA Markdown renderer (`vash/reporting/markdown.py`)

### Design
A **pure, deterministic** function assembling the detailed report from an enriched `report.json` (plus optional `db` for anything not embedded). Same input → identical output. The raw `report.json` is unchanged and remains the machine-readable artifact.

```python
# vash/reporting/__init__.py, vash/reporting/markdown.py
def render_report(report: dict, db: "StateDB | None" = None,
                  run_id: str | None = None) -> str: ...
```

### Sections (modeled on the VVAH reference report + GHSA advisory)
1. **Title** — `# Agentic SAST — <target module/repo>`.
2. **Summary** — executive prose (from `summary`/agent) + severity tallies.
3. **Scan Metrics** — from `scan_metrics`: files in scope/analyzed, coverage %, duration, cost, and a tokens-by-phase table.
4. **Threat Model** — from `threat_model`: system context, Assets table, Trust boundaries list, Ranked threats table, Open questions.
5. **Verification** — from `verification`: raw / true-positive / false-positive / needs-info / duplicates-collapsed / precision.
6. **Findings (N)** — each finding rendered VVAH-style:
   `### n. [SEVERITY] title` → Class/CWE (+ mitre link) → File → CVSS 3.1 (score + vector) → Confidence → "Also at:" (from `variants`) → **Description** → **Impact** → **Exploit scenario** → **Preconditions** → fenced code/evidence → **How to fix** (from `how_to_fix`, else `recommendation`) → **Adversarial verification** (from `validation`/validation_json).
   Followed by a **GHSA-style Advisory** sub-block: **Summary**, **Details**, **Proof of Concept** (from `poc`), **Impact** (CWE-tagged), **Affected / Patched versions** (rendered "Not determined — static analysis"), **Weaknesses** (CWE + link), **References** (CWE link; advisory URL placeholder).
7. **Exploit chains** — from `chains`, if any.

Missing/blind-unknowable fields render as explicit "Not determined (static run)" rather than being omitted silently.

### Wire-up
- `vash/stages/report.py::run_report` — after writing `report.json`, call `render_report(payload, db, ctx.run_id)` and write `results/<run_id>/report/report.md` (fail-soft; a render failure logs and leaves `report.json` intact).
- `vash/cli.py` — `report --format md` calls `vash.reporting.markdown.render_report(payload, db, run_id)`. Replace the thin `_render_markdown_report` body with a delegation to the new renderer (or remove it and call the new one).

### Tests
- Golden-ish: a fixture enriched `report.json` renders a markdown string containing every section header, a per-finding CVSS vector line, an "Also at:" line when variants exist, and the GHSA Advisory sub-block headers.
- Determinism: two calls on the same input produce byte-identical output.
- Empty findings: renders Summary + Scan Metrics + a "no reachable findings" note without error.
- `render_report` never raises on a minimally-valid payload missing optional sections (renders "Not determined" placeholders).

---

## Task breakdown (for the implementation plan)

1. **F1 — dynamic-validation gate:** CLI flags → `run_pipeline` precondition (`execution_enabled`, fail-fast `sandbox.require`) → `StageContext.execution_enabled` → `runner.run_agent` gate → stage call-sites → `run-in-docker.sh`. Tests: gate matrix + fail-fast + runner strip.
2. **F2 — RunReporter:** new `vash/progress.py` (TTY/non-TTY, throttled, fail-soft) → orchestrator wire-up (stage/task/finding/summary) → `StageContext.reporter`. Tests: non-TTY output, throttle, fail-soft.
3. **F3a — report enrichment:** `report.schema.json` new fields → `prompts/08-report.md` → `report.py` deterministic `_attach_scan_metrics`/`_attach_verification`/`_attach_cvss`. Tests: schema, attaches, cvss fallback.
4. **F3b — Markdown renderer:** new `vash/reporting/markdown.py::render_report` → `report.py` writes `report.md` → `cli.py report --md` delegates. Tests: sections, determinism, empty, fail-soft.

Order: F1 → F2 → F3a → F3b (F3b consumes F3a's fields; F1/F2 are independent and could be either first).

## Non-goals / YAGNI

- No live-target auto-exploitation beyond the existing PoC mechanism; `--dynamic-validation` only toggles the existing sandboxed execution.
- No in-tool PDF generation (the delivered PDFs are a separate, ad-hoc pipeline).
- No CVE-feed / advisory-database lookups; Patched-version, Credits, and exact Affected-range are rendered "Not determined (static run)".
- No change to the 9-stage pipeline structure, the graph engine, or how findings are produced/validated.
- No new external dependencies (`rich` is already present).

## Environment notes

- Work in `/Users/snatarajan14/my_backup/vash` on branch `evolve/vulnhunter-imports`.
- Run tests/tools via `/Users/snatarajan14/my_backup/vash/.venv/bin/python -m pytest` (stale console-script shebangs after the move).
- All new tests offline; keep the ~619-test suite green.
