# audit — wiring notes

Reference map: stage → prompt → schema → DB, the CLI, schemas, and config knobs.
Terse by design; read the source at the cited paths for behavior detail.

Package root: `audit/audit/` (installed as `audit`; console-script `audit = audit.cli:main`,
also runnable as `python -m audit` via `audit/audit/__main__.py`).

## 1. Stage table (all 8, pipeline order per `orchestrator.py:run_pipeline`)

Order: Recon → (Hunt → Validate → Gapfill)×N → Dedupe → Trace → (Feedback → Hunt → Validate
→ Dedupe → Trace)×M → Report. N = `gapfill_iterations`, M = `feedback_iterations` (config/stages.yaml `loops:`).

| # | Stage | Driver fn | Prompt file | Schema file | DB reads | DB writes | Output shape |
|---|---|---|---|---|---|---|---|
| 1 | Recon | `stages/recon.py:run_recon` | `01-recon.md` | `recon_output.schema.json` | `get_recon_output` (skip if already done) | `save_recon_output`; `add_task` per `payload["initial_tasks"]`; `record_cost`, `add_artifact` | `{subsystems[], architecture{}, initial_tasks[]}` |
| 2 | Hunt | `stages/hunt.py:run_hunt` | `02-hunt.md` | `finding.schema.json` (= HuntOutput) | `get_pending_tasks`, `get_recon_output` | `update_task_status` (running/done/failed/pending), `add_finding` per finding, `record_cost`, `add_artifact` (jsonl + scratch_dir) | `{task_id, findings[], gaps_observed[]}` |
| 3 | Validate | `stages/validate.py:run_validate` | `03-validate.md` | `validation.schema.json` | `get_unvalidated_findings`, `get_all_tasks` (for task context) | `set_finding_validation` (verdict + payload; failure → forced `needs_more_info`), `record_cost`, `add_artifact` | `{finding_id, verdict, rationale, alternative_explanation?, missing_preconditions?, suggested_test?, validator_confidence}` |
| 4 | Gapfill | `stages/gapfill.py:run_gapfill` | `04-gapfill.md` | `gapfill_output.schema.json` | `get_recon_output`, `get_all_tasks`, `get_findings` (counts per task) | `add_task` per new task (skips dup ids), `record_cost`, `add_artifact` | `{new_tasks[], coverage_analysis{light_subsystems[], unattempted_attack_classes[]}}` |
| 5 | Dedupe | `stages/dedupe.py:run_dedupe` | `05-dedupe.md` | `dedupe_output.schema.json` | `get_findings(validation_status="confirmed")` | `add_dedupe_group`, `assign_finding_group` (per member, canonical flag); on agent failure: 1 group per finding fallback; `record_cost`, `add_artifact` | `{groups[]: {group_id, root_cause, member_finding_ids[], canonical_finding_id, variant_summary?}}` |
| 6 | Trace | `stages/trace.py:run_trace` | `06-trace.md` | `trace.schema.json` | `get_findings(confirmed, canonical_only=True)`, `get_recon_output`, `get_trace` (resume check, per finding) | `add_trace` per finding (failure → conservative `reachable=false`), `record_cost`, `add_artifact` | `{finding_id, reachable, entry_points[]?, call_chain[]?, external_inputs[]?, confidence, rationale, blockers[]?}` |
| 7 | Feedback | `stages/feedback.py:run_feedback` | `07-feedback.md` | `feedback_output.schema.json` | `get_reachable_canonical_findings`, `get_recon_output`, `get_all_tasks` (existing-id dedup) | `add_task` per new task, `record_cost`, `add_artifact` | `{new_hunt_tasks[], rationale_per_task?}` |
| 8 | Report | `stages/report.py:run_report` | `08-report.md` | `report.schema.json` | `get_reachable_canonical_findings`, `_group_members_excluding` (raw SQL on `findings`) | `record_cost`, `add_artifact`; writes `results/<run_id>/report/report.json` to disk (not DB); empty-findings and agent-failure paths skip the agent call and write directly | `{run_id, target{repo_path,commit?}, summary{total, by_severity{}}, findings[]}` |

Concurrency: every stage's per-item fan-out uses `asyncio.Semaphore(sc.concurrency)` from
`StageConfig`, except Recon/Dedupe/Report/Gapfill which run as a single agent call.
`ctx.extras()` (from `stages/_common.py:StageContext`) merges `live_target`/`scope_notes` into
every stage's `user_input` when set. Cost/artifact bookkeeping is uniform: `db.record_cost(run_id,
stage, ref_id, result.raw_result_message)` + `db.add_artifact(run_id, stage, ref_id, "jsonl",
str(result.artifact_path))` after every successful agent call.

Engine (already verified, included for cross-reference):
- `orchestrator.py:run_pipeline` — stage order + `_budget_check` (raises `CostExceeded` before
  each stage if `db.total_cost(run_id) >= max_cost_usd`).
- `runner.py:run_agent` — schema-injects schema body into the prompt, handles repair turns,
  classifies quota/transient errors (`QuotaExhaustedError`, `TransientAgentError`, `AgentRunError`).
- `state.py:StateDB` tables: `runs`, `recon_outputs`, `tasks`, `findings`, `traces`,
  `dedupe_groups`, `costs`, `artifacts`.
- `stages/_common.py:StageContext` — `.stage(name)`, `.extras()`, `.prompt(name)`, `.schema(name)`,
  `.results_dir(stage)`, `.work_dir(stage, ref)`; `truncated_recon_summary(full, subsystem_filter=None)`
  passes only `architecture`/`subsystems` (+ matched `subsystem_for_task`) downstream.

## 2. CLI (`audit/audit/cli.py`, Click group `main`)

Invocation forms: `audit <subcommand> ...` (installed console-script) or
`python -m audit <subcommand> ...` (both resolve to `audit.cli:main`).

Global option (on `main` group, before subcommand): `-v` / `--verbose` — DEBUG logging.

### `audit auth-check`
- `--allow-api-key` (flag) — honor `ANTHROPIC_API_KEY` for metered billing (also via env
  `AUDIT_ALLOW_API_KEY=1`).

### `audit run` — THE scan command
```
audit run --repo <path> [--run-id ID] [--resume] [--max-cost-usd N]
          [--max-concurrency N] [--max-recon-tasks N] [--target-url URL]
          [--target-creds KEY=VALUE ...] [--scope-notes PATH]
          [--config PATH] [--allow-api-key]
```
Flags:
- `--repo` (required) — path to target repo; must exist, must be a directory (`click.Path(exists=True, file_okay=False)`). Resolved to absolute (`Path(repo).resolve()`) before passing to `run_pipeline`.
- `--run-id` — run identifier; default `run_{uuid4().hex[:8]}` if omitted.
- `--resume` (flag) — resume an existing run-id (else a duplicate run-id raises).
- `--max-cost-usd` FLOAT — abort (raise `CostExceeded`) once cumulative cost crosses this.
- `--max-concurrency` INT — caps every stage's concurrency via `config.cap_concurrency(n)` (cost containment).
- `--max-recon-tasks` INT — caps initial Hunt tasks Recon may emit (passed to `run_recon(max_tasks=...)`).
- `--target-url` — optional live-deployment URL agents can hit; becomes `live_target={"url":..., "credentials":{...}}` in every stage's `user_input`.
- `--target-creds KEY=VALUE` (multiple) — repeatable; ignored with a warning if `--target-url` absent.
- `--scope-notes PATH` — text file read verbatim and passed as `scope_notes` extra to every stage.
- `--config PATH` — override default `config/stages.yaml` (`load_config(Path(config_path))`).
- `--allow-api-key` (flag) — same as auth-check.

Repo path: `--repo` (resolved absolute). Run-id: `--run-id` (random if omitted) / `--resume`.
Cost cap: `--max-cost-usd` (checked by `orchestrator._budget_check` before every stage/iteration).
State DB: fixed path `REPO_ROOT/state.db` (`REPO_ROOT` = repo root two levels up from `cli.py`,
i.e. the `audit` clone root) — not configurable via flag. Results: `REPO_ROOT/results/<run_id>/<stage>/`.

Exit codes: `2` auth error; `3` `CostExceeded`; re-raises other exceptions (non-zero via traceback).

### `audit status [--run-id ID]`
No run-id → table of all runs (`db.list_runs()`). With run-id → detail table: tasks by status,
findings raw/confirmed/canonical/reachable, total cost.

### `audit report --run-id ID [--format json|md]`
Reads `results/<run_id>/report/report.json` (errors if missing) and prints as JSON (default) or
renders Markdown via `_render_markdown_report`.

## 3. Schemas (`schemas/*.schema.json`) — top-level fields

| Schema file | Top-level required fields |
|---|---|
| `recon_output.schema.json` | `subsystems`, `architecture`, `initial_tasks` |
| `hunt_task.schema.json` | `task_id`, `attack_class`, `scope_hint`, `target_files`, `rationale`, `priority` (+ optional `source`) |
| `finding.schema.json` (HuntOutput) | `task_id`, `findings`, `gaps_observed` |
| `validation.schema.json` | `finding_id`, `verdict`, `rationale`, `validator_confidence` (+ optional `alternative_explanation`, `missing_preconditions`, `suggested_test`) |
| `gapfill_output.schema.json` | `new_tasks`, `coverage_analysis` |
| `dedupe_output.schema.json` | `groups` |
| `trace.schema.json` | `finding_id`, `reachable`, `confidence`, `rationale` (+ optional `entry_points`, `call_chain`, `external_inputs`, `blockers`) |
| `feedback_output.schema.json` | `new_hunt_tasks` (+ optional `rationale_per_task`) |
| `report.schema.json` | `run_id`, `target`, `summary`, `findings` |

All schemas are draft-07, `additionalProperties: false` throughout (strict — repair turns exist
because of this).

### `finding.schema.json` — FULL field list (title: HuntOutput)
Top level (required: `task_id`, `findings`, `gaps_observed`):
- `task_id` (string)
- `findings` (array), each item required: `finding_id` (pattern `^f_[a-z0-9_-]{1,64}$`), `file`,
  `line_start` (int ≥1), `line_end` (int ≥1), `vuln_class`, `severity` (enum: critical/high/medium/low/informational),
  `description` (minLength 20), `evidence_snippet`, `confidence` (0–1);
  optional: `cwe` (pattern `^CWE-[0-9]+$`), `hedged_language` (bool),
  `poc` (object, required if present: `language`, `code`, `succeeded`; optional `compile_output`, `run_output`, `notes`)
- `gaps_observed` (array), each item required: `file_or_subsystem`, `reason`; optional: `suggested_attack_class`

### `recon_output.schema.json` — FULL field list (title: ReconOutput)
Top level (required: `subsystems`, `architecture`, `initial_tasks`):
- `subsystems` (array, minItems 1), each item required: `name`, `path`, `language`, `purpose`;
  optional: `external_dependencies` (array of string)
- `architecture` (object, required: `build_commands`, `entry_points`, `trust_boundaries`):
  - `build_commands` (array of string), optional `test_commands` (array of string)
  - `entry_points` (array), each item required: `kind`, `location`; optional: `auth_required` (bool), `notes`
  - `trust_boundaries` (array), each item required: `name`, `description`; optional: `source_zone`, `sink_zone`
  - `external_inputs` (array, optional at architecture level), each item required: `name`, `kind`; optional: `controllable_by`
- `initial_tasks` (array, minItems 1, items `$ref: hunt_task.schema.json`)

### `validation.schema.json` — FULL field list (title: ValidationVerdict)
Required: `finding_id`, `verdict` (enum: confirmed/rejected/needs_more_info), `rationale` (minLength 30),
`validator_confidence` (0–1).
Optional: `alternative_explanation`, `missing_preconditions` (array of string), `suggested_test`.

## 4. Config knobs (`config.py` + `config/stages.yaml`)

`StageConfig` fields (per stage): `name`, `model`, `concurrency`, `tools` (list), `max_turns`,
`permission_mode`, `repair_attempts`.

`HarnessConfig` fields: `stages: dict[str, StageConfig]`, `gapfill_iterations` (default 2),
`feedback_iterations` (default 1). `.get(stage)` raises `KeyError` with the known-stage list if
unknown. `.cap_concurrency(cap)` mutates every stage's concurrency to `min(current, cap)` (used by
`--max-concurrency`; raises `ValueError` if `cap < 1`).

`load_config(path=None)` defaults to `<repo_root>/config/stages.yaml`. `defaults:` block supplies
fallback `max_turns` (25), `permission_mode` (`acceptEdits`), `repair_attempts` (1) for any stage
that omits them. Per-stage `model`/`concurrency`/`tools` are required (no default) — `KeyError` on
`spec["model"]` etc. if absent from a stage block.

`config/stages.yaml` stage → model/concurrency/tools map (as configured):

| Stage | model | concurrency | tools | max_turns | repair_attempts |
|---|---|---|---|---|---|
| recon | claude-opus-4-7 | 1 | Read, Grep, Glob, Bash | 60 | 2 |
| hunt | claude-sonnet-4-6 | 50 | Read, Grep, Glob, Bash | 25 (default) | 1 (default) |
| validate | claude-opus-4-7 | 10 | Read, Grep, Glob (no Bash) | 25 (default) | 1 (default) |
| gapfill | claude-sonnet-4-6 | 1 | Read, Grep, Glob | 25 (default) | 2 |
| dedupe | claude-sonnet-4-6 | 1 | Read | 25 (default) | 1 (default) |
| trace | claude-opus-4-7 | 10 | Read, Grep, Glob, Bash | 25 (default) | 1 (default) |
| feedback | claude-sonnet-4-6 | 1 | Read, Grep, Glob | 25 (default) | 2 |
| report | claude-sonnet-4-6 | 1 | Read | 25 (default) | 1 (default) |

`loops:` → `gapfill_iterations: 2`, `feedback_iterations: 1` (bounds the Hunt/Validate/Gapfill and
post-Trace feedback loops in `orchestrator.py`).

Design intent per comments in `stages.yaml`: Hunt (sonnet) vs Validate (opus) model diversity is
deliberate — "deliberate disagreement" between finder and adversarial reviewer. Trace runs on Opus
as "the stage that matters most" (reachability confirmation gates everything downstream of it,
including Report).
