# VASH — Vanguard Agentic Security Harness

VASH is a **static-first, agentic Python vulnerability scanner**. Its backbone is
an 8-stage pipeline — recon → hunt → validate → gapfill → dedupe → trace →
feedback → report — inherited from evilsocket/audit and grounded by a
deterministic AST call-graph; a 9th stage, Chain, now runs after Feedback to
synthesize multi-finding exploit chains before the report is written. Many
narrow, single-attack-class agents; a differently-modeled Validate agent that
adversarially tries to **disprove** every finding by reading code — static
confirmation, not re-execution; and an explicit reachability trace as the
gate. That's the architecture, not "ask one big model to find bugs."

VASH forks [evilsocket/audit](https://github.com/evilsocket/audit) (the base
pipeline below) and grafts capability + production features from [Capital One
VulnHunter](https://github.com/capitalone/VulnHunter) and [Visa
VVAH](https://github.com/visa/visa-vulnerability-agentic-harness). See
[Attribution](#attribution) for exactly what came from where.

Driven by your **Claude Pro / Max subscription** through the official Claude
Code Agent SDK. No API key needed if you already use `claude login`.

## Origin

The base pipeline is a from-scratch reimplementation of the architecture
described in Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/)
post, which tested Anthropic's Mythos preview LLM against Cloudflare's own
codebase. The blog argues that real-world vulnerability discovery does **not**
come from asking one big model "find bugs here" — it comes from:

1. **Many narrow agents** working in parallel on tightly-scoped questions
   ("Look for command injection in this specific function, with this trust
   boundary above it") rather than one exhaustive agent.
2. **Deliberate disagreement** — a second agent, on a different model, that
   tries to *disprove* the first agent's findings.
3. **A reachability trace** as the gating step — most "is this code buggy?"
   findings are noise unless an attacker-controlled input can actually reach
   the sink from outside the system.
4. **A feedback loop** so reachable bugs in one place automatically seed
   hunts for the same pattern elsewhere.

evilsocket/audit packaged that architecture into a runnable agent (prompts,
schemas, state store, orchestrator). VASH forks that engine wholesale — see
[Attribution](#attribution) — and extends it with a deterministic call-graph,
completeness guarantees, static disprove-gates, exploit-chain synthesis, and
two new decoupled commands (`vash remediate`, `vash validate`).

## The pipeline

![Vulnerability discovery harness — the base 8-stage architecture](https://raw.githubusercontent.com/evilsocket/audit/main/docs/pipeline.png)

<sub>Diagram from Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) post (reproduced via evilsocket/audit) — the base 8-stage architecture VASH forked. It predates VASH's 9th (Chain) stage below.</sub>

| # | Stage        | Default model | Purpose |
|---|--------------|---------------|---------|
| 1 | Recon        | Opus 4.7   | Map the repo; emit narrowly-scoped Hunt tasks + the completeness input inventory (F1) |
| 2 | Hunt         | Sonnet 4.6 | One attack class per agent; compile/run PoCs |
| 3 | Validate     | Opus 4.7   | Adversarial re-read; tries to **disprove** via static gates (F5) — different model from Hunt |
| 4 | Gapfill      | Sonnet 4.6 | Re-queue under-covered areas |
| 5 | Dedupe       | Sonnet 4.6 | Cluster findings by root cause |
| 6 | Trace        | Opus 4.7   | Prove attacker-controlled input reaches the sink |
| 7 | Feedback     | Sonnet 4.6 | Turn reachable traces into new Hunt tasks |
| 8 | Chain (V11)  | Sonnet 4.6 | Synthesize multi-finding exploit chains from ALL confirmed findings — read-only, fail-soft |
| 9 | Report       | Sonnet 4.6 | Schema-validated structured report (`findings` + `chains` + `input_inventory` + `coverage`) |

Each stage is one markdown prompt in `prompts/` + one JSON Schema in
`schemas/`; the orchestrator passes the schema into the system prompt so
every output is shape-stable on the first try.

Between Recon and the Hunt/Validate/Gapfill loop, four fail-open
task-synthesis passes run automatically and feed the Hunt queue: deterministic
entry→sink taint chunking (V8), sink-backward orphan auditing (F3), gated
specialist sweeps (V12), and the terminal catch-all coverage sweep (F6). An
input-reconciliation pass also runs after the loop, before Dedupe, to
guarantee every F1-enumerated input ends up with a final disposition. See
[Capabilities](#capabilities).

## Capabilities

Grafted onto the base pipeline above (codes cross-reference
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md)):

- **Completeness input-inventory + reconciliation (F1)** — Recon enumerates
  every attacker-controllable input up front; a reconciliation pass after
  Hunt/Validate guarantees each one gets a `covered`/`uncovered` disposition
  in the final report. Nothing silently falls off the map.
- **Deterministic taint-path chunking (V8) + sink-backward orphan audit
  (F3)** — a deterministic BFS over the AST call-graph turns every enumerated
  input into forward entry→sink Hunt tasks; a backward pass audits sinks that
  no input was shown to reach (disjoint from V8 by construction).
- **Gated specialist sweeps (V12)** — repo-wide Hunt passes for
  crypto/authz/deserialization/batch-ETL/IaC classes, but only for the
  specialists whose surface actually exists in the repo (regex-gated), so
  Validate budget is never spent disproving a guaranteed false positive.
- **Catch-all coverage (F6) + cohesive partitioning (F2)** — a terminal
  low-priority sweep queues one Hunt task per eligible file no other task
  reached ("every file got ≥1 hunt", provably); F2 groups those files by
  call-graph connectivity instead of directory prefix, so each task sees a
  coherent source+sink slice.
- **Graph neighbor-context (V6)** — composes the call-graph (callers,
  callees, blast-radius, symbol-at-line) into small JSON blocks injected into
  Hunt and Validate; fail-open when no graph is available.
- **Per-language hints (V9) + repo-kind OWASP/CWE baselines (V10)** — a
  per-language security-hints knowledge base sharpens what Hunt looks for; a
  repo-kind classifier seeds Recon with the OWASP/CWE categories that kind of
  repo is statistically prone to.
- **CVSS severity (V4)** — Validate computes a CVSS 3.1 vector per finding;
  severity is derived from that band rather than a model's free-text guess
  (fails open to the model's own severity if vectoring fails).
- **Design-controls context (V5)** — Recon surfaces existing mitigations it
  finds (via git history and code) as a `design_controls` list, injected into
  Hunt/Validate/Chain so agents check whether a control already neutralizes a
  suspected issue before confirming it.
- **Static disprove-gates (F5)** — Validate actively tries to disprove every
  finding before confirming it: downgrade-on-uncertainty, checks *every* call
  site (not just the one Hunt found), searches the full codebase for an
  existing defense, and eliminates findings with no attacker-controlled
  input — all read-only, no execution.
- **Exploit-chain construction (V11)** — the Chain stage (#8 above) looks
  across all confirmed findings and synthesizes multi-finding attack paths
  that are more dangerous together than any single bug; each chain carries
  its own severity while per-finding CVSS stays authoritative.
- **Self-tuning miss-analysis (3.ST)** — an offline benchmark tool
  (`python -m bench.analyze_misses --run-id ID`) diagnoses, for each
  benchmark CVE a scored run missed, which pipeline phase
  (recon/hunt/validate/dedupe/trace) lost it. A tuning aid for maintainers —
  not part of a live `vash run`.
- **Coverage honesty** — the report's `coverage` block is explicit about what
  it could NOT confirm: `catchall_dropped` and `coverage_complete` mean a
  truncated sweep can never silently read as "fully covered."
- **Secret/PII redaction on egress** — the terminal deliverables every
  command writes or prints are passed through a Luhn/IIN- and keyword-gated
  redactor before they leave the process. See [Safety](#safety) for exactly
  which artifacts are (and aren't) covered.

## Install

Requires **Python 3.11+**.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # runtime only
pip install -e ".[dev]"     # + pytest/pytest-asyncio, to run the test suite
```

This pulls in `graphifyy` (the PyPI distribution name; imported as
`graphify`) — the AST call-graph extractor that grounds the V8/F3/V6/F2/V11
completeness and context features above. VASH pins it to
`>=0.8.14,<0.9.0` and degrades to a grep/glob fallback (`vash/graph/fallback.py`)
if graphify is missing or errors — those features fail open rather than
crashing the run.

Then verify auth:

```bash
vash auth-check
```

`vash` resolves auth automatically, in order: an LLM gateway
(`ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` — e.g. OpenRouter), a headless
subscription token (`CLAUDE_CODE_OAUTH_TOKEN`, from `claude setup-token` —
best for CI), or an interactive subscription login
(`~/.claude/.credentials.json`, from `claude login` — best for local dev). The
metered `ANTHROPIC_API_KEY` is honored only opt-in, via `--allow-api-key` or
`AUDIT_ALLOW_API_KEY=1`\* in the env. Amazon Bedrock / Google Vertex /
Microsoft Foundry work the same way the underlying `claude` CLI supports them
(`CLAUDE_CODE_USE_BEDROCK=1` etc. — see the [Claude Code auth
docs](https://code.claude.com/docs/en/authentication)); VASH doesn't add its
own flags on top of those. Full precedence details and OpenRouter setup are
in [Using a different model / provider](#using-a-different-model--provider)
below.

<sub>\* Yes, `AUDIT_ALLOW_API_KEY` — that env var name predates the
`audit`→`vash` rename and is unchanged in the current code; it's not a typo in
this doc.</sub>

## Quickstart

```bash
# 1. Install + auth (see above)
vash auth-check

# 2. Scan
vash run --repo /path/to/target --run-id my-run
vash status --run-id my-run
vash report --run-id my-run --format md > report.md

# 3. (optional, decoupled) generate patches for the confirmed findings
vash remediate --run-id my-run

# 4. (optional, decoupled) get an independent second opinion
vash validate --run-id my-run
```

By default `vash run` uses **subscription billing** via your Claude.ai
login — it does **not** call the metered Anthropic API. The auth module
scrubs `ANTHROPIC_API_KEY` from the environment so a stray value can't
silently divert billing.

## Using a different model / provider

The auth module picks one of three modes, in this order:

1. **LLM gateway** (OpenRouter, custom proxy, etc.) — when
   `ANTHROPIC_BASE_URL` points away from `anthropic.com` AND
   `ANTHROPIC_AUTH_TOKEN` is set. The gateway env is left intact;
   only `ANTHROPIC_API_KEY` is scrubbed (it would otherwise outrank the
   gateway token).
2. **Subscription OAuth (headless)** — `CLAUDE_CODE_OAUTH_TOKEN` from
   `claude setup-token`. Best for CI.
3. **Subscription OAuth (interactive)** — `~/.claude/.credentials.json`
   from `claude login`. Best for local dev.

### OpenRouter

OpenRouter exposes Claude-compatible Anthropic-API endpoints behind its
own credit system; that lets you spend OpenRouter credits instead of an
Anthropic subscription, and gives you access to Sonnet/Opus *and* other
models through the same SDK path. See [OpenRouter's Agent SDK guide](https://openrouter.ai/docs/guides/community/anthropic-agent-sdk).

```bash
export ANTHROPIC_BASE_URL="https://openrouter.ai/api"
export ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
export ANTHROPIC_API_KEY=""           # must be explicitly empty / unset
# optional: pick a non-Anthropic model
export ANTHROPIC_MODEL="anthropic/claude-sonnet-4-6"
# or e.g.: ANTHROPIC_MODEL="openai/gpt-5"
#         ANTHROPIC_MODEL="google/gemini-2.5-pro"
#         ANTHROPIC_MODEL="qwen/qwen3-coder-480b"

vash auth-check                       # confirms "using LLM gateway at https://openrouter.ai/api"
vash run --repo /path/to/target --run-id orun --max-cost-usd 30
```

Caveats:
- Per-stage model overrides in `config/stages.yaml` are model **names**
  (e.g. `claude-opus-4-7`); OpenRouter accepts slash-prefixed forms like
  `anthropic/claude-opus-4-7`. Edit the YAML if you want different
  providers per stage. Otherwise `ANTHROPIC_MODEL` forces every stage
  onto one model.
- Non-Claude models may not produce schema-compliant JSON as reliably.
  The runner's schema-validation + repair turn still applies; quality
  varies by model.
- Tool-use semantics (Read/Grep/Glob/Bash) are part of the Claude Code
  CLI, not the model — they work as long as the gateway speaks the
  Anthropic Messages API.

### Other gateways / cloud providers

Same recipe — anything that exposes the Anthropic Messages API at a URL
+ a bearer token works:

```bash
export ANTHROPIC_BASE_URL="https://your-proxy.example.com"
export ANTHROPIC_AUTH_TOKEN="$YOUR_TOKEN"
unset ANTHROPIC_API_KEY
```

For Amazon Bedrock / Google Vertex / Microsoft Foundry, Claude Code has
first-class env-var flags (`CLAUDE_CODE_USE_BEDROCK=1` etc.) that
outrank everything else. See the [Claude Code auth docs](https://code.claude.com/docs/en/authentication).

## Commands

`vash` has six subcommands. `-v` / `--verbose` on the top-level group
enables DEBUG logging for any of them, e.g. `vash -v run --repo ...`.

### `vash run` — the scan

```bash
vash run --repo PATH [--run-id ID] [--resume] [--max-cost-usd N]
          [--max-concurrency N] [--max-recon-tasks N]
          [--target-url URL] [--target-creds KEY=VALUE ...]
          [--scope-notes FILE] [--config FILE] [--allow-api-key]
```

Runs the full 9-stage pipeline against `--repo` and writes
`results/<run-id>/report/report.json` + `results/<run-id>/run_summary.json`.

| Flag | Meaning |
|---|---|
| `--repo PATH` | **Required.** Target source-code repo (must already exist). |
| `--run-id ID` | Run identifier. Default: random `run_<8 hex chars>`. |
| `--resume` | Resume an existing `--run-id` — re-queues any task left `running` or `failed`, then continues. |
| `--max-cost-usd N` | Abort cleanly (exit 3) once cumulative spend crosses `N`. Checked between stages and cooperatively inside Hunt. |
| `--max-concurrency N` | Caps every stage's concurrency to `N` (a ceiling on `config/stages.yaml`'s per-stage values). |
| `--max-recon-tasks N` | Caps how many initial Hunt tasks Recon may emit. |
| `--target-url URL` | Optional live deployment to reproduce findings against — see [Live-target reproduction](#live-target-reproduction-optional). |
| `--target-creds KEY=VALUE` | Repeatable; credentials passed to the agents alongside `--target-url`. Ignored (with a warning) if `--target-url` isn't set. |
| `--scope-notes FILE` | Text file of target-specific scope rules, appended verbatim to every stage's input — see [Scope notes](#scope-notes-optional). Must already exist. |
| `--config FILE` | Override `config/stages.yaml`. |
| `--allow-api-key` | Honor `ANTHROPIC_API_KEY` for metered billing (also via `AUDIT_ALLOW_API_KEY=1`). |

### `vash remediate` — static patch generation (decoupled, opt-in)

```bash
vash remediate --run-id ID [--repo PATH] [--policy FILE] [--out DIR]
                [--verify] [--dangerously-no-sandbox] [--allow-api-key]
```

Reads a prior `vash run`'s **confirmed** findings from `state.db`, runs each
through the hard gate in `config/remediation_policy.yaml` (fail-closed — see
[Configuration](#configuration)), and for every patch-eligible finding has a
read-only agent (no Bash, no Write — see the `remediate` stage in
`config/stages.yaml`) generate a unified diff + a security test. Nothing is
ever applied to the target. Not part of `vash run`.

| Flag | Meaning |
|---|---|
| `--run-id ID` | **Required.** The prior run to remediate. |
| `--repo PATH` | Target repo (must already exist). Default: the path recorded for that run. |
| `--policy FILE` | Remediation policy YAML. Default: `config/remediation_policy.yaml`. |
| `--out DIR` | Output dir. Default: `results/<run-id>/remediation`. |
| `--verify` | Ask to run the target's own tests to check a generated patch. Gated by `vash.sandbox.require()` — needs `VASH_SANDBOX=1` or `--dangerously-no-sandbox`, else refused fail-soft (recorded on the patch's `risk_notes`). Real test execution is still **DEFERRED** either way — nothing executes yet. |
| `--dangerously-no-sandbox` | Dev-only: bypass the `--verify` sandbox gate with a loud warning instead of requiring an active sandbox. Unsafe against untrusted source; no effect without `--verify`. |
| `--allow-api-key` | Same as `run`. |

### `vash validate` — independent second opinion (decoupled, opt-in)

```bash
vash validate --run-id ID [--repo PATH] [--model MODEL]
               [--min-confidence N] [--out DIR] [--allow-api-key]
```

Re-reads a prior `vash run`'s confirmed findings with a fresh, read-only
agent that actively tries to reach the *opposite* verdict before agreeing
(VVAH's second-opinion stance) — deliberately a different model tier than
the scan's own Validate stage. Never mutates `state.db`. Not part of
`vash run`.

| Flag | Meaning |
|---|---|
| `--run-id ID` | **Required.** The prior run to re-verify. |
| `--repo PATH` | Target repo (must already exist). Default: the path recorded for that run. |
| `--model MODEL` | Override the second-opinion model. Default: `config/stages.yaml`'s `revalidate` stage model (`claude-sonnet-4-6`). |
| `--min-confidence N` | Confidence gate, 0–10. A `validated` verdict scored below this is downgraded to `needs_review`. Default: `7`. |
| `--out DIR` | Output dir. Default: `results/<run-id>/revalidation`. |
| `--allow-api-key` | Same as `run`. |

Findings the second opinion rejects are marked **OVERTURNED** and listed
separately — the false positives it caught that the scan itself missed.

### `vash status [--run-id ID]`

No `--run-id`: a table of every run (`run_id`, repo, status, cost). With
`--run-id`: task counts (total/pending/done/failed), finding counts
(raw/confirmed/canonical/reachable), and total cost for that run. Exits 1 on
an unknown `--run-id`.

### `vash report --run-id ID [--format json|md]`

Prints `results/<run-id>/report/report.json` — already redacted at write
time, redacted *again* here (idempotently) since CLI stdout is itself an
egress point. `--format md` (default `json`) renders the same data as
human-readable Markdown. Exits 1 if that run hasn't reached the Report stage
yet.

### `vash auth-check [--allow-api-key]`

Verifies auth resolves to a usable mode and prints which one (OAuth token /
API key / keychain login / gateway), the `claude` CLI path + version, and
which env vars were scrubbed. Exits 2 on failure.

## Outputs

- **`results/<run-id>/report/report.json`** — the schema-validated final
  report (`schemas/report.schema.json`): `run_id`, `target` (`repo_path` +
  optional `commit`), `summary` (`total` + `by_severity`), `findings[]`
  (`finding_id`, `title`, `severity`, `vuln_class`, `cwe`, `file`,
  `line_start`/`line_end`, `description`, `evidence`, `trace` with
  `entry_points`/`call_chain`, optional `poc`/`variants`, `recommendation`),
  `chains[]` (V11 — multi-finding exploit chains: `title`, `finding_ids`
  (≥2), `severity`, `blocked_by_controls`, `narrative`), `input_inventory[]`
  (F1 — the completeness ledger: every enumerated input with its
  `covered`/`uncovered`/`null` disposition), and `coverage` (4.7 — the
  consolidated disclosure: `inputs_enumerated`/`covered`/`uncovered`,
  `tasks_by_source`, `findings_by_status`, `source_files`, `covered_files`,
  `catchall_tasks`, `catchall_dropped`, `coverage_complete` — `false`
  whenever `catchall_dropped > 0` or any input never reached a disposition;
  never read `coverage_complete: false` as full coverage).
- **`results/<run-id>/run_summary.json`** — the same per-stage
  `calls`/`usd`/`duration_ms` breakdown (+ a TOTAL row) printed after every
  `vash run` and by `vash status --run-id`, plus findings-by-severity/status
  and tasks-by-source counts.
- **`results/<run-id>/remediation/`** (from `vash remediate`, default
  `--out`) — `patches/<finding_id>.diff` (unified diff), `tests/<finding_id>_test.<ext>`
  (a security test), `remediation.json` (per-finding `status`: `patched` /
  `guidance_only` / `cannot_fix`), `REMEDIATION.md` (human-readable summary).
- **`results/<run-id>/revalidation/`** (from `vash validate`, default
  `--out`) — `revalidation.json` (per-finding verdict: `validated` /
  `failed` [OVERTURNED] / `needs_review`, with confidence), `REVALIDATION.md`.
- **Redaction** — `report.json`, `REMEDIATION.md` + `patches/` + `tests/`,
  and `REVALIDATION.md` are all passed through `vash/redact.py` (secret/PII/PAN
  redaction) before they're written, and `vash report`'s stdout is redacted
  again at print time. This does **not** cover every artifact under
  `results/` — see [Safety](#safety) for what's excluded (raw per-stage agent
  transcripts, `state.db`).

## Configuration

- **`config/stages.yaml`** — per-stage `model` / `concurrency` / `tools`
  allowlist / `max_turns` / `repair_attempts`, plus global `defaults`
  (`max_turns: 25`, `permission_mode: acceptEdits` — never
  `bypassPermissions`, `repair_attempts: 1`) and `loops`
  (`gapfill_iterations: 2`, `feedback_iterations: 1`) that bound the
  Hunt↔Validate↔Gapfill and Feedback recursion. Model diversity between Hunt
  (`claude-sonnet-4-6`) and Validate (`claude-opus-4-7`) is deliberate — it's
  the "deliberate disagreement" rule from [Origin](#origin). The decoupled
  `remediate` (`claude-opus-4-7`, high-stakes patch generation) and
  `revalidate` (`claude-sonnet-4-6`, deliberately a different tier from
  Validate) stages are read-only by config — `tools: [Read, Grep, Glob]`,
  no `Bash`, no `Write`. `vash run --config FILE` overrides the whole file;
  `vash validate --model` overrides just the `revalidate` model.
- **`config/remediation_policy.yaml`** — loaded by `vash remediate` (via
  `vash/remediation_policy.py`) *before* any patch agent runs. This is an
  enforcement hard gate, not guidance: `default_action: allow` or `deny`,
  with explicit `deny`/`allow` CWE lists (VASH ships `default_action: allow`
  with both lists empty — permissive by default; operators tighten per
  program). Evaluation order is `kill_switch → deny → allow →
  default_action`. The kill-switch (env `VASH_REMEDIATE_DISABLE` truthy, or
  the presence of a `./.vash-remediate-off` file) forces every decision to
  guidance-only regardless of the lists — for pausing a bad batch without
  editing YAML. **Fail-closed**: a missing or invalid policy file makes
  every finding guidance-only (`vash remediate` prints a warning). Reserved
  `deny_paths`/`forbid_patch_paths` fields exist for a future `--apply`/PR
  path but aren't consulted by the current CWE-only gate.

## Cost containment

A real production codebase can produce 15-50 Hunt tasks and 25+ findings to
validate. At default concurrency this gets expensive. Flags to keep it sane
(full reference in [`vash run`](#vash-run--the-scan) above):

```bash
vash run --repo /path/to/target \
  --max-concurrency 1 \           # one claude subprocess at a time
  --max-recon-tasks 15 \          # cap initial Hunt fanout
  --max-cost-usd 30               # abort cleanly if exceeded
```

The budget guard fires between *and* within stages — a per-task check in
Hunt cooperatively aborts rather than running 30 more tasks past the cap.

## Live-target reproduction (optional)

If the target has a running deployment, point the agents at it. Hunt now
**reproduces** each finding against the live service instead of compiling
a local PoC, Validate **rejects** findings that don't reproduce, and Trace
**confirms** reachability with real HTTP round-trips. The static path
remains available — these flags are opt-in.

```bash
vash run --repo /path/to/target --run-id live \
  --max-concurrency 1 --max-cost-usd 30 \
  --target-url http://server.local:8888 \
  --target-creds email=admin@system.com \
  --target-creds password=changechangeme
```

Rules the agents follow when `--target-url` is set:
- Network egress is restricted to that host + `127.0.0.1`. No other external
  hosts.
- A finding that doesn't reproduce against the live target is dropped or
  rejected (depending on stage) — "no fabrication".
- Credentials flow into every relevant stage's user_input as a dict.

## Scope notes (optional)

Targets often have intentionally-loose-by-design surfaces that aren't bugs
(e.g. plaintext API keys when that's a feature, test-only Mailpit endpoints,
anonymous-analytics ingest). Drop them in a text file and pass it in — the
notes are appended verbatim to every stage's user_input, and Recon / Hunt /
Validate honor exclusions you list.

```bash
vash run --repo /path/to/target --scope-notes target_scope.md
```

Example `target_scope.md`:

```markdown
- Mailpit (port 1025) is test-only; ignore.
- Plaintext API keys in the database are a required feature.
- Don't flag rate-limit absence on anonymous /ping endpoints.
- Only consider critical/high severity.
```

## Recon mines git history

Recon greps the git history for past security patches
(`CVE`, `sec:`, `fix.*auth`, `sanitize`, …) — patched files are hardened,
but **sibling files with the same idiom often aren't**. Findings get seeded
against the unpatched copies. Adds zero cost on repos without that pattern;
catches real cross-component bugs on repos that have it.

## Logic chains

The pipeline's default is one-attack-class-per-task (the Cloudflare paper's
narrow-scope rule). Recon can also emit `logic_chain` tasks for high-impact
multi-component paths (auth-bypass + IDOR + path-traversal that compose into
RCE, etc.) — one chain per task, with the `scope_hint` naming the specific
chain. This is the one allowed exception to single-attack-class scoping.

This is a Hunt-time mechanism — Recon proactively goes looking for a
*specific named* chain. It's complementary to (not the same as) the Chain
**stage** (V11, #8 in [The pipeline](#the-pipeline)), which runs once at the
end and synthesizes chains post-hoc from whatever findings end up confirmed,
regardless of how they were found.

## Layout

```
prompts/        11 prompts: 9 numbered pipeline-stage prompts (01-recon..09-chain)
                 + remediate.md / revalidate.md for the two decoupled commands.
                 Loaded as system prompts.
schemas/        12 JSON schemas — every agent output (and report.json itself)
                 is validated against one of these before it's trusted.
config/         stages.yaml (model/concurrency/tools per stage) +
                 remediation_policy.yaml (the `vash remediate` CWE hard-gate).
vash/           Python package (CLI entry point: vash.cli:main)
  auth.py            OAuth/API-key/gateway resolution + env scrubbing
  sandbox.py         execution-sandbox gate for `remediate --verify` (4.1)
  redact.py          secret/PII/PAN redaction before egress (VVAH port)
  cvss.py            CVSS 3.1 base-score calculator (VVAH port, V4)
  baselines.py       repo-kind -> OWASP/CWE baselines (VVAH port, V10)
  lang/hints.py      per-language security-hints KB (VVAH port, V9)
  taint.py           entry->sink taint-path chunking (V8)
  specialists.py     gated repo-wide specialist sweeps (V12)
  catchall.py        terminal coverage sweep (F6)
  partition.py       union-find cohesive partitioning (F2)
  graph_context.py   graph neighbor-context blocks (V6)
  graph/             graphify wrapper + grep/glob fallback + GraphQuery
  remediation_policy.py   loads + evaluates config/remediation_policy.yaml
  state.py           SQLite DAO (runs, tasks, findings, traces, dedupe, costs)
  runner.py          claude-agent-sdk wrapper: schema validation + repair turn
  orchestrator.py    pipeline driver (run_pipeline)
  stages/            one module per stage, incl. remediate.py / revalidate.py
bench/          benchmark harness: corpus clone, scorer, recall_gate,
                 self-tuning miss-analysis (3.ST) — see CI & recall gate below
work/           per-Hunt-task scratch dirs (sandbox for PoC compile/run)
results/        results/<run-id>/{report,remediation,revalidation}/ + run_summary.json
state.db        SQLite (gitignored)
licenses/       full upstream license texts (audit MIT; VulnHunter + VVAH Apache-2.0)
```

## Safety

Hunt agents have Bash and run inside per-task scratch dirs
(`work/<run-id>/hunt/...`). They are **not** sandboxed at the OS level. Run
`vash run` inside a disposable VM or container when you don't trust the
target source — a target with malicious build scripts could otherwise
execute on your host during PoC compilation.

Every agent — every scan stage, and the decoupled `remediate`/`validate`
commands too — reads everything you `--add-dir`, including any `.env` or
`secrets/` directories in the target, and its raw JSONL transcript is written
**unredacted** to `results/<run-id>/<stage>/` (or `results/<run-id>/remediation/agent/`
/ `results/<run-id>/revalidation/agent/` for the decoupled commands). Only
the terminal deliverables — `report/report.json`,
`remediation/REMEDIATION.md` + `patches/` + `tests/`,
`revalidation/REVALIDATION.md` — are passed through redaction before being
written (see [Outputs](#outputs)); that redaction is pattern-based
(Luhn/IIN-gated card numbers, SSN-shaped strings, keyword-gated generic
secrets) and best-effort, not a guarantee. `state.db` always keeps the true,
unredacted evidence. Treat `results/`, `work/`, and `state.db` as sensitive
whenever the target repo contains real secrets.

### Static-first guarantee — `remediate` / `validate`, and the sandbox gate

The two paragraphs above are about `vash run` (Hunt/Trace do intentionally
compile/run PoCs, as described). The **decoupled** `vash remediate` and
`vash validate` commands are different: both are read-only by config (no
`Bash`, no `Write` — see the `remediate` / `revalidate` stage comments in
`config/stages.yaml`) and never execute anything from the target. A patch
is a unified diff produced by an agent *reading* code; it is written to disk
and never applied or run.

The only execution ever contemplated on that decoupled path is
`remediate --verify` — optionally running the target's **own** test suite to
confirm a generated patch. That execution is still DEFERRED (no test is
actually run yet), and it is now gated: before doing anything else, `--verify`
calls `vash.sandbox.require()`, which refuses unless it detects an active
isolation sandbox (`VASH_SANDBOX=1`, set by a gVisor/container wrapper, or a
`/.dockerenv` marker). With no sandbox, the refusal is fail-soft — it's
recorded on the affected patches' `risk_notes` rather than aborting the
batch. `--dangerously-no-sandbox` bypasses the gate with a loud warning, for
local dev only; never pass it against source you don't already trust.

## CI & recall gate

Every PR runs two gates in GitHub Actions (`.github/workflows/ci.yml`):

1. **The full offline test suite** (`python -m pytest -q`) — the
   enforceable regression gate. All tests must stay green; deterministic,
   no network, no LLM calls.
2. **The recall gate** (`python -m bench.recall_gate`) — compares a
   scorecard's `cve_recall` against the committed floor in
   `bench/baseline_scorecard.json` (currently the offline-reproducible
   corpus baseline, 6/11 on `datamodel-code-generator`; see
   `bench/tests/test_bench.py::test_known_baseline_datamodel_code_generator_recall_is_6_of_11`).
   CI cannot run a live `vash run` scan on every PR (LLM cost/quota/time),
   so the PR job runs this gate in **smoke mode** — no `--current`
   scorecard, so it only confirms the baseline file parses and is wired up
   correctly, and always exits 0 given a valid baseline. **This is not a
   live recall check.**

To actually enforce the recall floor, a nightly or manual job records a real
scorecard (via `vash run` + scoring with `bench.scorer.score_corpus`,
already unit-tested and reused as-is — recall math is never reimplemented
here) and passes it as `--current`:

```bash
vash run --repo <clone of the benchmark target> --run-id nightly
# score the run's confirmed findings with bench.scorer.score_corpus(...)
# against bench/ground_truth/*.json and write the result (a dict with a
# cve_recall/class_recall field) to current_scorecard.json
python -m bench.recall_gate \
  --baseline bench/baseline_scorecard.json \
  --current current_scorecard.json
```

With `--current` supplied, the gate compares `cve_recall` (or
`--metric class_recall`) against the baseline and **exits 1** if it
regressed beyond `--tolerance` (default `0.0`) — that's the check that
actually fails a build on a recall regression.

## Attribution

VASH forks [evilsocket/audit](https://github.com/evilsocket/audit) (MIT) and
grafts capability + production features from [Capital One
VulnHunter](https://github.com/capitalone/VulnHunter) and [Visa
VVAH](https://github.com/visa/visa-vulnerability-agentic-harness) (both
Apache-2.0). See [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) for the
full component-by-component breakdown of what was ported verbatim vs.
adapted, and [`NOTICE`](NOTICE) for the Apache-2.0 §4 attribution notice.
Full license texts are under [`licenses/`](licenses/); verbatim ports keep
their in-file Apache-2.0 headers (enforced by `tests/test_licensing.py`).

## License

[MIT](LICENSE) for VASH's own code. Reused Apache-2.0 files (see
[Attribution](#attribution)) keep their Apache-2.0 header and license — this
repo is not uniformly MIT. No warranty either way.

## Acknowledgements

- The base pipeline's design is from Cloudflare's [Project
  Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) blog post,
  packaged into a runnable agent by
  [evilsocket/audit](https://github.com/evilsocket/audit). Credit for that
  architecture goes there.
- Built on the official [Claude Code Agent
  SDK](https://code.claude.com/docs/en/agent-sdk/overview).
- The capability and production grafts on top are from [Capital One
  VulnHunter](https://github.com/capitalone/VulnHunter) and [Visa
  VVAH](https://github.com/visa/visa-vulnerability-agentic-harness) — see
  [Attribution](#attribution).
