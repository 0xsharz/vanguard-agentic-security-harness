# `vash poc --run-id <ID>` — Design Spec

**Status:** DESIGN APPROVED — implementation DEFERRED (saved for later).
**Date:** 2026-07-26
**Branch:** evolve/vulnhunter-imports
**Author:** brainstormed with user (sharzz), 2026-07-26 ~03:00 IST.

> This spec captures an approved design. It is NOT yet implemented. When picking it
> up, run the `superpowers:writing-plans` skill to turn the "Implementation task
> breakdown" section into a task-by-task TDD plan, then execute via
> `superpowers:subagent-driven-development`. **Read the Caveats section first —
> it is load-bearing.**

---

## 1. Problem

A default `vash run` on a bare host is **static**: the Hunt agent reasons source→sink,
but the runner strips `Bash` (no active sandbox), so every finding lands with
`poc_succeeded=0` and `needs_poc=true`. It is *reasoned*, never *executed*.

Today the ONLY way to get executed-PoC confirmation is to re-run the **entire**
pipeline (recon → hunt → … → report) with `--dynamic-validation` inside Docker:
~$100 and a *fresh, stochastic* hunt that may surface a different finding set than
the static run you are trying to verify. There is no way to say: "take the findings
I already have and just prove them."

The finding schema already anticipated the fix — `needs_poc`'s own description reads:
*"Set true when execution wasn't available (static-only host)... A later sandboxed
run should attempt to prove it."* **`vash poc` is that run.**

## 2. Solution

A 4th **decoupled, opt-in** command (family: `run` / `remediate` / `validate` /
**`poc`**) that reuses a completed run's findings and runs **only** the
PoC-generation-and-execution step against them in the sandbox — **skipping recon +
hunt entirely**.

It is purely additive. It changes nothing about `vash run` or the
`--dynamic-validation` full-pipeline path. If never called, today's behavior is
unchanged.

### Relationship to the existing `--dynamic-validation` path

| You want… | Command | Cost | Hunt |
|---|---|---|---|
| Everything at once, PoC-confirmed | `vash run --dynamic-validation` (Docker) | ~$100 | fresh, stochastic |
| Fast static findings first | `vash run` (host) | cheap | static, `poc_succeeded=0` |
| …then prove those exact findings | `vash poc --run-id <ID>` (Docker) | ~$10–25* | **skipped** — reuses findings |

\* optimistic — see Caveat 4.

## 3. Command surface

```
vash poc --run-id <ID>
    [--repo PATH]                 # default: the repo path recorded for the run
    [--scope reachable|confirmed] # default: reachable  (= exactly what the report delivers)
    [--model M]                   # default: config/stages.yaml `poc` stage
    [--max-concurrency N]
    [--max-cost-usd N]
    [--out DIR]                   # default: results/<run-id>/poc
    [--dangerously-no-sandbox]    # dev-only escape
    [--allow-api-key]
```

Structurally a near-clone of `vash remediate`: loads a prior run by `--run-id`, gates
the sandbox, writes to its own out dir.

## 4. The two design decisions (locked with user)

1. **Write-back to the run DB** (chosen over read-only). `vash poc` updates each
   finding's `poc_succeeded` / `needs_poc` in the run's `findings` table, so a later
   `vash report --run-id <ID>` reflects executed-PoC status inline — one source of
   truth. This is the only decoupled command that mutates a finished run (see
   Caveat 5 for the fail-safe rules that make it safe).

2. **Annotate + emit filtered report** (chosen over annotate-only / hard-filter).
   No finding row is ever deleted. The reproduced/not distinction lives in
   `poc_succeeded`; the filtered "confirmed-only" view is *derived* from it.

These reconcile as: **DB carries the executed-PoC truth; the finding set is
preserved; report views separate reproduced from not; a confirmed-only view filters
on `poc_succeeded=1`.** The static verdict (`validation_status='confirmed'`) and its
reasoning are preserved — the PoC is added as *evidence*, it does not overturn the
static verdict or drop rows.

## 5. Architecture — 5 small pieces, all following existing patterns

1. **`vash/stages/poc.py` → `run_poc_confirm(ctx, db, ...)`** — the new stage. Loads
   findings (default `db.get_reachable_canonical_findings` — exactly the delivered
   set), then per-finding runs an agent with `Bash` enabled + a scratch dir. Mirrors
   `hunt.py`'s per-task concurrent loop, but scoped to *one known finding* instead of
   an attack-class task. Budget-checked + concurrency-limited like hunt.

2. **`prompts/10-poc.md`** — new prompt. Given the finding's
   file/line/class/description/evidence **and its existing `poc.code` if the static
   hunt emitted one** (seed, don't regenerate blind), instruct: write a minimal PoC
   that reproduces *this specific* finding, execute it in the sandbox, report whether
   the vulnerable behavior was observed. Emits
   `{finding_id, reproduced: bool, poc:{language,code,succeeded,run_output}, confidence, rationale}`.

3. **`config/stages.yaml` → `poc:` stage** — `tools: [Read, Grep, Glob, Bash]`
   (Bash = PoC execution, sandbox-gated), `model: claude-sonnet-5`, concurrency ~10,
   a bounded `max_turns` so a single finding can't spiral (see Caveat 4).
   New `schemas/poc_confirm.schema.json` for the agent output.

4. **`StateDB.set_finding_poc(finding_id, succeeded, poc_payload)`** — new writer:
   sets `poc_succeeded`, clears `needs_poc`, stores the PoC json. **Leaves
   `validation_status` untouched.** Only ever called on a clean agent result (see
   Caveat 5).

5. **`vash/reporting/poc.py` → `render_poc_report(...)`** — emits the three artifacts:
   - `results/<id>/poc/poc_report.json` — ALL findings, each annotated
     `reproduced:true/false` + poc/run_output + summary `{total, reproduced, not_reproduced}`.
   - `results/<id>/poc/POC-REPORT.md` — sectioned: ✅ Reproduced (N) / ⚠️ Not reproduced (M),
     per-finding PoC code + run_output excerpt. **Must state Caveat 1 in prose.**
   - `results/<id>/poc/confirmed-only.json` — filtered to `poc_succeeded=1` (zero-FP delivered set).

## 6. Data flow

```
vash poc --run-id dmcg-static
  │
  1. sandbox.require()  ── bare host → REFUSE
  │      ("vash poc executes PoCs; run in Docker or pass --dangerously-no-sandbox")
  2. load run + repo_path from state.db; warn if recorded commit != current repo (Caveat 7)
  3. findings = get_reachable_canonical_findings(run_id)   # default scope
  4. for each finding (concurrent, budget-checked):
  │     agent(prompt=10-poc, Bash ON, scratch/, seed=finding.poc.code) → writes & RUNS a PoC
  │     on CLEAN result:   db.set_finding_poc(fid, succeeded, poc_payload)   # WRITE-BACK
  │     on agent failure:  leave needs_poc=true ("not attempted", NOT "not reproduced")  # Caveat 5
  5. render → results/<id>/poc/{poc_report.json, POC-REPORT.md, confirmed-only.json}
```

## 7. Default scope decision

**Default `--scope reachable`** = `get_reachable_canonical_findings` — the exact set
`vash report` delivers, so "verify my report" is literal. `--scope confirmed` widens
to all confirmed canonical findings (pre-trace-reachability). *(Recommended default;
user to confirm or flip at implementation time.)*

## 8. Docker ergonomics decision

Add a thin **`scripts/poc-in-docker.sh`** wrapper mirroring `run-in-docker.sh`, so it
is one command:
`./scripts/poc-in-docker.sh <repo> <run-id> [--scope ...]`. *(Recommended; the
underlying `docker run ... vash poc --run-id <ID>` also works directly.)*

## 9. Safety

The sandbox gate is *harder* than remediate's: for `vash poc`, execution **is** the
command, so it refuses on a bare host unless `--dangerously-no-sandbox`. Runs inside
Docker (`/.dockerenv` → `is_sandboxed()`), consistent with "never execute untrusted
code outside the sandbox."

## 10. Caveats (HONEST — read before implementing)

### Inherent limits (cannot be engineered away)

1. **"Not reproduced" ≠ "false positive."** A failed PoC means EITHER (a) it was a
   false positive, OR (b) the vuln is real but un-triggerable in a sealed sandbox
   (needs a network callback, a live secret, a running server, specific timing). These
   are indistinguishable from outside. `confirmed-only.json` therefore **silently drops
   some genuinely-real findings.** Treat it as "high-confidence proven subset," NEVER
   as "the FPs were these." The report MUST say this in prose.

2. **Whole vuln classes are unprovable-in-sandbox by design** — SSRF w/ external
   callback, ReDoS/DoS needing scale/timing, TOCTOU races, info-disclosure needing a
   live secret. `vash poc` systematically under-credits exactly these. (This is *why*
   VVAH stays fully static.)

3. **Improves precision/confidence, NOT recall.** It can only prove findings you
   already have — it will never surface a CVE the static hunt missed (e.g. the
   stochastic 54655/55415 misses). **`vash poc` by itself does not move the 5/11
   benchmark number.** The "~6–7/11" hope comes from D7 templates + *filtering the ~20
   extras*, not from poc adding finds. Do not frame it as a recall win.

### Implementation risks (mitigable, but real)

4. **Still needs LLM PoC *generation*, not just script re-execution.** Static runs
   usually set `needs_poc=true` and often DON'T leave a runnable `poc.code` — the agent
   reasoned, it didn't write a script. So for most findings `vash poc` does real
   generative work (explore → write → run → iterate). Consequence: the **$10–25
   estimate is optimistic**, per-finding cost can spiral, and results are **stochastic**
   (run twice → slightly different subsets). Mitigation: bounded `max_turns` +
   `--max-cost-usd`; measure real cost before quoting.

5. **Write-back is a footgun.** It's the only decoupled command that mutates a
   finished run. If a PoC attempt *flakes* (agent error, sandbox hiccup, budget
   cutoff), we must NOT write `poc_succeeded=0` onto a finding that was fine — that
   silently degrades a good run record. **Fail-safe rules (must implement):**
   agent failure → leave `needs_poc=true` ("not attempted"), only ever write a real
   reproduced/not-reproduced result; snapshot the DB (or affected rows) before
   write-back; make re-runs idempotent.

6. **Inherits the Docker + container-token blocker.** `vash poc` requires the sandbox,
   so it needs `claude setup-token` → `CLAUDE_CODE_OAUTH_TOKEN` — the same hurdle that
   has blocked the Docker benchmark. Build + unit-test fully offline (stubbed agent),
   but the **real end-to-end path can't be proven until that token exists.** This
   feature does not remove that blocker; it sits behind it.

7. **Repo/line drift.** PoCs run against `repo_path` as it is *now*. If the target
   moved/changed since the static scan, `file:line` references may point at different
   code and PoCs become nonsense. Mitigation: check the run's recorded commit vs the
   repo, warn on mismatch (step 2).

### Net take

Worth building — it turns "$100 re-scan to verify" into "cheap targeted proof," the
natural fit for a static-first workflow. But it is a **verification/precision tool
with soft edges**, not a zero-FP oracle. Its output is "here's what I could prove";
the un-proven pile is a *mix* of FPs and hard-to-trigger reals — the report must say
so plainly or it will mislead.

## 11. Testing (offline gate, per convention)

`tests/test_poc_stage.py` (stub `run_agent`, no network):
- write-back sets `poc_succeeded` + clears `needs_poc` on a clean result;
- **agent failure leaves `needs_poc=true`** and does NOT write `poc_succeeded=0` (Caveat 5);
- the 3 report artifacts are produced; `confirmed-only.json` filters to `poc_succeeded=1`;
- the sandbox gate refuses on a bare host (no `--dangerously-no-sandbox`);
- CLI wiring smoke test (`vash poc --run-id ...` dispatches `run_poc_confirm`).
Full offline suite stays green.

## 12. Explicitly out of scope (YAGNI)

No re-trace, no re-dedupe, no new chains. No `--from-report <path>` (key off
`--run-id` only). No new report *renderer framework* — one small function. Reuse the
finding's existing `poc.code` when present rather than always regenerating. No change
to `vash run` or `--dynamic-validation`.

## 13. Cost

For a ~13–25 finding run: ~1 agent call each ≈ **$10–25, no recon/hunt** — vs ~$100
for a full `--dynamic-validation` re-scan. See Caveat 4: optimistic; measure.

---

## 14. Implementation task breakdown (for a later `writing-plans` pass)

Ordered; each is a small, testable unit. TDD (failing test first) per repo convention.

- **T1 — `StateDB.set_finding_poc` + snapshot helper.** New writer (sets
  `poc_succeeded`, clears `needs_poc`, stores poc json; leaves `validation_status`).
  DB/rows snapshot before write-back. Tests in `tests/test_state.py` style.
- **T2 — `schemas/poc_confirm.schema.json`.** Agent output contract.
- **T3 — `config/stages.yaml` `poc:` stage** (tools incl. Bash, sonnet, bounded max_turns).
- **T4 — `prompts/10-poc.md`.** Per-finding PoC-repro prompt; seed with `poc.code` if present.
- **T5 — `vash/stages/poc.py::run_poc_confirm`.** Concurrent per-finding loop; sandbox
  gate FIRST; fail-safe write-back (Caveat 5); budget/concurrency.
- **T6 — `vash/reporting/poc.py::render_poc_report`.** 3 artifacts; Caveat 1 prose in MD.
- **T7 — `vash/cli.py` `poc` command.** Mirror `remediate`/`validate` wiring; scope +
  sandbox flags.
- **T8 — `scripts/poc-in-docker.sh`.** Thin wrapper mirroring `run-in-docker.sh`.
- **T9 — `tests/test_poc_stage.py`** (see §11) + full offline suite green.
- **T10 — docs:** README + CLAUDE.md backlog note; `docs/wiring-notes.md` new-command row.

**Next step when resuming:** invoke `superpowers:writing-plans` on §14 to produce the
detailed TDD plan, then `superpowers:subagent-driven-development` to execute.
