# VASH — live-run discrepancies (dmcg-full, opus/sonnet, no cap)

Observed while running the tool end-to-end against datamodel-code-generator@0.55.0.
Plan (per user): complete the full run first, note ALL issues here, then fix one-by-one.

## D1 — [FIXED] graphify node paths were package-relative -> mismatch with recon -> taint dead
- Symptom: `taint: 0 entry→sink path tasks (inputs=20–31)` on every run despite F1 finding many inputs.
- Meaning: graphify's call-graph is not resolving any input→sink path, so the deterministic
  recall engine (V8) contributes nothing; recall falls back to LLM hunters + F1 inventory + specialists.
- Suspects: (a) graphify Python symbol resolution (file:line → node id mismatch); (b) PYTHON_SINKS
  regexes not matching dmcg's actual sinks (jinja2 `Template`, codegen `exec`/`compile`, x-python-*);
  (c) reachability BFS over `calls` edges when graphify emits few/no call edges for this codebase.
- Investigate after run: dump the graph (node/edge counts, confidence), run find_sinks manually,
  check symbol_at_line resolution; use 3.ST analyze_misses on any missed CVE.

## D2 — F3 sink-backward produces 0 tasks  [tied to D1]
- Symptom: `sink-backward: 0 orphan-sink audit tasks`. Consistent with find_sinks returning ~0 sinks.
- Likely same root cause as D1 (sink detection / graph). Confirm once D1 is diagnosed.

## (more to be appended as the run progresses / after scoring)

## D3 — transient `unknown_api_error` retries during Hunt  [MEDIUM — rate-limit pressure]
- Symptom: `transient API error (attempt N/4): unknown_api_error — retrying in 30s/120s` on several
  hunt tasks; runner auto-retries (audit resilience). Most recover; slows the run.
- Cause: concurrency=4 against a *subscription* OAuth token (tighter limits than an API key).
- Impact: slower wall-clock; a task exhausting all 4 retries → `failed` → that finding missed (recall hit).
- Fix options (later): lower --max-concurrency to 2–3, add jitter/longer backoff, or use an API key for
  higher limits. Note-only per "run fully first."

## D4 — 0/11 corpus recall: missed the DOMINANT codegen class  [CRITICAL — recall]
- Result: recall 0/11 (baseline 6/11). VASH found 16 findings but NONE matched the 11 CVEs.
- Root: 6 of 11 CVEs are `codegen` (CWE-94) in the template/jinja2/pydantic **model-generation** code —
  datamodel-code-generator's SIGNATURE vuln (malicious schema → injected generated code). VASH produced
  only 1 "code_injection" (in format.py — the black/isort formatter, NOT the codegen engine) and 0 in
  template/jinja2. It found PERIPHERAL vulns (ssrf, path-traversal, header-injection, DoS, race) instead.
- Contributing: D1 (taint engine=0 tasks → no deterministic path to codegen sinks) + hunters never framed
  the schema→generated-code injection. The recon/hunt prompts don't target "this tool GENERATES code."

## D5 — [INVALID / my scoring error] executed-PoC confirmation actually WORKS
- Result: all 16 findings have `poc.succeeded=0` AND `needs_poc=0` — i.e. the PoC field is empty on every
  finding. Despite running in the sandbox with Bash available, Hunt did not execute/record a reproducing
  PoC for any finding. So the "confirm by execution → zero false positives" mechanism is NOT actually
  confirming; the 16 findings are LLM-static-reasoned and UNVERIFIED (likely FP-inflated).
- Suspects: (a) the restored Hunt PoC prompt asks for a PoC but the schema `poc` object isn't being
  populated/parsed; (b) hunters skip PoC when no `live_target` (the prompt's live-vs-local branch);
  (c) PoCs run but success isn't recorded to the finding. Needs a Hunt-artifact inspection.


## CORRECTIONS (my analysis errors)
- D5 INVALID: 30/31 raw findings have poc_succeeded=1 — PoCs DO execute+reproduce (I mis-checked the report, which strips `poc`).
- D4 recall is 2/11 (not 0/11): report findings lack `cwe` so the corpus matcher scored 0; DB class-mapped = 2/11. Still < 6/11 baseline.
- Report gap: report.py drops `cwe` + `poc` from findings -> benchmark scorer can't class-match. FIX: include `cwe` (+ maybe poc summary) in report findings.


## D1/D2 FIX (verified): re-based graphify node files to repo-root-relative in build.py. On dmcg: inputs 0->21/21 resolve, find_sinks 0->62, build_taint_tasks 0->5. F3 sink-backward now fires too (shared machinery).
