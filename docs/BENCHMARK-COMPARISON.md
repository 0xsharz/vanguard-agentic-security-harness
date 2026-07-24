# VASH vs audit vs VVAH — Benchmark Comparison

**Target:** `datamodel-code-generator` 0.55.0 (Python code-generator library, 50 source files)
**Ground truth:** 11 in-version CVEs across 4 classes — codegen (6, CWE-94), SSRF (3, CWE-918), path-traversal (1, CWE-22), info-leak (1, CWE-200). *(A 12th CVE, CVE-2026-55390, is excluded as not-in-version.)*
**Date:** 2026-07-25

## Methodology (kept identical across tools — no hints given)

- **Same target** mounted read-only into each tool's container.
- **Same models:** Opus 4.8 for recon / validate / trace; Sonnet 5 for hunt / gapfill / dedupe / feedback / chain / report. (audit's stale model IDs were bumped to match; its pipeline/prompts were left pristine.)
- **Same sandbox:** each tool run in its own Docker container (execution isolated; PoCs run in-sandbox).
- **Same scorer:** a finding matches a CVE when `class(finding) == class(CVE)` **and** any of the CVE's advisory file-hints is a substring of the finding's file path; greedy 1:1; in-version CVEs only. Class is taken from the finding's CWE when present, else mapped from its vuln-class.
- **Scoring basis:** each tool's **confirmed findings** (validated true-positives) — the fair "detection capability" basis. VVAH is scored from its delivered SARIF; VASH/audit from their run DB. The "reported" row below shows each tool's *final report* after dedupe/trace filtering.

## Scorecard

| Metric | **VASH** | **audit** (evilsocket) | **VVAH** (Visa) | ai-proofscan (ref) |
|---|---|---|---|---|
| **Recall — detected (confirmed)** | **6/11 (55%)** | 4/11 (36%) | 4/11 (36%) | 6/11 (55%) |
| Recall — final report | 2/11 ⚠️ | 3/11 | 4/11 | — |
| Unique CVEs (found by only this tool) | **2** (55415, 55391) | 0 | 1 (54621) | — |
| Confirmed findings | 45 | 21 | 20 | — |
| Canonical / reported | 21 | 13 | 20 | — |
| Exploit chains | 5 | 0 | — | — |
| **Cost (USD)** | $96.52 | **$47.94** | (your run) | — |
| Wall-clock | 2.71 hr | 2.90 hr | — | — |
| Pipeline | 9-stage + deterministic graph engine | 8-stage LLM | agentic SAST, template-aware | static-first |

## Per-CVE matrix (detection)

| CVE | Class | File hints | VASH | audit | VVAH |
|---|---|---|:---:|:---:|:---:|
| CVE-2026-54621 | codegen | template, jinja2, UnionType | · | · | **✓** |
| CVE-2026-54653 | codegen | pydantic_base, dataclass, msgspec | · | · | · |
| CVE-2026-54654 | codegen | template, jinja2, TypeAlias, comment | · | · | · |
| CVE-2026-54655 | codegen | jsonschema | ✓ | ✓ | ✓ |
| CVE-2026-54656 | codegen | validator | · | · | · |
| CVE-2026-54690 | ssrf | http | ✓ | ✓ | ✓ |
| CVE-2026-54691 | ssrf | http, arguments, __main__ | ✓ | ✓ | · |
| CVE-2026-55415 | codegen | imports | **✓** | · | · |
| CVE-2026-55389 | traversal | jsonschema | ✓ | ✓ | ✓ |
| CVE-2026-55391 | ssrf | http | **✓** | · | · |
| CVE-2026-55403 | infoleak | http | · | · | · |
| **TOTAL** | | | **6/11** | **4/11** | **4/11** |

**Overlap:** all three find the 3 "easy" `.py` CVEs (54655, 54690, 55389). Everything else is where the tools differ.
**Missed by all three:** 54653, 54654, 54656 (codegen), 55403 (infoleak) — deeper template/model or http-header instances no tool reached.

## Per-tool analysis

### VASH — best detector (6/11), but its report hides it
- Ties the ai-proofscan baseline and **finds 2 CVEs no other tool did** — `55415` (codegen in `imports`) and `55391` (SSRF). Its deterministic taint + sink-backward engine (fed by a fixed call-graph) sweeps SSRF/codegen/traversal broadly, and it builds **5 exploit chains** (multi-step attack paths) neither competitor produces.
- **But** its final report shows only 2/11: dedupe collapses each duplicate cluster to one "canonical" finding, and when the canonical it keeps sits in a *different* file than the advisory cites, the corpus match is dropped. **The detection is real; the report loses it (fix D8).**
- Most expensive ($96) — the deterministic engine roughly doubles the hunt-task count (71 vs ~27). That buys the extra recall.

### audit (evilsocket) — lean, cheap baseline (4/11 at half the cost)
- Pure 8-stage LLM hunting, no deterministic engine, no chain stage. Matches VASH on the 4 easy/`.py` CVEs, finds nothing unique, and costs **half** ($48). Solid, economical, but leaves recall on the table (no template awareness, no graph-driven coverage).

### VVAH (Visa) — template-aware (4/11), the only tool to catch a template CVE
- Its unique win is `54621` — codegen injection **inside a `.jinja2` template file**. VVAH scans template files; VASH and audit scan only `.py`, so they can't see codegen instances that live in the templates. This is VVAH's real, transferable edge.

## Actionable gaps for VASH (ranked)

- **D8 (highest value, no re-scan) — report over-filtering.** Dedupe keeps a canonical finding in a non-matching file, dropping 4 of 6 real corpus hits from the final report (6 detected → 2 reported). Fix the canonical-selection / carry all cluster members' locations into the report. Turns the *reported* number from 2/11 to 6/11 with zero extra scanning.
- **D7 — scan template files.** Add `.jinja2`/`.mako`/`.j2` (and other codegen templates) to `find_sinks`; likely recovers `54621` and other template-resident codegen (VVAH's edge).
- **D6 — cost.** The deterministic engine doubled tasks → $96. Cap taint/sink-backward task counts and reuse the graph across stages to cut cost toward audit's $48 without losing the 6/11 detection.
- **D3 — rate-limiting.** Subscription-token throttling (concurrency 4) caused retries + failed tasks and stretched wall-clock; an API key or lower concurrency would speed + de-risk runs.
- (Closed this cycle: **D1/D2** graph path-mismatch that had disabled taint entirely; **D4** report missing CWE; **D5** was a false alarm — PoCs do execute.)

## Bottom line

On **detection capability**, ranked: **VASH 6/11 > audit 4/11 = VVAH 4/11**, with VASH tying the ai-proofscan baseline and uniquely catching 2 CVEs. VASH is the strongest *detector* but currently the most expensive, and a report-presentation bug (D8) masks its true recall. audit is the efficient baseline; VVAH's template-scanning is the one capability VASH should adopt. Fix D8 + D7 + cost and VASH is clearly ahead on the metric that matters.

---
*Artifacts: `~/vash/results/dmcg-fix/VASH-dmcg-fix-report.pdf` · `~/audit-orig/audit-dmcg-report.pdf` · `~/vul_testing/datamodel-code-generator-0.55.0_report.{md,sarif}` (VVAH).*
