# VASH vs audit vs VVAH — Benchmark Comparison

**Target:** `datamodel-code-generator` 0.55.0 (Python code-generator library, 50 source files)
**Ground truth:** 11 in-version CVEs — codegen (6, CWE-94), SSRF (3, CWE-918), path-traversal (1, CWE-22), info-leak (1, CWE-200). *(CVE-2026-55390 excluded as not-in-version.)*
**Date:** 2026-07-25 (updated with post-fix results)

---

## ⭐ UPDATE — post-fix result: VASH now BEATS VVAH (5/11 > 4/11)

After shipping the D8 (report-delivery) and D7 (template-scanning) fixes, VASH was re-run on the same target and re-scored with the same `bench/scorer.py::score_corpus`. **On the fair DELIVERED, static basis (VVAH is 100% static too), VASH now leads:**

| DELIVERED recall | findings | cost/time | basis |
|---|---|---|---|
| **VASH 5/11 (0.455)** 🏆 | 25 (+5 chains) | ~2.5hr / $103 | host-static, all D8+D7 fixes (run `dmcg-outperform`) |
| VVAH 4/11 | 20 | ~3hr | static |
| audit 2/11 | 13 | $48 | static |

**VASH cve_found = 54621, 54653, 54654, 54690, 55389.** The decisive edge is **D7 (template scanning)**: catch-all coverage grew from **50 → 70 source files** (the 20 `.jinja2` templates were previously invisible), and VASH delivered **both** template codegen CVEs **54621 + 54654** — VVAH delivered only 54621. It also newly delivered **54653** (`msgspec.py` codegen — no tool had it before).

**Proven progression (re-scored, not assumed):** old VASH **2/11** → **4/11** (D8 per-file-canonical alone, re-scored on the *same* 45 executed-PoC-confirmed findings — recovered 54690 `http.py` SSRF + 55415 `imports.py`) → **5/11** (D8+D7 fresh host run — added the templates + msgspec).

**Honest caveats:**
- This E run is **host-static** (no executed-PoC), so its 20 non-corpus "extras" are not PoC-filtered — but VVAH is also static (16 extras), so extras are comparable and the recall comparison is apples-to-apples.
- The fresh host hunt is **stochastic**: it gained templates + msgspec but *missed* 54655 (`jsonschema` codegen) and 55415 (`imports`) that the earlier Docker-confirmed set had. A **Docker run (D7 + executed-PoC)** would likely combine both → an estimated **6–7/11** *and* PoC-filtered precision (VASH's zero-FP edge). That run is deferred until a container OAuth token is minted (`claude setup-token`).

Fix commits on `evolve/vulnhunter-imports` (whole-branch review: **READY TO MERGE**); plan at `docs/superpowers/plans/2026-07-25-vash-outperform.md`.

---

## Methodology (identical across tools — no hints given)

- **Same target** mounted read-only into each tool's own Docker container (execution isolated; PoCs run in-sandbox).
- **Same models:** Opus 4.8 for recon / validate / trace; Sonnet 5 for the rest. (audit's stale model IDs were bumped to match; its pipeline/prompts were left pristine. VVAH ran via its own CLI backend.)
- **Same scorer:** a finding matches a CVE when `class(finding) == class(CVE)` **and** any advisory file-hint is a substring of the finding's file path; greedy 1:1; in-version CVEs only. Class from the finding's CWE when present, else mapped from vuln-class.

### Scoring basis — read this before trusting any number
The only cross-tool-comparable metric is each tool's **delivered output** — the report/SARIF a user actually receives, *after that tool's own dedup/filter*:
- VVAH → its SARIF (20 findings, already deduped: 97 raw → 40 FP dropped → 34 dupes merged → 20).
- audit / VASH → their `report.json` (13 / 21 findings, after dedup + trace).

A tool's **pre-dedup confirmed** count is **not** comparable across tools, because VVAH's pre-dedup set (its 97 raw candidates) isn't available — only its final 20. So we rank on **delivered** only.

## Scorecard (ranked by delivered recall)

| Metric | **VVAH** (Visa) | **audit** (evilsocket) | **VASH** |
|---|---|---|---|
| **Recall — DELIVERED (the ranking metric)** | **4/11 (36%)** | 2/11 (18%) | 2/11 (18%) |
| Delivered findings | 20 | 13 | 21 |
| Exploit chains | 6 | 0 | 5 |
| Cost | ~7.2M tokens / ~3 hr | **$48 / 2.9 hr** | $96 / 2.7 hr |
| Coverage | 74 files, 82.2% | 50 files | 50 files |
| Precision (reported) | 20.6% (97→20) | — | — |
| Pipeline | agentic SAST, **template-aware** | lean 8-stage LLM | 9-stage + deterministic graph engine |
| **VASH-internal note:** pre-dedup *confirmed* | n/a (unavailable) | 4/11 | 6/11 *(dedup/report drops 4 → delivers 2; see D8)* |

*ai-proofscan reference baseline on this corpus: 6/11.*

## Per-CVE matrix (delivered output — apples-to-apples)

| CVE | Class | Hints | VVAH | audit | VASH |
|---|---|---|:---:|:---:|:---:|
| 54621 | codegen | template, jinja2, UnionType | **✓** | · | · |
| 54653 | codegen | pydantic_base, dataclass, msgspec | · | · | · |
| 54654 | codegen | template, jinja2, TypeAlias | · | · | · |
| 54655 | codegen | jsonschema | ✓ | ✓ | ✓ |
| 54656 | codegen | validator | · | · | · |
| 54690 | ssrf | http | **✓** | · | · |
| 54691 | ssrf | http, arguments, __main__ | · | · | · |
| 55415 | codegen | imports | · | · | · |
| 55389 | traversal | jsonschema | ✓ | ✓ | ✓ |
| 55391 | ssrf | http | · | · | · |
| 55403 | infoleak | http | · | · | · |
| **TOTAL** | | | **4/11** | **2/11** | **2/11** |

- **All three deliver:** 54655 (codegen in `jsonschema.py`) and 55389 (traversal in `jsonschema.py`).
- **VVAH uniquely delivers 2:** 54621 (codegen inside `UnionTypeAliasAnnotation.jinja2` — a **template file**) and 54690 (SSRF in `http.py`).
- **Nobody delivers:** 54653/54654/54656/55415 (codegen), 54691/55391 (ssrf), 55403 (infoleak) — 7 of 11 missed by all.

## Per-tool analysis

### VVAH (Visa) — best on this benchmark (4/11 delivered)
20 verified findings (4 critical RCE, 6 high), 6 exploit chains, 82% file coverage. Its decisive edges: it **scans template files** (`.jinja2`) — catching codegen that lives in templates (54621) — and it cleanly surfaces the `http.py` SSRF (54690). Trade-off: lowest precision it reports (20.6%) and highest analysis budget (~3 hr / 7.2M tokens).

### audit (evilsocket) — cheapest, ties VASH on delivery (2/11)
Pure 8-stage LLM hunting, no deterministic engine, no templates. Delivers the 2 easy `.py` CVEs at **half the cost** ($48). Efficient baseline; leaves recall on the table (no template awareness, no graph coverage).

### VASH — ties last on delivery (2/11), but with the highest ceiling
Delivers only 2/11 — the **same 2** as audit — despite its pipeline *confirming* 6/11 as true-positives internally. Its dedup/trace/report logic (**D8**) discards 4 confirmed corpus matches before the report. It also can't see template files (like audit), and costs the most ($96, from the deterministic engine doubling task count). It does produce 5 exploit chains. **Its potential recall is real but unrealized as delivered.**

## Fix backlog for VASH (ranked by impact)

- **D8 (highest) — report throws away confirmed matches.** Dedup keeps a canonical finding in a non-matching file, dropping 4 of 6 real corpus hits before the report (delivers 2, confirmed 6). Pure report logic — no re-scan needed. This alone would move VASH's *delivered* recall from 2/11 toward 6/11 and past VVAH — **but that's a claim to be proven by re-scoring the fixed report, not assumed.**
- **D7 — scan template files.** Add `.jinja2`/`.mako`/`.j2` to `find_sinks`; VVAH's unique win (54621) lives there.
- **D6 — cost.** Deterministic engine doubled tasks → $96 (2× audit). Cap taint/sink-backward counts.
- **D3 — rate-limiting.** Subscription-token throttling stretched wall-clock + failed tasks; an API key would help.
- (Closed: **D1/D2** graph path-mismatch that had disabled taint; **D4** report missing CWE; **D5** false alarm — PoCs do execute.)

## Bottom line (honest)

On **delivered output — the only fair cross-tool metric — VVAH wins (4/11), and VASH ties audit for last (2/11).** VVAH earns it by scanning templates and delivering its matches cleanly. VASH's engine actually *confirms* more (6/11 internally) but a report-filtering bug (D8) discards most of it, so **as it stands today VASH is not better than VVAH on this benchmark.** Whether VASH can pull ahead depends on fixing D8 + D7 and re-scoring — an unproven hypothesis, not a result.

---
*Artifacts: `~/vash/results/dmcg-fix/VASH-dmcg-fix-report.pdf` · `~/audit-orig/audit-dmcg-report.pdf` · `~/vul_testing/datamodel-code-generator-0.55.0_report.{md,sarif}` (VVAH).*
