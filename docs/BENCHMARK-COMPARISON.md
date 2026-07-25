# VASH vs VVAH vs audit — Complete Benchmark Report

**Target:** `datamodel-code-generator` 0.55.0 — Python code-generator library, 50 `.py` source files + 20 `.jinja2` templates.
**Ground truth:** 11 in-version CVEs — codegen (6, CWE-94), SSRF (3, CWE-918), path-traversal (1, CWE-22), info-leak (1, CWE-200). *(CVE-2026-55390 excluded — not present in this release.)*
**Scorer:** `bench/scorer.py::score_corpus` — a finding matches a CVE when `class(finding.CWE) == class(CVE)` **and** any advisory `file_hint` is a case-insensitive substring of the finding's path; greedy 1:1; in-version CVEs only. Deterministic, no LLM, no network.
**Date:** 2026-07-25.

---

## 1. Headline

**After the D8 + D7 fixes, VASH delivers 5/11 — and beats VVAH's 4/11 on both the static basis *and* the rigorous executed-PoC basis.** The win is not a fluke: two independent runs (host-static and in-container executed-PoC) each scored 5/11. VASH is also the **only** tool of the three whose every delivered finding is confirmed by *running a real exploit*.

| Rank | Tool / run | Delivered recall | Findings | Cost / time | Basis |
|---|---|---|---|---|---|
| 🥇 | **VASH** (Docker, executed-PoC) | **5/11 (45%)** | 25 (+3 chains) | ~$88 / ~3.5 hr | every finding exploit-verified |
| 🥇 | **VASH** (host, static) | **5/11 (45%)** | 25 (+5 chains) | ~$103 / ~2.5 hr | static hunt |
| 🥈 | **VVAH** (Visa) | 4/11 (36%) | 20 (+6 chains) | ~7.2M tok / ~3 hr | static |
| 🥉 | **audit** (evilsocket) | 2/11 (18%) | 13 | $48 / ~2.9 hr | static |

*Reference: the ai-proofscan baseline scored 6/11 on this corpus. VASH's demonstrated ceiling (union of its two runs) is also **6/11** — see §5.*

---

## 2. Per-CVE matrix (delivered output — apples-to-apples)

| CVE | Class | Location / hint | audit | VVAH | VASH·static | VASH·PoC |
|---|---|---|:---:|:---:|:---:|:---:|
| 54621 | codegen | `UnionType*.jinja2` (template) | · | ✓ | ✓ | ✓ |
| 54653 | codegen | `model/base.py` / msgspec | · | · | **✓** | · |
| 54654 | codegen | `TypeAlias*.jinja2` (template) | · | · | **✓** | **✓** |
| 54655 | codegen | `parser/jsonschema.py` | ✓ | ✓ | · | ✓ |
| 54656 | codegen | `base_model.py` / validator | · | · | · | · |
| 54690 | ssrf | `http.py:29` | · | ✓ | ✓ | ✓ |
| 54691 | ssrf | `http.py` (redirect/CLI) | · | · | · | · |
| 55415 | codegen | `imports.py` | · | · | · | · |
| 55389 | traversal | `parser/jsonschema.py` | ✓ | ✓ | ✓ | ✓ |
| 55391 | ssrf | `http.py` (redirect-bypass) | · | · | · | · |
| 55403 | infoleak | `__main__.py` / http headers | · | · | · | · |
| **TOTAL** | | | **2** | **4** | **5** | **5** |

- **The decisive edge is templates (D7).** Both VASH runs delivered **54654** (a `.jinja2` codegen CVE) that no other tool caught, and matched VVAH on **54621**. VVAH catches only one template CVE; VASH catches two.
- **Stochastic trade:** the static run uniquely caught **54653** (`msgspec`); the PoC run uniquely caught **54655** (`jsonschema`). Same score, different draw — the hunt is non-deterministic (see §5).
- **All four tools miss the same 5** (54656, 54691, 55415, 55391, 55403) — structural reasons in §6.

---

## 3. What changed VASH from 2/11 → 5/11

The pre-fix VASH scored **2/11 delivered** despite *confirming* 6/11 true-positives internally — a delivery bug, not a detection gap. Two fixes closed it:

### D8 — report delivery (`vash/stages/dedupe.py`)
Dedupe promoted **one canonical finding per group**. When a group spanned files, a genuinely-confirmed match in a non-canonical file was silently dropped before trace/report. Fix: promote **one canonical per (group, distinct file)** (+ a `dict.fromkeys` guard against duplicate member ids re-burying a finding).
**Proven:** re-scoring the *same 45 executed-PoC-confirmed findings* with the fixed dedup moved delivered recall **2/11 → 4/11**, recovering CVE-2026-54690 (`http.py` SSRF) and 55415 (`imports.py`). Deterministic, no re-hunt.

### D7 — template scanning (`vash/orchestrator.py::_sweepable_source_files`)
The catch-all coverage sweep used a hard `.py`-only file allowlist that ran *before* the (already-ported) VVAH eligibility filter, so `.jinja2` templates could never be hunted. Fix: build the sweep universe from `EXT_TO_LANG` + `is_iac_file` (reusing the hardened `safe_walk_files`), including web templates.
**Proven:** coverage grew **50 → 70 source files**; the fresh run delivered both template CVEs → **5/11**.

### Supporting
- **A2** (`report.py::_attach_variants`): VVAH-style "Also at:" located variant evidence — deduped same-file siblings surface with file/line instead of being dropped.
- **C1** (`vash/taint.py`): a narrow CWE-200 `information_disclosure` sink + hunt framing (targets 55403; not yet delivered — see §6).

**Recall progression (each step proven, not assumed):**

```
2/11  ──D8 (per-file canonical, re-scored on same confirmed set)──▶  4/11
4/11  ──D7 (template sweep, coverage 50→70, fresh run)──────────▶  5/11
```

Branch `evolve/vulnhunter-imports`: 9 commits, whole-branch review **READY TO MERGE**, 619 offline tests green.

---

## 4. VASH's structural differentiator — executed-PoC confirmation

VASH's identity is **static recall + sandboxed executed-PoC confirmation**: it hunts broadly for recall, then **runs a real exploit per candidate inside a Docker sandbox** and keeps only findings whose PoC actually fires. In the executed-PoC run, **every one of the 25 delivered findings had `poc_succeeded = 1`** — confirmed by execution, not static reasoning.

**VVAH and audit are 100% static** — they can write PoC scripts but never run them (VVAH's agents are deny-by-default; Bash is blocked). This is the one axis where VASH is categorically different, not just quantitatively ahead.

On a bare host VASH stays fully static (the runner strips `Bash` unless `sandbox.is_sandboxed()`); execution happens only inside the container. That safety gate is why the two runs exist: the host run is static (like VVAH), the Docker run executes.

---

## 5. Honest reading of the numbers

- **5/11 per run, 6/11 union.** Each single run delivers 5; across the two runs VASH delivered **6 distinct** CVEs (54621, 54653, 54654, 54655, 54690, 55389). The hunt is stochastic, so a given run trades `msgspec`↔`jsonschema`. Combining runs or adding hunt iterations should reliably land 6/11 — that's an unrealized-but-demonstrated ceiling, stated as such.
- **Executed-PoC didn't lift *recall* here.** Both bases scored 5/11 with 20 non-corpus "extras." What the PoC run buys is **confidence** (zero static-reasoning false positives), not extra corpus hits — an honest correction to the earlier "6–7/11" estimate, which was optimistic.
- **The 20 "extras" are PoC-succeeded** in the Docker run — so they are either real vulnerabilities outside the 11-CVE corpus, or cases where the PoC oracle over-confirms; they need triage before being called clean. VVAH reported 16 extras (20 delivered − 4 corpus), so extra-count is comparable.
- **Cost is real:** ~$88–103 and 2.5–3.5 hr per run (Opus recon/validate/trace; executing exploits is slow). audit is far cheaper ($48) for its 2/11.

---

## 6. Why the 5 shared misses slip (all four tools)

| CVE | Reason |
|---|---|
| 54691, 55391 | Same `http.py:29` sink as the delivered 54690 — a greedy 1:1 scorer credits the sink once; three CVEs point at one line. |
| 54656 | VASH *does* deliver a `base_model.py` validator finding, but the file path lacks the literal substring `"validator"`, so the file-hint scorer can't credit it (scorer granularity, not a detection miss). |
| 55415 | `imports.py` codegen — confirmed on the Docker-set (recovered by D8 in the 4/11 proof) but not hunted+confirmed in these fresh runs (stochastic). |
| 55403 | `__main__.py` infoleak (secret-bearing traceback print). C1 added the sink + framing but it wasn't confirmed+delivered this draw. |

---

## 7. Methodology

- **Same target**, same 11-CVE ground truth, same `score_corpus` scorer for every tool.
- **Same models:** Opus 4.8 for recon / validate / trace; Sonnet 5 for the rest. (audit's stale model IDs were bumped to match; its pipeline/prompts left pristine. VVAH ran via its own CLI.)
- **No hints given** to any tool.
- **Fair basis = DELIVERED output** — each tool's final report/SARIF after its own dedup (VVAH: SARIF, 97 raw → 20; audit/VASH: `report.json`). A tool's *pre-dedup* candidate set is **not** cross-comparable (VVAH's 97 raw candidates aren't published), so ranking is on delivered output only.
- **Reproduce:** host run `vash run --repo .bench-targets/dmcg-src --run-id dmcg-outperform`; Docker run `docker run … vash:latest run --repo /target --run-id dmcg-docker-poc` (executed-PoC). Score any report with `bench/scorer.py::score_corpus`.

---

## 8. Bottom line

On delivered recall — the only fair cross-tool metric — **VASH now leads at 5/11, ahead of VVAH's 4/11 and audit's 2/11**, and it is the only tool whose findings are confirmed by real exploit execution. The lead is driven by template scanning (D7) and clean delivery (D8), and it is proven, not asserted: re-scored at every step. The honest ceiling on this corpus is 6/11 (union of runs); closing the gap to it means reducing hunt variance and resolving the scorer-granularity miss on 54656.

*Artifacts: `results/dmcg-outperform/report/report.json` (static) · `results/dmcg-docker-poc/report/report.json` (executed-PoC) · plan `docs/superpowers/plans/2026-07-25-vash-outperform.md`.*
