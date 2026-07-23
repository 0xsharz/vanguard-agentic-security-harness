# Third-Party Licenses & Attribution

VASH reuses code and design from three prior tools. This file documents, per
component, what was reused, from where, under which license, and whether it was
copied verbatim or adapted. Full license texts are under [`licenses/`](licenses/).

VASH's own original code is under the **MIT License** ([`LICENSE`](LICENSE)).
Reused portions retain their upstream license; files copied verbatim from an
Apache-2.0 source keep their Apache-2.0 header and remain under Apache-2.0.

## Summary of sources

| Source | License | Copyright | License text |
|---|---|---|---|
| [evilsocket/audit](https://github.com/evilsocket/audit) | MIT | evilsocket | [licenses/audit-MIT.txt](licenses/audit-MIT.txt) |
| [Capital One VulnHunter](https://github.com/capitalone/VulnHunter) | Apache-2.0 | Capital One | [licenses/VulnHunter-Apache-2.0.txt](licenses/VulnHunter-Apache-2.0.txt) |
| [Visa VVAH](https://github.com/visa/visa-vulnerability-agentic-harness) | Apache-2.0 | Visa, Inc. | [licenses/VVAH-Apache-2.0.txt](licenses/VVAH-Apache-2.0.txt) |

## Component-level attribution

### Base engine — evilsocket/audit (MIT)
VASH is a **fork** of audit. The entire base pipeline (recon, hunt, validate,
gapfill, dedupe, trace, feedback, report), SQLite `StateDB`, the Claude Agent SDK
runner, cost budgeting, and the CLI originate from audit and are extended in
place. Package/CLI renamed `audit` → `vash`.

### Verbatim ports — Visa VVAH (Apache-2.0)
These files were copied byte-for-byte and **retain their Apache-2.0 header**
(guarded by `tests/test_licensing.py`). Only import paths / thin adapters differ.

| VASH file | VVAH source | What it does |
|---|---|---|
| `vash/cvss.py` | `vvaharness/report/cvss.py` | CVSS 3.1 base-score calculator (V4) |
| `vash/lang/hints.py` | `vvaharness/lang/hints.py` | per-language security-hints KB (V9) |
| `vash/baselines.py` | `vvaharness/pipeline/stages/s2` baselines | repo-kind → OWASP/CWE baselines (V10) |
| `vash/redact.py` | `vvaharness/report/redact.py` | secret/PII/PAN redaction before egress (4.2) |

### Adapted from Visa VVAH (Apache-2.0) — not verbatim
| VASH area | VVAH source | Feature |
|---|---|---|
| `vash/graph/query.py::taint_paths`, `vash/taint.py` | `s3_decompose._bfs_to_sinks` / `_add_taint_chunks` | deterministic entry→sink taint chunking (V8) |
| `vash/specialists.py` | `s3_decompose._gate_specialists` + regexes | gated specialist passes (V12) |
| `vash/catchall.py` | `s3_decompose._catchall_eligible` + skip-sets | terminal coverage sweep (F6) |
| `vash/partition.py` | `s3_decompose._cohesive_groups` (concept) | union-find cohesive partitioning (F2) |
| `prompts/09-chain.md` | `s8_chain` system prompt | exploit-chain construction (V11) |
| `prompts/03-validate.md` (CVSS block) | `s6_verify` | CVSS-vector verification (V4) |
| `config/remediation_policy.yaml`, `vash/remediation_policy.py` | `inputs/remediation_policy.yaml` + `remediation_agent` governance | remediation policy hard-gate — fail-closed CWE allow/deny + kill-switch (Phase 5). The YAML retains VVAH's Apache-2.0 header; CWE lists / kill-switch names tuned for VASH. |
| `vash/stages/remediate.py::_CLASS_GUIDANCE` | `inputs/remediation_playbook.yaml` | per-class remediation guidance (Phase 5) |

### Adapted from Capital One VulnHunter (Apache-2.0) — not verbatim
| VASH area | VulnHunter source | Feature |
|---|---|---|
| `prompts/01-recon.md`, input reconciliation | `phase1_recon` input inventory | completeness input-inventory (F1) |
| `prompts/02-hunt.md` (sink-backward section) | `phase2_hunt` sink-driven audit | sink-backward modality (F3) |
| `prompts/03-validate.md` (disprove-gates) | `phase2b_verify` per-class gates | static verification rigor (F5) |
| `bench/analyze_misses.py` | `local_harness/benchmark/analyze_misses.py` | self-tuning miss-analysis (3.ST) |
| `vash/graph/build.py` | `vulnhunter-fix/.../graph/build.py` (graphify) | AST call-graph (linchpin) |
| `prompts/remediate.md` | `vulnhunter-fix/prompts/implement.md` + `worker_agent_{injection,authz,crypto,resource}.md` | static root-cause patch + security-test prompt, adapted to generate-only (Phase 5) |

### Benchmark ground truth
`bench/ground_truth/datamodel-code-generator.json` contains real, source-verified
CVE metadata (public advisory data) used as the recall measuring stick. It is
factual test data, not a scanning technique.

## Compliance notes (Apache-2.0 §4)
- The [`NOTICE`](NOTICE) file is provided and reproduces the required attributions.
- Reused Apache-2.0 files retain their in-file license headers.
- Changes were made to adapt every reused portion to VASH's Python static-first
  pipeline; this constitutes the "stating changes" requirement.
- The full Apache-2.0 and MIT texts are included under [`licenses/`](licenses/).
