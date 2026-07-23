# Benchmark Ground Truth

One JSON file per target repository; each is an array of known findings
`audit` is expected to detect. Adapted from VulnHunter's ground-truth shape
(`harness/local_harness/benchmark/ground_truth/README.md`), extended with
`file`/`line` so `bench.scorer` can match deterministically (no LLM judge).

Two ground-truth shapes are supported side by side, one JSON file may use
either, and `bench.scorer.score_auto()` dispatches per-file based on whether
its entries carry `file_hint`.

## Shape 1 — basename + CWE + line (original)

```json
[
  {
    "finding_id": "GT-001",
    "type": "CWE-94",
    "file": "jsonschema.py",
    "line": 120,
    "source_code": "https://github.com/org/repo/tree/<commit_hash>",
    "description": "Human-readable description, for the MISSED-findings report."
  }
]
```

| Field | Meaning |
|---|---|
| `finding_id` | Unique label for this ground-truth item. |
| `type` | Vulnerability class. Prefer a `CWE-NNN` id — `bench.scorer` matches on CWE when both sides have one, falling back to a case-insensitive label comparison otherwise. |
| `file` | Path (or just a basename) of the vulnerable file. Matched by `os.path.basename()` only, so clone-root prefixes don't matter. |
| `line` | Optional. A hint line number; a detected finding matches if its `[line_start, line_end]` falls within `line_tolerance` (default 15) lines of it. Omit to skip the line check entirely (file+class match is enough). |
| `source_code` | `https://github.com/{org}/{repo}/tree/{commit_hash}` — `bench.clone` clones exactly this commit. |
| `description` | Shown in the missed-findings section of the rendered scorecard. |

Matched by `bench.scorer.score()` — basename(file) + CWE/type class,
line-tolerant, greedy 1:1.

## Shape 2 — class + file_hint (corpus-faithful, REAL data)

For targets whose public advisories publish no exact file:line — only a
vulnerability class and one or more file-name hints — ground truth instead
carries `file_hint` (a list of substrings) in place of `file`/`line`/`type`:

```json
[
  {
    "finding_id": "CVE-2026-54655",
    "cwe": "CWE-94",
    "class": "codegen",
    "file_hint": ["jsonschema"],
    "in_version": true,
    "source_code": "https://github.com/org/repo@1.2.3",
    "description": "Human-readable description, for the MISSED-findings report."
  }
]
```

| Field | Meaning |
|---|---|
| `finding_id` | The CVE id. |
| `cwe` | `CWE-NNN` id. |
| `class` | Coarse vulnerability class per `bench.scorer.CWE_CLASS` — one of `codegen`, `ssrf`, `traversal`, `infoleak`, `deser`, `cmdinj`, `sqli`, `xss`, `xxe`, `ssti`. |
| `file_hint` | List of substrings. A detected finding matches this CVE iff `class_of(finding.cwe) == class` AND its `file` path contains (case-insensitively) at least one of these substrings. |
| `in_version` | Optional, defaults `true`. `false` marks a CVE whose vulnerable code was verified (by inspection) not to exist in the pinned version being scanned — excluded from the recall denominator and reported separately under `excluded`, rather than counted as a miss. |
| `source_code` | `https://github.com/{org}/{repo}@{version}` — this shape pins a released version, not a commit; `bench.clone`'s commit-hash cloning (`parse_source_url`) doesn't parse this form yet, so the live clone/scan phases for a Shape-2 target are follow-up work (a version-based fetch, e.g. from PyPI), not wired up by this ground-truth change alone. |
| `description` | Shown in the missed-findings section of the rendered scorecard. |

Matched by `bench.scorer.score_corpus()` — class(CWE) + file_hint substring,
greedy 1:1, `in_version:false` excluded from the denominator. Ported from the
ai-proofscan project's `benchmark/match.py` + `benchmark/corpus.yaml`
(`/Users/snatarajan14/ai-proofscan/old_one/benchmark/`) — the same author's
prior, adversarially-reviewed matcher and corpus for this exact target,
mirrored here rather than reinvented.

`datamodel-code-generator.json` ships the **REAL**, source-verified 12-CVE
corpus for `datamodel-code-generator` 0.55.0 (Shape 2) — replacing the
earlier synthetic placeholder entries. One entry, `CVE-2026-55390`, is
`in_version: false` (0.55.0 ships no XSD parser or `schemaLocation`/XSD
references at all — the vulnerable code was added in a later release),
leaving 11 CVEs in the recall denominator.

## Notes

- Multiple findings sharing the same `{org}/{repo}/{commit_hash}` (derived
  from `source_code`) are scanned together — one `audit run` per unique
  repo+commit. This grouping convention assumes Shape 1's commit-hash
  `source_code` form; see the Shape 2 row above for the version-pinned
  caveat.
- Runtime output (`bench/bench_workdir/`) is gitignored and never committed.
