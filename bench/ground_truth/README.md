# Benchmark Ground Truth

One JSON file per target repository; each is an array of known findings
`audit` is expected to detect. Adapted from VulnHunter's ground-truth shape
(`harness/local_harness/benchmark/ground_truth/README.md`), extended with
`file`/`line` so `bench.scorer` can match deterministically (no LLM judge).

## Schema

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

`datamodel-code-generator.json` ships as the seed target with 3
**SYNTHETIC SEED** entries (clearly labeled as such in each `description`) —
illustrative placeholders, not confirmed CVEs, per the same "no zero-days"
convention VulnHunter's own `EXAMPLE.json` uses. Replace the commit hash and
details with a real, source-verified finding before using this for a real
benchmark run.

## Notes

- Multiple findings sharing the same `{org}/{repo}/{commit_hash}` (derived
  from `source_code`) are scanned together — one `audit run` per unique
  repo+commit.
- Runtime output (`bench/bench_workdir/`) is gitignored and never committed.
