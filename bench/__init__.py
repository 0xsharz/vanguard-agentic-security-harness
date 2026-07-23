"""bench — offline-testable benchmark harness that scores `audit` scans
against known-vulnerable seed targets.

Additive package: nothing here is imported by, or modifies, the `audit`
package itself. See /Users/snatarajan14/vash/docs/wiring-notes.md for the
`audit` CLI/result shapes this package parses, and
.superpowers/sdd/task-0.3-brief.md for the task this was built for.

Modules:
    scorer          -- deterministic (no-LLM) matcher: detected findings vs.
                       ground truth -> {tp, fp, fn, recall, precision, missed}.
    parse_results   -- turn an `audit` results dir / state.db into the
                       detected-findings list `scorer` consumes.
    audit_cmd       -- build (never execute) the `audit run` command line.
    clone           -- clone a benchmark target repo at a pinned commit.
    tally           -- aggregate per-finding scores into a scorecard.
    run             -- phase driver (clone -> scan -> score -> tally) with a
                       resumable JSON state file; `--tally-only` renders a
                       scorecard from existing state without scanning.
    analyze_misses  -- self-tuning miss analysis: for each CVE `scorer`
                       scores as missed, locate WHICH pipeline stage lost it
                       (recon/hunt/validate/dedupe/trace) and, optionally
                       (`--diagnose`, needs network), suggest a minimal
                       prompt fix for a human to apply.
    recall_gate     -- CI recall-regression gate: compares a committed
                       scorecard's cve_recall/class_recall (bench.scorer
                       output shape) against committed baseline_scorecard
                       .json. Smoke mode (no --current) when CI has no
                       live scorecard to compare; see .superpowers/sdd/
                       task-4.5-brief.md.
"""
