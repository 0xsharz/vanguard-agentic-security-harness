"""CI recall-regression gate: compares a COMMITTED current scorecard against
a COMMITTED baseline scorecard and fails (exit 1) if recall dropped.

Context (task 4.5, .superpowers/sdd/task-4.5-brief.md): production
hardening for VASH. Every PR must clear (a) the full offline test suite
(the enforceable regression gate — see .github/workflows/ci.yml) and (b)
this recall-gate, which enforces a recall FLOOR once a real scorecard is
supplied. A live `vash run` scan is impractical in CI (LLM cost/quota/
time), so this module never scans and never computes recall itself — it
only *compares* two already-computed numbers, each produced by
bench.scorer.score_corpus() (its `cve_recall`/`class_recall` fields — see
scorer.py) and written to a scorecard JSON by a separate nightly/manual
job. Reuses bench.scorer's recall math; does not reimplement it.

Without `--current` (the mode CI runs on every PR, since it has no live
scorecard to compare), this is SMOKE mode: it only confirms the baseline
file parses and carries the metric, then exits 0. It does NOT confirm
today's recall is still >= the floor — see README.md "CI & recall gate"
for how a nightly/manual job supplies a real `--current` scorecard.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def check(
    current: dict,
    baseline: dict,
    *,
    metric: str = "cve_recall",
    tolerance: float = 0.0,
) -> tuple[bool, str]:
    """Compare `current[metric]` against `baseline[metric]`.

    `current`/`baseline` are scorecard dicts shaped like
    bench.scorer.score_corpus()'s return value (or the hand-authored
    bench/baseline_scorecard.json) — this function does no recall
    computation of its own, only the pass/fail comparison.

    Returns `(ok, message)`. `ok` is False iff
    `current[metric] < baseline[metric] - tolerance` (a regression beyond
    the allowed slack). `message` states both numbers, the delta, and the
    tolerance, e.g. for CI log output.
    """
    current_val = float(current[metric])
    baseline_val = float(baseline[metric])
    delta = current_val - baseline_val
    ok = current_val >= baseline_val - tolerance
    verdict = "PASS" if ok else "FAIL"
    message = (
        f"{verdict}: {metric} current={current_val:.4f} "
        f"baseline={baseline_val:.4f} delta={delta:+.4f} "
        f"(tolerance={tolerance:.4f})"
    )
    return ok, message


def _load_scorecard(path: str, *, metric: str) -> dict:
    """Load + validate a scorecard JSON file.

    Raises ValueError — one catchable type — with a clear message on any
    problem: missing/unreadable file, invalid JSON, wrong shape, or a
    missing/non-numeric metric. Used for both --baseline and --current so
    both fail closed the same way.
    """
    try:
        text = Path(path).read_text()
    except OSError as exc:
        raise ValueError(f"cannot read scorecard {path!r}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"scorecard {path!r} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"scorecard {path!r} must be a JSON object, got {type(data).__name__}"
        )
    if metric not in data:
        raise ValueError(f"scorecard {path!r} has no {metric!r} field")
    value = data[metric]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"scorecard {path!r} field {metric!r} is not numeric: {value!r}")
    return data


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m bench.recall_gate",
        description=(
            "CI recall-regression gate. Compares a COMMITTED --current "
            "scorecard against a COMMITTED --baseline scorecard "
            "(bench.scorer.score_corpus() output shape: cve_recall / "
            "class_recall). CI cannot run a live vash scan, so when "
            "--current is omitted this only smoke-checks that --baseline "
            "parses and is wired up correctly (exits 0 if so)."
        ),
    )
    parser.add_argument(
        "--baseline", required=True,
        help="Path to the committed baseline scorecard JSON "
             "(bench/baseline_scorecard.json).",
    )
    parser.add_argument(
        "--current", default=None,
        help="Path to a scorecard JSON recorded from a real `vash run` + "
             "bench scoring pass. Omit for CI's smoke mode.",
    )
    parser.add_argument(
        "--metric", default="cve_recall",
        help="Scorecard field to gate on (default: cve_recall; also valid: "
             "class_recall, or any other numeric field of the scorecard).",
    )
    parser.add_argument(
        "--tolerance", type=float, default=0.0,
        help="Allowed regression slack before failing (default: 0.0).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        baseline = _load_scorecard(args.baseline, metric=args.metric)
    except ValueError as exc:
        print(f"FAIL: {exc}")
        return 1

    if args.current is None:
        print(
            "SMOKE MODE: no --current supplied (CI has no LLM budget/quota "
            "to run a live scan here). Baseline loaded and validated only "
            "— this does NOT confirm today's recall. See README.md 'CI & "
            "recall gate' for how a nightly/manual job supplies a real "
            "--current scorecard.\n"
            f"  baseline file: {args.baseline}\n"
            f"  {args.metric} = {baseline[args.metric]}\n"
            "Gate wiring OK."
        )
        return 0

    try:
        current = _load_scorecard(args.current, metric=args.metric)
    except ValueError as exc:
        print(f"FAIL: {exc}")
        return 1

    ok, message = check(current, baseline, metric=args.metric, tolerance=args.tolerance)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
