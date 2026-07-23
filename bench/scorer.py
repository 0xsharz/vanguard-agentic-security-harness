"""Deterministic (no-LLM, no-network) scorer: detected findings vs. ground truth.

This is the unit-tested heart of the benchmark harness. Given a list of
findings `audit` actually detected (see `parse_results.py`) and a list of
known ground-truth findings for the scanned target (see
`ground_truth/*.json`), it computes tp/fp/fn/recall/precision by matching
each ground-truth item to at most one detected finding.

Match rule (per the task brief): basename(file) + CWE/type class, line-tolerant.
  - File: compared by basename only (detected findings may report paths
    relative to a different clone root than ground truth's `file` field).
  - Class: if both sides carry a `CWE-NNN` value (in `cwe`, or in `type`/
    `vuln_class` when it's itself a CWE id), compare those; otherwise fall
    back to a case-insensitive comparison of `vuln_class`/`type` labels.
  - Line: only enforced when the ground-truth item specifies a `line` hint;
    a detected finding matches if that line falls within
    `line_tolerance` (default 15) lines of the finding's [line_start, line_end].

This is intentionally a rule-based replacement for VulnHunter's LLM-as-judge
(harness/local_harness/benchmark/judge.py) — `audit` findings carry
structured file/line/CWE fields (see schemas/finding.schema.json,
report.schema.json), so a fuzzy LLM comparator isn't needed for this shape,
and a rule-based one is deterministic, free, and CI-friendly.
"""

from __future__ import annotations

import posixpath
from typing import Any

DEFAULT_LINE_TOLERANCE = 15


def _basename(path: str | None) -> str:
    if not path:
        return ""
    # Normalize both slash conventions before delegating to posixpath so a
    # ground-truth entry authored with "/" and a Windows-style detected path
    # still resolve to the same basename.
    return posixpath.basename(path.replace("\\", "/"))


def _norm(value: Any) -> str:
    return str(value).strip().lower() if value else ""


def _cwe_of(item: dict) -> str | None:
    """Extract a normalized `cwe-nnn` id from an item's `cwe`, `type`, or
    `vuln_class` field, whichever (if any) actually holds a CWE id."""
    for key in ("cwe", "type", "vuln_class"):
        v = _norm(item.get(key))
        if v.startswith("cwe-"):
            return v
    return None


def _class_label(item: dict) -> str:
    """Best-effort free-text class label when neither side has a CWE id."""
    return _norm(item.get("vuln_class") or item.get("type"))


def classes_match(detected: dict, gt: dict) -> bool:
    d_cwe, g_cwe = _cwe_of(detected), _cwe_of(gt)
    if d_cwe and g_cwe:
        return d_cwe == g_cwe
    label = _class_label(detected)
    return bool(label) and label == _class_label(gt)


def files_match(detected: dict, gt: dict) -> bool:
    d_file, g_file = detected.get("file"), gt.get("file")
    if not d_file or not g_file:
        return False
    return _basename(d_file) == _basename(g_file)


def lines_match(detected: dict, gt: dict, tolerance: int = DEFAULT_LINE_TOLERANCE) -> bool:
    g_line = gt.get("line")
    if g_line is None:
        return True  # no line hint in ground truth -> nothing to check

    d_start = detected.get("line_start")
    if d_start is None:
        return True  # detected finding carries no lines -> don't penalize

    d_end = detected.get("line_end", d_start)
    if d_end is None:
        d_end = d_start
    lo, hi = (d_start, d_end) if d_start <= d_end else (d_end, d_start)
    return (lo - tolerance) <= g_line <= (hi + tolerance)


def is_match(detected: dict, gt: dict, line_tolerance: int = DEFAULT_LINE_TOLERANCE) -> bool:
    return (
        files_match(detected, gt)
        and classes_match(detected, gt)
        and lines_match(detected, gt, line_tolerance)
    )


def score(
    detected: list[dict],
    ground_truth: list[dict],
    *,
    line_tolerance: int = DEFAULT_LINE_TOLERANCE,
) -> dict:
    """Greedily, deterministically match detected findings to ground truth.

    Each ground-truth item claims at most one detected finding (first
    unclaimed match, in input order), and each detected finding satisfies at
    most one ground-truth item — so duplicate detections of the same real
    bug can't be double-counted as multiple true positives.

    Returns:
        {
          "tp": int, "fp": int, "fn": int,
          "recall": float,      # tp / (tp + fn), 0.0 if no ground truth
          "precision": float,   # tp / (tp + fp), 0.0 if nothing detected
          "missed": [ground-truth items with no matching detection],
          "matches": [{"ground_truth_id": ..., "detected_id": ...}, ...],
        }
    """
    unclaimed = list(detected)
    missed: list[dict] = []
    matches: list[dict] = []

    for gt in ground_truth:
        found_idx = None
        for i, d in enumerate(unclaimed):
            if is_match(d, gt, line_tolerance):
                found_idx = i
                break
        if found_idx is None:
            missed.append(gt)
        else:
            d = unclaimed.pop(found_idx)
            matches.append({
                "ground_truth_id": gt.get("finding_id"),
                "detected_id": d.get("finding_id"),
            })

    tp = len(matches)
    fn = len(missed)
    fp = len(unclaimed)

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "missed": missed,
        "matches": matches,
    }
