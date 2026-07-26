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
    `vuln_class` when it's itself a CWE id), compare those. `cwe` is
    OPTIONAL on detected findings (schemas/finding.schema.json), so a side
    lacking one is first resolved via a small free-text `vuln_class` ->
    CWE synonym table before falling back to a case-insensitive comparison
    of raw `vuln_class`/`type` labels.
  - Line: only enforced when the ground-truth item specifies a `line` hint;
    a detected finding matches if that line falls within
    `line_tolerance` (default 15) lines of the finding's [line_start, line_end].

This is intentionally a rule-based replacement for VulnHunter's LLM-as-judge
(harness/local_harness/benchmark/judge.py) — `audit` findings carry
structured file/line/CWE fields (see schemas/finding.schema.json,
report.schema.json), so a fuzzy LLM comparator isn't needed for this shape,
and a rule-based one is deterministic, free, and CI-friendly.

A second, corpus-faithful matcher (`score_corpus`, plus its `class_of` /
`finding_matches_cve` building blocks) lives below `score()` — see its
docstring for when it applies. `score_auto()` dispatches between the two
based on ground-truth entry shape.
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


# Small, deliberately-conservative free-text -> CWE-id synonym table. This
# exists solely to bridge `cwe` being OPTIONAL on detected findings
# (schemas/finding.schema.json requires `vuln_class` but not `cwe`): a real
# `audit` run may report only a free-text `vuln_class` with no `cwe` at all,
# while ground truth conventionally encodes class as a `CWE-NNN` id in
# `type` (bench/ground_truth/README.md). Only well-known, unambiguous
# labels are listed; an unrecognized label resolves to no CWE (safe
# fallback to the free-text label comparison below) rather than guessing.
_VULN_CLASS_TO_CWE = {
    "code injection": "cwe-94", "code-injection": "cwe-94", "eval injection": "cwe-94",
    "sql injection": "cwe-89", "sqli": "cwe-89", "sql-injection": "cwe-89",
    "cross-site scripting": "cwe-79", "xss": "cwe-79",
    "path traversal": "cwe-22", "path-traversal": "cwe-22", "directory traversal": "cwe-22",
    "command injection": "cwe-78", "os command injection": "cwe-78", "command-injection": "cwe-78",
    "sensitive data exposure": "cwe-200", "information exposure": "cwe-200",
    "info-leak": "cwe-200", "info leak": "cwe-200",
    "insecure deserialization": "cwe-502", "deserialization": "cwe-502",
    "ssrf": "cwe-918", "server-side request forgery": "cwe-918",
    "xxe": "cwe-611", "xml external entity": "cwe-611",
    "hardcoded credentials": "cwe-798", "hardcoded secret": "cwe-798",
    "open redirect": "cwe-601",
    "insecure randomness": "cwe-330", "weak randomness": "cwe-330",
}


def _resolved_cwe(item: dict) -> str | None:
    """`_cwe_of`, plus a synonym-table fallback for items that only carry a
    recognized free-text `vuln_class`/`type` label and no CWE id anywhere."""
    cwe = _cwe_of(item)
    if cwe:
        return cwe
    for key in ("vuln_class", "type"):
        label = _norm(item.get(key))
        if label in _VULN_CLASS_TO_CWE:
            return _VULN_CLASS_TO_CWE[label]
    return None


def _class_label(item: dict) -> str:
    """Best-effort free-text class label when neither side has a CWE id."""
    return _norm(item.get("vuln_class") or item.get("type"))


def classes_match(detected: dict, gt: dict) -> bool:
    d_cwe, g_cwe = _resolved_cwe(detected), _resolved_cwe(gt)
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


# ---------------------------------------------------------------------------
# Corpus-faithful scorer: real ground truth (class + file_hint), ported from
# the ai-proofscan project's benchmark/match.py + benchmark/corpus.yaml
# (/Users/snatarajan14/ai-proofscan/old_one/benchmark/{match.py,corpus.yaml})
# — same author's prior, adversarially-reviewed matcher + corpus for
# datamodel-code-generator 0.55.0, mirrored here rather than reinvented.
# Field names are adapted to this repo's ground-truth convention
# (`finding_id` in place of match.py's `id`); the matching algorithm itself
# — CWE->class + case-insensitive file_hint substring, greedy 1:1,
# in_version exclusion — is unchanged.
#
# This path exists because some advisories (see bench/ground_truth/
# README.md Shape 2) publish no exact file:line for a CVE, only a
# vulnerability class and one or more file-name hints — too coarse for
# `score()`'s basename+CWE+line matching above, but still matchable via
# class + substring. GT entries with `file` and no `file_hint` keep going
# through `score()` (see `score_auto` below).
# ---------------------------------------------------------------------------

CWE_CLASS = {
    "CWE-94": "codegen",
    "CWE-95": "codegen",
    "CWE-918": "ssrf",
    "CWE-22": "traversal",
    "CWE-23": "traversal",
    "CWE-73": "traversal",
    "CWE-200": "infoleak",
    "CWE-201": "infoleak",
    "CWE-359": "infoleak",
    "CWE-502": "deser",
    "CWE-78": "cmdinj",
    "CWE-89": "sqli",
    "CWE-79": "xss",
    "CWE-611": "xxe",
    "CWE-1336": "ssti",
}


def class_of(cwe: str, fallback: str = "") -> str:
    """Map a CWE id (e.g. "CWE-94") to its coarse vulnerability class (e.g.
    "codegen") via CWE_CLASS. An unmapped CWE falls back to `fallback` if
    given, else to the CWE id itself (never raises on an unknown CWE)."""
    return CWE_CLASS.get(cwe, fallback or cwe)


def finding_matches_cve(finding: dict, cve: dict) -> bool:
    """True iff `finding`'s CWE class matches `cve`'s class AND `finding`'s
    file path contains (case-insensitively) at least one of `cve`'s
    `file_hint` substrings. Mirrors ai-proofscan's benchmark/match.py
    `_finding_matches_cve`."""
    if class_of(finding.get("cwe", "")) != cve.get("class"):
        return False
    file_path = (finding.get("file") or "").lower()
    return any(hint.lower() in file_path for hint in cve.get("file_hint", []))


def score_corpus(confirmed: list[dict], expected: list[dict]) -> dict:
    """Greedily, deterministically match `confirmed` findings to `expected`
    corpus CVEs by class(cwe) + file_hint substring (see
    `finding_matches_cve`) — mirrors ai-proofscan's benchmark/match.py
    `match()`.

    Each `expected` CVE claims at most one `confirmed` finding (first
    unclaimed match, in `confirmed` order), so a single detection can't
    double-count against two CVEs that happen to share a class + hint.

    `expected` items flagged `in_version: false` target code verified not to
    exist in the scanned release — unfindable by construction, so they're
    excluded from the recall denominator and reported separately (in
    `excluded`) rather than counted as a miss.

    Returns:
        {
          "cve_found": [finding_id, ...],
          "cve_missed": [finding_id, ...],
          "cve_recall": float,          # |found| / |in-version expected|, 0.0 if none
          "class_found": [class, ...],  # sorted, distinct classes among found CVEs
          "class_recall": float,        # |classes found| / |distinct in-version classes|
          "extra": [confirmed items claimed by no CVE],
          "excluded": [finding_id, ...],  # in_version:false CVEs, denominator-excluded
        }
    """
    excluded = [cve["finding_id"] for cve in expected if not cve.get("in_version", True)]
    expected = [cve for cve in expected if cve.get("in_version", True)]

    used = [False] * len(confirmed)
    cve_found: list[str] = []
    cve_missed: list[str] = []
    class_found: set[str] = set()

    for cve in expected:
        assigned = None
        for i, finding in enumerate(confirmed):
            if used[i]:
                continue
            if finding_matches_cve(finding, cve):
                assigned = i
                break
        if assigned is not None:
            used[assigned] = True
            cve_found.append(cve["finding_id"])
            class_found.add(cve["class"])
        else:
            cve_missed.append(cve["finding_id"])

    distinct_classes = {cve["class"] for cve in expected}
    total = len(expected)
    extra = [finding for i, finding in enumerate(confirmed) if not used[i]]

    return {
        "cve_found": cve_found,
        "cve_missed": cve_missed,
        "cve_recall": (len(cve_found) / total) if total else 0.0,
        "class_found": sorted(class_found),
        "class_recall": (len(class_found) / len(distinct_classes)) if distinct_classes else 0.0,
        "extra": extra,
        "excluded": excluded,
    }


def score_auto(detected: list[dict], ground_truth: list[dict], *,
               line_tolerance: int = DEFAULT_LINE_TOLERANCE) -> dict:
    """Route to the matcher that fits the ground-truth entries' shape: the
    corpus matcher (`score_corpus`) when any entry carries `file_hint` (the
    real, source-verified corpus shape — see bench/ground_truth/README.md
    Shape 2); otherwise the basename+CWE matcher (`score`) for backward
    compatibility with the original ground-truth shape (Shape 1)."""
    if any("file_hint" in gt for gt in ground_truth):
        return score_corpus(detected, ground_truth)
    return score(detected, ground_truth, line_tolerance=line_tolerance)
