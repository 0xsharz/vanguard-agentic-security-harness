"""Generate benchmark scorecards (JSON + Markdown) from state data.

Adapted from VulnHunter's harness/local_harness/benchmark/tally.py (Capital
One, Apache License 2.0) — same aggregate-by-type + markdown-report shape,
repointed at `bench`'s `judgments` records (produced by `run.py`'s
deterministic scorer phase rather than an LLM judge, so there's no
"confidence"/free-text "reasoning" from a model — `reasoning` here is a
short deterministic note like "matched via file+CWE"). Full license text:
https://www.apache.org/licenses/LICENSE-2.0 (also see
/Users/snatarajan14/VulnHunter/LICENSE).

  Copyright Capital One (VulnHunter contributors).
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from bench.config import TALLY_JSON, TALLY_MARKDOWN, atomic_write_json


def generate_tally(state: dict) -> dict:
    """Generate a scorecard from the state dict's `judgments`.

    Each `judgments[finding_id]` entry is expected to look like:
        {"detected": bool|None, "reasoning": str, "matched_finding_id": str|None,
         "type": str, "benchmark_file": str, "repo_name": str, "commit_hash": str}
    (`detected=None` means "couldn't be scored", e.g. scan failed.)
    """
    judgments = state.get("judgments", {})
    scan_targets = state.get("scan_targets", {})

    findings_list = []
    by_type: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "detected": 0, "missed": 0, "error": 0}
    )

    for finding_id, judgment in judgments.items():
        detected = judgment.get("detected")
        finding_type = judgment.get("type", "Unknown")

        by_type[finding_type]["total"] += 1
        if detected is True:
            by_type[finding_type]["detected"] += 1
        elif detected is False:
            by_type[finding_type]["missed"] += 1
        else:
            by_type[finding_type]["error"] += 1

        findings_list.append({
            "finding_id": finding_id,
            "benchmark_file": judgment.get("benchmark_file", ""),
            "type": finding_type,
            "repo": judgment.get("repo_name", ""),
            "commit": (judgment.get("commit_hash", "") or "")[:8],
            "detected": detected,
            "reasoning": judgment.get("reasoning", ""),
            "matched_finding_id": judgment.get("matched_finding_id"),
        })

    total = len(findings_list)
    detected_count = sum(1 for f in findings_list if f["detected"] is True)
    missed_count = sum(1 for f in findings_list if f["detected"] is False)
    error_count = sum(1 for f in findings_list if f["detected"] is None)
    detection_rate = detected_count / total if total > 0 else 0.0

    scan_failures = sum(1 for t in scan_targets.values() if t.get("status") == "scan_failed")

    tally = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scoring_method": "deterministic (bench.scorer) — no LLM judge",
        "summary": {
            "total_findings": total,
            "detected": detected_count,
            "missed": missed_count,
            "errors": error_count,
            "detection_rate": round(detection_rate, 4),
            "scan_failures": scan_failures,
            "by_type": dict(by_type),
        },
        "findings": sorted(findings_list, key=lambda f: (f["benchmark_file"], f["finding_id"])),
    }
    return tally


def write_tally_json(tally: dict, path=None) -> None:
    atomic_write_json(path or TALLY_JSON, tally)


def render_markdown(tally: dict) -> str:
    summary = tally["summary"]
    findings = tally["findings"]

    lines = []
    lines.append("# audit Benchmark Report\n")
    lines.append(f"**Generated**: {tally['generated_at']}")
    lines.append(f"**Scoring**: {tally.get('scoring_method', 'unknown')}")
    lines.append(f"**Benchmark**: {summary['total_findings']} ground-truth findings\n")

    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Ground-Truth Findings | {summary['total_findings']} |")
    lines.append(f"| Detected (True Positives) | {summary['detected']} |")
    lines.append(f"| Missed (False Negatives) | {summary['missed']} |")
    lines.append(f"| Scoring Errors | {summary['errors']} |")
    lines.append(f"| Detection Rate (Recall) | {summary['detection_rate']:.1%} |")
    lines.append(f"| Scan Failures | {summary['scan_failures']} |")
    lines.append("")

    lines.append("## Detection by Vulnerability Class\n")
    lines.append("| Type | Total | Detected | Missed | Rate |")
    lines.append("|------|-------|----------|--------|------|")
    for vtype, counts in sorted(summary["by_type"].items()):
        total = counts["total"]
        det = counts["detected"]
        rate = f"{det/total:.0%}" if total > 0 else "N/A"
        lines.append(f"| {vtype} | {total} | {det} | {counts['missed']} | {rate} |")
    lines.append("")

    lines.append("## Per-Finding Results\n")
    lines.append("| # | Benchmark File | Finding ID | Type | Detected |")
    lines.append("|---|----------------|-----------|------|----------|")
    for i, f in enumerate(findings, 1):
        det_str = "YES" if f["detected"] is True else ("NO" if f["detected"] is False else "ERR")
        lines.append(f"| {i} | {f['benchmark_file']} | {f['finding_id']} | {f['type']} | {det_str} |")
    lines.append("")

    missed = [f for f in findings if f["detected"] is False]
    if missed:
        lines.append("## Missed Findings (False Negatives)\n")
        for f in missed:
            lines.append(f"### {f['finding_id']} — {f['type']} in {f['repo']}")
            lines.append(f"**Reasoning**: {f['reasoning']}\n")

    return "\n".join(lines)


def write_tally_markdown(tally: dict, path=None) -> None:
    path = path or TALLY_MARKDOWN
    with open(path, "w") as f:
        f.write(render_markdown(tally))


def print_summary(tally: dict) -> None:
    s = tally["summary"]
    print(f"\n{'='*60}")
    print(f"BENCHMARK RESULTS: {s['detected']}/{s['total_findings']} detected "
          f"({s['detection_rate']:.1%})")
    print(f"{'='*60}")
    print(f"  Detected:  {s['detected']}")
    print(f"  Missed:    {s['missed']}")
    print(f"  Errors:    {s['errors']}")
    print(f"  Scan fails: {s['scan_failures']}")
    print()
    for vtype, counts in sorted(s["by_type"].items()):
        total = counts["total"]
        det = counts["detected"]
        rate = f"{det/total:.0%}" if total > 0 else "N/A"
        print(f"  {vtype:20s} {det}/{total} ({rate})")
    print(f"{'='*60}\n")
