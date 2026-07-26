"""Phase driver for the audit-scoring benchmark: clone -> scan -> score -> tally.

Adapted from VulnHunter's harness/local_harness/benchmark/run.py (Capital
One, Apache License 2.0) — same phase structure and resumable JSON state
file, repointed at `audit`:
  - SCAN no longer shells out to `claude -p "/vulnhunt ..."`; it builds (via
    `bench.audit_cmd.build_scan_command`) the real `audit run --repo
    <clone_dir> --run-id <id> [--max-cost-usd N]` command and stores it in
    state. Actually executing that command (spends LLM budget) is Phase 1's
    job — `record_scan_complete()` is the hook a Phase-1 runner calls once
    it has done so, to tell this driver where the results landed.
  - JUDGE is replaced by SCORE: `audit` findings carry structured file/line/
    CWE fields (schemas/finding.schema.json, report.schema.json), so instead
    of an LLM comparing free text, `bench.scorer.score()` matches
    deterministically via `bench.parse_results`. No LLM call, ever, in this
    phase.
Full license text: https://www.apache.org/licenses/LICENSE-2.0 (also see
/Users/snatarajan14/VulnHunter/LICENSE).

  Copyright Capital One (VulnHunter contributors) for the adapted phase
  structure. Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License. You may
  obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

Usage:
    python -m bench.run --tally-only [--state PATH]
    python -m bench.run --scan-only          # clone + build scan commands only
    python -m bench.run --score-only          # score already-scanned targets + tally
    python -m bench.run                       # clone + build commands + score + tally

IMPORTANT: this module never executes `audit run` (or any other LLM-spending
command) itself — `phase_scan` only builds and stores the command line.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

from bench.audit_cmd import build_scan_command
from bench.clone import clone_at_commit, parse_source_url, target_dir_name
from bench.config import (
    CLONE_BASE_DIR,
    GROUND_TRUTH_DIR,
    STATE_FILE,
    TALLY_JSON,
    TALLY_MARKDOWN,
    atomic_write_json,
)
from bench.parse_results import load_detected_findings
from bench.scorer import score as score_findings
from bench.tally import generate_tally, print_summary, write_tally_json, write_tally_markdown


def load_all_ground_truth(ground_truth_dir: Path | None = None):
    """Load every ground-truth JSON file. Returns [(filename, findings), ...]
    with `_repo_url`/`_repo_name`/`_commit_hash` parsed onto each finding."""
    ground_truth_dir = Path(ground_truth_dir) if ground_truth_dir else GROUND_TRUTH_DIR
    results = []
    for json_file in sorted(glob.glob(os.path.join(str(ground_truth_dir), "*.json"))):
        with open(json_file) as f:
            findings = json.load(f)
        for finding in findings:
            repo_url, repo_name, commit_hash = parse_source_url(finding["source_code"])
            finding["_repo_url"] = repo_url
            finding["_repo_name"] = repo_name
            finding["_commit_hash"] = commit_hash
        results.append((os.path.basename(json_file), findings))
    return results


def deduplicate_targets(ground_truth, clone_base_dir: Path | None = None):
    """Build unique (repo_url, commit_hash) scan targets from ground truth."""
    clone_base_dir = Path(clone_base_dir) if clone_base_dir else CLONE_BASE_DIR
    targets: dict[str, dict] = {}
    for filename, findings in ground_truth:
        for finding in findings:
            key = target_dir_name(finding["_repo_name"], finding["_commit_hash"])
            if key not in targets:
                targets[key] = {
                    "key": key,
                    "repo_url": finding["_repo_url"],
                    "commit_hash": finding["_commit_hash"],
                    "repo_name": finding["_repo_name"],
                    "clone_dir": str(clone_base_dir / key),
                    "findings": [],
                }
            targets[key]["findings"].append({
                **finding,
                "benchmark_file": filename,
            })
    return targets


def load_state(state_path: Path | None = None) -> dict:
    state_path = Path(state_path) if state_path else STATE_FILE
    if state_path.is_file():
        try:
            with open(state_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"  WARNING: {state_path} is corrupt, starting fresh")
    return {"scan_targets": {}, "judgments": {}}


def save_state(state: dict, state_path: Path | None = None) -> None:
    atomic_write_json(state_path or STATE_FILE, state)


def phase_clone(targets: dict, state: dict) -> None:
    """Phase 1: clone all repos at pinned commits. Not exercised by this
    task's offline tests (requires network)."""
    print(f"\n{'='*60}\nPHASE 1: CLONE ({len(targets)} targets)\n{'='*60}\n")
    for key, target in targets.items():
        existing = state["scan_targets"].get(key, {})
        if existing.get("status") in ("cloned", "command_built", "scanned") and \
                os.path.isdir(target["clone_dir"]):
            print(f"  [skip] {key} — already cloned")
            continue

        target_dir, error = clone_at_commit(target["repo_url"], target["commit_hash"], target["clone_dir"])
        if error:
            print(f"  [FAIL] {key}: {error}")
            state["scan_targets"][key] = {**existing, "clone_dir": target["clone_dir"],
                                          "status": "clone_failed", "error": error}
        else:
            state["scan_targets"][key] = {**existing, "clone_dir": target["clone_dir"], "status": "cloned"}
        save_state(state)


def phase_scan(targets: dict, state: dict, *, force_rescan: bool = False,
                max_cost_usd: float | None = None) -> None:
    """Phase 2: BUILD (never execute) the `audit run` command for each
    target. Actually running it and calling `record_scan_complete()` is
    Phase 1's (the live-run milestone's) job, not this task's."""
    print(f"\n{'='*60}\nPHASE 2: SCAN — build commands only ({len(targets)} targets)\n{'='*60}\n")
    for key, target in targets.items():
        existing = state["scan_targets"].get(key, {})
        if not force_rescan and existing.get("status") == "scanned":
            print(f"  [skip] {key} — already scanned")
            continue
        run_id = existing.get("run_id") or f"bench_{key}"
        cmd = build_scan_command(target["clone_dir"], run_id, max_cost_usd=max_cost_usd)
        state["scan_targets"][key] = {
            **existing,
            "clone_dir": target["clone_dir"],
            "run_id": run_id,
            "scan_command": cmd,
            "status": "command_built",
        }
        print(f"  [{key}] would run: {' '.join(cmd)}")
        save_state(state)


def record_scan_complete(state: dict, key: str, run_id: str, *,
                          results_root: str | None = None, db_path: str | None = None) -> None:
    """Hook for the (Phase 1) live runner: call after actually executing the
    built `audit run` command, to tell the scorer where to look."""
    existing = state["scan_targets"].get(key, {})
    state["scan_targets"][key] = {
        **existing, "run_id": run_id, "status": "scanned",
        "results_root": results_root, "db_path": db_path,
    }


def phase_score(targets: dict, state: dict, *, force_rescore: bool = False) -> None:
    """Phase 3: deterministically score each scanned target's detected
    findings against its ground truth. No LLM call — see bench.scorer."""
    print(f"\n{'='*60}\nPHASE 3: SCORE (deterministic, no LLM)\n{'='*60}\n")
    scored = 0
    for key, target in targets.items():
        target_state = state["scan_targets"].get(key, {})
        gt_items = target["findings"]

        if target_state.get("status") != "scanned":
            for finding in gt_items:
                fid = finding["finding_id"]
                if force_rescore or fid not in state["judgments"]:
                    state["judgments"][fid] = _error_judgment(
                        finding, target, f"scan not available (status: {target_state.get('status', 'unknown')})")
            continue

        run_id = target_state["run_id"]
        detected = load_detected_findings(
            run_id,
            results_root=target_state.get("results_root"),
            db_path=target_state.get("db_path"),
        )
        result = score_findings(detected, gt_items)

        matched_by_gt = {m["ground_truth_id"]: m["detected_id"] for m in result["matches"]}
        missed_ids = {m["finding_id"] for m in result["missed"]}

        for finding in gt_items:
            fid = finding["finding_id"]
            if fid in matched_by_gt:
                state["judgments"][fid] = {
                    "detected": True,
                    "matched_finding_id": matched_by_gt[fid],
                    "reasoning": "matched via basename(file) + CWE/type class (line-tolerant)",
                    "type": finding.get("type", ""),
                    "benchmark_file": finding.get("benchmark_file", ""),
                    "repo_name": target.get("repo_name", ""),
                    "commit_hash": target.get("commit_hash", ""),
                }
            elif fid in missed_ids:
                state["judgments"][fid] = {
                    "detected": False,
                    "matched_finding_id": None,
                    "reasoning": "no detected finding matched on file+class(+line)",
                    "type": finding.get("type", ""),
                    "benchmark_file": finding.get("benchmark_file", ""),
                    "repo_name": target.get("repo_name", ""),
                    "commit_hash": target.get("commit_hash", ""),
                }
        scored += len(gt_items)
        save_state(state)
    print(f"  Scored {scored} ground-truth finding(s)")


def _error_judgment(finding: dict, target: dict, reason: str) -> dict:
    return {
        "detected": None,
        "matched_finding_id": None,
        "reasoning": reason,
        "type": finding.get("type", ""),
        "benchmark_file": finding.get("benchmark_file", ""),
        "repo_name": target.get("repo_name", ""),
        "commit_hash": target.get("commit_hash", ""),
    }


def phase_tally(state: dict, *, tally_json_path=None, tally_md_path=None) -> dict:
    """Phase 4: render a scorecard from state["judgments"] — reads only,
    never scans or scores."""
    print(f"\n{'='*60}\nPHASE 4: TALLY\n{'='*60}\n")
    tally = generate_tally(state)
    write_tally_json(tally, tally_json_path)
    write_tally_markdown(tally, tally_md_path)
    print_summary(tally)
    return tally


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="audit benchmark harness (offline-safe by default)")
    parser.add_argument("--scan-only", action="store_true", help="Clone + build scan commands only")
    parser.add_argument("--score-only", action="store_true", help="Skip clone/scan, only score + tally")
    parser.add_argument("--tally-only", action="store_true",
                        help="Regenerate the scorecard from existing state, no scan/score")
    parser.add_argument("--force-rescan", action="store_true")
    parser.add_argument("--force-rescore", action="store_true")
    parser.add_argument("--repos", type=str, default=None, help="Only process targets matching this substring")
    parser.add_argument("--state", type=str, default=None, help="Override the state file path")
    parser.add_argument("--ground-truth-dir", type=str, default=None)
    parser.add_argument("--max-cost-usd", type=float, default=None)
    parser.add_argument("--tally-json", type=str, default=None)
    parser.add_argument("--tally-markdown", type=str, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    state_path = Path(args.state) if args.state else STATE_FILE

    if args.tally_only:
        state = load_state(state_path)
        phase_tally(state, tally_json_path=args.tally_json, tally_md_path=args.tally_markdown)
        return 0

    ground_truth = load_all_ground_truth(args.ground_truth_dir)
    if not ground_truth:
        print(f"Error: no ground-truth files found in "
              f"{args.ground_truth_dir or GROUND_TRUTH_DIR}")
        return 1

    targets = deduplicate_targets(ground_truth)
    if args.repos:
        targets = {k: v for k, v in targets.items() if args.repos.lower() in k.lower()}
        if not targets:
            print(f"No targets match filter: {args.repos}")
            return 1

    state = load_state(state_path)

    if not args.score_only:
        phase_clone(targets, state)
        save_state(state, state_path)
        phase_scan(targets, state, force_rescan=args.force_rescan, max_cost_usd=args.max_cost_usd)
        save_state(state, state_path)

    if args.scan_only:
        print("\n  --scan-only: skipping score + tally phases.")
        return 0

    phase_score(targets, state, force_rescore=args.force_rescore)
    save_state(state, state_path)
    phase_tally(state, tally_json_path=args.tally_json, tally_md_path=args.tally_markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
