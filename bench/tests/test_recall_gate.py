"""Tests for bench/recall_gate.py — the CI recall-regression gate (task 4.5,
.superpowers/sdd/task-4.5-brief.md).

All deterministic, offline, no network, no LLM: `check()` is pure-Python
comparison of two already-computed numbers pulled from scorecard dicts
(the actual recall math lives in bench.scorer.score_corpus, exercised by
bench/tests/test_bench.py — not reimplemented or re-tested here). CLI tests
mirror test_bench.py's `test_tally_only_offline_smoke` subprocess pattern.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from bench.recall_gate import check, main

AUDIT_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE_PATH = AUDIT_REPO_ROOT / "bench" / "baseline_scorecard.json"


# ---------------------------------------------------------------------------
# check()
# ---------------------------------------------------------------------------

def test_check_current_equals_baseline_is_ok():
    ok, message = check({"cve_recall": 0.5}, {"cve_recall": 0.5})
    assert ok is True
    assert "0.5" in message


def test_check_current_greater_than_baseline_is_ok():
    ok, message = check({"cve_recall": 0.8}, {"cve_recall": 0.5})
    assert ok is True


def test_check_current_less_than_baseline_beyond_tolerance_is_not_ok():
    ok, message = check({"cve_recall": 0.3}, {"cve_recall": 0.5})
    assert ok is False


def test_check_current_less_than_baseline_within_tolerance_is_ok():
    ok, message = check({"cve_recall": 0.48}, {"cve_recall": 0.5}, tolerance=0.05)
    assert ok is True


def test_check_current_less_than_baseline_at_exact_tolerance_boundary_is_ok():
    # current == baseline - tolerance exactly -> not a regression (>=, not >)
    ok, message = check({"cve_recall": 0.45}, {"cve_recall": 0.5}, tolerance=0.05)
    assert ok is True


def test_check_message_contains_both_numbers():
    current, baseline = {"cve_recall": 0.4545}, {"cve_recall": 0.5454}
    ok, message = check(current, baseline)
    assert ok is False
    assert "0.4545" in message
    assert "0.5454" in message


def test_check_respects_metric_kwarg():
    # cve_recall regressed but class_recall tied -> gating on class_recall passes
    ok, message = check(
        {"cve_recall": 0.1, "class_recall": 1.0},
        {"cve_recall": 0.9, "class_recall": 1.0},
        metric="class_recall",
    )
    assert ok is True
    assert "class_recall" in message


# ---------------------------------------------------------------------------
# committed baseline scorecard
# ---------------------------------------------------------------------------

def test_committed_baseline_parses_and_has_cve_recall():
    data = json.loads(BASELINE_PATH.read_text())
    assert data["cve_recall"] == pytest.approx(6 / 11)
    assert "class_recall" in data


# ---------------------------------------------------------------------------
# CLI, via subprocess (mirrors test_bench.py's --tally-only offline smoke)
# ---------------------------------------------------------------------------

def test_cli_smoke_mode_no_current_exits_0_and_prints_baseline_metric():
    result = subprocess.run(
        [sys.executable, "-m", "bench.recall_gate", "--baseline", str(BASELINE_PATH)],
        cwd=str(AUDIT_REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SMOKE" in result.stdout
    assert "0.5454" in result.stdout


def test_cli_regression_mode_exits_1_on_regressed_current(tmp_path: Path):
    current_path = tmp_path / "current_scorecard.json"
    current_path.write_text(json.dumps({"tool": "vash", "cve_recall": 0.1, "class_recall": 1.0}))

    result = subprocess.run(
        [sys.executable, "-m", "bench.recall_gate",
         "--baseline", str(BASELINE_PATH), "--current", str(current_path)],
        cwd=str(AUDIT_REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL" in result.stdout


def test_cli_pass_mode_exits_0_on_non_regressed_current(tmp_path: Path):
    current_path = tmp_path / "current_scorecard.json"
    current_path.write_text(json.dumps({"tool": "vash", "cve_recall": 0.9, "class_recall": 1.0}))

    result = subprocess.run(
        [sys.executable, "-m", "bench.recall_gate",
         "--baseline", str(BASELINE_PATH), "--current", str(current_path)],
        cwd=str(AUDIT_REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_cli_fails_closed_on_missing_baseline_file(tmp_path: Path):
    missing = tmp_path / "does_not_exist.json"
    result = subprocess.run(
        [sys.executable, "-m", "bench.recall_gate", "--baseline", str(missing)],
        cwd=str(AUDIT_REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1
    assert "FAIL" in result.stdout


def test_cli_fails_closed_on_invalid_current_json(tmp_path: Path):
    current_path = tmp_path / "bad.json"
    current_path.write_text("{not json")
    result = subprocess.run(
        [sys.executable, "-m", "bench.recall_gate",
         "--baseline", str(BASELINE_PATH), "--current", str(current_path)],
        cwd=str(AUDIT_REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1
    assert "FAIL" in result.stdout


def test_cli_fails_closed_on_current_missing_metric(tmp_path: Path):
    current_path = tmp_path / "current_scorecard.json"
    current_path.write_text(json.dumps({"tool": "vash"}))  # no cve_recall
    result = subprocess.run(
        [sys.executable, "-m", "bench.recall_gate",
         "--baseline", str(BASELINE_PATH), "--current", str(current_path)],
        cwd=str(AUDIT_REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1
    assert "FAIL" in result.stdout


# ---------------------------------------------------------------------------
# main(), called in-process (no subprocess) — the brief's other suggested
# test style. main() returns an int (bench/run.py's convention); only the
# `if __name__ == "__main__"` guard converts that to sys.exit().
# ---------------------------------------------------------------------------

def test_main_returns_0_in_smoke_mode_in_process():
    assert main(["--baseline", str(BASELINE_PATH)]) == 0


def test_main_returns_1_on_regression_in_process(tmp_path: Path):
    current_path = tmp_path / "current_scorecard.json"
    current_path.write_text(json.dumps({"cve_recall": 0.0}))
    assert main(["--baseline", str(BASELINE_PATH), "--current", str(current_path)]) == 1


def test_main_returns_0_on_pass_in_process(tmp_path: Path):
    current_path = tmp_path / "current_scorecard.json"
    current_path.write_text(json.dumps({"cve_recall": 1.0}))
    assert main(["--baseline", str(BASELINE_PATH), "--current", str(current_path)]) == 0


# ---------------------------------------------------------------------------
# workflow YAML (optional per brief, included for completeness)
# ---------------------------------------------------------------------------

def test_ci_workflow_exists_and_references_pytest_and_recall_gate():
    workflow = AUDIT_REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert workflow.is_file()
    text = workflow.read_text()
    assert "pytest" in text
    assert "bench.recall_gate" in text
    assert "pull_request" in text
