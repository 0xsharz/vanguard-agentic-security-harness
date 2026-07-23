"""Unit tests for the bench harness: scorer, parse_results, and a handful of
pure helpers. All deterministic, offline, no network, no LLM.

Also includes the `--tally-only` offline smoke test (via subprocess against
a fake state file) required by task-0.3-brief.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from audit.state import StateDB
from bench import parse_results, scorer
from bench.audit_cmd import build_scan_command
from bench.clone import parse_source_url, target_dir_name

AUDIT_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# scorer.py
# ---------------------------------------------------------------------------

def _detected(finding_id, file, line_start, line_end, vuln_class, cwe=None, severity="high"):
    return {
        "finding_id": finding_id, "file": file, "line_start": line_start,
        "line_end": line_end, "vuln_class": vuln_class, "cwe": cwe, "severity": severity,
    }


def _gt(finding_id, file, line, gt_type):
    return {"finding_id": finding_id, "file": file, "line": line, "type": gt_type,
            "description": "x" * 30}


def test_scorer_perfect_match_one_to_one():
    detected = [_detected("f_1", "src/pkg/jsonschema.py", 118, 122, "code-injection", cwe="CWE-94")]
    gt = [_gt("GT-001", "jsonschema.py", 120, "CWE-94")]

    result = scorer.score(detected, gt)

    assert result["tp"] == 1
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["recall"] == 1.0
    assert result["precision"] == 1.0
    assert result["missed"] == []
    assert result["matches"] == [{"ground_truth_id": "GT-001", "detected_id": "f_1"}]


def test_scorer_false_negative_appears_in_missed():
    detected = [_detected("f_1", "other.py", 10, 20, "sqli", cwe="CWE-89")]
    gt = [_gt("GT-001", "jsonschema.py", 120, "CWE-94")]

    result = scorer.score(detected, gt)

    assert result["tp"] == 0
    assert result["fn"] == 1
    assert result["fp"] == 1
    assert result["recall"] == 0.0
    assert result["precision"] == 0.0
    assert result["missed"] == gt


def test_scorer_false_positive_extra_detection():
    detected = [
        _detected("f_1", "jsonschema.py", 120, 120, "code-injection", cwe="CWE-94"),
        _detected("f_2", "unrelated.py", 5, 5, "xss", cwe="CWE-79"),
    ]
    gt = [_gt("GT-001", "jsonschema.py", 120, "CWE-94")]

    result = scorer.score(detected, gt)

    assert result["tp"] == 1
    assert result["fp"] == 1
    assert result["fn"] == 0
    assert result["precision"] == 0.5
    assert result["recall"] == 1.0


def test_scorer_line_tolerance_within_default_matches():
    # default tolerance is 15; gt line 120, detected range [130, 134] -> diff 10
    detected = [_detected("f_1", "jsonschema.py", 130, 134, "code-injection", cwe="CWE-94")]
    gt = [_gt("GT-001", "jsonschema.py", 120, "CWE-94")]

    result = scorer.score(detected, gt)
    assert result["tp"] == 1
    assert result["missed"] == []


def test_scorer_line_tolerance_exceeded_no_match():
    # gt line 120, detected range [200, 210] -> diff 80, outside default tolerance 15
    detected = [_detected("f_1", "jsonschema.py", 200, 210, "code-injection", cwe="CWE-94")]
    gt = [_gt("GT-001", "jsonschema.py", 120, "CWE-94")]

    result = scorer.score(detected, gt)
    assert result["tp"] == 0
    assert result["fn"] == 1
    assert result["fp"] == 1


def test_scorer_custom_line_tolerance():
    detected = [_detected("f_1", "jsonschema.py", 200, 200, "code-injection", cwe="CWE-94")]
    gt = [_gt("GT-001", "jsonschema.py", 120, "CWE-94")]

    # diff is 80; tolerance of 100 should match, tolerance of 10 should not
    assert scorer.score(detected, gt, line_tolerance=100)["tp"] == 1
    assert scorer.score(detected, gt, line_tolerance=10)["tp"] == 0


def test_scorer_cwe_match_overrides_differing_free_text_label():
    # vuln_class labels differ in wording, but both carry the same CWE -> match.
    detected = [_detected("f_1", "http.py", 45, 45, "sensitive data exposure in logs", cwe="CWE-200")]
    gt = [_gt("GT-002", "http.py", 45, "CWE-200")]

    result = scorer.score(detected, gt)
    assert result["tp"] == 1


def test_scorer_class_mismatch_blocks_match_even_with_same_file():
    detected = [_detected("f_1", "http.py", 45, 45, "info-leak", cwe="CWE-200")]
    gt = [_gt("GT-001", "http.py", 45, "CWE-22")]  # different CWE, same file/line

    result = scorer.score(detected, gt)
    assert result["tp"] == 0
    assert result["fn"] == 1


def test_scorer_basename_only_matching_ignores_directory_prefix():
    detected = [_detected("f_1", "/clone/dir/src/pkg/jsonschema.py", 120, 120,
                           "code-injection", cwe="CWE-94")]
    gt = [_gt("GT-001", "jsonschema.py", 120, "CWE-94")]

    result = scorer.score(detected, gt)
    assert result["tp"] == 1


def test_scorer_greedy_one_to_one_no_double_counting():
    # Two detected findings and two ground-truth items sharing the same
    # file+class; each ground-truth item must claim a distinct detection.
    detected = [
        _detected("f_1", "jsonschema.py", 100, 100, "code-injection", cwe="CWE-94"),
        _detected("f_2", "jsonschema.py", 300, 300, "code-injection", cwe="CWE-94"),
    ]
    gt = [
        _gt("GT-001", "jsonschema.py", 100, "CWE-94"),
        _gt("GT-002", "jsonschema.py", 300, "CWE-94"),
    ]

    result = scorer.score(detected, gt)
    assert result["tp"] == 2
    assert result["fp"] == 0
    assert result["fn"] == 0
    matched_detected_ids = {m["detected_id"] for m in result["matches"]}
    assert matched_detected_ids == {"f_1", "f_2"}


def test_scorer_one_detection_cannot_satisfy_two_ground_truth_items():
    detected = [_detected("f_1", "jsonschema.py", 100, 100, "code-injection", cwe="CWE-94")]
    gt = [
        _gt("GT-001", "jsonschema.py", 100, "CWE-94"),
        _gt("GT-002", "jsonschema.py", 105, "CWE-94"),
    ]

    result = scorer.score(detected, gt)
    assert result["tp"] == 1
    assert result["fn"] == 1
    assert len(result["missed"]) == 1


def test_scorer_empty_ground_truth():
    detected = [_detected("f_1", "x.py", 1, 1, "sqli", cwe="CWE-89")]
    result = scorer.score(detected, [])
    assert result == {"tp": 0, "fp": 1, "fn": 0, "recall": 0.0, "precision": 0.0,
                       "missed": [], "matches": []}


def test_scorer_empty_detected():
    gt = [_gt("GT-001", "jsonschema.py", 120, "CWE-94")]
    result = scorer.score([], gt)
    assert result["tp"] == 0
    assert result["fp"] == 0
    assert result["fn"] == 1
    assert result["recall"] == 0.0
    assert result["precision"] == 0.0
    assert result["missed"] == gt


def test_scorer_no_line_hint_in_ground_truth_skips_line_check():
    detected = [_detected("f_1", "jsonschema.py", 9999, 9999, "code-injection", cwe="CWE-94")]
    gt = [{"finding_id": "GT-001", "file": "jsonschema.py", "type": "CWE-94",
           "description": "x" * 30}]  # no "line" key at all

    result = scorer.score(detected, gt)
    assert result["tp"] == 1


# ---------------------------------------------------------------------------
# parse_results.py
# ---------------------------------------------------------------------------

def _write_fake_report(results_root: Path, run_id: str, findings: list[dict]) -> Path:
    report_dir = results_root / run_id / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "run_id": run_id,
        "target": {"repo_path": "/tmp/fake-target"},
        "summary": {"total": len(findings), "by_severity": {}},
        "findings": findings,
    }
    path = report_dir / "report.json"
    path.write_text(json.dumps(report))
    return path


def _report_finding(finding_id="f_abc123", file="src/pkg/jsonschema.py",
                    line_start=115, line_end=125, vuln_class="code-injection",
                    cwe="CWE-94", severity="high"):
    return {
        "finding_id": finding_id, "title": "Code injection via schema eval",
        "severity": severity, "vuln_class": vuln_class, "cwe": cwe,
        "file": file, "line_start": line_start, "line_end": line_end,
        "description": "x" * 40, "evidence": "eval(schema_expr)",
        "trace": {"entry_points": [], "call_chain": []},
        "recommendation": "Avoid dynamic eval of schema-derived strings.",
    }


def test_load_report_and_detected_from_report(tmp_path: Path):
    results_root = tmp_path / "results"
    _write_fake_report(results_root, "run_x", [_report_finding()])

    report = parse_results.load_report("run_x", results_root=results_root)
    assert report is not None
    assert report["run_id"] == "run_x"

    detected = parse_results.detected_from_report(report)
    assert detected == [{
        "finding_id": "f_abc123", "file": "src/pkg/jsonschema.py",
        "line_start": 115, "line_end": 125, "vuln_class": "code-injection",
        "cwe": "CWE-94", "severity": "high",
        "title": "Code injection via schema eval", "source": "report",
    }]


def test_load_report_missing_returns_none(tmp_path: Path):
    assert parse_results.load_report("run_missing", results_root=tmp_path / "results") is None


def test_load_state_db_findings_extracts_cwe_from_raw_json(tmp_path: Path):
    db_path = tmp_path / "state.db"
    db = StateDB(db_path)
    run_id = db.create_run("/tmp/fake-target", "run_x")
    db.add_task(run_id, {
        "task_id": "t_1", "attack_class": "code-injection",
        "scope_hint": "schema eval path", "target_files": ["jsonschema.py"],
        "rationale": "r", "priority": 1, "source": "recon",
    })
    db.add_finding(run_id, "t_1", {
        "finding_id": "f_abc123", "file": "src/pkg/jsonschema.py",
        "line_start": 115, "line_end": 125, "vuln_class": "code-injection",
        "cwe": "CWE-94", "severity": "high",
        "description": "x" * 40, "evidence_snippet": "eval(schema_expr)",
        "confidence": 0.9,
    })
    db.close()

    findings = parse_results.load_state_db_findings("run_x", db_path=db_path)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "f_abc123"
    assert f["file"] == "src/pkg/jsonschema.py"
    assert f["line_start"] == 115
    assert f["line_end"] == 125
    assert f["vuln_class"] == "code-injection"
    assert f["cwe"] == "CWE-94"  # pulled out of raw_json, not a real column
    assert f["severity"] == "high"
    assert f["source"] == "state_db"


def test_load_state_db_findings_missing_db_returns_empty(tmp_path: Path):
    assert parse_results.load_state_db_findings("run_x", db_path=tmp_path / "nope.db") == []


def test_load_detected_findings_prefers_report_when_present(tmp_path: Path):
    results_root = tmp_path / "results"
    db_path = tmp_path / "state.db"
    _write_fake_report(results_root, "run_x", [_report_finding(finding_id="from_report")])

    detected = parse_results.load_detected_findings(
        "run_x", results_root=results_root, db_path=db_path)
    assert len(detected) == 1
    assert detected[0]["finding_id"] == "from_report"
    assert detected[0]["source"] == "report"


def test_load_detected_findings_falls_back_to_state_db_when_report_missing(tmp_path: Path):
    results_root = tmp_path / "results"  # empty — no report.json written
    db_path = tmp_path / "state.db"
    db = StateDB(db_path)
    run_id = db.create_run("/tmp/fake-target", "run_x")
    db.add_task(run_id, {
        "task_id": "t_1", "attack_class": "code-injection", "scope_hint": "x",
        "target_files": ["jsonschema.py"], "rationale": "r", "priority": 1, "source": "recon",
    })
    db.add_finding(run_id, "t_1", {
        "finding_id": "from_db", "file": "jsonschema.py", "line_start": 1, "line_end": 2,
        "vuln_class": "code-injection", "severity": "high",
        "description": "x" * 40, "evidence_snippet": "e", "confidence": 0.5,
    })
    db.close()

    detected = parse_results.load_detected_findings(
        "run_x", results_root=results_root, db_path=db_path)
    assert len(detected) == 1
    assert detected[0]["finding_id"] == "from_db"
    assert detected[0]["source"] == "state_db"


def test_load_detected_findings_prefer_state_db_skips_report(tmp_path: Path):
    results_root = tmp_path / "results"
    db_path = tmp_path / "state.db"
    _write_fake_report(results_root, "run_x", [_report_finding(finding_id="from_report")])
    # no state.db written at all -> prefer="state_db" should return [] rather
    # than silently falling back to the report.
    detected = parse_results.load_detected_findings(
        "run_x", results_root=results_root, db_path=db_path, prefer="state_db")
    assert detected == []


def test_load_detected_findings_rejects_bad_prefer():
    with pytest.raises(ValueError):
        parse_results.load_detected_findings("run_x", prefer="bogus")


# ---------------------------------------------------------------------------
# small pure helpers: audit_cmd.build_scan_command, clone.parse_source_url
# ---------------------------------------------------------------------------

def test_build_scan_command_constructs_real_audit_run_invocation():
    cmd = build_scan_command("/tmp/clones/target_abcd1234", "bench_target_abcd1234",
                              max_cost_usd=5.0)
    assert cmd == ["audit", "run", "--repo", "/tmp/clones/target_abcd1234",
                   "--run-id", "bench_target_abcd1234", "--max-cost-usd", "5.0"]


def test_build_scan_command_never_executes_anything(monkeypatch):
    # Guard against regressions: this function must be pure — no subprocess calls.
    import subprocess as sp

    def _boom(*a, **kw):
        raise AssertionError("build_scan_command must not execute a subprocess")

    monkeypatch.setattr(sp, "run", _boom)
    monkeypatch.setattr(sp, "Popen", _boom)
    build_scan_command("/tmp/x", "run_1")


def test_parse_source_url_and_target_dir_name():
    url = "https://github.com/koxudaxi/datamodel-code-generator/tree/0123456789abcdef"
    repo_url, repo_name, commit_hash = parse_source_url(url)
    assert repo_url == "https://github.com/koxudaxi/datamodel-code-generator"
    assert repo_name == "datamodel-code-generator"
    assert commit_hash == "0123456789abcdef"
    assert target_dir_name(repo_name, commit_hash) == "datamodel-code-generator_01234567"


# ---------------------------------------------------------------------------
# ground truth seed file: shape sanity (no network, just json + our schema rules)
# ---------------------------------------------------------------------------

def test_seed_ground_truth_file_matches_expected_shape():
    path = AUDIT_REPO_ROOT / "bench" / "ground_truth" / "datamodel-code-generator.json"
    entries = json.loads(path.read_text())
    assert len(entries) >= 3
    for entry in entries:
        assert entry["finding_id"]
        assert entry["type"].startswith("CWE-")
        assert entry["file"]
        assert isinstance(entry["line"], int)
        assert entry["source_code"].startswith("https://github.com/")
        assert "SYNTHETIC SEED" in entry["description"]


# ---------------------------------------------------------------------------
# --tally-only offline smoke (subprocess; the "hard rule" allowed offline run)
# ---------------------------------------------------------------------------

def test_tally_only_offline_smoke(tmp_path: Path):
    """Build a fake, already-"scored" state file (as if clone/scan/score had
    already run) and confirm `python -m bench.run --tally-only` renders a
    scorecard from it WITHOUT scanning, scoring, cloning, or touching the
    network/LLM."""
    fake_state = {
        "scan_targets": {
            "datamodel-code-generator_01234567": {
                "status": "scanned", "run_id": "bench_dmcg",
                "repo_name": "datamodel-code-generator", "commit_hash": "0123456789abcdef",
            },
        },
        "judgments": {
            "GT-001": {
                "detected": True, "matched_finding_id": "f_abc123",
                "reasoning": "matched via basename(file) + CWE/type class (line-tolerant)",
                "type": "CWE-94", "benchmark_file": "datamodel-code-generator.json",
                "repo_name": "datamodel-code-generator", "commit_hash": "0123456789abcdef",
            },
            "GT-002": {
                "detected": False, "matched_finding_id": None,
                "reasoning": "no detected finding matched on file+class(+line)",
                "type": "CWE-200", "benchmark_file": "datamodel-code-generator.json",
                "repo_name": "datamodel-code-generator", "commit_hash": "0123456789abcdef",
            },
        },
    }
    state_path = tmp_path / "fake_state.json"
    state_path.write_text(json.dumps(fake_state))
    tally_json_path = tmp_path / "tally.json"
    tally_md_path = tmp_path / "BENCHMARK_REPORT.md"

    result = subprocess.run(
        [sys.executable, "-m", "bench.run", "--tally-only",
         "--state", str(state_path),
         "--tally-json", str(tally_json_path),
         "--tally-markdown", str(tally_md_path)],
        cwd=str(AUDIT_REPO_ROOT), capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "BENCHMARK RESULTS: 1/2 detected" in result.stdout

    assert tally_json_path.is_file()
    tally = json.loads(tally_json_path.read_text())
    assert tally["summary"]["total_findings"] == 2
    assert tally["summary"]["detected"] == 1
    assert tally["summary"]["missed"] == 1

    assert tally_md_path.is_file()
    assert "audit Benchmark Report" in tally_md_path.read_text()
