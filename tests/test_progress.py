"""Tests for vash.progress.RunReporter — rich, fail-soft run-progress
reporter. Presentation only: every method must swallow its own errors so a
display bug can never break the pipeline (see vash/progress.py docstring).
"""

from __future__ import annotations

import io

from rich.console import Console

from vash.progress import RunReporter
from vash.state import StateDB


def _reporter():
    buf = io.StringIO()
    return RunReporter(Console(file=buf, force_terminal=False, width=100), "r1", throttle=5), buf


def test_stage_banner_and_finding_line():
    r, buf = _reporter()
    r.stage_start("hunt", model="sonnet", count=41)
    r.finding_confirmed(severity="high", vuln_class="code_injection",
                        file="a/b.ejs", line=74, confidence=0.8)
    out = buf.getvalue()
    assert "HUNT" in out and "41 tasks" in out
    assert "code_injection" in out and "a/b.ejs:74" in out and "HIGH" in out


def test_task_done_throttle_nontty():
    r, buf = _reporter()
    for i in range(1, 13):
        r.task_done("hunt", done=i, total=41)
    # non-TTY: prints on every 5th (5,10) -> 2 progress lines
    assert buf.getvalue().count("hunt") == 2


def test_run_summary_failsoft_on_bad_db():
    r, _ = _reporter()

    class BadDB:
        def get_findings(self, _):
            raise RuntimeError("boom")

    r.run_summary(BadDB(), "r1")  # must not raise


def test_run_summary_counts(tmp_path):
    """Self-contained: seed a tiny real StateDB (tmp_path — pytest's built-in
    tmp-dir fixture; no custom conftest fixture exists in this repo) with a
    handful of findings via the real db API, then render the summary table."""
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "r_progress_summary")
    db.add_task(rid, {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "x",
        "target_files": ["a.py"], "rationale": "r", "priority": 1, "source": "recon",
    })
    db.add_finding(rid, "t_1", {
        "finding_id": "f_1", "file": "a.py", "line_start": 1, "line_end": 2,
        "vuln_class": "sqli", "severity": "high",
        "description": "d", "evidence_snippet": "e", "confidence": 0.9,
    })
    db.add_finding(rid, "t_1", {
        "finding_id": "f_2", "file": "a.py", "line_start": 3, "line_end": 4,
        "vuln_class": "xss", "severity": "medium",
        "description": "d", "evidence_snippet": "e", "confidence": 0.5,
    })
    db.add_finding(rid, "t_1", {
        "finding_id": "f_3", "file": "a.py", "line_start": 5, "line_end": 6,
        "vuln_class": "xss", "severity": "medium",
        "description": "d", "evidence_snippet": "e", "confidence": 0.5,
    })
    db.set_finding_validation("f_1", "confirmed", {
        "finding_id": "f_1", "verdict": "confirmed",
        "rationale": "ok", "validator_confidence": 0.9,
    })
    db.set_finding_validation("f_2", "rejected", {
        "finding_id": "f_2", "verdict": "rejected",
        "rationale": "fp", "validator_confidence": 0.9,
    })
    # f_3 deliberately left unvalidated -> counted as "pending" by run_summary.

    r, buf = _reporter()
    r.run_summary(db, rid)
    out = buf.getvalue().lower()
    assert "summary" in out

    db.close()
