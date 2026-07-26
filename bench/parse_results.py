"""Turn an `audit` run's output into the detected-findings list `scorer.py` consumes.

Per docs/wiring-notes.md:
  - `audit run`'s `--repo` flag points at the *scanned target*, but state.db
    and results/ are written relative to the `audit` tool's OWN checkout root
    (`REPO_ROOT` in audit/cli.py = two levels up from cli.py), not the
    target. So for a given `run_id`, results always live at
    `<audit_repo_root>/results/<run_id>/report/report.json`, and raw findings
    are always queryable from the single shared `<audit_repo_root>/state.db`
    `findings` table, filtered by `run_id` — regardless of which target was
    scanned.
  - `report.json` (schemas/report.schema.json) holds only *reachable,
    canonical* findings (post-Trace, post-Dedupe) — what a human would
    actually see. Each item already carries `file`/`line_start`/`line_end`/
    `vuln_class`/`cwe?`/`severity` directly.
  - The `findings` table (audit/state.py `SCHEMA`) holds every *raw* Hunt
    finding regardless of validation/dedupe/trace outcome; its `cwe` isn't a
    column, so it's pulled out of the stored `raw_json` blob (which is the
    finding.schema.json-shaped HuntOutput item) when present.

This module is read-only: it never invokes `audit`, never touches the
network, and (for tests) accepts explicit `results_root`/`db_path` overrides
so it can be pointed at a fake fixture instead of a real scan.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from bench.config import AUDIT_RESULTS_ROOT, AUDIT_STATE_DB


def report_path_for_run(run_id: str, results_root: Path | None = None) -> Path:
    results_root = Path(results_root) if results_root else AUDIT_RESULTS_ROOT
    return results_root / run_id / "report" / "report.json"


def load_report(run_id: str, results_root: Path | None = None) -> dict | None:
    """Read `results/<run_id>/report/report.json`, or None if absent/unreadable."""
    path = report_path_for_run(run_id, results_root)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def detected_from_report(report: dict) -> list[dict]:
    """Normalize report.json's `findings[]` into scorer-ready dicts."""
    out = []
    for f in report.get("findings", []):
        out.append({
            "finding_id": f.get("finding_id"),
            "file": f.get("file"),
            "line_start": f.get("line_start"),
            "line_end": f.get("line_end"),
            "vuln_class": f.get("vuln_class"),
            "cwe": f.get("cwe"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "source": "report",
        })
    return out


def load_state_db_findings(
    run_id: str,
    db_path: Path | None = None,
    *,
    canonical_only: bool = False,
) -> list[dict]:
    """Query the `findings` table directly for raw (pre-report) findings.

    Useful when report.json is missing or empty (e.g. the report agent
    failed, or nothing survived Trace/Dedupe) but you still want to measure
    what Hunt/Validate actually saw, rather than unfairly scoring recall
    against a report-stage hiccup.
    """
    db_path = Path(db_path) if db_path else AUDIT_STATE_DB
    if not db_path.is_file():
        return []

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM findings WHERE run_id = ?"
        args: list = [run_id]
        if canonical_only:
            sql += " AND is_canonical = 1"
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()

    out = []
    for r in rows:
        raw = {}
        if r["raw_json"]:
            try:
                raw = json.loads(r["raw_json"])
            except json.JSONDecodeError:
                raw = {}
        out.append({
            "finding_id": r["finding_id"],
            "file": r["file"],
            "line_start": r["line_start"],
            "line_end": r["line_end"],
            "vuln_class": r["vuln_class"],
            "cwe": raw.get("cwe"),
            "severity": r["severity"],
            "source": "state_db",
        })
    return out


def load_detected_findings(
    run_id: str,
    *,
    results_root: Path | None = None,
    db_path: Path | None = None,
    prefer: str = "report",
) -> list[dict]:
    """Load the detected-findings list for one run, ready for `scorer.score()`.

    prefer="report" (default): use report.json if it exists and has at least
    one finding; otherwise fall back to the raw `findings` table.
    prefer="state_db": always use the raw `findings` table (skip report.json
    entirely — e.g. to measure pre-Trace/pre-Dedupe recall).
    """
    if prefer not in ("report", "state_db"):
        raise ValueError(f"prefer must be 'report' or 'state_db', got {prefer!r}")

    if prefer == "state_db":
        return load_state_db_findings(run_id, db_path)

    report = load_report(run_id, results_root)
    if report and report.get("findings"):
        return detected_from_report(report)
    return load_state_db_findings(run_id, db_path)
