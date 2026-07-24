"""Tests for report.py's post-hoc variant attach (VVAH DupLocation parity, A2).

A same-file... no — a same-*group*, different-file deduped sibling must never
be silently dropped to a bare finding_id string. `_group_members_excluding`
and `_attach_variants` demote it instead to a LOCATED reference
({finding_id, file, line_start, line_end, vuln_class}) attached to the
canonical finding, sourced authoritatively from run state (never left to the
report agent) — mirrors the existing `_attach_cwe` post-hoc attach pattern.

All OFFLINE: hand-built StateDB rows, no agent/network involved.
"""

from __future__ import annotations

from pathlib import Path

from vash.state import StateDB
from vash.stages.report import _attach_variants, _group_members_excluding


def _seed_group(db: StateDB, run_id: str) -> None:
    """One dedupe group `g1` with canonical f_c (pkg/x.py:10-12) and a
    same-group sibling f_v (pkg/y.py:30-31) — the located variant the
    report must surface as "Also at:"."""
    db.add_task(run_id, {
        "task_id": "t_1", "attack_class": "ssrf", "scope_hint": "x",
        "target_files": ["pkg/x.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })
    db.add_finding(run_id, "t_1", {
        "finding_id": "f_c", "file": "pkg/x.py", "line_start": 10, "line_end": 12,
        "vuln_class": "ssrf", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    db.add_finding(run_id, "t_1", {
        "finding_id": "f_v", "file": "pkg/y.py", "line_start": 30, "line_end": 31,
        "vuln_class": "ssrf", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    db.add_dedupe_group(run_id, {
        "group_id": "g1", "root_cause": "rc",
        "canonical_finding_id": "f_c", "member_finding_ids": ["f_c", "f_v"],
    })
    db.assign_finding_group("f_c", "g1", True)
    db.assign_finding_group("f_v", "g1", False)


def test_group_members_excluding_returns_located_dicts(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    _seed_group(db, rid)

    result = _group_members_excluding(db, rid, "g1", "f_c")
    assert result == [
        {"finding_id": "f_v", "file": "pkg/y.py", "line_start": 30,
         "line_end": 31, "vuln_class": "ssrf"}
    ]
    db.close()


def test_attach_variants_sets_located_siblings(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    _seed_group(db, rid)

    payload = {"findings": [{"finding_id": "f_c"}]}
    _attach_variants(db, rid, payload)

    assert payload["findings"][0]["variants"][0]["file"] == "pkg/y.py"
    assert payload["findings"][0]["variants"][0]["line_start"] == 30
    db.close()


def test_attach_variants_no_group_is_noop(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    db.add_task(rid, {
        "task_id": "t_1", "attack_class": "ssrf", "scope_hint": "x",
        "target_files": ["pkg/x.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })
    db.add_finding(rid, "t_1", {
        "finding_id": "f_solo", "file": "pkg/x.py", "line_start": 1, "line_end": 2,
        "vuln_class": "ssrf", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    # No group assigned to f_solo — must not crash, must not invent variants.

    payload = {"findings": [{"finding_id": "f_solo"}]}
    _attach_variants(db, rid, payload)

    assert "variants" not in payload["findings"][0]
    db.close()
