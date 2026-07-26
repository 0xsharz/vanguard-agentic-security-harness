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


def _seed_cross_file_group(db: StateDB, run_id: str) -> None:
    """One dedupe group `g2` spanning two files, as D8's per-file promotion
    (dedupe.py::run_dedupe) actually leaves it: f_a1 (pkg/a.py) and f_b1
    (pkg/b.py) are BOTH canonical — one per distinct file — while f_a2
    (pkg/a.py) is the genuinely-demoted same-file sibling of f_a1. All three
    share the SAME group_id, exactly as run_dedupe assigns it."""
    db.add_task(run_id, {
        "task_id": "t_2", "attack_class": "ssrf", "scope_hint": "x",
        "target_files": ["pkg/a.py", "pkg/b.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })
    db.add_finding(run_id, "t_2", {
        "finding_id": "f_a1", "file": "pkg/a.py", "line_start": 10, "line_end": 12,
        "vuln_class": "ssrf", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    db.add_finding(run_id, "t_2", {
        "finding_id": "f_a2", "file": "pkg/a.py", "line_start": 40, "line_end": 41,
        "vuln_class": "ssrf", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    db.add_finding(run_id, "t_2", {
        "finding_id": "f_b1", "file": "pkg/b.py", "line_start": 5, "line_end": 6,
        "vuln_class": "ssrf", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    db.add_dedupe_group(run_id, {
        "group_id": "g2", "root_cause": "rc",
        "canonical_finding_id": "f_a1", "member_finding_ids": ["f_a1", "f_a2", "f_b1"],
    })
    db.assign_finding_group("f_a1", "g2", True)
    db.assign_finding_group("f_a2", "g2", False)
    db.assign_finding_group("f_b1", "g2", True)


def test_attach_variants_cross_file_group_excludes_other_headline(tmp_path: Path) -> None:
    """D8 + _attach_variants integration (final review, Fix 1): a cross-file
    group with TWO canonical (headline) findings must not cross-list each
    other as "Also at:" variants, and a demoted member must attach only to
    the headline that actually owns its file — never to an unrelated
    headline that merely shares the dedupe group.

    Before Fix 1: f_a1's variants wrongly included f_b1 (another headline,
    not a demoted sibling). A naive "just exclude other canonicals" fix is
    ALSO insufficient: since f_a1, f_a2, and f_b1 all share one group_id (D8
    never splits the group_id per file), f_b1 would still wrongly inherit
    f_a2 (pkg/a.py's demoted duplicate) unless the fix also scopes a demoted
    member to its own-file headline. This test proves both halves.
    """
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    _seed_cross_file_group(db, rid)

    payload = {"findings": [{"finding_id": "f_a1"}, {"finding_id": "f_b1"}]}
    _attach_variants(db, rid, payload)

    by_id = {f["finding_id"]: f for f in payload["findings"]}
    a1_variant_ids = [v["finding_id"] for v in by_id["f_a1"]["variants"]]
    assert a1_variant_ids == ["f_a2"]
    assert "f_b1" not in a1_variant_ids

    assert by_id["f_b1"]["variants"] == []
    db.close()
