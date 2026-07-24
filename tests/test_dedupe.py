"""Tests for feature D8 — per-file canonical promotion in dedupe (Stage 5).

The dedupe agent clusters confirmed findings into groups and picks ONE
canonical finding per group. When a group spans multiple files, naively
honoring only the LLM's single canonical pick buries a confirmed finding
that lives in a different file — trace.py (canonical-only) and report.py
(reachable-canonical-only) never see it, silently dropping a confirmed
result. run_dedupe now promotes one canonical PER DISTINCT FILE within
each group so a co-located confirmed finding survives to trace/report.

All OFFLINE: run_agent is stubbed, findings/DB rows are hand-built. No network.
"""

from __future__ import annotations

from pathlib import Path

import vash.stages.dedupe as dedupe_mod
from vash.config import load_config
from vash.runner import AgentResult
from vash.stages._common import StageContext
from vash.state import StateDB


def _fake_run_agent_factory(payload: dict):
    async def fake_run_agent(*, artifact_dir, artifact_name, **_kwargs) -> AgentResult:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{artifact_name}.jsonl"
        artifact_path.write_text("{}\n")
        return AgentResult(
            payload=payload,
            cost_usd=0.0, input_tokens=0, output_tokens=0,
            cache_read_tokens=0, cache_creation_tokens=0,
            num_turns=1, duration_ms=1, session_id="stub",
            artifact_path=artifact_path, repair_used=False,
            raw_result_message={"usage": {"input_tokens": 0, "output_tokens": 0},
                                "total_cost_usd": 0.0, "num_turns": 1, "duration_ms": 1},
        )
    return fake_run_agent


def _seed_confirmed(db: StateDB, run_id: str, fid: str, file: str) -> None:
    """Add one finding that is task-anchored + confirmed — exactly the
    selection run_dedupe (via get_findings(validation_status='confirmed'))
    consumes."""
    tid = f"t_{fid}"
    db.add_task(run_id, {
        "task_id": tid, "attack_class": "sqli", "scope_hint": "x",
        "target_files": [file], "rationale": "r", "priority": 1, "source": "recon",
    })
    db.add_finding(run_id, tid, {
        "finding_id": fid, "file": file, "line_start": 1, "line_end": 2,
        "vuln_class": "sqli", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    db.set_finding_validation(fid, "confirmed", {
        "finding_id": fid, "verdict": "confirmed",
        "rationale": "ok", "validator_confidence": 0.9,
    })


def _ctx(tmp_path: Path) -> StageContext:
    return StageContext(run_id="r1", repo_path=tmp_path, config=load_config())


async def test_dedupe_promotes_one_canonical_per_distinct_file(
    tmp_path: Path, monkeypatch
) -> None:
    """A group spanning two files (A: 2 findings, B: 1 finding) with the LLM's
    canonical pick in file A must ALSO promote the sole file-B member — the
    D8 fix — while the second file-A member (same file as the canonical)
    stays non-canonical."""
    import vash.stages._common as common_mod
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")

    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed(db, "r1", "f_a1", "pkg/a.py")
        _seed_confirmed(db, "r1", "f_a2", "pkg/a.py")
        _seed_confirmed(db, "r1", "f_b1", "pkg/b.py")

        group = {
            "group_id": "g_1",
            "root_cause": "Unescaped string concatenation into SQL query builder.",
            "canonical_finding_id": "f_a1",
            "member_finding_ids": ["f_a1", "f_a2", "f_b1"],
        }
        monkeypatch.setattr(dedupe_mod, "run_agent",
                            _fake_run_agent_factory({"groups": [group]}))

        n = await dedupe_mod.run_dedupe(_ctx(tmp_path), db)
        assert n == 1

        canonical_ids = {f.finding_id for f in db.get_findings("r1", canonical_only=True)}
        assert "f_a1" in canonical_ids       # the LLM's canonical stays canonical
        assert "f_b1" in canonical_ids       # co-located file-B finding is promoted too
        assert "f_a2" not in canonical_ids   # second file-A member stays non-canonical
        assert canonical_ids == {"f_a1", "f_b1"}
    finally:
        db.close()


async def test_dedupe_single_file_group_keeps_one_canonical(
    tmp_path: Path, monkeypatch
) -> None:
    """Pre-existing behavior is unchanged: a group whose members are all in
    one file still yields exactly one canonical — the LLM's choice."""
    import vash.stages._common as common_mod
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")

    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed(db, "r1", "f_a1", "pkg/a.py")
        _seed_confirmed(db, "r1", "f_a2", "pkg/a.py")

        group = {
            "group_id": "g_1",
            "root_cause": "Unescaped string concatenation into SQL query builder.",
            "canonical_finding_id": "f_a2",
            "member_finding_ids": ["f_a1", "f_a2"],
        }
        monkeypatch.setattr(dedupe_mod, "run_agent",
                            _fake_run_agent_factory({"groups": [group]}))

        n = await dedupe_mod.run_dedupe(_ctx(tmp_path), db)
        assert n == 1

        canonical_ids = {f.finding_id for f in db.get_findings("r1", canonical_only=True)}
        assert canonical_ids == {"f_a2"}
    finally:
        db.close()
