"""Exact-duplicate skipping in Validate (Stage 3), and its coverage invariant.

Validate costs one full agent call per finding, and each call re-reads the same
file into a fresh context. Hunt legitimately raises the identical finding from
several tasks — taint, specialist, and catchall all hunt the same file for
different attack classes — so the pipeline was paying repeatedly for the same
verdict. Measured on the archived runs: 7 exact duplicates on dmcg-outperform
(~$3.31) and 3 on jsonschema (~$1.13).

The key is deliberately the strictest one available — same file, same exact line
range, same vuln_class — so collapsing on it needs no judgement, no similarity
threshold and no model call. Anything looser is a semantic decision and stays
with Dedupe, which runs later, with an LLM, for exactly that purpose.

`test_every_finding_gets_a_verdict` is the invariant that matters. The failure
mode this optimisation could introduce is a finding that silently never gets
validated, which downstream reads as "not confirmed" and drops it from the
report. That is a recall regression wearing a cost saving's clothes, and it is
the same shape as the gapfill/effort mistake — so it is pinned here.

All OFFLINE: run_agent is stubbed, findings are hand-built. No network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import vash.stages.validate as validate_mod
from vash.config import load_config
from vash.runner import AgentResult
from vash.stages._common import StageContext
from vash.stages.validate import _identity_key, _partition_duplicates
from vash.state import StateDB


def _finding(fid: str, *, file: str = "app.py", ls: int = 10, le: int = 12,
             cls: str = "command_injection") -> dict:
    return {
        "finding_id": fid, "file": file, "line_start": ls, "line_end": le,
        "vuln_class": cls, "severity": "high", "description": f"desc {fid}",
        "evidence_snippet": "snippet", "confidence": 0.9,
    }


def _mk(tmp_path: Path, findings: list[dict]) -> tuple[StageContext, StateDB, str]:
    db = StateDB(tmp_path / "state.db")
    run_id = db.create_run(str(tmp_path))
    db.add_task(run_id, {"task_id": "t1", "attack_class": "command_injection",
                         "scope_hint": "h", "target_files": ["app.py"],
                         "rationale": "r", "priority": 1})
    for f in findings:
        db.add_finding(run_id, "t1", f)
    ctx = StageContext(run_id=run_id, repo_path=tmp_path, config=load_config())
    return ctx, db, run_id


def _stub(monkeypatch, calls: list[str], verdict: str = "confirmed"):
    async def fake(*, artifact_dir, artifact_name, **_kw) -> AgentResult:
        calls.append(artifact_name)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload={"finding_id": artifact_name, "verdict": verdict,
                     "rationale": "ok", "validator_confidence": 0.9},
            cost_usd=0.0, input_tokens=0, output_tokens=0, cache_read_tokens=0,
            cache_creation_tokens=0, num_turns=1, duration_ms=1,
            session_id="stub", artifact_path=ap, repair_used=False,
            raw_result_message={"usage": {}, "total_cost_usd": 0.0,
                                "num_turns": 1, "duration_ms": 1},
        )
    monkeypatch.setattr(validate_mod, "run_agent", fake)


# ─────────────────────────────────────────────────────────────────────────
# The key: strict, and sensitive to every component.
# ─────────────────────────────────────────────────────────────────────────

def test_identity_key_distinguishes_every_component() -> None:
    from vash.state import Finding

    def F(**kw):
        base = dict(finding_id="f", task_id="t", run_id="r", file="a.py",
                    line_start=1, line_end=2, vuln_class="xss", severity="high",
                    description="d", evidence="e", poc_succeeded=False,
                    confidence=0.5, raw_json={}, validation_status=None,
                    validation_json=None, group_id=None, is_canonical=False)
        base.update(kw)
        return Finding(**base)

    base = _identity_key(F())
    assert _identity_key(F(file="b.py")) != base
    assert _identity_key(F(line_start=9)) != base
    assert _identity_key(F(line_end=9)) != base
    assert _identity_key(F(vuln_class="sqli")) != base
    # identity ignores things that are NOT part of "same finding"
    assert _identity_key(F(finding_id="other", severity="low")) == base


def test_partition_is_order_preserving_and_deterministic() -> None:
    from vash.state import Finding

    def F(fid, cls):
        return Finding(finding_id=fid, task_id="t", run_id="r", file="a.py",
                       line_start=1, line_end=2, vuln_class=cls, severity="high",
                       description="d", evidence="e", poc_succeeded=False,
                       confidence=0.5, raw_json={}, validation_status=None,
                       validation_json=None, group_id=None, is_canonical=False)

    items = [F("f1", "xss"), F("f2", "xss"), F("f3", "sqli"), F("f4", "xss")]
    reps, dupes = _partition_duplicates(items)
    assert [r.finding_id for r in reps] == ["f1", "f3"]          # first wins
    assert [d.finding_id for d in dupes["f1"]] == ["f2", "f4"]
    assert _partition_duplicates(items)[0][0].finding_id == "f1"  # stable


# ─────────────────────────────────────────────────────────────────────────
# THE COVERAGE INVARIANT.
# ─────────────────────────────────────────────────────────────────────────

async def test_every_finding_gets_a_verdict(tmp_path: Path, monkeypatch) -> None:
    """No finding may be left unvalidated. An unvalidated finding reads as
    "not confirmed" downstream and silently vanishes from the report — a recall
    regression disguised as a cost saving."""
    ctx, db, run_id = _mk(tmp_path, [
        _finding("f1"), _finding("f2"), _finding("f3"),          # all identical
        _finding("f4", cls="sqli"),
    ])
    calls: list[str] = []
    _stub(monkeypatch, calls)

    await validate_mod.run_validate(ctx, db)

    assert len(calls) == 2, f"expected 2 agent calls (one per identity), got {calls}"
    assert not db.get_unvalidated_findings(run_id), "a finding was left unvalidated"
    assert len(db.get_findings(run_id, validation_status="confirmed")) == 4


async def test_duplicates_are_marked_inherited(tmp_path: Path, monkeypatch) -> None:
    """A reviewer must be able to tell that no validator looked at this record,
    and which record it did look at."""
    ctx, db, run_id = _mk(tmp_path, [_finding("f1"), _finding("f2")])
    _stub(monkeypatch, [])

    await validate_mod.run_validate(ctx, db)

    by_id = {f.finding_id: f for f in db.get_findings(run_id)}
    assert by_id["f1"].validation_json.get("inherited_from") is None
    assert by_id["f2"].validation_json["inherited_from"] == "f1"
    assert "exact duplicate" in by_id["f2"].validation_json["inherited_reason"]


async def test_rejection_is_inherited_too(tmp_path: Path, monkeypatch) -> None:
    """Inheriting only confirmations would quietly upgrade duplicates of a
    rejected finding into un-validated ones."""
    ctx, db, run_id = _mk(tmp_path, [_finding("f1"), _finding("f2")])
    _stub(monkeypatch, [], verdict="rejected")

    await validate_mod.run_validate(ctx, db)

    assert len(db.get_findings(run_id, validation_status="rejected")) == 2
    assert not db.get_unvalidated_findings(run_id)


async def test_representative_failure_does_not_orphan_duplicates(
    tmp_path: Path, monkeypatch
) -> None:
    """If the one agent call fails, its duplicates must still land on a verdict
    rather than staying NULL forever."""
    from vash.runner import AgentRunError

    ctx, db, run_id = _mk(tmp_path, [_finding("f1"), _finding("f2")])

    async def boom(*, artifact_dir, artifact_name, **_kw):
        raise AgentRunError("schema fail")
    monkeypatch.setattr(validate_mod, "run_agent", boom)

    await validate_mod.run_validate(ctx, db)

    assert not db.get_unvalidated_findings(run_id)
    assert len(db.get_findings(run_id, validation_status="needs_more_info")) == 2


async def test_distinct_findings_are_never_collapsed(
    tmp_path: Path, monkeypatch
) -> None:
    """The saving must come only from provable duplicates."""
    ctx, db, run_id = _mk(tmp_path, [
        _finding("f1", file="a.py"), _finding("f2", file="b.py"),
        _finding("f3", ls=99), _finding("f4", cls="sqli"),
    ])
    calls: list[str] = []
    _stub(monkeypatch, calls)

    await validate_mod.run_validate(ctx, db)

    assert len(calls) == 4, "distinct findings must each get their own call"
