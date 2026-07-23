"""V4 — CVSS-vector verification wireup in the Validate stage.

Covers: (a) the CVSS-rating -> audit-severity mapping helper, and (b) the
`run_validate` wireup that parses a validator-emitted `cvss_vector`, computes
score/rating via `audit.cvss`, stores both on the validation JSON, and makes
the CVSS band authoritative for the finding's severity. Offline: `run_agent`
is monkeypatched to a canned stub (no Claude call, no network), mirroring
`tests/test_pipeline_e2e.py`'s stub pattern.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import audit.stages._common as common_mod
import audit.stages.validate as validate_mod
from audit.config import load_config
from audit.runner import AgentResult
from audit.stages._common import StageContext
from audit.stages.validate import _severity_from_cvss_rating, run_validate
from audit.state import StateDB

RUN_ID = "r1"
TASK_ID = "t_1"
FINDING_ID = "f_1"

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# ---------------------------------------------------------------------------
# Pure mapping helper (CVSS rating -> audit's lowercase severity enum)
# ---------------------------------------------------------------------------

def test_severity_from_cvss_rating_maps_known_bands() -> None:
    assert _severity_from_cvss_rating("Critical") == "critical"
    assert _severity_from_cvss_rating("High") == "high"
    assert _severity_from_cvss_rating("Medium") == "medium"
    assert _severity_from_cvss_rating("Low") == "low"


def test_severity_from_cvss_rating_is_case_insensitive() -> None:
    assert _severity_from_cvss_rating("critical") == "critical"
    assert _severity_from_cvss_rating("HIGH") == "high"


def test_severity_from_cvss_rating_none_or_unknown_unmapped() -> None:
    # "None"/"Unknown"/absent must NOT map to a severity — caller keeps
    # the finding's existing severity.
    assert _severity_from_cvss_rating("None") is None
    assert _severity_from_cvss_rating("Unknown") is None
    assert _severity_from_cvss_rating(None) is None
    assert _severity_from_cvss_rating("") is None


# ---------------------------------------------------------------------------
# run_validate wireup over a real StateDB, run_agent stubbed
# ---------------------------------------------------------------------------

@pytest.fixture
def ctx(tmp_path: Path) -> StageContext:
    return StageContext(run_id=RUN_ID, repo_path=tmp_path, config=load_config())


@pytest.fixture(autouse=True)
def _redirect_results_and_work(monkeypatch, tmp_path):
    # Mirrors test_pipeline_e2e.py: never let a stage write into the real
    # repo's results/ or work/ directories during a test.
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")


def _seed(db: StateDB, *, severity: str) -> None:
    db.create_run("/repo", RUN_ID)
    db.add_task(RUN_ID, {
        "task_id": TASK_ID, "attack_class": "sqli", "scope_hint": "x",
        "target_files": ["a.py"], "rationale": "r", "priority": 1, "source": "recon",
    })
    db.add_finding(RUN_ID, TASK_ID, {
        "finding_id": FINDING_ID, "file": "a.py", "line_start": 1, "line_end": 2,
        "vuln_class": "sqli", "severity": severity,
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })


def _stub_run_agent(payload: dict):
    async def fake_run_agent(*, artifact_dir, artifact_name, **_kwargs) -> AgentResult:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{artifact_name}.jsonl"
        artifact_path.write_text('{"kind": "stub"}\n')
        return AgentResult(
            payload=dict(payload),
            cost_usd=0.0, input_tokens=1, output_tokens=1,
            cache_read_tokens=0, cache_creation_tokens=0,
            num_turns=1, duration_ms=1, session_id="stub-session",
            artifact_path=artifact_path, repair_used=False,
            raw_result_message={"usage": {"input_tokens": 1, "output_tokens": 1},
                                 "total_cost_usd": 0.0, "num_turns": 1,
                                 "duration_ms": 1, "session_id": "stub-session"},
        )
    return fake_run_agent


async def test_validate_stores_cvss_and_updates_severity(monkeypatch, tmp_path, ctx) -> None:
    db = StateDB(tmp_path / "state.db")
    _seed(db, severity="medium")
    monkeypatch.setattr(validate_mod, "run_agent", _stub_run_agent({
        "finding_id": FINDING_ID, "verdict": "confirmed",
        "rationale": "x" * 30, "validator_confidence": 0.9,
        "cvss_vector": CRITICAL_VECTOR,
    }))

    confirmed = await run_validate(ctx, db)

    assert confirmed == 1
    f = db.get_findings(RUN_ID)[0]
    assert f.severity == "critical"  # CVSS band now authoritative over "medium"
    assert f.validation_json["cvss_score"] == 9.8
    assert f.validation_json["cvss_rating"] == "Critical"
    db.close()


async def test_validate_no_vector_keeps_existing_severity(monkeypatch, tmp_path, ctx) -> None:
    db = StateDB(tmp_path / "state.db")
    _seed(db, severity="medium")
    monkeypatch.setattr(validate_mod, "run_agent", _stub_run_agent({
        "finding_id": FINDING_ID, "verdict": "confirmed",
        "rationale": "x" * 30, "validator_confidence": 0.9,
    }))

    confirmed = await run_validate(ctx, db)

    assert confirmed == 1
    f = db.get_findings(RUN_ID)[0]
    assert f.severity == "medium"  # fail-open: unchanged, no vector present
    assert "cvss_score" not in f.validation_json
    assert "cvss_rating" not in f.validation_json
    db.close()


async def test_validate_malformed_vector_keeps_existing_severity(monkeypatch, tmp_path, ctx) -> None:
    db = StateDB(tmp_path / "state.db")
    _seed(db, severity="low")
    monkeypatch.setattr(validate_mod, "run_agent", _stub_run_agent({
        "finding_id": FINDING_ID, "verdict": "confirmed",
        "rationale": "x" * 30, "validator_confidence": 0.9,
        "cvss_vector": "not-a-real-vector",
    }))

    confirmed = await run_validate(ctx, db)

    assert confirmed == 1
    f = db.get_findings(RUN_ID)[0]
    assert f.severity == "low"  # fail-open: unchanged, malformed vector
    assert "cvss_score" not in f.validation_json
    assert "cvss_rating" not in f.validation_json
    db.close()


async def test_validate_rejected_verdict_ignores_cvss(monkeypatch, tmp_path, ctx) -> None:
    """A rejected verdict must not touch severity, even if a vector is present."""
    db = StateDB(tmp_path / "state.db")
    _seed(db, severity="high")
    monkeypatch.setattr(validate_mod, "run_agent", _stub_run_agent({
        "finding_id": FINDING_ID, "verdict": "rejected",
        "rationale": "x" * 30, "validator_confidence": 0.9,
        "cvss_vector": CRITICAL_VECTOR,
    }))

    confirmed = await run_validate(ctx, db)

    assert confirmed == 0
    f = db.get_findings(RUN_ID)[0]
    assert f.severity == "high"  # unchanged — rejected verdicts are out of scope
    db.close()
