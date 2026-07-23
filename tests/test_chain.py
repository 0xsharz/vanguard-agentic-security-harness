"""Tests for feature V11 — exploit-chain construction (ported VVAH s8_chain).

The Chain stage runs after Trace/Feedback and before Report: one read-only LLM
pass sees ALL confirmed canonical findings together and constructs multi-step
exploit CHAINS (combinations more dangerous than any single bug). Key contracts
exercised here:
  - schemas/chain.schema.json accepts a valid analysis and rejects a chain with
    <2 finding_ids or a bad severity enum.
  - state.add_chain_analysis / get_chain_analysis round-trip.
  - run_chain stores the analysis and returns the chain count; skips (returns 0,
    no agent call) with <2 confirmed findings; on agent failure stores an EMPTY
    analysis and never raises (fail-soft).
  - Report surfaces stored chains into the agent user_input and the fallback.

All OFFLINE: run_agent is stubbed, findings/DB rows are hand-built. No network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import vash.stages.chain as chain_mod
import vash.stages.report as report_mod
from vash.config import load_config
from vash.json_utils import validate_schema
from vash.runner import AgentRunError, AgentResult
from vash.stages._common import StageContext
from vash.state import StateDB

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"

CHAIN_OK = {
    "summary": "Two moderate bugs compose into a pre-auth account takeover.",
    "chains": [
        {
            "title": "Info leak -> leaked token -> auth bypass = account takeover",
            "finding_ids": ["f_leak_1", "f_auth_2"],
            "severity": "high",
            "blocked_by_controls": [],
            "narrative": "The leak at app.py:12 exposes a session token that "
                         "the auth check at views.py:40 accepts verbatim.",
        }
    ],
}


# ---- schema: schemas/chain.schema.json -------------------------------------


def test_schema_accepts_valid_chain_analysis() -> None:
    errors = validate_schema(CHAIN_OK, SCHEMAS / "chain.schema.json")
    assert errors == [], errors


def test_schema_accepts_empty_chains() -> None:
    errors = validate_schema(
        {"summary": "no chains found", "chains": []}, SCHEMAS / "chain.schema.json"
    )
    assert errors == [], errors


def test_schema_rejects_chain_with_single_finding_id() -> None:
    bad = {
        "summary": "x",
        "chains": [{**CHAIN_OK["chains"][0], "finding_ids": ["f_only_1"]}],
    }
    errors = validate_schema(bad, SCHEMAS / "chain.schema.json")
    assert errors, "expected a validation error for a chain with <2 finding_ids"


def test_schema_rejects_bad_severity_enum() -> None:
    bad = {
        "summary": "x",
        "chains": [{**CHAIN_OK["chains"][0], "severity": "catastrophic"}],
    }
    errors = validate_schema(bad, SCHEMAS / "chain.schema.json")
    assert errors, "expected a validation error for a bad severity enum"


def test_schema_rejects_missing_required_chain_field() -> None:
    bad = {
        "summary": "x",
        "chains": [{k: v for k, v in CHAIN_OK["chains"][0].items() if k != "narrative"}],
    }
    errors = validate_schema(bad, SCHEMAS / "chain.schema.json")
    assert errors, "expected a validation error for a chain missing 'narrative'"


# ---- state: chains table round-trip ----------------------------------------


def test_add_and_get_chain_analysis_round_trip(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")
        assert db.get_chain_analysis("r1") is None
        db.add_chain_analysis("r1", CHAIN_OK)
        got = db.get_chain_analysis("r1")
        assert got == CHAIN_OK
    finally:
        db.close()


def test_add_chain_analysis_replaces(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/some/repo", "r1")
        db.add_chain_analysis("r1", {"summary": "first", "chains": []})
        db.add_chain_analysis("r1", CHAIN_OK)
        assert db.get_chain_analysis("r1") == CHAIN_OK  # INSERT OR REPLACE
    finally:
        db.close()


# ---- run_chain wiring (audit/stages/chain.py) ------------------------------


def _fake_run_agent_factory(captured: list[dict], payload: dict):
    async def fake_run_agent(*, user_input, artifact_dir, artifact_name, **_kwargs) -> AgentResult:
        captured.append(user_input)
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


def _seed_confirmed_reachable(
    db: StateDB, run_id: str, fid: str, *,
    vuln_class: str = "ssrf", severity: str = "medium",
    validation: dict | None = None, trace: dict | None = None,
) -> None:
    """Add one finding that is confirmed + canonical + reachable — exactly the
    selection run_chain (via get_reachable_canonical_findings) consumes."""
    tid = f"t_{fid}"
    db.add_task(run_id, {
        "task_id": tid, "attack_class": vuln_class, "scope_hint": "app.py",
        "target_files": ["app.py"], "rationale": "x", "priority": 1,
    })
    db.add_finding(run_id, tid, {
        "finding_id": fid, "file": "app.py", "line_start": 10, "line_end": 12,
        "vuln_class": vuln_class, "severity": severity, "description": "d",
        "evidence_snippet": "e", "confidence": 0.9,
    })
    db.set_finding_validation(fid, "confirmed", validation or {
        "finding_id": fid, "verdict": "confirmed", "rationale": "ok",
        "validator_confidence": 0.9,
    })
    db.assign_finding_group(fid, f"g_{fid}", True)
    db.add_trace(fid, trace or {
        "finding_id": fid, "reachable": True, "confidence": 0.9,
        "rationale": "reachable", "entry_points": [], "call_chain": [],
    })


def _ctx(tmp_path: Path) -> StageContext:
    return StageContext(run_id="r1", repo_path=tmp_path, config=load_config())


async def test_run_chain_stores_and_returns_count(tmp_path: Path, monkeypatch) -> None:
    import vash.stages._common as common_mod
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")
    captured: list[dict] = []
    monkeypatch.setattr(chain_mod, "run_agent",
                        _fake_run_agent_factory(captured, CHAIN_OK))
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_reachable(db, "r1", "f_leak_1")
        _seed_confirmed_reachable(db, "r1", "f_auth_2")
        n = await chain_mod.run_chain(_ctx(tmp_path), db)
        assert n == 1  # len(CHAIN_OK["chains"])
        assert db.get_chain_analysis("r1") == CHAIN_OK
    finally:
        db.close()
    # user_input references findings by finding_id, NOT by 0-based index.
    assert len(captured) == 1
    ui = captured[0]
    assert {f["finding_id"] for f in ui["findings"]} == {"f_leak_1", "f_auth_2"}
    assert all("finding_id" in f and "index" not in f for f in ui["findings"])
    assert "design_controls" in ui


async def test_run_chain_user_input_carries_cvss_and_exploitability(
    tmp_path: Path, monkeypatch
) -> None:
    import vash.stages._common as common_mod
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")
    captured: list[dict] = []
    monkeypatch.setattr(chain_mod, "run_agent",
                        _fake_run_agent_factory(captured, {"summary": "s", "chains": []}))
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        db.save_recon_output("r1", {"design_controls": [{"kind": "authn",
                                    "location": "a.py:1", "description": "login gate"}]})
        _seed_confirmed_reachable(
            db, "r1", "f_cvss_1",
            validation={"finding_id": "f_cvss_1", "verdict": "confirmed",
                        "rationale": "ok", "validator_confidence": 0.9,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cvss_rating": "Critical"},
            trace={"finding_id": "f_cvss_1", "reachable": True, "confidence": 0.9,
                   "rationale": "reachable", "entry_points": [], "call_chain": [],
                   "exploitability": {"impact": 2, "narrative": "leads to RCE"}},
        )
        _seed_confirmed_reachable(db, "r1", "f_plain_2")
        await chain_mod.run_chain(_ctx(tmp_path), db)
    finally:
        db.close()
    ui = captured[0]
    by_id = {f["finding_id"]: f for f in ui["findings"]}
    assert by_id["f_cvss_1"]["cvss_vector"].startswith("CVSS:3.1/")
    assert by_id["f_cvss_1"]["cvss_rating"] == "Critical"
    assert by_id["f_cvss_1"]["exploitability"]["narrative"] == "leads to RCE"
    # A finding with no CVSS/exploitability simply omits those keys.
    assert "cvss_vector" not in by_id["f_plain_2"]
    assert "exploitability" not in by_id["f_plain_2"]
    assert ui["design_controls"][0]["kind"] == "authn"


async def test_run_chain_skips_with_fewer_than_two(tmp_path: Path, monkeypatch) -> None:
    called = {"n": 0}

    async def boom(**_kwargs):
        called["n"] += 1
        raise AssertionError("run_agent must NOT be called with <2 findings")

    monkeypatch.setattr(chain_mod, "run_agent", boom)
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_reachable(db, "r1", "f_only_1")  # only ONE finding
        n = await chain_mod.run_chain(_ctx(tmp_path), db)
        assert n == 0
        assert called["n"] == 0
        assert db.get_chain_analysis("r1") is None  # nothing stored on skip
    finally:
        db.close()


async def test_run_chain_failsoft_on_agent_error(tmp_path: Path, monkeypatch) -> None:
    import vash.stages._common as common_mod
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")

    async def failing(**_kwargs):
        raise AgentRunError("model produced junk")

    monkeypatch.setattr(chain_mod, "run_agent", failing)
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_reachable(db, "r1", "f_a")
        _seed_confirmed_reachable(db, "r1", "f_b")
        # Must NOT raise — fail-soft.
        n = await chain_mod.run_chain(_ctx(tmp_path), db)
        assert n == 0
        stored = db.get_chain_analysis("r1")
        assert stored is not None
        assert stored["chains"] == []          # empty analysis stored
        assert "failed" in stored["summary"].lower()
    finally:
        db.close()


# ---- Report surfacing (audit/stages/report.py) -----------------------------


async def test_report_passes_chains_into_user_input(tmp_path: Path, monkeypatch) -> None:
    import vash.stages._common as common_mod
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")
    captured: list[dict] = []
    # A schema-valid report payload so run_report writes it out cleanly.
    report_payload = {
        "run_id": "r1", "target": {"repo_path": str(tmp_path)},
        "summary": {"total": 1, "by_severity": {"medium": 1}}, "findings": [],
    }
    monkeypatch.setattr(report_mod, "run_agent",
                        _fake_run_agent_factory(captured, report_payload))
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_reachable(db, "r1", "f_leak_1")  # >=1 ready finding
        db.add_chain_analysis("r1", CHAIN_OK)
        await report_mod.run_report(_ctx(tmp_path), db)
    finally:
        db.close()
    assert len(captured) == 1
    assert captured[0]["chains"] == CHAIN_OK["chains"]


async def test_report_fallback_includes_chains(tmp_path: Path, monkeypatch) -> None:
    import json
    import vash.stages._common as common_mod
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")

    async def failing(**_kwargs):
        raise AgentRunError("report agent produced junk")

    monkeypatch.setattr(report_mod, "run_agent", failing)
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_reachable(db, "r1", "f_leak_1")
        db.add_chain_analysis("r1", CHAIN_OK)
        out_path = await report_mod.run_report(_ctx(tmp_path), db)
    finally:
        db.close()
    report = json.loads(out_path.read_text())
    assert report["chains"] == CHAIN_OK["chains"]  # fallback carried the chains
