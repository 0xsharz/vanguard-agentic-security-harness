"""Tests for Phase 6 — `vash validate` (decoupled, static-first, independent
per-finding second-opinion re-verification).

Contracts exercised (all OFFLINE — run_agent is stubbed, findings/DB rows are
hand-built, no network):
  - schemas/revalidation.schema.json accepts a valid record; rejects a bad
    `verdict` enum, an out-of-range `confidence`, and an additional property.
  - run_revalidate: writes revalidation.json + REVALIDATION.md; a stubbed
    `failed` verdict on a scan-confirmed finding is surfaced as an
    OVERTURNED/disagreement in the summary + markdown; a `validated` with
    confidence below `min_confidence` is downgraded to `needs_review` (VVAH
    s6 gate) and is NOT counted as agreement; a per-finding agent error is
    fail-soft (batch continues, recorded as needs_review).
  - agrees_with_scan is computed deterministically by the stage — never
    trusted from the model's own self-report.
  - Redaction: a secret in a finding's evidence does not leak into
    REVALIDATION.md or revalidation.json.
  - CLI `validate` command is registered and wired to run_revalidate.
"""

from __future__ import annotations

import json
from pathlib import Path

import vash.stages.revalidate as revalidate_mod
from vash.config import load_config
from vash.json_utils import validate_schema
from vash.runner import AgentResult, AgentRunError
from vash.stages._common import StageContext
from vash.stages.revalidate import DEFAULT_MIN_CONFIDENCE, run_revalidate
from vash.state import StateDB

REPO = Path(__file__).resolve().parent.parent
SCHEMAS = REPO / "schemas"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # redact.py masks this as [REDACTED-AWS-KEY]


# ─────────────────────────────────────────────────────────────────────────────
# schemas/revalidation.schema.json
# ─────────────────────────────────────────────────────────────────────────────

VALIDATED_OK = {
    "finding_id": "f_sqli_1",
    "verdict": "validated",
    "confidence": 9,
    "agrees_with_scan": True,
    "rationale": "Re-traced every call site of the sink in app.py; none sanitize "
                 "the input; the scan's confirmation holds under adversarial review.",
    "alternative_explanation": "Considered whether the ORM's query builder "
                               "auto-parameterizes here; grep shows this call "
                               "bypasses the builder entirely.",
}


def test_schema_accepts_valid_record() -> None:
    assert validate_schema(VALIDATED_OK, SCHEMAS / "revalidation.schema.json") == []


def test_schema_rejects_bad_verdict_enum() -> None:
    bad = {**VALIDATED_OK, "verdict": "confirmed"}  # scan vocabulary, not revalidate's
    errors = validate_schema(bad, SCHEMAS / "revalidation.schema.json")
    assert errors, "expected a validation error for a bad verdict enum"


def test_schema_rejects_confidence_out_of_range() -> None:
    bad = {**VALIDATED_OK, "confidence": 11}
    errors = validate_schema(bad, SCHEMAS / "revalidation.schema.json")
    assert errors, "expected a validation error for out-of-range confidence"


def test_schema_rejects_additional_property() -> None:
    bad = {**VALIDATED_OK, "cwe": "CWE-89"}
    errors = validate_schema(bad, SCHEMAS / "revalidation.schema.json")
    assert errors, "expected a validation error for an additionalProperty"


# ─────────────────────────────────────────────────────────────────────────────
# run_revalidate — stubbed run_agent, hand-built DB
# ─────────────────────────────────────────────────────────────────────────────

VALIDATED_PAYLOAD = {
    "finding_id": "WILL_BE_OVERWRITTEN",
    "verdict": "validated",
    "confidence": 9,
    "agrees_with_scan": True,
    "rationale": "Re-traced every call site of the sink; none sanitize; the "
                 "scan's confirmation holds under active adversarial review.",
    "alternative_explanation": "Considered an upstream allow-list; grep of the "
                               "whole repo shows none exists on this path.",
}

FAILED_PAYLOAD = {
    "finding_id": "WILL_BE_OVERWRITTEN",
    "verdict": "failed",
    "confidence": 9,
    "agrees_with_scan": False,
    "rationale": "The scan missed that this route is behind an admin-only auth "
                 "decorator applied in middleware.py; no external caller reaches it.",
    "alternative_explanation": "The finding assumed public reachability; grepping "
                               "every caller shows each entry point is gated by "
                               "@require_admin, closing the path.",
}

LOW_CONFIDENCE_VALIDATED_PAYLOAD = {
    "finding_id": "WILL_BE_OVERWRITTEN",
    "verdict": "validated",
    "confidence": 5,
    "agrees_with_scan": True,
    "rationale": "Sink looks reachable but I could not fully rule out an "
                 "upstream filter that may live in a module I could not find.",
    "alternative_explanation": "A filter might exist elsewhere in the repo; not "
                               "fully ruled out within the turn budget.",
}


def _agent_result(payload: dict, artifact_path: Path) -> AgentResult:
    return AgentResult(
        payload=dict(payload),
        cost_usd=0.0, input_tokens=0, output_tokens=0,
        cache_read_tokens=0, cache_creation_tokens=0,
        num_turns=1, duration_ms=1, session_id="stub",
        artifact_path=artifact_path, repair_used=False,
        raw_result_message={"usage": {"input_tokens": 0, "output_tokens": 0},
                            "total_cost_usd": 0.0, "num_turns": 1, "duration_ms": 1},
    )


def _fake_run_agent_factory(captured: list[dict], payload: dict):
    """Every call returns the same payload (finding_id gets overwritten by the
    stage regardless) — for single-finding tests."""
    async def fake_run_agent(*, user_input, artifact_dir, artifact_name, **_kw) -> AgentResult:
        captured.append(user_input)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return _agent_result(payload, ap)
    return fake_run_agent


def _fake_run_agent_by_id(captured: list[dict], payload_map: dict[str, dict]):
    """Different stub payload per finding_id (keyed by artifact_name, which the
    stage sets to f.finding_id) — for mixed-batch tests."""
    async def fake_run_agent(*, user_input, artifact_dir, artifact_name, **_kw) -> AgentResult:
        captured.append(user_input)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return _agent_result(payload_map[artifact_name], ap)
    return fake_run_agent


def _seed_confirmed_canonical(db: StateDB, run_id: str, fid: str, *,
                              vuln_class: str = "sql_injection",
                              severity: str = "high", cwe: str | None = "CWE-89",
                              evidence: str = "query = f\"SELECT ... {name}\"",
                              description: str = "Untrusted input flows to SQL sink.") -> None:
    """Add one finding that is confirmed + canonical — exactly what
    run_revalidate's selector (get_findings confirmed, canonical_only) consumes."""
    tid = f"t_{fid}"
    db.add_task(run_id, {"task_id": tid, "attack_class": vuln_class,
                         "scope_hint": "app.py", "target_files": ["app.py"],
                         "rationale": "x", "priority": 1})
    finding = {"finding_id": fid, "file": "app.py", "line_start": 10, "line_end": 12,
               "vuln_class": vuln_class, "severity": severity,
               "description": description, "evidence_snippet": evidence,
               "confidence": 0.9}
    if cwe:
        finding["cwe"] = cwe
    db.add_finding(run_id, tid, finding)
    db.set_finding_validation(fid, "confirmed", {
        "finding_id": fid, "verdict": "confirmed",
        "rationale": "confirmed for the purposes of this revalidation test.",
        "validator_confidence": 0.9})
    db.assign_finding_group(fid, f"g_{fid}", True)


def _ctx(tmp_path: Path, run_id: str = "r1") -> StageContext:
    return StageContext(run_id=run_id, repo_path=tmp_path, config=load_config())


async def test_run_revalidate_writes_all_artifacts(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(revalidate_mod, "run_agent",
                        _fake_run_agent_factory(captured, VALIDATED_PAYLOAD))
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_revalidate(_ctx(tmp_path), db, out_dir=out)
    finally:
        db.close()

    assert len(captured) == 1                                   # agent invoked once
    assert captured[0]["finding"]["finding_id"] == "f_sqli_1"    # full raw finding passed
    assert captured[0]["scan_verdict"] == "confirmed"
    assert summary["counts"] == {"validated": 1, "failed": 0, "needs_review": 0}
    assert (out / "revalidation.json").is_file()
    assert (out / "REVALIDATION.md").is_file()

    rec = json.loads((out / "revalidation.json").read_text())["records"][0]
    assert rec["finding_id"] == "f_sqli_1"                       # authoritative id
    assert rec["verdict"] == "validated"
    assert rec["agrees_with_scan"] is True


async def test_run_revalidate_overturned_finding_flagged(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(revalidate_mod, "run_agent",
                        _fake_run_agent_factory(captured, FAILED_PAYLOAD))
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_revalidate(_ctx(tmp_path), db, out_dir=out)
    finally:
        db.close()

    assert summary["counts"] == {"validated": 0, "failed": 1, "needs_review": 0}
    assert summary["overturned_finding_ids"] == ["f_sqli_1"]
    rec = summary["records"][0]
    assert rec["verdict"] == "failed"
    assert rec["agrees_with_scan"] is False                      # disagreement surfaced
    md = (out / "REVALIDATION.md").read_text()
    assert "OVERTURNED" in md
    assert "f_sqli_1" in md


async def test_run_revalidate_low_confidence_validated_downgraded(
    tmp_path: Path, monkeypatch
) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(revalidate_mod, "run_agent",
                        _fake_run_agent_factory(captured, LOW_CONFIDENCE_VALIDATED_PAYLOAD))
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_revalidate(_ctx(tmp_path), db, out_dir=out, min_confidence=7)
    finally:
        db.close()

    assert summary["counts"] == {"validated": 0, "failed": 0, "needs_review": 1}
    rec = summary["records"][0]
    assert rec["verdict"] == "needs_review"
    assert rec["downgraded"] is True
    assert rec["original_verdict"] == "validated"
    assert rec["agrees_with_scan"] is False           # downgraded verdict is not agreement
    assert summary["overturned_finding_ids"] == []    # unresolved, not a disagreement


async def test_run_revalidate_failsoft_on_agent_error(tmp_path: Path, monkeypatch) -> None:
    async def failing(**_kw):
        raise AgentRunError("model produced junk")

    monkeypatch.setattr(revalidate_mod, "run_agent", failing)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        # Must NOT raise — one finding's failure is fail-soft.
        summary = await run_revalidate(_ctx(tmp_path), db, out_dir=out)
    finally:
        db.close()

    assert summary["counts"] == {"validated": 0, "failed": 0, "needs_review": 1}
    rec = summary["records"][0]
    assert rec["verdict"] == "needs_review"
    assert rec.get("error") is True
    assert "failed" in rec["rationale"].lower()
    assert (out / "REVALIDATION.md").is_file()                   # batch still finished


async def test_run_revalidate_failsoft_on_unexpected_error(tmp_path: Path, monkeypatch) -> None:
    async def kaboom(**_kw):
        raise ValueError("boom")   # not an AgentRunError -> generic fail-soft branch

    monkeypatch.setattr(revalidate_mod, "run_agent", kaboom)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_revalidate(_ctx(tmp_path), db, out_dir=out)
    finally:
        db.close()
    assert summary["counts"]["needs_review"] == 1                # did not raise


async def test_run_revalidate_mixed_batch_counts(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict] = []
    payload_map = {"f_sqli_1": VALIDATED_PAYLOAD, "f_authz_2": FAILED_PAYLOAD}
    monkeypatch.setattr(revalidate_mod, "run_agent",
                        _fake_run_agent_by_id(captured, payload_map))
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1", cwe="CWE-89")
        _seed_confirmed_canonical(db, "r1", "f_authz_2", cwe="CWE-862",
                                  vuln_class="missing_authz")
        summary = await run_revalidate(_ctx(tmp_path), db, out_dir=out)
    finally:
        db.close()
    assert summary["counts"] == {"validated": 1, "failed": 1, "needs_review": 0}
    assert len(captured) == 2                                    # agent ran twice
    assert summary["overturned_finding_ids"] == ["f_authz_2"]


async def test_run_revalidate_model_override_passed_through(
    tmp_path: Path, monkeypatch
) -> None:
    captured_models: list[str] = []

    async def fake_run_agent(*, model, artifact_dir, artifact_name, **_kw) -> AgentResult:
        captured_models.append(model)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return _agent_result(VALIDATED_PAYLOAD, ap)

    monkeypatch.setattr(revalidate_mod, "run_agent", fake_run_agent)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        await run_revalidate(_ctx(tmp_path), db, out_dir=out, model="claude-haiku-9")
    finally:
        db.close()
    assert captured_models == ["claude-haiku-9"]                 # override wins over config


async def test_run_revalidate_redacts_secret_in_evidence(tmp_path: Path, monkeypatch) -> None:
    payload = {**VALIDATED_PAYLOAD,
              "rationale": f"Key {AWS_KEY} is reachable from the sink with no "
                           "upstream check on any call site."}
    captured: list[dict] = []
    monkeypatch.setattr(revalidate_mod, "run_agent",
                        _fake_run_agent_factory(captured, payload))
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(
            db, "r1", "f_sqli_1",
            evidence=f"client = boto3.client('s3', aws_access_key_id='{AWS_KEY}')",
            description=f"Hardcoded AWS key {AWS_KEY} reachable from the SQL path.",
        )
        await run_revalidate(_ctx(tmp_path), db, out_dir=out)
    finally:
        db.close()

    md = (out / "REVALIDATION.md").read_text()
    js = (out / "revalidation.json").read_text()
    assert AWS_KEY not in md and AWS_KEY not in js               # secret never leaks
    assert "[REDACTED-AWS-KEY]" in md                             # masked in evidence preview
    assert "[REDACTED-AWS-KEY]" in js                             # masked in rationale


async def test_run_revalidate_empty_when_no_confirmed_findings(
    tmp_path: Path, monkeypatch
) -> None:
    async def boom(**_kw):
        raise AssertionError("agent must not run with zero findings")

    monkeypatch.setattr(revalidate_mod, "run_agent", boom)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        summary = await run_revalidate(_ctx(tmp_path), db, out_dir=out)
    finally:
        db.close()
    assert summary["total"] == 0
    assert summary["counts"] == {"validated": 0, "failed": 0, "needs_review": 0}
    assert (out / "revalidation.json").is_file()                # still emits artifacts
    assert (out / "REVALIDATION.md").is_file()


async def test_run_revalidate_does_not_mutate_scan_verdict(tmp_path: Path, monkeypatch) -> None:
    """Read-only guarantee: revalidate must never write back to
    findings.validation_status/validation_json — only its OWN artifacts."""
    captured: list[dict] = []
    monkeypatch.setattr(revalidate_mod, "run_agent",
                        _fake_run_agent_factory(captured, FAILED_PAYLOAD))
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        await run_revalidate(_ctx(tmp_path), db, out_dir=out)
        # Scan's own confirmed verdict must be untouched despite the second
        # opinion overturning it.
        [f] = db.get_findings("r1", validation_status="confirmed", canonical_only=True)
        assert f.validation_json["verdict"] == "confirmed"
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# CLI wiring
# ─────────────────────────────────────────────────────────────────────────────

def test_cli_registers_validate_command() -> None:
    from vash.cli import main
    assert "validate" in main.commands


def test_cli_validate_command_options() -> None:
    from vash.cli import main
    params = {p.name for p in main.commands["validate"].params}
    assert {"run_id", "repo", "model", "min_confidence", "out_dir"} <= params


def test_cli_validate_default_min_confidence_matches_stage_default() -> None:
    from vash.cli import main
    opt = next(p for p in main.commands["validate"].params if p.name == "min_confidence")
    assert opt.default == DEFAULT_MIN_CONFIDENCE
