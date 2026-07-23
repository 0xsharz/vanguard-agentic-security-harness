"""Tests for feature V5 — Operator Context Pack: design_controls.

Recon already maps architecture / entry points / trust boundaries and mines
git history for past security patches (prompts/01-recon.md). V5 adds one more
map: the security mechanisms (auth, input validation, sanitizers, output
encoding, CSRF, rate-limiting, access control, crypto) Recon observes while
reading, each with file:line. That list is injected downstream as a HINT to
verify empirically — never a trusted exclusion.

Covers:
- schemas/recon_output.schema.json accepts/rejects `design_controls`.
- truncated_recon_summary passes design_controls through (empty list when
  absent) -> this is the single choke point that feeds Hunt/Gapfill/Feedback.
- run_validate injects design_controls into user_input only when present.
- prompts/01-recon.md and prompts/03-validate.md/02-hunt.md carry the
  required "map, don't assert sufficiency" / "verify empirically, pointer
  not proof" language, deferring to the pre-existing empirical-verify rules.

All tests are OFFLINE: no network, no target-code execution. Validate's
wiring tests monkeypatch audit.stages.validate.run_agent and
audit.graph.build_or_load exactly like tests/test_graph_context.py's wiring
tests, and pin graph_cache_path under tmp_path so no cache directory is
created inside the real repo's work/ tree.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import audit.graph as graph_mod
import audit.stages.validate as validate_mod
from audit.config import load_config
from audit.json_utils import validate_schema
from audit.runner import AgentResult
from audit.stages._common import StageContext, truncated_recon_summary
from audit.state import StateDB

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"
PROMPTS = Path(__file__).resolve().parent.parent / "prompts"

RECON_BASE = {
    "subsystems": [
        {"name": "web", "path": "app.py", "language": "python", "purpose": "Flask HTTP handlers"},
    ],
    "architecture": {
        "build_commands": [],
        "entry_points": [{"kind": "http_route", "location": "app.py:lookup"}],
        "trust_boundaries": [],
    },
    "initial_tasks": [
        {
            "task_id": "t_web_sqli_1",
            "attack_class": "sql_injection",
            "scope_hint": "GET /lookup reads `name` from query string, passed via f-string into cur.execute() in app.py:30",
            "target_files": ["app.py"],
            "rationale": "Direct format string concatenation of untrusted input.",
            "priority": 1,
        }
    ],
}

DESIGN_CONTROL_OK = {
    "kind": "input_validation",
    "location": "app.py:22",
    "description": "Regex allowlist on `name` before it reaches the query.",
    "applies_to": "GET /lookup",
}


# ---- schema: schemas/recon_output.schema.json ------------------------------


def test_schema_accepts_recon_without_design_controls() -> None:
    """design_controls is optional — pre-V5 recon outputs still validate."""
    errors = validate_schema(RECON_BASE, SCHEMAS / "recon_output.schema.json")
    assert errors == [], errors


def test_schema_accepts_recon_with_valid_design_controls() -> None:
    payload = {**RECON_BASE, "design_controls": [DESIGN_CONTROL_OK]}
    errors = validate_schema(payload, SCHEMAS / "recon_output.schema.json")
    assert errors == [], errors


@pytest.mark.parametrize("missing", ["kind", "location", "description"])
def test_schema_rejects_design_control_missing_required_field(missing: str) -> None:
    bad_control = {k: v for k, v in DESIGN_CONTROL_OK.items() if k != missing}
    payload = {**RECON_BASE, "design_controls": [bad_control]}
    errors = validate_schema(payload, SCHEMAS / "recon_output.schema.json")
    assert errors, f"expected a validation error for design_control missing '{missing}'"


# ---- truncated_recon_summary (audit/stages/_common.py) --------------------


def test_truncated_recon_summary_passes_through_design_controls() -> None:
    full = {**RECON_BASE, "design_controls": [DESIGN_CONTROL_OK]}
    out = truncated_recon_summary(full)
    assert out["design_controls"] == [DESIGN_CONTROL_OK]


def test_truncated_recon_summary_design_controls_empty_when_absent() -> None:
    out = truncated_recon_summary(RECON_BASE)
    assert out["design_controls"] == []


def test_truncated_recon_summary_design_controls_survives_subsystem_filter() -> None:
    full = {**RECON_BASE, "design_controls": [DESIGN_CONTROL_OK]}
    out = truncated_recon_summary(full, subsystem_filter="web")
    assert out["design_controls"] == [DESIGN_CONTROL_OK]


# ---- run_validate wiring (audit/stages/validate.py) ------------------------


async def _fake_run_agent_factory(captured: list[dict], payload: dict):
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
            raw_result_message={},
        )
    return fake_run_agent


def _seed_run_with_one_finding(db: StateDB, run_id: str, repo_path: Path) -> None:
    db.create_run(str(repo_path), run_id)
    db.add_task(run_id, {
        "task_id": "t1", "attack_class": "sql_injection", "scope_hint": "app.py",
        "target_files": ["app.py"], "rationale": "x", "priority": 1,
    })
    db.add_finding(run_id, "t1", {
        "finding_id": "f1", "file": "app.py", "line_start": 1, "line_end": 1,
        "vuln_class": "sql_injection", "severity": "high", "description": "d",
        "evidence_snippet": "e", "confidence": 0.9,
    })


def _no_graph_ctx(tmp_path: Path, monkeypatch) -> StageContext:
    """A StageContext whose ctx.graph() deterministically fail-opens to None
    (mirrors test_graph_context.py's fail_open_on_build_error convention) so
    these tests exercise design_controls wiring only, offline and fast, with
    no cache directory created under the real repo's work/ tree."""
    def boom(root, cache):
        raise RuntimeError("graph not needed for this test")
    monkeypatch.setattr(graph_mod, "build_or_load", boom)
    return StageContext(run_id="r1", repo_path=tmp_path, config=load_config(),
                         graph_cache_path=tmp_path / "graph.json")


async def test_run_validate_injects_design_controls_when_present(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(
        validate_mod, "run_agent",
        await _fake_run_agent_factory(captured, {
            "finding_id": "f1", "verdict": "rejected", "rationale": "x",
            "validator_confidence": 0.5, "alternative_explanation": "x",
        }),
    )
    db = StateDB(tmp_path / "state.db")
    try:
        _seed_run_with_one_finding(db, "r1", tmp_path)
        db.save_recon_output("r1", {**RECON_BASE, "design_controls": [DESIGN_CONTROL_OK]})
        ctx = _no_graph_ctx(tmp_path, monkeypatch)
        await validate_mod.run_validate(ctx, db)
    finally:
        db.close()

    assert len(captured) == 1
    assert captured[0]["design_controls"] == [DESIGN_CONTROL_OK]


async def test_run_validate_omits_design_controls_when_recon_has_none(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(
        validate_mod, "run_agent",
        await _fake_run_agent_factory(captured, {
            "finding_id": "f1", "verdict": "rejected", "rationale": "x",
            "validator_confidence": 0.5, "alternative_explanation": "x",
        }),
    )
    db = StateDB(tmp_path / "state.db")
    try:
        _seed_run_with_one_finding(db, "r1", tmp_path)
        db.save_recon_output("r1", RECON_BASE)  # no design_controls key at all
        ctx = _no_graph_ctx(tmp_path, monkeypatch)
        await validate_mod.run_validate(ctx, db)
    finally:
        db.close()

    assert len(captured) == 1
    assert "design_controls" not in captured[0]


async def test_run_validate_omits_design_controls_when_no_recon_saved(tmp_path: Path, monkeypatch) -> None:
    """No recon output saved at all (get_recon_output -> None) must not crash
    and must omit design_controls — matches test_pipeline_e2e.py's shape
    where the canned recon stub has no design_controls key."""
    captured: list[dict] = []
    monkeypatch.setattr(
        validate_mod, "run_agent",
        await _fake_run_agent_factory(captured, {
            "finding_id": "f1", "verdict": "rejected", "rationale": "x",
            "validator_confidence": 0.5, "alternative_explanation": "x",
        }),
    )
    db = StateDB(tmp_path / "state.db")
    try:
        _seed_run_with_one_finding(db, "r1", tmp_path)
        # deliberately no db.save_recon_output call
        ctx = _no_graph_ctx(tmp_path, monkeypatch)
        await validate_mod.run_validate(ctx, db)
    finally:
        db.close()

    assert len(captured) == 1
    assert "design_controls" not in captured[0]


# ---- prompt content ---------------------------------------------------------


def test_recon_prompt_instructs_mapping_design_controls() -> None:
    text = (PROMPTS / "01-recon.md").read_text()
    assert "design_controls" in text
    assert "map the design controls" in text.lower()
    # Must be framed as a map of what exists, not a sufficiency claim.
    assert "not an assertion" in text.lower()


def test_hunt_prompt_uses_design_controls_to_prioritize() -> None:
    text = (PROMPTS / "02-hunt.md").read_text()
    assert "design_controls" in text
    assert "prioritize" in text.lower()
    # Must not licence trusting a listed control outright.
    assert "not proof" in text.lower() or "never proof" in text.lower() or "not treat" in text.lower()


def test_validate_prompt_has_verify_empirically_pointer_not_proof_language() -> None:
    text = (PROMPTS / "03-validate.md").read_text()
    assert "design_controls" in text
    assert "pointer" in text.lower()
    # Grafted language must defer to the pre-existing rules by name, not
    # replace or weaken them.
    assert "verify defenses empirically" in text.lower()
    assert "prose never satisfies a gate" in text.lower()
