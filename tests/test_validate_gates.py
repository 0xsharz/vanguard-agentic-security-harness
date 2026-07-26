"""F5 (redo) — VulnHunter static per-class disprove-gates grafted into Validate.

Covers the `# Verification rigor (per-class disprove-gates)` section added to
prompts/03-validate.md, ported from VulnHunter's phase2b_verify.md ("For EACH
remaining candidate, verify" -> #3 defenses / #5 downgrade discipline, plus the
no-input and multi-writer rules from #1 and #5). Static only: no execution, and
no new schema field — a finding the gates can't settle statically is the
existing `needs_more_info` verdict, so this file also confirms
schemas/validation.schema.json is untouched by the graft.

This supersedes tests/test_exploitability.py (deleted): that file covered the
ai-proofscan-sourced `exploitability` block this task reverts.
"""

from __future__ import annotations

import json
from pathlib import Path

from vash.json_utils import validate_schema

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
PROMPTS = ROOT / "prompts"


def _validate_prompt() -> str:
    return (PROMPTS / "03-validate.md").read_text()


def test_validate_prompt_has_verification_rigor_section() -> None:
    text = _validate_prompt()
    assert "# Verification rigor (per-class disprove-gates)" in text


def test_validate_prompt_has_downgrade_discipline() -> None:
    text = _validate_prompt()
    assert "Downgrade discipline" in text
    assert "every** call site" in text or "ALL** call" in text
    assert "needs_more_info" in text.split("# Verification rigor")[1]


def test_validate_prompt_has_full_codebase_defense_search() -> None:
    text = _validate_prompt()
    assert "Full-codebase defense search" in text
    assert "middleware" in text
    assert "WHOLE repo" in text


def test_validate_prompt_has_no_input_elimination() -> None:
    text = _validate_prompt()
    assert "No-input elimination" in text
    assert "no attacker-controlled input" in text
    assert "reliability/quality issue" in text


def test_validate_prompt_has_multi_writer_rule() -> None:
    text = _validate_prompt()
    assert "Multi-writer rule" in text
    assert "server-controlled" in text
    assert "ALL write paths" in text


def test_validate_prompt_gates_reference_existing_rules_not_restate() -> None:
    # Guardrail: Part B should point at "Additional disprove rules" rather than
    # re-deriving sanitizer-context / empirical-verify / severity-context text.
    text = _validate_prompt()
    gates_section = text.split("# Verification rigor")[1]
    assert "verify defenses empirically" in gates_section.lower()
    # The graft must not duplicate the sanitizer-context-mismatch prose.
    assert gates_section.lower().count("html escaper") == 0


def test_validate_prompt_still_json_only_output_contract() -> None:
    # The graft must not disturb Validate's existing output contract.
    text = _validate_prompt()
    assert "schemas/validation.schema.json" in text
    assert "No prose" in text


def test_validate_prompt_no_execution_language_introduced() -> None:
    # Static-only guardrail: Part B must not introduce PoC/execution language
    # (that remains a deferred, opt-in concern; live_target dynamic-confirm
    # already existed pre-graft and is untouched).
    gates_section = _validate_prompt().split("# Verification rigor")[1]
    for banned in ("execute the exploit", "run the payload", "build and run"):
        assert banned not in gates_section.lower()


# ---- schemas/validation.schema.json: unchanged by the Part B prompt-only graft ----


def test_validation_schema_unchanged_verdict_enum() -> None:
    schema = json.loads((SCHEMAS / "validation.schema.json").read_text())
    assert set(schema["properties"]["verdict"]["enum"]) == {
        "confirmed", "rejected", "needs_more_info",
    }
    # No new top-level property was added for the disprove-gates graft.
    assert set(schema["properties"].keys()) == {
        "finding_id", "verdict", "rationale", "alternative_explanation",
        "missing_preconditions", "suggested_test", "validator_confidence",
        "cvss_vector", "cvss_score", "cvss_rating",
    }


def test_validation_schema_still_accepts_rejected_with_call_site_rationale() -> None:
    # A verdict shaped by the new downgrade-discipline gate: rejected only
    # after all call sites were checked, no new fields required.
    payload = {
        "finding_id": "f_x",
        "verdict": "rejected",
        "rationale": (
            "Grepped all 5 call sites of the sink; each passes a "
            "parameterized query, none concatenate attacker input."
        ),
        "alternative_explanation": "Benign: every call site binds parameters.",
        "validator_confidence": 0.9,
    }
    assert validate_schema(payload, SCHEMAS / "validation.schema.json") == []


def test_validation_schema_still_accepts_needs_more_info_with_suggested_test() -> None:
    payload = {
        "finding_id": "f_y",
        "verdict": "needs_more_info",
        "rationale": (
            "One of 4 call sites verified safe; the remaining 3 require "
            "reading a vendored module not present in this checkout."
        ),
        "alternative_explanation": "Could be safe if the vendored module also escapes.",
        "validator_confidence": 0.5,
        "suggested_test": "Vendor the missing module and re-check call sites 2-4.",
    }
    assert validate_schema(payload, SCHEMAS / "validation.schema.json") == []
