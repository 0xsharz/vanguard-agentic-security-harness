"""R1: prompts/02-hunt.md restores audit's original PoC-execution method
(verbatim, recovered from `git show 7ba60b0^:prompts/02-hunt.md`) and adds
the new execution-availability rule (attempt + drop/downgrade when
sandboxed; reason statically + `needs_poc: true` when not).

Text-content assertions only — mirrors tests/test_design_controls.py's
"prompt content" convention (read the real file, assert substrings). No
agent is run.
"""

from __future__ import annotations

from pathlib import Path

PROMPTS = Path(__file__).resolve().parent.parent / "prompts"


def _text() -> str:
    return (PROMPTS / "02-hunt.md").read_text()


# ---- audit's PoC mechanism, restored verbatim ------------------------------


def test_tools_available_restores_bash_and_scratch_dir_usage() -> None:
    text = _text()
    assert "Read, Grep, Glob, Bash." in text
    assert "cd $scratch_dir" in text
    assert "compile / run PoCs" in text


def test_method_restores_attempt_a_poc_step() -> None:
    text = _text()
    assert "**Attempt a PoC**" in text
    assert "live_target" in text
    assert "drop the finding" in text.lower()
    assert "$scratch_dir" in text


def test_objective_restores_prove_by_execution() -> None:
    text = _text()
    assert "compiling it in your scratch directory" in text


def test_no_leftover_static_only_contradiction() -> None:
    # The 7ba60b0 static-only phrasing must be fully reverted, not merely
    # supplemented — otherwise the prompt tells the model two different
    # things about whether it has Bash.
    text = _text()
    assert "Hunt has no Bash" not in text
    assert "never compiles, runs, or otherwise executes" not in text


# ---- new: execution-availability rule --------------------------------------


def test_execution_availability_rule_present() -> None:
    text = _text()
    assert "Execution availability" in text
    assert "execution_available" in text
    assert "needs_poc" in text
    assert "zero false positives" in text.lower()


def test_execution_availability_rule_precedes_attempt_a_poc_substeps() -> None:
    text = _text()
    rule_idx = text.index("Execution availability")
    attempt_idx = text.index("**Attempt a PoC**")
    live_target_substep_idx = text.index("If `live_target` is in input")
    assert attempt_idx < rule_idx < live_target_substep_idx


def test_inputs_block_documents_execution_available_field() -> None:
    text = _text()
    inputs_section = text.split("# Tools available")[0]
    assert "execution_available" in inputs_section
