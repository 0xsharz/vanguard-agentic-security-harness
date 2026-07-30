"""The tool-LOADING contract (cost + defence-in-depth).

`ClaudeAgentOptions` has two similar-looking knobs that do different things:

    allowed_tools -> "auto-allowed WITHOUT PROMPTING for permission"
    tools         -> "the base set of AVAILABLE built-in tools"

`runner.py` originally passed only `allowed_tools`, which meant every agent ran
with the **entire Claude Code preset loaded** — 31 tool schemas plus 42 slash
commands — even though `config/stages.yaml` grants at most six. Measured on the
pinned SDK: 23,879 tokens of context with the preset vs 8,817 with hunt's real
tool set. Every turn re-sends the whole context, so that dead weight was
multiplied by ~13 turns across ~200 agent calls per run.

Passing the SAME gated list to both makes the declared config the effective one.
Two safety properties fall out of that and are pinned below:

  * The R1 Bash gate becomes STRUCTURAL. On a bare host `_gate_tools` already
    removed Bash from `allowed_tools`; now it is absent from `tools` too, so the
    model cannot even emit the call. Before this change it emitted Bash calls and
    got denied — 348 denied Bash calls across the archived runs, each a wasted
    turn. The permission layer is still there; it is no longer the only thing
    standing between a bare host and target-code execution.

  * Decoy built-ins disappear. `ReportFindings` is a Claude Code tool that looks
    exactly like what a security agent should call, and hunt/validate called it
    445 times — but `run_agent` validates the final TEXT against the finding
    schema and never parses tool_use blocks, so every one of those calls went
    nowhere. Same for `ToolSearch`/`Task`, which let a stage fan out into
    subagents it was never configured for.

Offline and hermetic: `ClaudeAgentOptions` is replaced by a capturing stub and
the SDK client never opens a session.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vash import runner, sandbox
from vash.config import load_config


@pytest.fixture(autouse=True)
def _not_sandboxed(monkeypatch, tmp_path):
    """Bare-host baseline; individual tests opt into a sandbox explicitly."""
    monkeypatch.delenv("VASH_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "_DOCKERENV", tmp_path / "no-such-dockerenv")


def _capture_options(monkeypatch, seen: list[dict]):
    """Replace ClaudeAgentOptions with a recorder and stub out the session."""

    class _Opts:
        def __init__(self, **kw):
            seen.append(kw)

    class _FakeClient:
        def __init__(self, options=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def query(self, _prompt):
            return None

    async def _fake_drain(_client, _art):
        return "{}", {"is_error": False, "usage": {}, "total_cost_usd": 0.0,
                      "num_turns": 1, "duration_ms": 1, "session_id": "stub"}

    monkeypatch.setattr(runner, "ClaudeAgentOptions", _Opts)
    monkeypatch.setattr(runner, "ClaudeSDKClient", _FakeClient)
    monkeypatch.setattr(runner, "_drain", _fake_drain)
    monkeypatch.setattr(runner, "_validate", lambda *_a, **_k: [])


async def _run(tmp_path: Path, *, stage: str, allowed_tools: list[str],
               execution_enabled: bool = False) -> None:
    prompt = tmp_path / "p.md"
    prompt.write_text("system prompt")
    schema = tmp_path / "s.json"
    schema.write_text(json.dumps({"type": "object"}))
    await runner.run_agent(
        stage=stage,
        prompt_file=prompt,
        user_input={},
        schema_file=schema,
        allowed_tools=allowed_tools,
        model="claude-sonnet-5",
        cwd=tmp_path / "cwd",
        artifact_dir=tmp_path / "art",
        artifact_name="task1",
        execution_enabled=execution_enabled,
    )


# ─────────────────────────────────────────────────────────────────────────
# The cost contract: `tools` is passed, and it is the gated list.
# ─────────────────────────────────────────────────────────────────────────

async def test_tools_is_passed_to_the_sdk(tmp_path: Path, monkeypatch) -> None:
    """Without this the full Claude Code preset loads — the 69% regression."""
    seen: list[dict] = []
    _capture_options(monkeypatch, seen)

    await _run(tmp_path, stage="validate", allowed_tools=["Read", "Grep", "Glob"])

    assert "tools" in seen[0], (
        "ClaudeAgentOptions must receive `tools`; passing only `allowed_tools` "
        "loads the entire built-in preset into every turn's context"
    )
    assert seen[0]["tools"] == ["Read", "Grep", "Glob"]


async def test_tools_and_allowed_tools_agree(tmp_path: Path, monkeypatch) -> None:
    """The declared set is the effective set — no silently-loaded extras."""
    seen: list[dict] = []
    _capture_options(monkeypatch, seen)

    await _run(tmp_path, stage="validate", allowed_tools=["Read", "Grep", "Glob"])

    assert seen[0]["tools"] == seen[0]["allowed_tools"]


# ─────────────────────────────────────────────────────────────────────────
# Defence in depth: the bare-host Bash gate is now structural.
# ─────────────────────────────────────────────────────────────────────────

async def test_bash_absent_from_loaded_tools_on_bare_host(
    tmp_path: Path, monkeypatch
) -> None:
    seen: list[dict] = []
    _capture_options(monkeypatch, seen)

    await _run(tmp_path, stage="hunt",
               allowed_tools=["Read", "Grep", "Glob", "Bash", "Write", "Edit"])

    assert "Bash" not in seen[0]["tools"], (
        "on a bare host Bash must be absent from the model's context, not "
        "merely denied at the permission layer"
    )
    assert "Bash" not in seen[0]["allowed_tools"]


async def test_bash_loaded_when_execution_enabled(tmp_path: Path, monkeypatch) -> None:
    """Inside a sandbox with --dynamic-validation, PoC execution still works."""
    monkeypatch.setenv("VASH_SANDBOX", "1")
    seen: list[dict] = []
    _capture_options(monkeypatch, seen)

    await _run(tmp_path, stage="hunt",
               allowed_tools=["Read", "Grep", "Glob", "Bash", "Write", "Edit"],
               execution_enabled=True)

    assert "Bash" in seen[0]["tools"]


# ─────────────────────────────────────────────────────────────────────────
# Capability preservation: the executed-PoC path needs Write/Edit.
# ─────────────────────────────────────────────────────────────────────────

def test_hunt_config_keeps_poc_authoring_tools() -> None:
    """Hunt made 98 successful Write + 38 successful Edit calls across the
    archived runs, authoring the PoC files (evil.py, poc_ssrf_oas.py, ...).
    They previously worked only because permission_mode=acceptEdits
    auto-approved undeclared tools. Now that this list is what actually gets
    loaded, dropping them would delete VASH's key differentiator."""
    hunt = load_config().get("hunt")
    assert "Write" in hunt.tools
    assert "Edit" in hunt.tools


def test_read_only_stages_declare_no_execution_tool() -> None:
    """Pins the documented intent of the analysis stages.

    `_gate_tools` can only SUBTRACT — it fires on `if "Bash" in allowed_tools`,
    so a stage that never declared Bash was never protected by it. Combined with
    passing only `allowed_tools` (which does not restrict availability), Bash was
    reachable from the preset and read-only shell genuinely executed in stages
    documented `# no Bash: pure analysis`: `find`/`grep -rn`/`ls` ran in validate
    across six archived runs including dmcg-outperform and fmtinj-1.

    Passing `tools=` closes that structurally. This test stops it reopening: if
    someone adds Bash to a read-only stage, it fails here rather than silently
    granting shell to the stage whose whole job is disagreeing with Hunt.
    """
    cfg = load_config()
    for name in ("validate", "gapfill", "dedupe", "feedback", "chain", "report"):
        sc = cfg.stages.get(name)
        if sc is None:
            continue
        assert "Bash" not in sc.tools, (
            f"stage {name} is documented read-only but declares Bash"
        )


def test_no_stage_loads_decoy_or_fanout_tools() -> None:
    """ReportFindings is never parsed by run_agent (it validates final TEXT),
    and Task/Agent/ToolSearch let a stage fan out into unconfigured subagents."""
    banned = {"ReportFindings", "Task", "Agent", "ToolSearch", "Workflow"}
    cfg = load_config()
    for name, sc in cfg.stages.items():
        assert not (banned & set(sc.tools)), f"stage {name} declares a banned tool"
