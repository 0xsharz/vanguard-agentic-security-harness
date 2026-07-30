"""Per-stage `effort` — the output-token lever, and its capability boundary.

Once the tool-loading fix removes the dead tool schemas from every turn, OUTPUT
becomes the largest single cost line: 53.6% of a measured 9-stage run. `effort`
is the direct lever on it — lower effort yields fewer, more-consolidated tool
calls and less preamble, so it cuts turn count as well as output length.

The whole point of doing this per-stage is that it is NOT safe anywhere except
one stage. The rule, learned from a live run rather than reasoned out:

    A stage may be turned down ONLY if it cannot change WHICH findings are
    delivered, or HOW MANY.

The first attempt at this file used a looser rule — "stages that only
synthesise" — and put gapfill and feedback on the safe list. Both call
db.add_task, so both GENERATE hunt tasks. At effort=medium gapfill emitted zero
tasks instead of six and the pipeline collapsed behind it: 1 hunt task instead
of 7, 1 finding instead of 8, 1 delivered instead of 5, 0 exploit chains instead
of 3, and the planted CWE-78 gone. The run was 90% cheaper. Cheap and wrong is
the exact failure this file exists to prevent.

`test_recall_bearing_stages_are_not_turned_down` guards the hand-written list;
`test_task_generating_stages_are_detected_from_source` guards the list itself by
deriving task-generators from the source, so a new one cannot be added upstream
without failing here.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from vash import runner, sandbox
from vash.config import load_config


# A stage may be turned down ONLY if it cannot change WHICH findings are
# delivered, or HOW MANY. Everything below fails that test:
#
#   recon/gapfill/feedback -- call db.add_task, so they generate hunt tasks
#   hunt/validate/trace    -- find, confirm, prove reachability
#   dedupe                 -- assigns is_canonical, and canonical == delivered
#   chain                  -- exploit chains ARE delivered output
#
# This list started shorter and was corrected by a live run: with effort=medium,
# gapfill emitted 0 hunt tasks instead of 6 and the pipeline collapsed behind it
# (1 finding instead of 8, 0 chains instead of 3, planted CWE-78 lost) while
# getting 90% cheaper. Cheap and wrong is the failure mode this file exists to
# prevent, so treat additions here as removals from the safe list, never the
# other way round.
PROTECTED = ("recon", "hunt", "validate", "trace",
             "gapfill", "feedback", "dedupe", "chain")
# Renders prose from a payload the _attach_* helpers already built in Python.
TURNDOWN_OK = ("report",)


@pytest.fixture(autouse=True)
def _not_sandboxed(monkeypatch, tmp_path):
    monkeypatch.delenv("VASH_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "_DOCKERENV", tmp_path / "no-such-dockerenv")


def _capture(monkeypatch, seen: list[dict]):
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

        async def query(self, _p):
            return None

    async def _fake_drain(_c, _a):
        return "{}", {"is_error": False, "usage": {}, "total_cost_usd": 0.0,
                      "num_turns": 1, "duration_ms": 1, "session_id": "s"}

    monkeypatch.setattr(runner, "ClaudeAgentOptions", _Opts)
    monkeypatch.setattr(runner, "ClaudeSDKClient", _FakeClient)
    monkeypatch.setattr(runner, "_drain", _fake_drain)
    monkeypatch.setattr(runner, "_validate", lambda *_a, **_k: [])


async def _run(tmp_path: Path, **kw) -> None:
    prompt = tmp_path / "p.md"
    prompt.write_text("sys")
    schema = tmp_path / "s.json"
    schema.write_text(json.dumps({"type": "object"}))
    await runner.run_agent(
        stage="dedupe", prompt_file=prompt, user_input={}, schema_file=schema,
        allowed_tools=["Read"], model="claude-sonnet-5", cwd=tmp_path / "c",
        artifact_dir=tmp_path / "a", artifact_name="t", **kw,
    )


# ─────────────────────────────────────────────────────────────────────────
# Plumbing: set -> passed; unset -> omitted entirely.
# ─────────────────────────────────────────────────────────────────────────

async def test_effort_is_forwarded_when_set(tmp_path: Path, monkeypatch) -> None:
    seen: list[dict] = []
    _capture(monkeypatch, seen)
    await _run(tmp_path, effort="low")
    assert seen[0]["effort"] == "low"


async def test_effort_is_omitted_when_unset(tmp_path: Path, monkeypatch) -> None:
    """Omitted, not pinned to "high" — an un-opted-in stage must behave exactly
    as it did before this option existed, and must not be frozen to whatever
    "high" happens to mean in a future SDK."""
    seen: list[dict] = []
    _capture(monkeypatch, seen)
    await _run(tmp_path)
    assert "effort" not in seen[0]


# ─────────────────────────────────────────────────────────────────────────
# Config validation happens at LOAD time, not mid-run.
# ─────────────────────────────────────────────────────────────────────────

def test_bad_effort_value_fails_at_config_load(tmp_path: Path) -> None:
    """A typo must not surface as a 400 from the SDK after recon has already
    been billed."""
    cfg = tmp_path / "stages.yaml"
    cfg.write_text(textwrap.dedent("""
        defaults:
          max_turns: 25
        stages:
          dedupe:
            model: claude-sonnet-5
            concurrency: 1
            tools: [Read]
            effort: higher
    """))
    with pytest.raises(ValueError, match="effort must be one of"):
        load_config(cfg)


def test_effort_is_normalised(tmp_path: Path) -> None:
    cfg = tmp_path / "stages.yaml"
    cfg.write_text(textwrap.dedent("""
        stages:
          dedupe:
            model: claude-sonnet-5
            concurrency: 1
            tools: [Read]
            effort: "  LOW  "
    """))
    assert load_config(cfg).get("dedupe").effort == "low"


# ─────────────────────────────────────────────────────────────────────────
# THE CAPABILITY GUARD.
# ─────────────────────────────────────────────────────────────────────────

def test_recall_bearing_stages_are_not_turned_down() -> None:
    """No stage that can change the delivered finding set may be turned down.

    Measured consequence of getting this wrong: effort=medium on gapfill made it
    emit 0 hunt tasks instead of 6. The run cost 90% less and lost the planted
    CWE-78 entirely. If this test fails, revert the config — do not re-baseline
    the benchmark against a weakened scanner."""
    cfg = load_config()
    for name in PROTECTED:
        sc = cfg.stages.get(name)
        if sc is None:
            continue
        assert sc.effort is None, (
            f"stage {name!r} has effort={sc.effort!r}; discovery stages must "
            "stay at the SDK default"
        )


# ─────────────────────────────────────────────────────────────────────────
# Thinking: the inverted-default fix.
# ─────────────────────────────────────────────────────────────────────────

async def test_thinking_is_forwarded_with_summarized_display(
    tmp_path: Path, monkeypatch
) -> None:
    """`display` is free — thinking is billed identically whatever it is set to;
    the flag only decides whether the text comes back. Opus 4.8 defaults it to
    "omitted", which streams empty ThinkingBlocks into the artifact. For a
    security tool the reasoning behind a finding is audit evidence."""
    seen: list[dict] = []
    _capture(monkeypatch, seen)
    await _run(tmp_path, thinking="adaptive")
    assert seen[0]["thinking"] == {"type": "adaptive", "display": "summarized"}


async def test_thinking_is_omitted_when_unset(tmp_path: Path, monkeypatch) -> None:
    seen: list[dict] = []
    _capture(monkeypatch, seen)
    await _run(tmp_path)
    assert "thinking" not in seen[0]


def test_fixed_budget_thinking_is_rejected(tmp_path: Path) -> None:
    """`{"type": "enabled", "budget_tokens": N}` is removed on Opus 4.7+ and
    Sonnet 5 and returns a 400 — it must not be reachable from config."""
    cfg = tmp_path / "stages.yaml"
    cfg.write_text(textwrap.dedent("""
        stages:
          dedupe:
            model: claude-sonnet-5
            concurrency: 1
            tools: [Read]
            thinking: enabled
    """))
    with pytest.raises(ValueError, match="thinking must be one of"):
        load_config(cfg)


def test_opus_stages_have_thinking_explicitly_enabled() -> None:
    """The inverted default, pinned.

    Opus 4.8 runs WITHOUT extended thinking when `thinking` is unset; Sonnet 5
    runs adaptive. So omitting the key gave recon/validate/trace — the three
    stages put on Opus *because they matter most* — the least reasoning in the
    pipeline, while the cheap Sonnet synthesis stages got it for free. If this
    test fails, that inversion is back."""
    cfg = load_config()
    for name in ("recon", "validate", "trace"):
        sc = cfg.stages.get(name)
        if sc is None:
            continue
        assert sc.model.startswith("claude-opus"), (
            f"{name} is no longer on Opus — re-check whether this test still applies"
        )
        assert sc.thinking == "adaptive", (
            f"stage {name!r} is on {sc.model} with thinking={sc.thinking!r}; "
            "Opus does not think unless adaptive is explicit"
        )


def test_task_generating_stages_are_detected_from_source() -> None:
    """Don't trust the hand-maintained PROTECTED list — derive it.

    Any stage whose module calls db.add_task generates hunt tasks and therefore
    controls coverage. If a new one appears, this fails until it is protected."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / "vash" / "stages"
    for f in root.glob("*.py"):
        if "add_task(" not in f.read_text():
            continue
        assert f.stem in PROTECTED, (
            f"stage {f.stem!r} calls add_task (generates hunt tasks) but is not "
            "in PROTECTED — turning it down would silently cut coverage"
        )


def test_safe_stage_is_actually_turned_down() -> None:
    """Otherwise the lever is wired but doing nothing."""
    cfg = load_config()
    for name in TURNDOWN_OK:
        sc = cfg.stages.get(name)
        if sc is None:
            continue
        assert sc.effort in ("low", "medium"), (
            f"stage {name!r} synthesises derived data but has effort={sc.effort!r}"
        )
