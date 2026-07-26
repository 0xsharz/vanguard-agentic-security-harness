"""StageContext.extras() — verify optional live_target / scope_notes
flow into agent user_input."""

from __future__ import annotations

from pathlib import Path

from vash.config import HarnessConfig, StageConfig
from vash.stages._common import StageContext


def _ctx(**kwargs) -> StageContext:
    cfg = HarnessConfig(stages={"hunt": StageConfig(
        name="hunt", model="x", concurrency=1, tools=["Read"],
        max_turns=10, permission_mode="default", repair_attempts=0)})
    return StageContext(run_id="r", repo_path=Path("/tmp"), config=cfg, **kwargs)


def test_extras_empty_when_nothing_set() -> None:
    assert _ctx().extras() == {}


def test_extras_includes_live_target() -> None:
    lt = {"url": "http://x:8080", "credentials": {"email": "a", "password": "b"}}
    e = _ctx(live_target=lt).extras()
    assert e == {"live_target": lt}


def test_extras_includes_scope_notes() -> None:
    e = _ctx(scope_notes="Mailpit is out of scope.").extras()
    assert e == {"scope_notes": "Mailpit is out of scope."}


def test_extras_includes_both() -> None:
    lt = {"url": "http://x:8080", "credentials": {}}
    e = _ctx(live_target=lt, scope_notes="notes").extras()
    assert "live_target" in e and "scope_notes" in e


def test_extras_skips_falsy_values() -> None:
    # empty dict / empty string should also be skipped (no point passing noise)
    assert _ctx(live_target={}).extras() == {}
    assert _ctx(scope_notes="").extras() == {}
