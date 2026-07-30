"""Load per-stage configuration from config/stages.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


_EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
# "enabled" (the fixed budget_tokens form) is deliberately NOT accepted: it is
# removed on Opus 4.7+ and Sonnet 5 and returns a 400. Depth is controlled by
# `effort`, not a token budget.
_THINKING_MODES = ("adaptive", "disabled")


@dataclass
class StageConfig:
    name: str
    model: str
    concurrency: int
    tools: list[str]
    max_turns: int
    permission_mode: str
    repair_attempts: int
    # Thinking depth + overall token spend for this stage. `None` means "don't
    # pass it", which leaves the SDK default (`high`) in force — that was the
    # only behaviour available before, so an omitted key is byte-compatible with
    # the previous config. Output tokens are the single largest cost line once
    # the tool-loading fix lands (53.6% of a measured run), and effort is the
    # direct lever on them: lower effort means fewer, more-consolidated tool
    # calls and less preamble, so it cuts turns as well as output length.
    # Set it only on stages that synthesise already-derived data; the stages
    # that actually FIND vulnerabilities (recon/hunt/validate/trace) are left
    # at the default deliberately — see config/stages.yaml.
    effort: str | None = None
    # Extended-thinking mode. `None` means "don't pass it" — but that does NOT
    # mean "no thinking", and the difference is why this option exists:
    #
    #   Sonnet 5   omitted -> runs ADAPTIVE (thinking on)
    #   Opus 4.8   omitted -> runs WITHOUT thinking; adaptive must be explicit
    #
    # So leaving it unset produced the exact inverse of this pipeline's intent:
    # recon / validate / trace are on Opus *because they matter most* ("trace is
    # the stage that matters most"), and they were the three running with no
    # thinking at all, while the cheaper Sonnet synthesis stages got it for free.
    # Nobody chose that; it is a default nobody read. Setting `adaptive` on the
    # Opus stages costs more per call and is expected to buy recall.
    thinking: str | None = None


@dataclass
class HarnessConfig:
    stages: dict[str, StageConfig] = field(default_factory=dict)
    gapfill_iterations: int = 1
    feedback_iterations: int = 1

    def get(self, stage: str) -> StageConfig:
        try:
            return self.stages[stage]
        except KeyError:
            raise KeyError(
                f"Unknown stage {stage!r}. Known: {sorted(self.stages)}"
            ) from None

    def cap_concurrency(self, cap: int) -> None:
        """Mutate every stage's concurrency to min(current, cap). Useful
        for cost-contained test runs."""
        if cap < 1:
            raise ValueError("concurrency cap must be >= 1")
        for sc in self.stages.values():
            sc.concurrency = min(sc.concurrency, cap)


def _effort(stage: str, value: object) -> str | None:
    """Validate an effort level at LOAD time, not at API-call time.

    A typo ('lo', 'higher') would otherwise surface as a 400 from the SDK
    partway through a paid run, after recon has already been billed. Fail on
    the config instead."""
    if value is None:
        return None
    v = str(value).strip().lower()
    if v not in _EFFORT_LEVELS:
        raise ValueError(
            f"stage {stage!r}: effort must be one of {_EFFORT_LEVELS}, got {value!r}"
        )
    return v


def _thinking(stage: str, value: object) -> str | None:
    """Validate a thinking mode at LOAD time (see `_effort`)."""
    if value is None:
        return None
    v = str(value).strip().lower()
    if v not in _THINKING_MODES:
        raise ValueError(
            f"stage {stage!r}: thinking must be one of {_THINKING_MODES}, "
            f"got {value!r} (the fixed-budget 'enabled' form is removed on "
            f"Opus 4.7+/Sonnet 5 and returns a 400 — use `effort` for depth)"
        )
    return v


def load_config(path: Path | None = None) -> HarnessConfig:
    if path is None:
        path = Path(__file__).resolve().parent.parent / "config" / "stages.yaml"
    raw = yaml.safe_load(path.read_text())
    defaults = raw.get("defaults", {}) or {}
    stages: dict[str, StageConfig] = {}
    for name, spec in (raw.get("stages") or {}).items():
        stages[name] = StageConfig(
            name=name,
            model=spec["model"],
            concurrency=int(spec["concurrency"]),
            tools=list(spec["tools"]),
            max_turns=int(spec.get("max_turns", defaults.get("max_turns", 25))),
            permission_mode=spec.get(
                "permission_mode", defaults.get("permission_mode", "acceptEdits")
            ),
            repair_attempts=int(
                spec.get("repair_attempts", defaults.get("repair_attempts", 1))
            ),
            effort=_effort(name, spec.get("effort", defaults.get("effort"))),
            thinking=_thinking(name, spec.get("thinking", defaults.get("thinking"))),
        )
    loops = raw.get("loops", {}) or {}
    return HarnessConfig(
        stages=stages,
        gapfill_iterations=int(loops.get("gapfill_iterations", 1)),
        feedback_iterations=int(loops.get("feedback_iterations", 1)),
    )
