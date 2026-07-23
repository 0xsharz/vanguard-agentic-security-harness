"""Shared helpers for stage modules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from audit.config import HarnessConfig, StageConfig


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROMPTS = REPO_ROOT / "prompts"
SCHEMAS = REPO_ROOT / "schemas"
RESULTS = REPO_ROOT / "results"
WORK = REPO_ROOT / "work"


@dataclass
class StageContext:
    run_id: str
    repo_path: Path
    config: HarnessConfig
    # Optional operator context — when set, downstream prompts use them.
    live_target: dict | None = None    # {"url": "...", "credentials": {...}}
    scope_notes: str | None = None     # verbatim text appended to user_input
    # Path to the cached code graph (audit.graph). Set by the taint step (V8)
    # once built so later graph consumers (V6/F2) can reuse the same cache.
    graph_cache_path: Path | None = None

    def stage(self, name: str) -> StageConfig:
        return self.config.get(name)

    def extras(self) -> dict:
        """Optional fields merged into every agent's user_input."""
        out: dict = {}
        if self.live_target:
            out["live_target"] = self.live_target
        if self.scope_notes:
            out["scope_notes"] = self.scope_notes
        return out

    def prompt(self, name: str) -> Path:
        path = PROMPTS / f"{name}.md"
        if not path.exists():
            raise FileNotFoundError(f"Missing prompt: {path}")
        return path

    def schema(self, name: str) -> Path:
        path = SCHEMAS / f"{name}.schema.json"
        if not path.exists():
            raise FileNotFoundError(f"Missing schema: {path}")
        return path

    def results_dir(self, stage: str) -> Path:
        d = RESULTS / self.run_id / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    def work_dir(self, stage: str, ref: str | None = None) -> Path:
        d = WORK / self.run_id / stage / (ref or "default")
        d.mkdir(parents=True, exist_ok=True)
        return d


def truncated_recon_summary(full: dict, subsystem_filter: str | None = None) -> dict:
    """Pass only the architecture facts downstream agents need."""
    out: dict = {
        "architecture": full.get("architecture", {}),
        "subsystems": full.get("subsystems", []),
    }
    if subsystem_filter is not None:
        match = next(
            (s for s in out["subsystems"] if s.get("name") == subsystem_filter
             or subsystem_filter.startswith(s.get("path", "##nope##"))),
            None,
        )
        out["subsystem_for_task"] = match
    return out
