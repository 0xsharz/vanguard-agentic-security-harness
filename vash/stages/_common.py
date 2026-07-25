"""Shared helpers for stage modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from vash.config import HarnessConfig, StageConfig

if TYPE_CHECKING:
    from vash.progress import RunReporter


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
    # F1: resolved once per run by sandbox.resolve_execution() (dynamic_validation
    # flag AND an active sandbox/dev-escape) — the actual precondition threaded
    # down to run_agent()'s Bash gate. Default False = static-only.
    execution_enabled: bool = False
    # F2 (Task 2): optional rich run-progress reporter. Presentation-only and
    # fail-soft by construction (see vash.progress.RunReporter) — excluded from
    # repr/equality since it wraps a live Console, not run identity.
    reporter: "RunReporter | None" = field(default=None, repr=False, compare=False)
    # Path to the cached code graph (audit.graph). Set by the taint step (V8)
    # once built so later graph consumers (V6/F2) can reuse the same cache.
    graph_cache_path: Path | None = None
    # Memoized GraphQuery for this run (V6). Not part of equality/repr —
    # purely a run-scoped cache populated lazily by graph().
    _graph: "GraphQuery | None" = field(default=None, repr=False, compare=False)
    _graph_loaded: bool = field(default=False, repr=False, compare=False)

    def stage(self, name: str) -> StageConfig:
        return self.config.get(name)

    def graph(self):
        """Return a memoized GraphQuery for this run, or None (fail-open).

        Loads the graph V8 already cached at graph_cache_path (fast cache
        hit); falls back to the default cache path + build_or_load if unset.
        Never raises: any failure (missing/corrupt cache, graphify error,
        etc.) yields None so Hunt/Validate proceed exactly as before (no
        graph_context key added)."""
        if self._graph_loaded:
            return self._graph
        self._graph_loaded = True
        try:
            from vash.graph import GraphQuery, build_or_load
            cache = self.graph_cache_path or (self.work_dir("graph") / "graph.json")
            doc = build_or_load(self.repo_path, cache)
            self.graph_cache_path = cache
            self._graph = GraphQuery(doc, self.repo_path) if doc.nodes else None
        except Exception:
            self._graph = None
        return self._graph

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
        "design_controls": full.get("design_controls", []),   # V5
    }
    if subsystem_filter is not None:
        match = next(
            (s for s in out["subsystems"] if s.get("name") == subsystem_filter
             or subsystem_filter.startswith(s.get("path", "##nope##"))),
            None,
        )
        out["subsystem_for_task"] = match
    return out
