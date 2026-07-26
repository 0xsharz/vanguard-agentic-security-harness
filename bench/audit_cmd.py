"""Build (never execute) the `audit run` command line for a benchmark target.

Per the task brief: the SCAN step must build audit's REAL command —
`audit run --repo <clone_dir> --run-id <id> [--max-cost-usd N]` (see
docs/wiring-notes.md §2) — and construct/return it, not execute it. Actually
invoking this (subprocess.run(...)) is deliberately deferred to Phase 1: it
spends LLM budget, which this task's offline scaffold must not do.
"""

from __future__ import annotations


def build_scan_command(
    clone_dir: str,
    run_id: str,
    *,
    max_cost_usd: float | None = None,
    max_concurrency: int | None = None,
    max_recon_tasks: int | None = None,
    resume: bool = False,
    config_path: str | None = None,
    allow_api_key: bool = False,
    python_module: bool = False,
) -> list[str]:
    """Construct the argv for `audit run` (or `python -m audit run`) against
    one cloned benchmark target. Pure function — no subprocess, no I/O.
    """
    cmd = (["vash"] if not python_module else ["python", "-m", "vash"])
    cmd += ["run", "--repo", clone_dir, "--run-id", run_id]
    if resume:
        cmd.append("--resume")
    if max_cost_usd is not None:
        cmd += ["--max-cost-usd", str(max_cost_usd)]
    if max_concurrency is not None:
        cmd += ["--max-concurrency", str(max_concurrency)]
    if max_recon_tasks is not None:
        cmd += ["--max-recon-tasks", str(max_recon_tasks)]
    if config_path is not None:
        cmd += ["--config", config_path]
    if allow_api_key:
        cmd.append("--allow-api-key")
    return cmd
