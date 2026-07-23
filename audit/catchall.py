"""Terminal whole-repo coverage sweep (feature F6).

V8 hunts forward taint paths, F3 hunts orphan sinks, V12 hunts gated
specialist surfaces — but a file with NO input/sink/specialist signal is
still unhunted. This module is the completeness safety net: after every
targeted task has been queued (recon + taint + sink-backward + specialist),
build one LOW-priority (5) catch-all Hunt task per eligible source file that
none of those tasks reached, so coverage is provable ("every eligible file
got >=1 hunt"). Precision is protected downstream by Validate; these tasks
run last by priority.

The eligibility filter (``_CATCHALL_SKIP_EXTS`` / ``_CATCHALL_SKIP_NAMES`` /
``_CATCHALL_SKIP_DIR_PARTS`` / ``_catchall_eligible``) is PORTED VERBATIM from
VVAH's ``vvaharness/pipeline/stages/s3_decompose.py`` (L596-635) — it drops
docs/locks/snapshots/fixtures/minified/images while KEEPING credential-prone
configs (.env, .npmrc, *.key/pem/p12, ...). Only the `Path` import differs
(VVAH imports it alongside `PurePosixPath`, unused here).

``build_catchall_tasks`` is AUTHORED: VVAH's donor shards uncovered files into
manifest ``Chunk`` objects for its own strategist-LLM pipeline; audit needs
``hunt_task`` dicts instead, so the sharding/cap logic below is new, built to
the schema this project uses (``schemas/hunt_task.schema.json``).

Grouping itself is delegated to ``audit.partition.partition_files`` (feature
F2): when a call graph is available, uncovered files are grouped by call-graph
connectivity (a coherent caller+callee slice) instead of F6's original
top-2-directory grouping; with no graph, it degrades to that original
grouping exactly. Either way every eligible file still lands in exactly one
partition — F2 changes GROUPING, never COVERAGE.
"""

from __future__ import annotations

from pathlib import Path

from audit.partition import partition_files

# ---------------------------------------------------------------------------
# Ported verbatim from VVAH s3_decompose.py:
#   _CATCHALL_SKIP_EXTS (L596-604), _CATCHALL_SKIP_NAMES (L605-611),
#   _CATCHALL_SKIP_DIR_PARTS (L612-615), _catchall_eligible (L618-635).
# ---------------------------------------------------------------------------

# Files that can't realistically carry an exploitable vuln. Dropped from
# catch-all coverage so 90+ chunks of docs/locks/snapshots don't get scanned.
# Credential-prone configs (.env, .npmrc, .yarnrc, *.key/pem/p12…) are KEPT.
_CATCHALL_SKIP_EXTS = {
    ".md", ".mdx", ".txt", ".rst", ".adoc",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
    ".css", ".scss", ".sass", ".less",
    ".lock", ".log", ".map", ".min.js", ".min.css",
    ".snap", ".d.ts",
    ".csv", ".tsv", ".xls", ".xlsx",
    ".po", ".pot", ".mo",
}
_CATCHALL_SKIP_NAMES = {
    "license", "changelog", "changes", "authors", "contributors", "notice",
    "readme", "codeowners", ".gitignore", ".gitattributes", ".editorconfig",
    ".prettierrc", ".prettierignore", ".eslintignore", ".dockerignore",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "go.sum", "cargo.lock", "composer.lock",
}
_CATCHALL_SKIP_DIR_PARTS = {
    "__snapshots__", "__fixtures__", "fixtures", "__mocks__", "mocks",
    "docs", "doc", "examples", "example", "samples",
}


def _catchall_eligible(rel: str) -> bool:
    p = Path(rel)
    name = p.name.lower()
    if name in _CATCHALL_SKIP_NAMES:
        return False
    # Match either the single final suffix (".js") or any trailing
    # multi-suffix tail (".min.js") against the skip set. A bare
    # ``suffixes in SET`` check missed multi-dotted names like
    # ``foo.bundle.min.js`` whose full joined suffixes (".bundle.min.js")
    # is not itself a skip key — so test every trailing dotted tail.
    name = p.name.lower()
    if p.suffix.lower() in _CATCHALL_SKIP_EXTS:
        return False
    if any(name.endswith(ext) for ext in _CATCHALL_SKIP_EXTS):
        return False
    if any(part.lower() in _CATCHALL_SKIP_DIR_PARTS for part in p.parts[:-1]):
        return False
    return True


# ---------------------------------------------------------------------------
# Task synthesis — AUTHORED. Groups uncovered+eligible files into cohesive
# partitions (``partition_files`` — F2), shards each group at
# `max_files_per_task`, and caps the emitted task count at `max_tasks` —
# tracking exactly how many eligible files were dropped by that cap so
# coverage loss is NEVER silent (the orchestrator logs `dropped` as a
# warning).
# ---------------------------------------------------------------------------


def _dirkey(rel: str) -> str:
    """Top-2-directory prefix used to group nearby files into one task
    (e.g. "pkg/sub" for "pkg/sub/deep/file.py"; "." for a repo-root file)."""
    parts = Path(rel).parts[:-1]
    return "/".join(parts[:2]) if parts else "."


def _dominant_dirkey(files: list[str]) -> str:
    """Label a partition by its most-common top-2-directory (deterministic
    tie-break: lower dirkey string wins). Cosmetic only — used for the
    human-readable `scope_hint`; the partition's membership is already
    decided by `partition_files` before this is called."""
    counts: dict[str, int] = {}
    for f in files:
        k = _dirkey(f)
        counts[k] = counts.get(k, 0) + 1
    return min(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]


def build_catchall_tasks(
    all_source_files: list[str],
    covered_files: list[str] | set[str],
    *,
    graph=None,
    max_files_per_task: int = 25,
    max_tasks: int = 40,
) -> tuple[list[dict], int]:
    """Build LOW-priority (5) catch-all hunt tasks for every eligible source
    file not already covered by a targeted task (recon/taint/sink-backward/
    specialist).

    `graph` (a `GraphQuery`, or None) is forwarded to `partition_files` (F2):
    when available, uncovered files are grouped by call-graph connectivity
    instead of pure directory adjacency, so a task's files are more likely to
    be a coherent caller+callee slice. With no graph, grouping is identical
    to F6's original directory-only behavior. Either way, coverage is
    unaffected — F2 only changes GROUPING.

    Returns ``(tasks, dropped_file_count)``: `dropped_file_count` is the
    number of eligible-but-uncovered files that did NOT make it into a task
    because the `max_tasks` cap was exceeded. Never drops silently — callers
    must surface this count (the orchestrator logs it as a warning).
    """
    covered = set(covered_files)
    uncovered = [f for f in all_source_files if f not in covered]
    eligible = [f for f in uncovered if _catchall_eligible(f)]
    if not eligible:
        return [], 0

    groups = partition_files(eligible, graph, max_partition_size=max_files_per_task)

    tasks: list[dict] = []
    dropped = 0
    for n, files in enumerate(groups, 1):
        if n > max_tasks:
            dropped += len(files)
            continue
        dirkey = _dominant_dirkey(files)
        tasks.append({
            "task_id": f"t_catchall_{n:02d}",
            "source": "catchall",
            "attack_class": "unknown",
            "scope_hint": (
                f"Coverage sweep of '{dirkey}': files not covered by any "
                f"targeted task. Hunt for ANY vulnerability class "
                f"(injection, deserialization, path, ssrf, auth, crypto, "
                f"logic)."
            ),
            "target_files": files,
            "rationale": (
                "Completeness safety net — these source files reached no "
                "taint/sink/specialist task; hunted once so coverage is "
                "provable."
            ),
            "priority": 5,
        })
    return tasks, dropped
