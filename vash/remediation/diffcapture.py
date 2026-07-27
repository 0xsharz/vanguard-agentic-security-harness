"""Compute a patch from what the agent actually edited.

`git diff` produces the unified diff, so the result is valid by construction —
correct hunk headers, correct context, applies cleanly. That is the entire point
of the edit-then-diff design: the failure mode where a hand-written diff is
rejected as "corrupt patch" cannot occur here.

Nothing here executes target code; it runs `git` on a disposable copy.
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# A file reference handed to a git pathspec is untrusted: it comes from a
# finding or from model output. An absolute path, a `..` escape, or a Windows
# drive/UNC prefix would point outside the workspace.
#
# The UNC case is worth naming precisely, because it is not merely a stray
# write: `\\attacker\share\x` handed to `git add`/`git diff` on a Windows runner
# opens an outbound SMB connection and leaks the runner's NetNTLMv2 hash. That
# is credential theft. `Path.is_absolute()` does not recognise that form on a
# POSIX runner, so the shape is rejected explicitly and host-independently.
# (Threat and control adapted from Visa VVAH's diff path-safety guard.)
_UNC_OR_DRIVE = re.compile(r"^(?:[\\/]{2}|[A-Za-z]:)")
_LOC_SUFFIX = re.compile(r":\d+(?:-\d+)?$")


def safe_relative_path(workspace: Path, ref: str) -> str | None:
    """`ref` as a workspace-relative path, or None when it escapes.

    Strips a `:line` / `:start-end` location suffix, since findings carry file
    references in that form.
    """
    rel = _LOC_SUFFIX.sub("", (ref or "").strip())
    if not rel or Path(rel).is_absolute() or _UNC_OR_DRIVE.match(rel):
        return None
    try:
        root = workspace.resolve()
        target = (workspace / rel).resolve()
        target.relative_to(root)          # raises when the path escapes
    except (ValueError, OSError):
        return None
    return Path(rel).as_posix()


def _git(workspace: Path, *args: str, timeout: int = 60):
    return subprocess.run(["git", "-C", str(workspace), *args],
                          capture_output=True, text=True, timeout=timeout)


def capture_diff(workspace: Path, files: list[str]) -> str | None:
    """A unified diff of the agent's edits to `files`, or None if there are none.

    Scoped to the finding's own files so each patch contains only what that
    finding is about — an unrelated edit elsewhere in the workspace does not
    leak into it (and the post-gate reverts it separately).

    `git add -N` records intent-to-add so a newly-created file appears in the
    diff; it stages no content and commits nothing. Never raises.
    """
    workspace = Path(workspace)
    paths = [p for p in (safe_relative_path(workspace, f) for f in (files or [])) if p]
    if not paths:
        log.info("[remediate] diff: no usable paths for this finding")
        return None
    try:
        chk = _git(workspace, "rev-parse", "--is-inside-work-tree", timeout=15)
        if chk.returncode != 0 or chk.stdout.strip() != "true":
            return None
        _git(workspace, "add", "-N", "--", *paths, timeout=30)
        out = _git(workspace, "diff", "--", *paths)
        if out.returncode != 0:
            log.warning("[remediate] diff: git diff failed: %s",
                        (out.stderr or "").strip()[:200])
            return None
        diff = out.stdout
        return diff if diff.strip() else None
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("[remediate] diff: capture failed: %s", e)
        return None
