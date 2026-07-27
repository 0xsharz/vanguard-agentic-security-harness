"""What the agent actually changed — ground truth, not its own account.

The agent is told which files a finding covers, and it reports what it edited.
Neither is trustworthy on its own: a model can edit a file it was not asked to
touch and simply not mention it. So the workspace is asked directly, via
`git status`, and anything outside the finding's own files is reverted.

This matters more than it sounds. The patch handed to an operator is built from
the workspace; an unreported edit that survived here would ride along inside it.

Adapted from Visa VVAH's remediation policy post-gate. Executes no target code.
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

log = logging.getLogger(__name__)


@dataclass
class PostGateResult:
    changed: list[str] = field(default_factory=list)      # everything the agent touched
    allowed: list[str] = field(default_factory=list)      # within the finding's scope
    reverted: list[str] = field(default_factory=list)     # outside it, undone
    expected: list[str] = field(default_factory=list)     # outside it, but foreseen
    errors: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.reverted and not self.errors


def _git(workspace: Path, *args: str, timeout: int = 60):
    return subprocess.run(["git", "-C", str(workspace), *args],
                          capture_output=True, text=True, timeout=timeout)


def changed_paths(workspace: Path) -> list[str]:
    """Every path the agent modified, added or deleted in the workspace.

    Parsed STRUCTURALLY from `git status --porcelain -z --untracked-files=all`.
    Each record is `XY <path>` — two status characters, a space, then the exact
    unquoted path. A rename or copy record is followed by a SECOND, bare NUL
    token holding the original path with no `XY ` prefix; that token must be
    consumed verbatim. Applying the 3-character strip to it would mangle any
    original path whose third character is a space, and the mangled name would
    then slip past the scope check below.

    `--untracked-files=all` lists agent-created files individually without
    touching the index. Returns [] on any failure — the caller treats an empty
    result as "nothing to revert", which is the safe direction here because the
    diff is scoped to the finding's own files anyway.
    """
    workspace = Path(workspace)
    try:
        chk = _git(workspace, "rev-parse", "--is-inside-work-tree", timeout=15)
        if chk.returncode != 0 or chk.stdout.strip() != "true":
            return []
        out = _git(workspace, "status", "--porcelain", "-z", "--untracked-files=all")
        if out.returncode != 0:
            return []
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("[remediate] postgate: status failed: %s", e)
        return []

    files: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        if path and path not in seen:
            seen.add(path)
            files.append(path)

    records = out.stdout.split("\0")
    i, n = 0, len(records)
    while i < n:
        rec = records[i]
        i += 1
        if not rec:
            continue
        add(rec[3:] if len(rec) > 3 else "")
        if ("R" in rec[:2] or "C" in rec[:2]) and i < n:
            add(records[i])            # bare original path — verbatim
            i += 1
    return files


def _revert(workspace: Path, rel: str) -> bool:
    """Undo one path: restore a tracked file, delete an agent-created one."""
    try:
        r = _git(workspace, "checkout", "--", rel, timeout=30)
        if r.returncode == 0:
            return True
        p = workspace / rel
        if p.is_file() or p.is_symlink():
            p.unlink()
            return True
        return False
    except (OSError, subprocess.SubprocessError):
        return False


def _norm(p: str) -> str:
    """A path in one canonical form, for comparing scope.

    Strips a `:line` suffix and collapses a leading `./`. Note what this must
    NOT do: `str.lstrip("./")` strips a CHARACTER SET, not a prefix, so it turns
    `.env` into `env` and `.github/ci.yml` into `github/ci.yml`. A finding whose
    file is named `env` would then match an edit to `.env` — quietly admitting a
    secrets file into the patch. PurePosixPath collapses `.` segments without
    touching a leading dot in a name.
    """
    return PurePosixPath(p.split(":", 1)[0].strip()).as_posix()


def enforce(workspace: Path, allowed_files: list[str], *,
            expected_extra: list[str] | None = None) -> PostGateResult:
    """Revert every workspace edit outside `allowed_files`.

    `allowed_files` are the finding's own files. Scope is matched on the
    normalised relative path, so `app/notes.py` and `./app/notes.py` are the
    same file.

    `expected_extra` names paths that are still reverted but are *foreseen* —
    in practice the security test the agent was asked to write, which it often
    saves to disk as well as returning. Reverting it is right: the test belongs
    in its own artifact, not inside the patch. Calling it misbehaviour is not,
    and a warning that fires on nearly every finding is a warning an operator
    stops reading — which is exactly when it needs to be believed.
    """
    result = PostGateResult()
    allow = {_norm(f) for f in (allowed_files or []) if f}
    foreseen = {_norm(f) for f in (expected_extra or []) if f}
    for rel in changed_paths(workspace):
        result.changed.append(rel)
        if _norm(rel) in allow:
            result.allowed.append(rel)
            continue
        if _norm(rel) in foreseen:
            if _revert(workspace, rel):
                result.expected.append(rel)
                log.info("[remediate] postgate: %r is the generated security "
                         "test — kept out of the patch, delivered separately",
                         rel)
                continue
            # Could not undo it: it would ride along in the patch, so it is no
            # longer merely foreseen.
            result.errors.append(rel)
            log.error("[remediate] postgate: could NOT revert the generated "
                      "test %r — it may appear inside the patch", rel)
            continue
        if _revert(workspace, rel):
            result.reverted.append(rel)
            log.warning("[remediate] postgate: reverted out-of-scope edit %r "
                        "(the agent changed a file this finding does not cover)",
                        rel)
        else:
            result.errors.append(rel)
            log.error("[remediate] postgate: could NOT revert %r — the patch for "
                      "this finding may contain an unrelated change", rel)
    return result
