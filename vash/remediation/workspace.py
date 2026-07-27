"""A disposable copy of the target, for the remediation agent to edit.

Remediation used to ask the model to *write unified-diff text*. That is a
mechanical task models are bad at: on a real 7-finding run, `git apply --check`
rejected 4 of 7 patches — wrong hunk line counts, context that did not match the
file. Recomputing the counts recovered most of them, but it repaired a symptom.

The fix is to stop hand-writing diffs. The agent EDITS files and `git diff`
computes the patch, which is then valid by construction.

Editing needs somewhere safe to edit. VASH's guarantee is that it never modifies
the code under review, so the agent is given a **disposable copy** and is never
told where the real repository is:

    target repo (read-only, untouched)
          │  copy
          ▼
       workspace/       ← the agent may write HERE and nowhere else
          │  git diff
          ▼
        patch           → workspace destroyed

Nothing in this module executes target code. It copies files and runs `git` on
the copy.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp
from typing import Iterator

from vash.graph.config import _EXCLUDED_DIR_PARTS

log = logging.getLogger(__name__)

# Copying the tree once per finding is the cost of this design. A cap keeps a
# large monorepo from being duplicated repeatedly; past it, remediation degrades
# to guidance rather than filling the disk.
DEFAULT_MAX_BYTES = 512 * 1024 * 1024      # 512 MB of source

# `.git` is excluded deliberately: the copy gets its own fresh history so
# `git diff` has a clean baseline, and the target's history (branches, remotes,
# credentials in .git/config) never travels into a temp directory.
_SKIP_DIRS = frozenset(_EXCLUDED_DIR_PARTS) | {".tox", ".mypy_cache", ".pytest_cache"}


def _tree_size(repo: Path, cap: int) -> int | None:
    """Bytes under `repo`, ignoring skipped dirs. None once `cap` is exceeded —
    it stops walking rather than costing more than the copy it is guarding."""
    total = 0
    for p in repo.rglob("*"):
        try:
            if any(part in _SKIP_DIRS for part in p.relative_to(repo).parts):
                continue
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
                if total > cap:
                    return None
        except OSError:
            continue
    return total


def _neutralize_escaping_symlinks(workspace: Path) -> list[str]:
    """Delete any symlink in the copy that points outside the copy.

    The tree is copied with ``symlinks=True`` so a link is never *followed* out
    of the repo during the copy. But copying a link verbatim carries the escape
    into the workspace: the target repo is untrusted, and a repo containing
    ``shortcut.py -> /abs/path/into/the/target`` gives the agent a file that
    looks local and writes straight through to the real repository. Writing to
    it defeats every other control here — the agent never has to know where the
    target is, because the target came to it.

    Links that stay inside the workspace are legitimate and are kept. Walked
    with ``followlinks=False`` so a symlinked directory cannot loop us.
    """
    root = workspace.resolve()
    removed: list[str] = []

    def escapes(p: Path) -> bool:
        try:
            (p.parent / os.readlink(p)).resolve().relative_to(root)
            return False
        except ValueError:
            return True
        except OSError:
            return True          # unreadable link: remove rather than trust it

    for dirpath, dirnames, filenames in os.walk(workspace, followlinks=False):
        d = Path(dirpath)
        for name in list(dirnames) + filenames:
            p = d / name
            if not p.is_symlink() or not escapes(p):
                continue
            try:
                p.unlink()
                rel = str(p.relative_to(workspace))
                removed.append(rel)
                log.warning("[remediate] workspace: removed symlink %r — it "
                            "points outside the repository, so an edit through "
                            "it would have escaped the workspace", rel)
            except OSError as e:  # pragma: no cover - platform dependent
                log.error("[remediate] workspace: could NOT remove escaping "
                          "symlink %s: %s", p, e)
    return removed


def _git(workspace: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(workspace), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _init_baseline(workspace: Path) -> bool:
    """Give the copy its own git history so `git diff` has something to diff
    against — including when the target is not a git repository at all.

    Committed with identity supplied on the command line, so this works on a
    machine with no git identity configured and never touches global config.
    """
    try:
        if _git(workspace, "init", "-q").returncode != 0:
            return False
        _git(workspace, "config", "user.email", "remediate@vash.local")
        _git(workspace, "config", "user.name", "VASH remediate")
        _git(workspace, "add", "-A")
        # An empty tree is legal: --allow-empty keeps a bare repo usable.
        r = _git(workspace, "commit", "-q", "--allow-empty", "-m", "baseline",
                 timeout=120)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("[remediate] workspace: git baseline failed: %s", e)
        return False


@contextmanager
def workspace_for(repo_path: Path, *,
                  max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[Path | None]:
    """Yield a disposable copy of `repo_path`, or None when one cannot be made.

    The copy is removed on the way out **whatever happens** — success, an
    exception, or a caller that returns early. A None yield means the caller
    must degrade (guidance-only), not proceed unprotected.
    """
    repo_path = Path(repo_path)
    if not repo_path.is_dir():
        log.warning("[remediate] workspace: %s is not a directory", repo_path)
        yield None
        return

    if _tree_size(repo_path, max_bytes) is None:
        log.warning(
            "[remediate] workspace: %s exceeds %d bytes — refusing to copy it "
            "per finding; remediation degrades to guidance-only",
            repo_path, max_bytes,
        )
        yield None
        return

    tmp = Path(mkdtemp(prefix="vash-remediate-"))
    workspace = tmp / repo_path.name
    try:
        shutil.copytree(
            repo_path, workspace,
            ignore=shutil.ignore_patterns(*_SKIP_DIRS),
            symlinks=True,           # copy the link, never follow it out of the tree
            ignore_dangling_symlinks=True,
        )
        # ...then drop the links that would let an EDIT do what the copy would
        # not: reach outside the workspace.
        _neutralize_escaping_symlinks(workspace)
        if not _init_baseline(workspace):
            log.warning("[remediate] workspace: no git baseline — diff capture "
                        "will not be available for this finding")
        log.info("[remediate] workspace ready at %s (copy of %s)",
                 workspace, repo_path)
        yield workspace
    except OSError as e:
        log.warning("[remediate] workspace: could not copy %s: %s", repo_path, e)
        yield None
    finally:
        # The copy may contain agent-written files; removing it is the whole
        # point of it being disposable, so failure here is worth a warning.
        try:
            shutil.rmtree(tmp)
        except OSError as e:  # pragma: no cover - platform dependent
            log.warning("[remediate] workspace: could not remove %s: %s", tmp, e)
