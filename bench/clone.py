"""Clone benchmark target repos at pinned commits.

Adapted from VulnHunter's harness/local_harness/clone.py (Capital One,
Apache License 2.0) — logic is unchanged (this step isn't VulnHunter's
scanner, it's generic git plumbing); only the config import is repointed at
`bench.config`. Full license text: https://www.apache.org/licenses/LICENSE-2.0
(also see /Users/snatarajan14/VulnHunter/LICENSE).

  Copyright Capital One (VulnHunter contributors).
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

NOTE: not exercised by this task's tests (network + git are out of scope for
the offline-testable deliverable) — `parse_source_url` / `target_dir_name`
are pure and unit-tested; `clone_at_commit` is scaffold for the Phase 1
live-run wiring.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from bench.config import CLONE_BASE_DIR, CLONE_TIMEOUT


def parse_source_url(source_code_url: str) -> tuple[str, str, str]:
    """Parse a ground-truth `source_code` URL into (repo_url, repo_name, commit_hash).

    Format: https://github.com/{org}/{repo}/tree/{commit_hash}
    """
    parts = source_code_url.rstrip("/").split("/")
    # parts: ['https:', '', 'github.com', org, repo, 'tree', commit_hash]
    repo_url = "/".join(parts[:5])
    commit_hash = parts[-1]
    repo_name = parts[4]
    return repo_url, repo_name, commit_hash


def target_dir_name(repo_name: str, commit_hash: str) -> str:
    """Generate a unique directory name for a repo at a specific commit."""
    return f"{repo_name}_{commit_hash[:8]}"


def is_at_commit(target_dir: str, commit_hash: str) -> bool:
    """Check if an existing clone is at the expected commit."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
            cwd=target_dir,
        )
        return result.returncode == 0 and result.stdout.strip().startswith(commit_hash[:8])
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def clone_at_commit(repo_url: str, commit_hash: str, target_dir: str) -> tuple[str, str | None]:
    """Clone a repo at a specific commit hash.

    Strategy: reuse if already at the right commit; else fast `git fetch
    --depth=1 origin <hash>`; else fall back to a full clone + checkout.
    Returns (target_dir, error_msg|None).
    """
    if os.path.isdir(target_dir):
        if is_at_commit(target_dir, commit_hash):
            return (target_dir, None)
        shutil.rmtree(target_dir)

    os.makedirs(CLONE_BASE_DIR, exist_ok=True)

    try:
        os.makedirs(target_dir, exist_ok=True)
        init = subprocess.run(["git", "init"], capture_output=True, text=True,
                              timeout=10, cwd=target_dir)
        remote = subprocess.run(["git", "remote", "add", "origin", repo_url],
                                capture_output=True, text=True, timeout=10, cwd=target_dir)
        if init.returncode == 0 and remote.returncode == 0:
            fetch = subprocess.run(
                ["git", "fetch", "--depth=1", "origin", commit_hash],
                capture_output=True, text=True, timeout=CLONE_TIMEOUT, cwd=target_dir,
            )
            if fetch.returncode == 0:
                checkout = subprocess.run(
                    ["git", "checkout", "FETCH_HEAD"],
                    capture_output=True, text=True, timeout=30, cwd=target_dir,
                )
                if checkout.returncode == 0:
                    return (target_dir, None)
    except (subprocess.TimeoutExpired, OSError):
        pass

    if os.path.isdir(target_dir):
        shutil.rmtree(target_dir)

    try:
        result = subprocess.run(
            ["git", "clone", repo_url, target_dir],
            capture_output=True, text=True, timeout=CLONE_TIMEOUT,
        )
        if result.returncode != 0:
            return (target_dir, result.stderr.strip() or f"git clone exited {result.returncode}")

        checkout = subprocess.run(
            ["git", "checkout", commit_hash],
            capture_output=True, text=True, timeout=30, cwd=target_dir,
        )
        if checkout.returncode != 0:
            return (target_dir, checkout.stderr.strip() or f"git checkout exited {checkout.returncode}")

        return (target_dir, None)
    except subprocess.TimeoutExpired:
        return (target_dir, f"clone timed out after {CLONE_TIMEOUT}s")
    except OSError as e:
        return (target_dir, f"git unavailable: {e}")
