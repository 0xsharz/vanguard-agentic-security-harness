"""Shared constants + a tiny atomic-JSON-write helper for the bench harness.

Adapted from VulnHunter's harness/local_harness/config.py (Capital One,
Apache License 2.0) — `atomic_write_json` is reused near-verbatim (see
notice below); paths are repointed at `audit` instead of `/vulnhunt`.
Full license text: https://www.apache.org/licenses/LICENSE-2.0 (also see
/Users/snatarajan14/VulnHunter/LICENSE).

  Copyright Capital One (VulnHunter contributors).
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
AUDIT_REPO_ROOT = BENCH_DIR.parent  # /Users/snatarajan14/audit
GROUND_TRUTH_DIR = BENCH_DIR / "ground_truth"

# bench's own scratch space: clones + phase-driver state. Gitignored (like
# VulnHunter's benchmark_repos/ + benchmark_results/) — never committed.
WORK_DIR = BENCH_DIR / "bench_workdir"
CLONE_BASE_DIR = WORK_DIR / "repos"
STATE_FILE = WORK_DIR / "state.json"
TALLY_JSON = WORK_DIR / "tally.json"
TALLY_MARKDOWN = WORK_DIR / "BENCHMARK_REPORT.md"

# Where `audit run` actually writes, regardless of --repo. Per
# docs/wiring-notes.md §2: `REPO_ROOT` in audit/cli.py is the `audit` tool's
# OWN checkout root (two levels up from cli.py) — i.e. AUDIT_REPO_ROOT above
# — NOT the scanned target's directory.
AUDIT_STATE_DB = AUDIT_REPO_ROOT / "state.db"
AUDIT_RESULTS_ROOT = AUDIT_REPO_ROOT / "results"

DEFAULT_LINE_TOLERANCE = 15
CLONE_TIMEOUT = 300  # 5 minutes


def atomic_write_json(path: str | Path, obj, *, indent: int = 2, sort_keys: bool = False) -> None:
    """Write JSON to `path` atomically (temp file + os.replace).

    A crash or SIGINT mid-write would otherwise leave a truncated state file
    that a later `--tally-only` or resumed run can't parse.
    """
    path = str(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=indent, sort_keys=sort_keys)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
