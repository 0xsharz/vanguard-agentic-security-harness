"""Remediation support: a disposable workspace the agent edits, the diff git
computes from those edits, and the post-gate that checks what actually changed.

Nothing here executes target code. See `workspace.py` for why the agent edits a
copy rather than writing a diff by hand.
"""

from vash.remediation.diffcapture import capture_diff, safe_relative_path
from vash.remediation.postgate import PostGateResult, changed_paths, enforce
from vash.remediation.workspace import workspace_for

__all__ = [
    "PostGateResult",
    "capture_diff",
    "changed_paths",
    "enforce",
    "safe_relative_path",
    "workspace_for",
]
