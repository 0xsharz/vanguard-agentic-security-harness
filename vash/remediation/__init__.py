"""Remediation support: a disposable workspace the agent edits, the diff git
computes from those edits, the post-gate that checks what actually changed, and
the opt-in verification pass that runs the generated security test.

Only `verify.py` executes anything, and only when `--verify` cleared the sandbox
gate. See `workspace.py` for why the agent edits a copy rather than writing a
diff by hand.
"""

from vash.remediation.diffcapture import capture_diff, safe_relative_path
from vash.remediation.postgate import PostGateResult, changed_paths, enforce
from vash.remediation.verify import (
    NOT_ATTEMPTED,
    NOT_VERIFIED,
    VERIFIED,
    verify_patch,
)
from vash.remediation.workspace import workspace_for

__all__ = [
    "NOT_ATTEMPTED",
    "NOT_VERIFIED",
    "PostGateResult",
    "VERIFIED",
    "capture_diff",
    "changed_paths",
    "enforce",
    "safe_relative_path",
    "verify_patch",
    "workspace_for",
]
