"""Execution sandbox gate.

VASH's decoupled `remediate` / `validate` commands are static: read-only
tools (no Bash), patches are unified diffs derived by reading source — they
never execute anything belonging to the target (see `config/stages.yaml`'s
"static-first" comments on the `remediate` / `revalidate` stages). The only
place execution is ever contemplated for them is the DEFERRED
`remediate --verify` (running the target's own test suite to check a
generated patch), and any future opt-in PoC runner in that same decoupled
path.

This module is the GATE any such execution path MUST call before running
anything from the target repo. It decides PERMISSION only:

  * :func:`require` either returns (execution may proceed) or raises
    :class:`SandboxError` (it may not).
  * Nothing here executes target code, spawns a subprocess, or touches the
    network — pure stdlib (``os``, ``logging``, ``pathlib``).

This locks the static-first guarantee for that path: nothing from the
target ever runs until an active isolation sandbox is detected, or a
developer explicitly and loudly opts out for local work.

(The core `vash run` scan pipeline's Hunt/Trace stages are a separate,
pre-existing concern — they intentionally compile/run local PoCs and make
live-target HTTP calls, documented in README's "Safety" section. This gate
does not touch or apply to them.)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

# Coarse "we are inside *some* container" marker — present on essentially
# every Docker (and Docker-derived) container filesystem. Not a security
# boundary by itself, just a signal. Module-level (rather than inlined)
# so tests can monkeypatch it to a guaranteed-absent path for a hermetic
# "definitely no sandbox" case, independent of the machine actually running
# the test suite.
_DOCKERENV = Path("/.dockerenv")

# Values that mean "VASH_SANDBOX is set but not truthy" — mirrors the
# env-truthy convention already used for AUDIT_ALLOW_API_KEY in vash/cli.py.
_FALSY_ENV = ("", "0", "false", "False")

_REMEDY = (
    "target-code execution requires an active sandbox: set VASH_SANDBOX=1 "
    "inside a gVisor- or container-isolated environment before running with "
    "execution enabled, or pass --dangerously-no-sandbox for local dev "
    "(unsafe — only ever against source you already trust)."
)


class SandboxError(RuntimeError):
    """Raised by :func:`require` when target-code execution was requested
    but no active sandbox was detected and no dev escape was granted."""


def is_sandboxed() -> bool:
    """True if VASH appears to be running inside an isolation sandbox.

    Signal (intentionally simple — a tripwire, not a full isolation audit):
      * env ``VASH_SANDBOX`` is truthy — set by the gVisor/container wrapper
        that launches an execution-enabled VASH run, or
      * ``/.dockerenv`` exists — a coarse "inside some container" marker.
    """
    if os.environ.get("VASH_SANDBOX", "") not in _FALSY_ENV:
        return True
    return _DOCKERENV.exists()


def require(*, allow_no_sandbox: bool = False) -> None:
    """Gate that target-code execution MUST pass BEFORE running anything
    from the target repo (e.g. its own test suite for `remediate --verify`).

    Decides PERMISSION only — this function never executes target code.

      * ``allow_no_sandbox=True`` (the ``--dangerously-no-sandbox`` dev
        escape) — log a LOUD warning and return; execution is permitted,
        unguarded.
      * Else if :func:`is_sandboxed`: return; execution is permitted.
      * Else: raise :class:`SandboxError` with a clear remedy.
    """
    if allow_no_sandbox:
        log.warning(
            "[sandbox] --dangerously-no-sandbox: proceeding WITHOUT an "
            "active isolation sandbox. Target-controlled code may execute "
            "unconfined on this host. Dev-only escape — never use this "
            "against a target you do not already trust."
        )
        return
    if is_sandboxed():
        return
    raise SandboxError(_REMEDY)
