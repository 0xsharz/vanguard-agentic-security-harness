"""Remediation policy gate — ported from Visa VVAH's remediation_policy.yaml +
the remediation_agent governance (``~/visa-harness/vvaharness/remediation_agent``).

This is the HARD GATE that runs BEFORE any patch agent in ``vash remediate``.
It decides, per finding CWE, whether VASH may generate a patch (``PATCH``) or
must fall back to prose guidance only (``GUIDANCE_ONLY``). It is enforcement,
not advice: a denied finding never reaches the LLM patch agent.

Design (faithful to VVAH):
  * Evaluation order: ``kill_switch -> deny -> allow -> default_action``.
  * Fail-closed: a missing / unreadable / structurally-invalid policy file, or
    one whose ``default_action`` is not ``allow``/``deny``, makes EVERY decision
    ``GUIDANCE_ONLY``. A broken policy must never silently open the patch path.
  * Global kill-switch: an env var set truthy OR a sentinel file present forces
    every decision to ``GUIDANCE_ONLY`` (stop a bad batch without editing lists).

The gate matches exact CWE ids (normalised, e.g. ``89`` / ``cwe-89`` ->
``CWE-89``); descendants are enumerated explicitly in the YAML, matching VVAH.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

# decide() return values.
PATCH = "PATCH"
GUIDANCE_ONLY = "GUIDANCE_ONLY"

_TRUTHY = {"1", "true", "yes", "on"}


def _normalize_cwe(cwe: object) -> str | None:
    """Normalise a CWE reference to canonical ``CWE-<n>`` form, or None.

    Accepts ``"CWE-89"``, ``"cwe-89"``, ``"89"``, ``89``. Returns None for
    None/empty/non-numeric input (a finding with no usable CWE matches no rule
    and therefore falls through to ``default_action``)."""
    if cwe is None:
        return None
    m = re.search(r"(\d+)", str(cwe))
    return f"CWE-{m.group(1)}" if m else None


@dataclass
class RemediationPolicy:
    """A loaded, validated remediation policy. Construct via ``load_policy`` —
    never raise from the loader; an invalid policy yields ``valid=False`` and a
    fail-closed ``decide`` (everything ``GUIDANCE_ONLY``)."""

    valid: bool
    default_action: str = "deny"
    deny: frozenset[str] = field(default_factory=frozenset)
    allow: frozenset[str] = field(default_factory=frozenset)
    kill_switch: dict = field(default_factory=dict)
    source: str | None = None
    error: str | None = None

    def kill_switch_active(self) -> bool:
        """True when the global kill-switch env var is truthy OR the sentinel
        file is present. Either forces every decision to GUIDANCE_ONLY."""
        ks = self.kill_switch or {}
        env_var = ks.get("env_var")
        if env_var and os.environ.get(str(env_var), "").strip().lower() in _TRUTHY:
            return True
        f = ks.get("file")
        if f:
            try:
                if Path(str(f)).exists():
                    return True
            except OSError:
                pass
        return False

    def decide(self, cwe: object) -> str:
        """Return ``PATCH`` or ``GUIDANCE_ONLY`` for a finding's CWE.

        Order (VVAH): fail-closed -> kill_switch -> deny -> allow ->
        default_action."""
        if not self.valid:
            return GUIDANCE_ONLY  # fail-closed
        if self.kill_switch_active():
            return GUIDANCE_ONLY
        norm = _normalize_cwe(cwe)
        if norm is not None:
            if norm in self.deny:
                return GUIDANCE_ONLY
            if norm in self.allow:
                return PATCH
        # No rule matched (or the finding has no usable CWE) -> default_action.
        return PATCH if self.default_action == "allow" else GUIDANCE_ONLY


def load_policy(path: Path | str | None) -> RemediationPolicy:
    """Load + validate a remediation policy YAML. NEVER raises.

    Fail-closed: a missing / unreadable / invalid file (or one with a
    ``default_action`` other than ``allow``/``deny``) returns a policy whose
    ``decide`` always yields ``GUIDANCE_ONLY``."""
    if path is None:
        return RemediationPolicy(valid=False, error="no policy path given")
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text())
    except FileNotFoundError:
        log.error("[remediate] policy file not found: %s — fail-closed (deny all)", p)
        return RemediationPolicy(valid=False, source=str(p), error="file not found")
    except (OSError, yaml.YAMLError) as e:
        log.error("[remediate] policy file unreadable/invalid: %s: %s — "
                  "fail-closed (deny all)", p, e)
        return RemediationPolicy(valid=False, source=str(p), error=str(e))

    if not isinstance(raw, dict):
        log.error("[remediate] policy root is not a mapping: %s — fail-closed", p)
        return RemediationPolicy(valid=False, source=str(p),
                                 error="policy root is not a mapping")

    default_action = str(raw.get("default_action", "")).strip().lower()
    if default_action not in ("allow", "deny"):
        log.error("[remediate] policy default_action=%r invalid (want allow|deny): "
                  "%s — fail-closed", raw.get("default_action"), p)
        return RemediationPolicy(valid=False, source=str(p),
                                 error=f"invalid default_action {raw.get('default_action')!r}")

    deny = frozenset(
        n for c in (raw.get("deny") or []) if (n := _normalize_cwe(c)) is not None
    )
    allow = frozenset(
        n for c in (raw.get("allow") or []) if (n := _normalize_cwe(c)) is not None
    )
    kill_switch = raw.get("kill_switch") or {}
    if not isinstance(kill_switch, dict):
        kill_switch = {}

    return RemediationPolicy(
        valid=True,
        default_action=default_action,
        deny=deny,
        allow=allow,
        kill_switch=kill_switch,
        source=str(p),
    )
