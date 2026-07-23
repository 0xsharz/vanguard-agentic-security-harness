"""Gated repo-wide specialist Hunt sweeps (feature V12).

Per-task Hunt tasks (recon/taint/sink-backward/gapfill/feedback) each scope a
single file or a narrow (input -> sink) path. They systematically miss
cross-cutting bug classes that only show up when a specialist reasons across
the WHOLE repo at once: weak cryptography, auth/IDOR logic, unsafe
deserialization, batch/ETL data handling, and IaC misconfiguration. V12 adds
one repo-wide Hunt task per such specialist — but ONLY for the specialists
whose surface actually exists in this repo (gated), so Validate budget is
never spent proving a guaranteed false positive (e.g. hunting for weak
crypto in a repo with zero crypto usage).

The specialist *lens* (what the researcher is told to look for) is V9's
``SPECIALIST_HINTS`` / ``hints_for(..., specialist=...)`` in
``audit.lang.hints`` — already built, reused here unchanged; this module
supplies the other half: the *gate* (should this specialist even run here?)
and the *task synthesis* (turn "yes" into a valid hunt_task dict that flows
`specialist=` back into that lens via Hunt's one-line wireup).

The regex gate and ``_scan_any`` are PORTED VERBATIM from VVAH's
``vvaharness/pipeline/stages/s3_decompose.py`` (``_CRYPTO_RX`` L735,
``_DESER_RX`` L743, ``_BATCH_ETL_RX`` L749, ``_scan_any`` L768). The surface
predicates (``_has_authz_surface`` / ``_has_batch_surface``, VVAH L779/L758)
are ADAPTED from VVAH's ``ContextPackage`` to audit's recon_output dict shape
(``schemas/recon_output.schema.json``) plus the F1 attacker-input inventory.

Everything here is STATIC: files are read (utf-8, ``errors="replace"``) but
never executed, and every public entry point is safe to call from the
orchestrator's fail-open wireup — a malformed/partial recon dict (e.g. an
``entry_points`` list of bare strings instead of objects) must degrade to
"no signal", never raise.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable

from vash.lang.hints import SPECIALIST_HINTS, is_iac_file

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ported verbatim from VVAH s3_decompose.py (_CRYPTO_RX L735, _DESER_RX L743,
# _BATCH_ETL_RX L749).
# ---------------------------------------------------------------------------

_CRYPTO_RX = re.compile(
    r"\b(AES|RSA|HMAC|SHA-?(1|2|256|384|512)|MD5|PBKDF2|bcrypt|scrypt|argon2"
    r"|Cipher|KeyPair|SecretKey|X509|PKCS|TLS|SSLContext|jwt|jose|nacl|sodium"
    r"|hashlib|hmac\.|cryptography\.|javax\.crypto|BouncyCastle|OpenSSL"
    r"|Crypt::|Digest::|Mcrypt|RandomNumberGenerator|SecureRandom)\b",
    re.IGNORECASE,
)

_DESER_RX = re.compile(
    r"\b(ObjectInputStream|readObject|XMLDecoder|XStream|SnakeYAML|yaml\.load"
    r"|pickle\.|marshal\.load|unserialize|BinaryFormatter|Kryo|Hessian"
    r"|JdkSerializationRedisSerializer|Marshal\.load)\b",
)

_BATCH_ETL_RX = re.compile(
    r"\b(struct\.(?:un)?pack|codecs\.(?:encode|decode)\([^)]*ebcdic"
    r"|cp037|cp1047|COMP-3|packed[_-]?decimal|RECFM|LRECL"
    r"|glob\.glob|os\.listdir|shutil\.(?:move|copy)|csv\.(?:writer|reader)"
    r"|EXEC\s+PGM=|//\w+\s+DD\b|DISP=\()\b",
    re.IGNORECASE,
)


def _scan_any(repo_root: Path, files: list[str], rx: re.Pattern) -> bool:
    """True as soon as `rx` matches inside any file (statically read, utf-8,
    errors="replace"). Never raises — an unreadable file is just skipped."""
    for rel in files:
        p = repo_root / rel
        try:
            if rx.search(p.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


# ---------------------------------------------------------------------------
# Surface predicates — ADAPTED from VVAH's ContextPackage to audit's
# recon_output dict (schemas/recon_output.schema.json) + the F1 inputs list
# (db.get_inputs). Defensive against partially-shaped recon dicts (e.g. a
# lenient/stubbed recon whose entry_points are bare strings, not objects) —
# a gate must never raise, only under- or over-fire.
# ---------------------------------------------------------------------------

_AUTHZ_ENTRY_KINDS = {"http_route", "rpc", "grpc", "webhook"}
_AUTHZ_CONTROLLABLE_BY = {"anonymous_user", "authenticated_user"}
_AUTHZ_TRUST_LEVELS = {"unauthenticated", "authenticated"}
_BATCH_ENTRY_KINDS = {"cli", "file_input"}


def _has_authz_surface(recon: dict | None, inputs: list[dict] | None) -> bool:
    """True if this repo has ANY externally-reachable or authenticated
    surface — the precondition for access-control (IDOR / privilege
    escalation) findings to be possible at all.

    True when: an entry_point's kind is in {http_route, rpc, grpc, webhook};
    OR an entry_point declares `auth_required` (either value — its mere
    presence means an authorization decision exists to get wrong); OR an
    external_input's controllable_by is {anonymous_user, authenticated_user};
    OR any trust_boundary is declared; OR an F1 input's trust_level is
    {unauthenticated, authenticated}.
    """
    arch = (recon or {}).get("architecture") or {}
    for ep in arch.get("entry_points") or []:
        if not isinstance(ep, dict):
            continue
        if ep.get("kind") in _AUTHZ_ENTRY_KINDS:
            return True
        if "auth_required" in ep:
            return True
    for ei in arch.get("external_inputs") or []:
        if isinstance(ei, dict) and ei.get("controllable_by") in _AUTHZ_CONTROLLABLE_BY:
            return True
    if arch.get("trust_boundaries"):
        return True
    for inp in inputs or []:
        if isinstance(inp, dict) and inp.get("trust_level") in _AUTHZ_TRUST_LEVELS:
            return True
    return False


def _has_batch_surface(recon: dict | None, repo_root: Path, source: list[str]) -> bool:
    """True if this repo has a batch/file/CLI processing surface: an
    entry_point of kind {cli, file_input}, OR the source matches a batch/ETL
    signature (struct.pack, EBCDIC codecs, glob/listdir, csv, mainframe JCL DD
    statements, ...)."""
    arch = (recon or {}).get("architecture") or {}
    for ep in arch.get("entry_points") or []:
        if isinstance(ep, dict) and ep.get("kind") in _BATCH_ENTRY_KINDS:
            return True
    return _scan_any(repo_root, source, _BATCH_ETL_RX)


# ---------------------------------------------------------------------------
# Gating — one predicate per SPECIALIST_HINTS key. `logic-bug` is
# cross-cutting behavioural/state-machine reasoning with no file signature
# (VVAH has no gate for it either), so it is always on; every other
# specialist is dropped unless its surface predicate is true, so Validate
# budget is never spent proving a guaranteed false positive.
# ---------------------------------------------------------------------------


def active_specialists(
    recon: dict | None,
    inputs: list[dict] | None,
    repo_root: Path,
    source_files: list[str],
) -> list[str]:
    """Return the SPECIALIST_HINTS keys whose surface actually exists in this
    repo. Gated-OFF specialists are logged (mirrors VVAH's s3 message) and
    dropped. Never raises."""
    gates: dict[str, Callable[[], bool]] = {
        "crypto": lambda: _scan_any(repo_root, source_files, _CRYPTO_RX),
        "logic-bug": lambda: True,
        "access-control": lambda: _has_authz_surface(recon, inputs),
        "deserialization": lambda: _scan_any(repo_root, source_files, _DESER_RX),
        "batch-etl": lambda: _has_batch_surface(recon, repo_root, source_files),
        "iac": lambda: any(is_iac_file(f) for f in source_files),
    }
    kept: list[str] = []
    for name in SPECIALIST_HINTS:  # default enabled = every known specialist
        gate = gates.get(name)
        if gate is None or gate():
            kept.append(name)
        else:
            log.info("specialist '%s' gated OFF — no matching surface in repo", name)
    return kept


# ---------------------------------------------------------------------------
# Task synthesis — one repo-wide hunt_task per active specialist.
# ---------------------------------------------------------------------------

_ATTACK_CLASS: dict[str, str] = {
    "crypto": "weak_crypto",
    "logic-bug": "logic_error",
    "access-control": "auth_bypass",
    "deserialization": "deserialization",
    "batch-etl": "improper_input_handling",
    "iac": "security_misconfiguration",
}

_FOCUS: dict[str, str] = {
    "crypto": "Weak cryptography, key handling, and protocol-negotiation flaws",
    "logic-bug": "Behavioural / state-machine defects that cross a trust boundary",
    "access-control": "IDOR, missing authorization checks, and privilege escalation",
    "deserialization": "Unsafe deserialization of attacker-influenced bytes",
    "batch-etl": "Unsafe batch/ETL file, encoding, and bulk-data handling",
    "iac": "Infrastructure-as-code and CI/CD misconfiguration",
}


def build_specialist_tasks(
    active: list[str],
    source_files: list[str],
    repo_root: Path,
    *,
    max_files: int = 40,
) -> list[dict]:
    """One `hunt_task` dict per active specialist, scoped to (at most)
    `max_files` repo files. `repo_root` is accepted for interface symmetry
    with `active_specialists` (and headroom for a future per-specialist file
    scope); the current uniform one-task-per-specialist design doesn't need
    to read files here. A specialist with no source files is skipped (the
    schema requires >=1 target_files) rather than emitted empty."""
    tasks: list[dict] = []
    for name in active:
        target_files = source_files[:max_files]
        if not target_files:
            log.info("specialist '%s' skipped — no source files to scope", name)
            continue
        tasks.append({
            "task_id": f"t_spec_{name.replace('-', '_')}",
            "source": "specialist",
            "specialist": name,
            "attack_class": _ATTACK_CLASS[name],
            "scope_hint": (
                f"Repo-wide {name} specialist sweep. {_FOCUS[name]}. "
                f"Hunt this lens across the listed files."
            ),
            "target_files": target_files,
            "rationale": (
                f"Specialist '{name}' passed its surface gate — this repo has "
                f"matching indicators, so a repo-wide {name} sweep is worth "
                f"Validate budget instead of a guaranteed false positive."
            ),
            "priority": 3,
        })
    return tasks
