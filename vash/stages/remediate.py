"""`vash remediate` — decoupled, static-first, policy-gated patch generation.

This is a SEPARATE, opt-in command (NOT part of the scan loop) — the VASH analog
of VulnHunter's ``/vulnhunter-fix`` split. It reads the confirmed canonical
findings a prior scan already stored and, for each, turns the finding into a
safe, root-cause **patch + security regression test**, generated STATICALLY: the
agent reads code and emits a unified diff — it never executes the target to
produce a fix.

Governance (ported from Visa VVAH):
  * The remediation **policy gate** (:mod:`vash.remediation_policy`) runs BEFORE
    any patch agent. A finding whose CWE resolves to a deny decision (or any
    finding when the policy is invalid — fail-closed — or the kill-switch is on)
    is short-circuited to prose **guidance-only** output; the LLM patch agent is
    never invoked for it.

Static-first guardrails (OVERRIDE defaults):
  * Generation NEVER executes the target. ``verify=True`` (running the target's
    own tests) now passes through the execution sandbox gate
    (:mod:`vash.sandbox`, Phase 4.1) FIRST: with no active sandbox and no
    ``--dangerously-no-sandbox`` escape, it is refused (fail-soft — the
    refusal reason is recorded on each patched finding, the batch still
    completes); with a sandbox present (or the escape), it proceeds to the
    still-DEFERRED notice below. Either way NO target code is executed yet
    and patches stay ``needs_verification``.
  * v1 writes diffs only — it does NOT apply patches to the working tree.
  * Every written artifact is redacted via :mod:`vash.redact`.
  * Fail-soft per finding — one finding's failure never aborts the batch.

Fix discipline (adapted from VulnHunter ``vulnhunter-fix`` implement + per-class
worker prompts) lives in ``prompts/remediate.md``; per-class prose guidance
(mirroring VVAH's remediation playbook) lives in ``_CLASS_GUIDANCE`` below for
the deterministic guidance-only path (no LLM call).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from vash import sandbox
from vash.redact import redact, redact_json
from vash.remediation_policy import (
    GUIDANCE_ONLY,
    _normalize_cwe,
    load_policy,
)
from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.state import Finding, StateDB
from vash.stages._common import StageContext

log = logging.getLogger(__name__)

# Deferred-verify notice — logged verbatim when --verify PASSES the sandbox
# gate (vash.sandbox.require). Real test execution is a later task; it is
# intentionally NOT run here — the gate only decides whether it would be
# ALLOWED to run.
DEFERRED_VERIFY_MSG = (
    "[remediate] --verify passed the sandbox gate — real test execution is "
    "still deferred (a later task); patches remain needs_verification"
)

# Per-class remediation guidance, condensed from VVAH's remediation_playbook.yaml
# + VulnHunter's per-class worker prompts. Used on the deterministic
# guidance-only / cannot_fix paths (no LLM call).
_CLASS_GUIDANCE = {
    "injection": (
        "Root-cause fix at the sink: replace ad-hoc string concatenation with a "
        "structural separator — a parameterized query / prepared statement for "
        "SQL, an argv list with shell=False for OS commands, context-aware output "
        "encoding for HTML/JS, canonicalize-and-confine under an allowlisted base "
        "for paths, a schema-validated safe loader (never pickle) for "
        "deserialization, a parser with external entities disabled for XML, and a "
        "scheme+host allowlist that blocks internal/link-local IPs for "
        "SSRF/open-redirect. Reject untrusted input at the boundary; do not "
        "sanitize in place."
    ),
    "authz": (
        "Enforce the authorization check at the earliest deterministic boundary "
        "(middleware, route decorator, or method entry); fail closed (default "
        "deny, explicit allow only after an identity + role check); verify "
        "server-side; and remove any legacy/bypass fallback branch. Authorization "
        "intent is program-specific — a human must confirm the intended policy "
        "before a patch is applied."
    ),
    "crypto": (
        "Replace the weak primitive/mode with a strong, standard algorithm from a "
        "vetted library (never hand-rolled); source keys from a secret manager or "
        "the environment (never a literal) and plan rotation; use constant-time "
        "comparison for secrets/MACs. Migrations such as password re-hashing need "
        "a human-owned rollout (lazy upgrade on next login)."
    ),
    "resource": (
        "Bound the resource at the sink — a timeout, size cap, or semaphore — and "
        "error on breach; make check-then-use operations atomic to close the "
        "race; mask sensitive fields at the log/response call site and drop them "
        "from responses entirely where possible."
    ),
    "other": (
        "Apply the minimal root-cause fix at the point where untrusted data "
        "reaches the dangerous operation: validate/reject at the trust boundary, "
        "use the safe API for the sink, and preserve behavior for legitimate "
        "input. A human should confirm the intended contract before a patch is "
        "applied."
    ),
}

# CWE number -> coarse family (for guidance selection + prompt hinting).
_CRYPTO = {"295", "326", "327", "328", "330", "345", "347", "916"}
_AUTHZ = {"284", "285", "287", "290", "306", "639", "862", "863", "915"}
_RESOURCE = {"117", "200", "362", "400", "532", "770"}
_INJECTION = {"20", "22", "78", "79", "89", "94", "352", "434", "502",
              "601", "611", "643", "776", "918", "943"}


def _classify(cwe: object, vuln_class: str | None) -> str:
    """Map a finding to a coarse remediation family (injection/authz/crypto/
    resource/other) from its CWE first, then vuln_class keywords."""
    n = _normalize_cwe(cwe)
    if n is not None:
        num = n.split("-", 1)[1]
        if num in _CRYPTO:
            return "crypto"
        if num in _AUTHZ:
            return "authz"
        if num in _RESOURCE:
            return "resource"
        if num in _INJECTION:
            return "injection"
    vc = (vuln_class or "").lower()
    if any(k in vc for k in ("crypto", "hash", "cipher", "tls", "cert", "ssl")):
        return "crypto"
    if any(k in vc for k in ("authz", "authn", "auth", "access", "privilege", "idor")):
        return "authz"
    if any(k in vc for k in ("resource", "dos", "denial", "race", "toctou",
                             "leak", "log", "exposure")):
        return "resource"
    if any(k in vc for k in ("inj", "sql", "xss", "ssrf", "travers", "command",
                             "deserial", "redirect", "xxe", "template")):
        return "injection"
    return "other"


def _root_cause_line(f: Finding) -> str:
    return f"{f.vuln_class} at {f.file}:{f.line_start}-{f.line_end}: {f.description}"


def _finding_view(f: Finding, cwe: object) -> dict:
    """A focused, read-only view of a finding for the remediate agent."""
    v: dict = {
        "finding_id": f.finding_id,
        "file": f.file,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "vuln_class": f.vuln_class,
        "severity": f.severity,
        "description": f.description,
        "evidence": f.evidence,
    }
    n = _normalize_cwe(cwe)
    if n is not None:
        v["cwe"] = n
    return v


def _guidance_record(f: Finding, cwe: object, cls: str,
                     policy) -> dict:
    """A guidance-only record — emitted (no LLM call) when the policy gate
    denies a patch for this finding. No diff is generated."""
    if not policy.valid:
        reason = "policy invalid/missing — fail-closed"
    elif policy.kill_switch_active():
        reason = "global kill-switch active"
    else:
        reason = "CWE denied by remediation policy"
    rec: dict = {
        "finding_id": f.finding_id,
        "status": "guidance_only",
        "root_cause": _root_cause_line(f),
        "guidance": _CLASS_GUIDANCE.get(cls, _CLASS_GUIDANCE["other"]),
        "needs_verification": False,
        "risk_notes": (f"Remediation policy gate did not authorize an automated "
                       f"patch ({reason}); routed to a human. No diff generated."),
    }
    n = _normalize_cwe(cwe)
    if n is not None:
        rec["cwe"] = n
    return rec


def _cannot_fix_record(f: Finding, note: str) -> dict:
    """A cannot_fix record — emitted fail-soft when the patch agent errors or
    no safe static fix is derivable."""
    cwe = f.raw_json.get("cwe")
    rec: dict = {
        "finding_id": f.finding_id,
        "status": "cannot_fix",
        "root_cause": _root_cause_line(f),
        "guidance": _CLASS_GUIDANCE.get(_classify(cwe, f.vuln_class),
                                        _CLASS_GUIDANCE["other"]),
        "needs_verification": False,
        "risk_notes": note,
    }
    n = _normalize_cwe(cwe)
    if n is not None:
        rec["cwe"] = n
    return rec


async def _remediate_one(ctx: StageContext, db: StateDB, f: Finding, policy,
                         out_dir: Path) -> dict:
    """Policy-gate one finding, then either emit a guidance-only record (denied)
    or run the static patch agent (allowed). Raises on agent error (the caller
    turns that into a fail-soft cannot_fix record)."""
    cwe = f.raw_json.get("cwe")
    cls = _classify(cwe, f.vuln_class)

    # HARD GATE — runs BEFORE any patch agent.
    if policy.decide(cwe) == GUIDANCE_ONLY:
        return _guidance_record(f, cwe, cls, policy)

    sc = ctx.stage("remediate")
    user_input = {
        "finding": _finding_view(f, cwe),
        "vuln_class_family": cls,
        "trace": db.get_trace(f.finding_id) or {},
        "repo_path": str(ctx.repo_path),
        **ctx.extras(),
    }
    result = await run_agent(
        stage="remediate",
        prompt_file=ctx.prompt("remediate"),
        user_input=user_input,
        schema_file=ctx.schema("remediation"),
        allowed_tools=sc.tools,
        model=sc.model,
        cwd=ctx.repo_path,
        add_dirs=[ctx.repo_path],
        max_turns=sc.max_turns,
        permission_mode=sc.permission_mode,
        artifact_dir=out_dir / "agent",
        artifact_name=f.finding_id,
        repair_attempts=sc.repair_attempts,
    )
    db.record_cost(ctx.run_id, "remediate", f.finding_id, result.raw_result_message)
    db.add_artifact(ctx.run_id, "remediate", f.finding_id, "jsonl",
                    str(result.artifact_path))

    payload = dict(result.payload)
    payload["finding_id"] = f.finding_id             # authoritative
    payload["needs_verification"] = True             # --verify deferred -> always true
    if payload.get("status") not in ("patched", "cannot_fix"):
        # Never silently mint a patch: derive status from whether a diff exists.
        payload["status"] = "patched" if (payload.get("patch_diff") or "").strip() \
            else "cannot_fix"
    n = _normalize_cwe(cwe)
    if n is not None and not payload.get("cwe"):
        payload["cwe"] = n
    return payload


def _test_ext(test_path: str | None) -> str:
    if test_path:
        suf = Path(test_path).suffix
        if suf:
            return suf
    return ".py"


def _write_patch_and_test(record: dict, patches_dir: Path, tests_dir: Path) -> None:
    """Persist a record's diff + test to disk, REDACTED. No file is written for
    an empty diff/test (so denied/guidance findings produce no diff file)."""
    fid = record["finding_id"]
    diff = (record.get("patch_diff") or "")
    if diff.strip():
        (patches_dir / f"{fid}.diff").write_text(redact(diff))
    test = (record.get("security_test") or "")
    if test.strip():
        ext = _test_ext(record.get("test_path"))
        (tests_dir / f"{fid}_test{ext}").write_text(redact(test))


def _evidence_preview(f: Finding, limit: int = 1200) -> str:
    ev = f.evidence or ""
    return ev if len(ev) <= limit else ev[:limit] + "\n… (truncated)"


def _render_one(lines: list[str], f: Finding, record: dict) -> None:
    status = record["status"]
    lines.append(f"## `{f.finding_id}` — {f.vuln_class} ({status})")
    if record.get("cwe"):
        lines.append(f"- **CWE**: {record['cwe']}")
    lines.append(f"- **Location**: `{f.file}:{f.line_start}-{f.line_end}`  ")
    lines.append(f"- **Severity**: {f.severity}")
    lines.append(f"- **needs_verification**: {record.get('needs_verification', True)}")
    lines.append("")
    if record.get("root_cause"):
        lines.append(f"**Root cause**: {record['root_cause']}")
        lines.append("")
    lines.append("**Vulnerable code (evidence):**")
    lines.append("```")
    lines.append(_evidence_preview(f))
    lines.append("```")
    lines.append("")
    if status == "patched" and (record.get("patch_diff") or "").strip():
        lines.append("**Patch (unified diff — not applied, not executed):**")
        lines.append("```diff")
        lines.append(record["patch_diff"])
        lines.append("```")
        lines.append("")
        if (record.get("security_test") or "").strip():
            tp = record.get("test_path") or "(unspecified)"
            lines.append(f"**Security regression test** — `{tp}` "
                         "(RED pre-fix, GREEN post-fix; not run):")
            lines.append("```")
            lines.append(record["security_test"])
            lines.append("```")
            lines.append("")
    if record.get("guidance"):
        lines.append(f"**Guidance**: {record['guidance']}")
        lines.append("")
    if record.get("risk_notes"):
        lines.append(f"**Risk notes**: {record['risk_notes']}")
        lines.append("")
    lines.append("---")
    lines.append("")


def _apply_verify_gate_error(pairs: list[tuple[Finding, dict]], reason: str) -> None:
    """Fail-soft: record why `--verify` could not proceed on every PATCHED
    record in this batch (guidance_only/cannot_fix findings never had a
    patch to verify, so they are left untouched). The patch, its diff/test,
    and needs_verification are themselves untouched — nothing was executed;
    the sandbox gate only decides whether execution would have been allowed."""
    note = f"--verify refused: {reason}"
    for _f, record in pairs:
        if record.get("status") != "patched":
            continue
        existing = (record.get("risk_notes") or "").strip()
        record["risk_notes"] = f"{existing}  {note}".strip() if existing else note


def _render_markdown(run_id: str, pairs: list[tuple[Finding, dict]], policy,
                     verify: bool, counts: dict, verify_gate_error: str | None) -> str:
    lines: list[str] = []
    lines.append(f"# Remediation — `{run_id}`")
    lines.append("")
    lines.append("_Generated statically by `vash remediate`. Patches are unified "
                 "diffs produced by reading code — they were NOT executed and were "
                 "NOT applied to the working tree. Every patch is "
                 "`needs_verification=true` until a sandbox run confirms it._")
    lines.append("")
    policy_state = "valid" if policy.valid else "INVALID — fail-closed (guidance only)"
    if policy.valid and policy.kill_switch_active():
        policy_state += ", kill-switch ACTIVE (guidance only)"
    lines.append(f"- policy: `{policy.source}` ({policy_state})")
    lines.append(f"- outcomes: **{counts['patched']} patched**, "
                 f"{counts['guidance_only']} guidance-only, "
                 f"{counts['cannot_fix']} cannot-fix")
    if verify:
        if verify_gate_error:
            lines.append(f"- `--verify` requested but REFUSED by the execution "
                         f"sandbox gate: {verify_gate_error}")
        else:
            lines.append("- `--verify` requested: sandbox gate passed — real test "
                         "execution is still DEFERRED (a later task); patches "
                         "remain `needs_verification`.")
    lines.append("")
    lines.append("---")
    lines.append("")
    if not pairs:
        lines.append("_No confirmed canonical findings to remediate._")
        lines.append("")
    for f, record in pairs:
        _render_one(lines, f, record)
    return "\n".join(lines)


async def run_remediate(ctx: StageContext, db: StateDB, *, out_dir: Path,
                        policy_path: Path | str, verify: bool = False,
                        no_sandbox: bool = False) -> dict:
    """Turn a prior scan's confirmed canonical findings into static, policy-gated
    root-cause patches + security tests.

    Writes ``patches/<finding_id>.diff``, ``tests/<finding_id>_test.<ext>``,
    ``remediation.json`` and ``REMEDIATION.md`` under ``out_dir`` (all redacted),
    and returns a summary dict with per-status counts. NEVER executes the target;
    ``verify=True`` FIRST calls :func:`vash.sandbox.require` — a refusal is
    fail-soft (recorded on the batch's patched records) — then falls through to
    the still-deferred notice (real test execution is a later task).
    ``no_sandbox`` threads the ``--dangerously-no-sandbox`` dev escape into that
    gate; it does nothing when ``verify`` is False. Fail-soft per finding."""
    out_dir = Path(out_dir)
    patches_dir = out_dir / "patches"
    tests_dir = out_dir / "tests"
    for d in (out_dir, patches_dir, tests_dir):
        d.mkdir(parents=True, exist_ok=True)

    policy = load_policy(policy_path)
    if not policy.valid:
        log.warning("[%s] remediate: policy invalid/missing (%s) — FAIL-CLOSED: "
                    "every finding is guidance-only", ctx.run_id, policy.error)

    # --verify MUST pass the execution-sandbox gate FIRST. The gate decides
    # PERMISSION only — no target code runs here or in the (still-deferred)
    # notice below either way; a refusal is recorded fail-soft, once the
    # batch's records exist (below), rather than aborting the run.
    verify_gate_error: str | None = None
    if verify:
        try:
            sandbox.require(allow_no_sandbox=no_sandbox)
        except sandbox.SandboxError as e:
            verify_gate_error = str(e)
            log.warning("[%s] remediate: --verify requested but refused by "
                        "the sandbox gate: %s", ctx.run_id, e)
        else:
            log.info(DEFERRED_VERIFY_MSG)

    findings = db.get_findings(ctx.run_id, validation_status="confirmed",
                               canonical_only=True)
    log.info("[%s] remediate: %d confirmed canonical finding(s); policy=%s "
             "(default_action=%s, kill_switch=%s)", ctx.run_id, len(findings),
             policy.source,
             policy.default_action if policy.valid else "FAIL-CLOSED",
             policy.kill_switch_active() if policy.valid else "n/a")

    pairs: list[tuple[Finding, dict]] = []
    for f in findings:
        try:
            record = await _remediate_one(ctx, db, f, policy, out_dir)
        except (AgentRunError, TransientAgentError) as e:
            log.warning("[%s] remediate %s: agent failed: %s — cannot_fix "
                        "(fail-soft)", ctx.run_id, f.finding_id, e)
            record = _cannot_fix_record(f, f"remediation agent failed: {e}")
        except Exception as e:  # fail-soft: one finding never aborts the batch
            log.warning("[%s] remediate %s: unexpected error: %s — cannot_fix "
                        "(fail-soft)", ctx.run_id, f.finding_id, e)
            record = _cannot_fix_record(f, f"unexpected error: {e}")
        pairs.append((f, record))

    # Sandbox gate refused --verify: record why on every patched finding
    # (fail-soft — the batch above already ran to completion statically).
    if verify_gate_error:
        _apply_verify_gate_error(pairs, verify_gate_error)

    # Persist per-finding diff + test (redacted). Guidance/cannot_fix -> no diff.
    for _f, record in pairs:
        _write_patch_and_test(record, patches_dir, tests_dir)

    counts = {"patched": 0, "guidance_only": 0, "cannot_fix": 0}
    for _f, record in pairs:
        counts[record["status"]] = counts.get(record["status"], 0) + 1

    summary_payload = {
        "run_id": ctx.run_id,
        "generated_by": "vash remediate",
        "static_first": True,
        "verify_requested": verify,
        "verify_executed": False,
        "verify_gate_error": verify_gate_error,
        "policy": {
            "source": policy.source,
            "valid": policy.valid,
            "default_action": policy.default_action if policy.valid else None,
            "kill_switch_active": policy.kill_switch_active() if policy.valid else None,
        },
        "counts": counts,
        "records": [r for _f, r in pairs],
    }
    (out_dir / "remediation.json").write_text(
        json.dumps(redact_json(summary_payload), indent=2))

    md = _render_markdown(ctx.run_id, pairs, policy, verify, counts, verify_gate_error)
    (out_dir / "REMEDIATION.md").write_text(redact(md))

    log.info("[%s] remediate: patched=%d guidance_only=%d cannot_fix=%d -> %s",
             ctx.run_id, counts["patched"], counts["guidance_only"],
             counts["cannot_fix"], out_dir)

    return {
        "out_dir": str(out_dir),
        "counts": counts,
        "records": [r for _f, r in pairs],
        "total": len(pairs),
        "policy_valid": policy.valid,
    }
