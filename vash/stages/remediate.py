"""`vash remediate` — decoupled, static-first, policy-gated patch generation.

This is a SEPARATE, opt-in command (NOT part of the scan loop) — the VASH analog
of VulnHunter's ``/vulnhunter-fix`` split. It reads the confirmed canonical
findings a prior scan already stored and, for each, turns the finding into a
safe, root-cause **patch + security regression test**, generated STATICALLY — it
never executes the target to produce a fix.

The agent does not hand-write the diff. It EDITS files in a disposable copy of
the target (:mod:`vash.remediation.workspace`) and ``git diff`` computes the
patch, so the patch is valid by construction. The copy is the only place it can
write, it is never told where the real repository is, ``git status`` is consulted
as ground truth about what it actually touched, and the copy is destroyed
afterwards — so "VASH never modifies the code under review" stays true even
though the agent now holds a write tool. See :mod:`vash.remediation` and
``tests/test_remediate_target_untouched.py``.

Governance (ported from Visa VVAH):
  * The remediation **policy gate** (:mod:`vash.remediation_policy`) runs BEFORE
    any patch agent. A finding whose CWE resolves to a deny decision (or any
    finding when the policy is invalid — fail-closed — or the kill-switch is on)
    is short-circuited to prose **guidance-only** output; the LLM patch agent is
    never invoked for it.

Static-first guardrails (OVERRIDE defaults):
  * Generation NEVER executes the target. ``verify=True`` — the ONLY path here
    that runs anything — passes through the execution sandbox gate
    (:mod:`vash.sandbox`, Phase 4.1) FIRST: with no active sandbox and no
    ``--dangerously-no-sandbox`` escape it is refused (fail-soft — the refusal
    reason is recorded on each patched finding, the batch still completes and
    every patch stays ``needs_verification``). With the gate cleared, each
    patched finding's generated security test is run twice inside the
    disposable workspace — once against the patched code, once against the
    baseline — and only a RED→GREEN pair clears ``needs_verification``
    (:mod:`vash.remediation.verify`). A test that cannot run (a missing
    dependency, an unsupported language) is reported ``not_attempted``, never
    as evidence either way.
  * Diffs are written to ``out_dir``; they are NEVER applied to your tree.
  * Editing is not executing: the remediate agent gets no ``Bash``.
  * Every written artifact is redacted via :mod:`vash.redact`.
  * Fail-soft per finding — one finding's failure never aborts the batch.

Fix discipline (adapted from VulnHunter ``vulnhunter-fix`` implement + per-class
worker prompts) lives in ``prompts/remediate.md``; per-class prose guidance
(mirroring VVAH's remediation playbook) lives in ``_CLASS_GUIDANCE`` below for
the deterministic guidance-only path (no LLM call).
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import logging
from pathlib import Path, PurePosixPath

from vash import sandbox
from vash.redact import redact, redact_json
from vash.remediation_policy import (
    GUIDANCE_ONLY,
    _normalize_cwe,
    load_policy,
)
from vash.runner import AgentRunError, TransientAgentError, run_agent
from vash.remediation import (
    NOT_ATTEMPTED,
    VERIFIED,
    capture_diff,
    enforce,
    verify_patch,
    workspace_for,
)
from vash.state import Finding, StateDB
from vash.stages._common import StageContext

log = logging.getLogger(__name__)

# Logged verbatim when --verify PASSES the sandbox gate (vash.sandbox.require).
# From here on target code really does run — the generated security test, twice
# per patched finding, inside the disposable workspace and nowhere else.
VERIFY_ENABLED_MSG = (
    "[remediate] --verify passed the sandbox gate — each patched finding's "
    "security test will be RUN against the patched and the unpatched copy"
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


def _finding_files(f: Finding) -> list[str]:
    """The files this finding is about — the only ones the agent may edit.

    Anything else it touches is reverted by the post-gate. Sourced from the
    finding's own file plus any files_touched the hunter recorded.
    """
    files = [f.file]
    for extra in (f.raw_json.get("files_touched") or []):
        if isinstance(extra, str) and extra not in files:
            files.append(extra)
    return [x for x in files if x]


async def _remediate_one(ctx: StageContext, db: StateDB, f: Finding, policy,
                         out_dir: Path, *, verify_enabled: bool = False) -> dict:
    """Policy-gate one finding, then either emit a guidance-only record (denied)
    or run the static patch agent (allowed). Raises on agent error (the caller
    turns that into a fail-soft cannot_fix record).

    ``verify_enabled`` is the ONLY way any target code runs in this module: the
    caller sets it only after :func:`vash.sandbox.require` has cleared. It runs
    the generated security test inside the workspace, never against the real
    repository, and only for a finding that actually produced a patch."""
    cwe = f.raw_json.get("cwe")
    cls = _classify(cwe, f.vuln_class)

    # HARD GATE — runs BEFORE any patch agent.
    if policy.decide(cwe) == GUIDANCE_ONLY:
        return _guidance_record(f, cwe, cls, policy)

    sc = ctx.stage("remediate")
    finding_files = _finding_files(f)

    # The agent EDITS files and git computes the diff, so the patch is valid by
    # construction. It edits a DISPOSABLE COPY and is never told where the real
    # repository is — `cwd`/`add_dirs` below are the workspace, never
    # ctx.repo_path. That is what keeps "VASH never modifies your code" true
    # while the agent holds a write tool.
    with workspace_for(ctx.repo_path) as workspace:
        if workspace is None:
            # No safe place to edit -> guidance, never an unprotected edit.
            rec = _guidance_record(f, cwe, cls, policy)
            rec["guidance"] = (
                "Could not create an isolated workspace for this repository "
                "(too large, or unreadable), so no patch was generated. "
                + (rec.get("guidance") or "")
            ).strip()
            return rec

        user_input = {
            "finding": _finding_view(f, cwe),
            "vuln_class_family": cls,
            "trace": db.get_trace(f.finding_id) or {},
            "repo_path": str(workspace),          # the copy — never the target
            "editable_files": finding_files,
            **ctx.extras(),
        }
        result = await run_agent(
            stage="remediate",
            prompt_file=ctx.prompt("remediate"),
            user_input=user_input,
            schema_file=ctx.schema("remediation"),
            allowed_tools=sc.tools,
            model=sc.model,
            cwd=workspace,
            add_dirs=[workspace],
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

        # Ask git what the agent ACTUALLY changed, not what it says it changed,
        # and undo anything outside this finding's files before diffing.
        gate = enforce(workspace, finding_files,
                       expected_extra=[payload.get("test_path") or ""])
        if gate.expected:
            payload["security_test_written_to"] = gate.expected
        if gate.reverted:
            payload["out_of_scope_edits_reverted"] = gate.reverted
        if gate.errors:
            payload["out_of_scope_edits_unreverted"] = gate.errors

        captured = capture_diff(workspace, finding_files)
        if captured:
            payload["patch_diff"] = captured
        elif (payload.get("patch_diff") or "").strip():
            # The agent described a change it did not make. Trust the workspace.
            log.warning("[%s] remediate: %s returned a diff but edited nothing — "
                        "discarding it", ctx.run_id, f.finding_id)
            payload["patch_diff"] = ""

        # --verify: run the security test here, while the workspace still
        # exists and still holds the patched code. Only for a finding that
        # produced a patch — there is nothing to prove about an empty diff.
        # Fail-soft: verification never decides whether the batch completes.
        if verify_enabled and (payload.get("patch_diff") or "").strip():
            try:
                payload["verification"] = verify_patch(
                    workspace,
                    test_path=payload.get("test_path"),
                    test_source=payload.get("security_test") or "",
                    finding_files=finding_files,
                )
            except Exception as e:      # pragma: no cover - verify_patch traps its own
                log.warning("[%s] remediate: %s: verification errored: %s",
                            ctx.run_id, f.finding_id, e)
                payload["verification"] = {
                    "verdict": NOT_ATTEMPTED,
                    "reason": f"verification raised {type(e).__name__}: {e}",
                }
            log.info("[%s] remediate: %s verification=%s (%s)", ctx.run_id,
                     f.finding_id, payload["verification"].get("verdict"),
                     payload["verification"].get("reason"))
    payload["finding_id"] = f.finding_id             # authoritative
    # Only a RED→GREEN run clears this. No verification, a verdict of
    # not_verified, and a verdict of not_attempted all leave it true: absence of
    # verification must never read as verified.
    payload["needs_verification"] = (
        (payload.get("verification") or {}).get("verdict") != VERIFIED
    )
    has_diff = bool((payload.get("patch_diff") or "").strip())
    if payload.get("status") not in ("patched", "cannot_fix"):
        # Never silently mint a patch: derive status from whether a diff exists.
        payload["status"] = "patched" if has_diff else "cannot_fix"
    elif payload.get("status") == "patched" and not has_diff:
        # "patched" with nothing to apply is the report reading as a fix when
        # nothing was fixed. The analysis is still worth delivering; the claim
        # is not.
        payload["status"] = "guidance_only"
        payload["risk_notes"] = (
            "Reported as patched, but the agent made no edit to this finding's "
            "files, so there is no patch. The analysis below is unverified. "
            + (payload.get("risk_notes") or "")
        ).strip()
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


# A unified-diff hunk header declares how many lines each side spans. An LLM
# writing a diff by hand gets those counts wrong often enough to matter: on a
# real 7-finding run, 4 patches were rejected by `git apply` with "corrupt
# patch", and in every case the header disagreed with the body it introduced.
# The counts are not a judgement call — they are fully determined by the hunk
# body — so they are recomputed here rather than trusted.
_HUNK_HDR = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def _normalize_hunk_counts(diff: str) -> tuple[str, int]:
    """Rewrite each hunk header's line counts to match its body.

    **This is now a fallback, not the main path.** Patches are produced by
    `git diff` over the agent's edits, so their headers are correct by
    construction and this is expected to correct nothing. It is kept because a
    diff can still arrive from an older run's stored record, and because a
    correction firing here is a useful signal that something bypassed the
    edit-then-diff flow.

    Returns (normalized_diff, hunks_corrected). Start line numbers are left
    alone: those encode WHERE the hunk applies and cannot be re-derived from the
    diff. Any structural surprise leaves the diff untouched — an unapplied patch
    is recoverable, a silently mangled one is not.
    """
    try:
        lines = diff.splitlines()
        out: list[str] = []
        corrected = 0
        i = 0
        while i < len(lines):
            m = _HUNK_HDR.match(lines[i])
            if not m:
                out.append(lines[i])
                i += 1
                continue
            old_start, old_n, new_start, new_n, tail = m.groups()
            body: list[str] = []
            j = i + 1
            old = new = 0
            while j < len(lines):
                c = lines[j][:1]
                if _HUNK_HDR.match(lines[j]) or lines[j].startswith(("--- ", "+++ ", "diff ")):
                    break
                if c == " ":
                    old += 1
                    new += 1
                elif c == "-":
                    old += 1
                elif c == "+":
                    new += 1
                elif c == "\\":          # "\ No newline at end of file"
                    pass
                elif lines[j] == "":
                    old += 1              # a bare empty line is context
                    new += 1
                else:
                    break
                body.append(lines[j])
                j += 1
            if (int(old_n or 1), int(new_n or 1)) != (old, new):
                corrected += 1
            out.append(f"@@ -{old_start},{old} +{new_start},{new} @@{tail}")
            out.extend(body)
            i = j
        return "\n".join(out) + ("\n" if diff.endswith("\n") else ""), corrected
    except Exception:  # never let normalisation lose a patch
        return diff, 0


# A generated diff names the files it edits. Those names are model output, so
# they are untrusted input: an absolute path, a `..` escape or a Windows
# drive/UNC prefix would direct the edit OUTSIDE the repository under review.
# `git apply` refuses such paths by default, but `patch -p1` and
# `git apply --unsafe-paths` do not — and VASH hands the operator a file either
# way. The diff is therefore rejected before it is written.
# (Control adapted from Visa VVAH's remediation diff path-safety guard.)
_DIFF_TARGET = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?([^\t\n]+)")
_UNSAFE_PREFIX = re.compile(r"^(?:[A-Za-z]:|\\\\|//)")


def _unsafe_diff_paths(diff: str) -> list[str]:
    """Every path in `diff` that would edit outside the repository."""
    bad: list[str] = []
    for line in diff.splitlines():
        m = _DIFF_TARGET.match(line)
        if not m:
            continue
        raw = m.group(1).strip()
        if raw in ("/dev/null", ""):
            continue
        if raw.startswith("/") or _UNSAFE_PREFIX.match(raw):
            bad.append(raw)                       # absolute, drive or UNC
        elif any(part == ".." for part in PurePosixPath(raw).parts):
            bad.append(raw)                       # traversal
    return sorted(set(bad))


def _check_patch_applies(diff: str, repo_path: Path) -> tuple[bool | None, str]:
    """Does this diff actually apply to the target tree?

    Returns (applies, detail); applies is None when it could not be determined
    (no git, not a work tree). Uses `git apply --check`, which only reads.

    This exists because a patch that cannot be applied is worse than no patch:
    it looks like a fix in the report. On a real run 4 of 7 patches were rejected
    by git — the hunk headers were repairable, but one had context lines that
    simply did not match the file, and nothing in the output said so.
    """
    if not diff.strip():
        return None, "no diff"
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_path), "apply", "--check", "-"],
            input=diff, text=True, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"could not verify ({type(e).__name__})"
    if proc.returncode == 0:
        return True, "applies cleanly"
    err = (proc.stderr or "").strip().splitlines()
    detail = err[0] if err else f"git apply exited {proc.returncode}"
    if "not a git repository" in detail.lower():
        return None, "target is not a git work tree — could not verify"
    return False, detail


def _write_patch_and_test(record: dict, patches_dir: Path,
                          tests_dir: Path) -> str:
    """Persist a record's diff + test to disk, REDACTED. No file is written for
    an empty diff/test (so denied/guidance findings produce no diff file).

    Returns the diff text **as actually written** — which is not always the diff
    on the record. Redaction rewrites secrets, and a diff is position-sensitive:
    masking a token inside a context line makes that line stop matching the file,
    so the written patch no longer applies. The caller must run the apply-check
    against these bytes, not the unredacted original, or the report would promise
    "applies cleanly" for a file that cannot. This is not a corner case — a
    hardcoded-secret finding is exactly the one whose fix touches a secret.
    """
    fid = record["finding_id"]
    diff = (record.get("patch_diff") or "")
    if diff.strip():
        unsafe = _unsafe_diff_paths(diff)
        if unsafe:
            # Do not write a diff that edits outside the repo — downgrade it to
            # guidance so the operator still gets the analysis, without a file
            # they might apply with a tool that does not refuse the path.
            log.error("[remediate] %s: diff targets paths outside the repo %s — "
                      "withheld, downgraded to guidance", fid, unsafe)
            record["status"] = "guidance_only"
            record["patch_withheld"] = f"diff targeted unsafe paths: {', '.join(unsafe)}"
            record["patch_diff"] = ""
            # The patch may have verified inside the workspace, but it is not
            # being delivered — leaving needs_verification=False would mark a
            # withheld patch as confirmed fixed.
            record["needs_verification"] = True
            return ""
        diff, corrected = _normalize_hunk_counts(diff)
        if corrected:
            record["patch_diff"] = diff
            record["hunk_headers_corrected"] = corrected
            log.info("[remediate] %s: repaired %d hunk header(s) whose line "
                     "counts disagreed with the body", fid, corrected)
        written = redact(diff)
        if written != diff:
            record["patch_redacted"] = True
            log.warning("[remediate] %s: the patch contained a secret, so the "
                        "written .diff is redacted and will NOT apply verbatim "
                        "— apply the change by hand", fid)
        (patches_dir / f"{fid}.diff").write_text(written)
    else:
        written = ""
    test = (record.get("security_test") or "")
    if test.strip():
        ext = _test_ext(record.get("test_path"))
        (tests_dir / f"{fid}_test{ext}").write_text(redact(test))
    return written


def _evidence_preview(f: Finding, limit: int = 1200) -> str:
    ev = f.evidence or ""
    return ev if len(ev) <= limit else ev[:limit] + "\n… (truncated)"


def _render_verification(lines: list[str], record: dict) -> None:
    """The `--verify` outcome for one finding, if it was offered one.

    Each verdict is stated with what it does and does not mean. `not_attempted`
    in particular has to read as "nothing was learned" — an operator skimming a
    report will otherwise take any verification line as a pass.
    """
    v = record.get("verification") or {}
    verdict = v.get("verdict")
    # A record that stopped being a delivered patch (withheld for unsafe paths,
    # downgraded for having no edit) gets no verification badge: the thing that
    # was verified is not the thing the operator is being handed.
    if not verdict or record.get("status") != "patched":
        return
    reason = v.get("reason") or ""
    if verdict == VERIFIED:
        lines.append(f"- **verified by execution**: ✅ RED→GREEN — the security "
                     f"test (`{v.get('test_path', '?')}`, `{v.get('runner', '?')}`) "
                     f"fails on the unpatched copy and passes on the patched one.")
    elif verdict == NOT_ATTEMPTED:
        lines.append(f"- **verification NOT attempted**: {reason}. "
                     "This is not evidence for or against the patch.")
    else:
        lines.append(f"- **NOT verified**: {reason}")


def _render_one(lines: list[str], f: Finding, record: dict) -> None:
    status = record["status"]
    lines.append(f"## `{f.finding_id}` — {f.vuln_class} ({status})")
    if record.get("cwe"):
        lines.append(f"- **CWE**: {record['cwe']}")
    lines.append(f"- **Location**: `{f.file}:{f.line_start}-{f.line_end}`  ")
    lines.append(f"- **Severity**: {f.severity}")
    lines.append(f"- **needs_verification**: {record.get('needs_verification', True)}")
    _render_verification(lines, record)
    # Whether the diff actually applies. Absent = could not be determined.
    applies = record.get("applies_cleanly")
    if applies is True:
        lines.append("- **applies cleanly**: yes (`git apply --check`)")
    elif applies is False:
        lines.append(f"- **applies cleanly**: **NO** — {record.get('apply_check', 'rejected')}. "
                     "Treat the diff as guidance and apply the change by hand.")
    if record.get("patch_redacted"):
        lines.append("- **patch redacted**: the diff contained a secret, so the "
                     "written `.diff` is masked and will **not** apply verbatim — "
                     "make the change by hand using the root cause below.")
    if record.get("hunk_headers_corrected"):
        lines.append(f"- _note: {record['hunk_headers_corrected']} hunk header(s) had "
                     "line counts that disagreed with the body; recomputed before writing._")
    # What the agent did beyond this finding. An unreverted out-of-scope edit is
    # the one case where the patch may carry an unrelated change, so it is said
    # out loud rather than left in the JSON.
    if record.get("out_of_scope_edits_unreverted"):
        lines.append("- **⚠ out-of-scope edits could NOT be reverted**: "
                     f"`{'`, `'.join(record['out_of_scope_edits_unreverted'])}` — "
                     "this patch may contain an unrelated change; review it before applying.")
    if record.get("out_of_scope_edits_reverted"):
        lines.append("- _the agent also edited "
                     f"`{'`, `'.join(record['out_of_scope_edits_reverted'])}`, "
                     "outside this finding's files; reverted before the patch was built._")
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
        lines.append("**Patch** (computed by `git diff` from edits to a "
                     "throwaway copy — not applied to your tree, not executed):")
        lines.append("```diff")
        lines.append(record["patch_diff"])
        lines.append("```")
        lines.append("")
        if (record.get("security_test") or "").strip():
            tp = record.get("test_path") or "(unspecified)"
            ran = (record.get("verification") or {}).get("verdict") is not None
            lines.append(f"**Security regression test** — `{tp}` "
                         "(RED pre-fix, GREEN post-fix"
                         f"{'; see the verification line above' if ran else '; not run'}):")
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


def _verify_counts(pairs: list[tuple[Finding, dict]]) -> dict:
    """How the verification pass landed across the batch.

    ``not_run`` counts patched findings that were never offered to the verifier
    (no --verify, or the gate refused). It is kept distinct from
    ``not_attempted`` — "we did not try" and "we tried and could not" are
    different claims, and collapsing them is how a report starts implying more
    than it did.
    """
    out = {"verified": 0, "not_verified": 0, "not_attempted": 0, "not_run": 0}
    for _f, record in pairs:
        if record.get("status") != "patched":
            continue
        verdict = (record.get("verification") or {}).get("verdict")
        if verdict is None:
            out["not_run"] += 1
        elif verdict in out:
            out[verdict] += 1
        else:                                    # pragma: no cover - defensive
            out["not_attempted"] += 1
    return out


def _render_markdown(run_id: str, pairs: list[tuple[Finding, dict]], policy,
                     verify: bool, counts: dict, verify_gate_error: str | None,
                     verify_counts: dict | None = None) -> str:
    lines: list[str] = []
    lines.append(f"# Remediation — `{run_id}`")
    lines.append("")
    executed = verify and not verify_gate_error
    lines.append("_Generated by `vash remediate`. Each patch was produced by "
                 "editing a **disposable copy** of the repository and letting "
                 "`git diff` compute the diff — your working tree was never "
                 "modified. Patches are NOT applied for you._" +
                 ("" if executed else
                  " _Nothing was executed: patches are `needs_verification=true` "
                  "until a sandboxed `--verify` run confirms them._"))
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
                         f"sandbox gate: {verify_gate_error} — **no test was "
                         f"run**, so every patch below remains unverified.")
        else:
            vc = verify_counts or {}
            lines.append(
                f"- `--verify`: each patch's security test was run against the "
                f"patched **and** the unpatched copy — "
                f"**{vc.get('verified', 0)} verified** (RED→GREEN), "
                f"{vc.get('not_verified', 0)} not verified, "
                f"{vc.get('not_attempted', 0)} not attempted."
            )
            if vc.get("not_attempted"):
                lines.append("  - _`not attempted` means the test could not be "
                             "run at all (usually the workspace has the target's "
                             "source but not its installed dependencies). It is "
                             "**not** evidence either way._")
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

    # --verify MUST pass the execution-sandbox gate FIRST, because past this
    # point the generated security test really is executed. A refusal is
    # recorded fail-soft, once the batch's records exist (below), rather than
    # aborting the run — the static patches are still worth delivering.
    verify_gate_error: str | None = None
    if verify:
        try:
            sandbox.require(allow_no_sandbox=no_sandbox)
        except sandbox.SandboxError as e:
            verify_gate_error = str(e)
            log.warning("[%s] remediate: --verify requested but refused by "
                        "the sandbox gate: %s", ctx.run_id, e)
        else:
            log.info(VERIFY_ENABLED_MSG)
    verify_enabled = verify and verify_gate_error is None

    findings = db.get_findings(ctx.run_id, validation_status="confirmed",
                               canonical_only=True)
    log.info("[%s] remediate: %d confirmed canonical finding(s); policy=%s "
             "(default_action=%s, kill_switch=%s)", ctx.run_id, len(findings),
             policy.source,
             policy.default_action if policy.valid else "FAIL-CLOSED",
             policy.kill_switch_active() if policy.valid else "n/a")

    # Findings are independent — each gets its own workspace and its own agent —
    # so they run concurrently, bounded by the stage's configured concurrency.
    # (`concurrency` was declared in config/stages.yaml and silently ignored
    # here; 13 findings ran one at a time for 33 minutes.) Results are collected
    # by index so the report order stays deterministic regardless of finish
    # order, and each finding still fails soft on its own.
    sem = asyncio.Semaphore(max(1, ctx.stage("remediate").concurrency))
    records: list[dict | None] = [None] * len(findings)

    async def _one(i: int, f: Finding) -> None:
        async with sem:
            try:
                records[i] = await _remediate_one(
                    ctx, db, f, policy, out_dir, verify_enabled=verify_enabled)
            except (AgentRunError, TransientAgentError) as e:
                log.warning("[%s] remediate %s: agent failed: %s — cannot_fix "
                            "(fail-soft)", ctx.run_id, f.finding_id, e)
                records[i] = _cannot_fix_record(f, f"remediation agent failed: {e}")
            except Exception as e:  # fail-soft: one finding never aborts the batch
                log.warning("[%s] remediate %s: unexpected error: %s — cannot_fix "
                            "(fail-soft)", ctx.run_id, f.finding_id, e)
                records[i] = _cannot_fix_record(f, f"unexpected error: {e}")

    await asyncio.gather(*(_one(i, f) for i, f in enumerate(findings)))
    pairs: list[tuple[Finding, dict]] = [
        (f, r) for f, r in zip(findings, records) if r is not None
    ]

    # Sandbox gate refused --verify: record why on every patched finding
    # (fail-soft — the batch above already ran to completion statically).
    if verify_gate_error:
        _apply_verify_gate_error(pairs, verify_gate_error)

    # Persist per-finding diff + test (redacted). Guidance/cannot_fix -> no diff.
    for _f, record in pairs:
        written = _write_patch_and_test(record, patches_dir, tests_dir)
        # A patch that does not apply still LOOKS like a fix in the report, so
        # say which ones do — checking the bytes on disk, since redaction can
        # rewrite a context line and break an otherwise-valid patch. Read-only,
        # fail-soft: unknown stays unknown.
        applies, detail = _check_patch_applies(written, ctx.repo_path)
        if applies is not None:
            record["applies_cleanly"] = applies
            record["apply_check"] = detail
            if not applies:
                log.warning("[%s] remediate: patch for %s does NOT apply — %s",
                            ctx.run_id, record.get("finding_id"), detail)

    counts = {"patched": 0, "guidance_only": 0, "cannot_fix": 0}
    for _f, record in pairs:
        counts[record["status"]] = counts.get(record["status"], 0) + 1

    verify_counts = _verify_counts(pairs)
    if verify_enabled:
        log.info("[%s] remediate: verification — verified=%d not_verified=%d "
                 "not_attempted=%d", ctx.run_id, verify_counts["verified"],
                 verify_counts["not_verified"], verify_counts["not_attempted"])

    summary_payload = {
        "run_id": ctx.run_id,
        "generated_by": "vash remediate",
        "static_first": True,
        "verify_requested": verify,
        # True means "tests were actually run", not "--verify was passed" —
        # a gate refusal leaves this False and the reason below.
        "verify_executed": verify_enabled,
        "verify_counts": verify_counts,
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

    md = _render_markdown(ctx.run_id, pairs, policy, verify, counts,
                          verify_gate_error, verify_counts)
    (out_dir / "REMEDIATION.md").write_text(redact(md))

    log.info("[%s] remediate: patched=%d guidance_only=%d cannot_fix=%d -> %s",
             ctx.run_id, counts["patched"], counts["guidance_only"],
             counts["cannot_fix"], out_dir)

    return {
        "out_dir": str(out_dir),
        "counts": counts,
        "verify_counts": verify_counts,
        "verify_executed": verify_enabled,
        "records": [r for _f, r in pairs],
        "total": len(pairs),
        "policy_valid": policy.valid,
    }
