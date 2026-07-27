"""Tests for Phase 5 — `vash remediate` (decoupled, static-first, policy-gated
patch + security-test generation).

Contracts exercised (all OFFLINE — run_agent is stubbed, findings/DB rows are
hand-built, no network):
  - VVAH policy gate (vash/remediation_policy.py): allow-by-default patches a
    normal CWE; a denied CWE -> GUIDANCE_ONLY; kill-switch (env or file) ->
    everything GUIDANCE_ONLY; a missing/invalid policy -> fail-closed (all
    GUIDANCE_ONLY).
  - schemas/remediation.schema.json accepts a valid `patched` record (diff+test)
    and a `guidance_only` record (no diff); rejects a bad `status` enum.
  - run_remediate: writes patches/*.diff, tests/*, remediation.json,
    REMEDIATION.md; denied findings are guidance-only (no diff file);
    needs_verification=true on patches; --verify logs the deferred notice and
    does NOT execute; a per-finding agent error is fail-soft.
  - Every written artifact is redacted (a secret in evidence/description does not
    leak into REMEDIATION.md or remediation.json).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml

import vash.stages.remediate as remediate_mod
from vash.config import load_config
from vash.json_utils import validate_schema
from vash.remediation_policy import GUIDANCE_ONLY, PATCH, load_policy
from vash.runner import AgentResult, AgentRunError
from vash.stages._common import StageContext
from vash.stages.remediate import DEFERRED_VERIFY_MSG, run_remediate
from vash.state import StateDB

REPO = Path(__file__).resolve().parent.parent
SCHEMAS = REPO / "schemas"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # redact.py masks this as [REDACTED-AWS-KEY]


# ─────────────────────────────────────────────────────────────────────────────
# Policy YAML helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_policy(tmp_path: Path, **over) -> Path:
    base = {
        "schema_version": "1.0",
        "default_action": "allow",
        "deny": [],
        "allow": [],
        "kill_switch": {"env_var": "VASH_REMEDIATE_DISABLE_TEST",
                        "file": str(tmp_path / ".vash-remediate-off")},
    }
    base.update(over)
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(base))
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Policy gate (VVAH port) — vash/remediation_policy.py
# ─────────────────────────────────────────────────────────────────────────────

def test_policy_allow_by_default_patches_normal_cwe(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path))
    assert policy.valid
    assert policy.decide("CWE-89") == PATCH
    assert policy.decide("CWE-79") == PATCH


def test_policy_denied_cwe_is_guidance_only(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path, deny=["CWE-89"]))
    assert policy.decide("CWE-89") == GUIDANCE_ONLY   # denied
    assert policy.decide("CWE-22") == PATCH            # not denied -> default allow


def test_policy_kill_switch_env_forces_guidance(tmp_path: Path, monkeypatch) -> None:
    policy = load_policy(_write_policy(tmp_path))
    monkeypatch.setenv("VASH_REMEDIATE_DISABLE_TEST", "1")
    assert policy.kill_switch_active()
    assert policy.decide("CWE-89") == GUIDANCE_ONLY    # kill-switch beats allow


def test_policy_kill_switch_file_forces_guidance(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("VASH_REMEDIATE_DISABLE_TEST", raising=False)
    policy = load_policy(_write_policy(tmp_path))
    assert policy.decide("CWE-89") == PATCH            # inactive until file exists
    (tmp_path / ".vash-remediate-off").write_text("off")
    assert policy.decide("CWE-89") == GUIDANCE_ONLY


def test_policy_missing_file_fail_closed(tmp_path: Path) -> None:
    policy = load_policy(tmp_path / "does-not-exist.yaml")
    assert policy.valid is False
    assert policy.decide("CWE-89") == GUIDANCE_ONLY    # fail-closed: deny all


def test_policy_invalid_yaml_fail_closed(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("default_action: allow\n  deny: [oops\n : : :\n")  # not valid YAML
    policy = load_policy(p)
    assert policy.valid is False
    assert policy.decide("CWE-89") == GUIDANCE_ONLY


def test_policy_bad_default_action_fail_closed(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path, default_action="maybe"))
    assert policy.valid is False
    assert policy.decide("CWE-89") == GUIDANCE_ONLY


def test_policy_default_deny_only_allowlist_patches(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path, default_action="deny",
                                       allow=["CWE-89"]))
    assert policy.decide("CWE-89") == PATCH            # on the allowlist
    assert policy.decide("CWE-22") == GUIDANCE_ONLY    # default deny


def test_policy_cwe_normalization(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path, deny=["89"]))  # bare number
    assert policy.decide("CWE-89") == GUIDANCE_ONLY            # normalized match
    assert policy.decide(89) == GUIDANCE_ONLY                  # int accepted
    # A finding with no usable CWE falls through to default_action (allow here).
    assert policy.decide(None) == PATCH


def test_shipped_policy_loads_valid_and_has_apache_header(monkeypatch) -> None:
    path = REPO / "config" / "remediation_policy.yaml"
    assert "Licensed under the Apache License, Version 2.0" in path.read_text()
    monkeypatch.delenv("VASH_REMEDIATE_DISABLE", raising=False)
    policy = load_policy(path)
    assert policy.valid and policy.default_action == "allow"


# ─────────────────────────────────────────────────────────────────────────────
# schemas/remediation.schema.json
# ─────────────────────────────────────────────────────────────────────────────

PATCHED_OK = {
    "finding_id": "f_sqli_1",
    "status": "patched",
    "cwe": "CWE-89",
    "root_cause": "Untrusted `name` concatenated into SQL via f-string.",
    "patch_diff": "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-cur.execute(f\"...{name}\")\n"
                  "+cur.execute(\"... = ?\", (name,))\n",
    "security_test": "def test_sqli_blocked():\n    assert get_user(\"x' OR '1'='1\") == []\n",
    "test_path": "tests/test_sqli.py",
    "needs_verification": True,
    "risk_notes": "Verify in sandbox once Phase 4.1 lands.",
}

GUIDANCE_OK = {
    "finding_id": "f_authz_2",
    "status": "guidance_only",
    "cwe": "CWE-862",
    "guidance": "Enforce the authorization check at the route boundary; fail closed.",
    "needs_verification": False,
}


def test_schema_accepts_patched_record() -> None:
    assert validate_schema(PATCHED_OK, SCHEMAS / "remediation.schema.json") == []


def test_schema_accepts_guidance_only_record() -> None:
    assert validate_schema(GUIDANCE_OK, SCHEMAS / "remediation.schema.json") == []


def test_schema_rejects_bad_status_enum() -> None:
    bad = {**PATCHED_OK, "status": "totally-fixed"}
    errors = validate_schema(bad, SCHEMAS / "remediation.schema.json")
    assert errors, "expected a validation error for a bad status enum"


def test_schema_rejects_additional_property() -> None:
    bad = {**PATCHED_OK, "evidence": "leaked field"}
    errors = validate_schema(bad, SCHEMAS / "remediation.schema.json")
    assert errors, "expected a validation error for an additionalProperty"


# ─────────────────────────────────────────────────────────────────────────────
# run_remediate — stubbed run_agent, hand-built DB
# ─────────────────────────────────────────────────────────────────────────────

PATCH_PAYLOAD = {
    "finding_id": "WILL_BE_OVERWRITTEN",
    "status": "patched",
    "cwe": "CWE-89",
    "root_cause": "Untrusted input concatenated into SQL.",
    "patch_diff": "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-bad\n+good\n",
    "security_test": "def test_blocked():\n    assert safe()\n",
    "test_path": "tests/test_sqli.py",
    "needs_verification": False,      # stage MUST force this back to True
    "risk_notes": "static only",
}


def _fake_run_agent_factory(captured: list[dict], payload: dict, *, edits: bool = True):
    """A stub standing in for the patch agent.

    The real agent now EDITS files in the workspace and git computes the diff,
    so a stub that only returns a `patch_diff` string models an agent that
    described a change it never made — which VASH deliberately discards. Set
    `edits=False` to exercise exactly that case.
    """
    async def fake_run_agent(*, user_input, artifact_dir, artifact_name, **_kw) -> AgentResult:
        captured.append(user_input)
        if edits:
            # Edit the finding's file inside the workspace, as a real agent does.
            ws = Path(user_input["repo_path"])
            for rel in (user_input.get("editable_files") or []):
                target = ws / rel.split(":", 1)[0]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# patched by the stub agent\n"
                                  + (target.read_text() if target.is_file() else ""))
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload=dict(payload),
            cost_usd=0.0, input_tokens=0, output_tokens=0,
            cache_read_tokens=0, cache_creation_tokens=0,
            num_turns=1, duration_ms=1, session_id="stub",
            artifact_path=ap, repair_used=False,
            raw_result_message={"usage": {"input_tokens": 0, "output_tokens": 0},
                                "total_cost_usd": 0.0, "num_turns": 1, "duration_ms": 1},
        )
    return fake_run_agent


def _seed_confirmed_canonical(db: StateDB, run_id: str, fid: str, *,
                              vuln_class: str = "sql_injection",
                              severity: str = "high", cwe: str | None = "CWE-89",
                              evidence: str = "query = f\"SELECT ... {name}\"",
                              description: str = "Untrusted input flows to SQL sink.") -> None:
    """Add one finding that is confirmed + canonical — exactly what
    run_remediate's selector (get_findings confirmed, canonical_only) consumes."""
    tid = f"t_{fid}"
    db.add_task(run_id, {"task_id": tid, "attack_class": vuln_class,
                         "scope_hint": "app.py", "target_files": ["app.py"],
                         "rationale": "x", "priority": 1})
    finding = {"finding_id": fid, "file": "app.py", "line_start": 10, "line_end": 12,
               "vuln_class": vuln_class, "severity": severity,
               "description": description, "evidence_snippet": evidence,
               "confidence": 0.9}
    if cwe:
        finding["cwe"] = cwe
    db.add_finding(run_id, tid, finding)
    db.set_finding_validation(fid, "confirmed", {
        "finding_id": fid, "verdict": "confirmed",
        "rationale": "confirmed for the purposes of this remediation test.",
        "validator_confidence": 0.9})
    db.assign_finding_group(fid, f"g_{fid}", True)


def _ctx(tmp_path: Path, run_id: str = "r1") -> StageContext:
    return StageContext(run_id=run_id, repo_path=tmp_path, config=load_config())


async def test_run_remediate_writes_all_artifacts(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(remediate_mod, "run_agent",
                        _fake_run_agent_factory(captured, PATCH_PAYLOAD))
    policy = _write_policy(tmp_path)  # allow-by-default
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=policy)
    finally:
        db.close()

    assert len(captured) == 1                                   # agent invoked once
    assert summary["counts"] == {"patched": 1, "guidance_only": 0, "cannot_fix": 0}
    assert (out / "patches" / "f_sqli_1.diff").is_file()
    assert (out / "tests" / "f_sqli_1_test.py").is_file()
    assert (out / "remediation.json").is_file()
    assert (out / "REMEDIATION.md").is_file()

    rec = json.loads((out / "remediation.json").read_text())["records"][0]
    assert rec["finding_id"] == "f_sqli_1"                      # authoritative id
    assert rec["needs_verification"] is True                    # stage forced True
    assert rec["status"] == "patched"


async def test_run_remediate_denied_cwe_guidance_no_diff(tmp_path: Path, monkeypatch) -> None:
    async def boom(**_kw):
        raise AssertionError("patch agent must NOT run for a policy-denied CWE")

    monkeypatch.setattr(remediate_mod, "run_agent", boom)
    policy = _write_policy(tmp_path, deny=["CWE-89"])
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")         # CWE-89 -> denied
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=policy)
    finally:
        db.close()

    assert summary["counts"] == {"patched": 0, "guidance_only": 1, "cannot_fix": 0}
    assert not (out / "patches" / "f_sqli_1.diff").exists()     # NO diff for denied
    rec = summary["records"][0]
    assert rec["status"] == "guidance_only"
    assert not rec.get("patch_diff")                            # guidance -> no diff
    assert rec["guidance"]                                      # has prose guidance


async def test_run_remediate_verify_logs_deferred_and_does_not_execute(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(remediate_mod, "run_agent",
                        _fake_run_agent_factory(captured, PATCH_PAYLOAD))
    policy = _write_policy(tmp_path)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        with caplog.at_level(logging.INFO, logger="vash.stages.remediate"):
            # no_sandbox=True: since Phase 4.1, --verify FIRST passes through
            # the vash.sandbox execution gate (tests/test_sandbox.py covers
            # that gate itself + its refusal path in depth) — the dev escape
            # here is what lets this test still reach the deferred-notice
            # behavior below, hermetically, with no ambient sandbox needed.
            summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                          policy_path=policy, verify=True,
                                          no_sandbox=True)
    finally:
        db.close()

    assert DEFERRED_VERIFY_MSG in caplog.text                   # deferred notice logged
    # Patch is still generate-only: needs_verification stays True, nothing executed.
    assert summary["records"][0]["needs_verification"] is True
    doc = json.loads((out / "remediation.json").read_text())
    assert doc["verify_requested"] is True
    assert doc["verify_executed"] is False


async def test_run_remediate_failsoft_on_agent_error(tmp_path: Path, monkeypatch) -> None:
    async def failing(**_kw):
        raise AgentRunError("model produced junk")

    monkeypatch.setattr(remediate_mod, "run_agent", failing)
    policy = _write_policy(tmp_path)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        # Must NOT raise — one finding's failure is fail-soft.
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=policy)
    finally:
        db.close()

    assert summary["counts"] == {"patched": 0, "guidance_only": 0, "cannot_fix": 1}
    assert not (out / "patches" / "f_sqli_1.diff").exists()
    assert (out / "REMEDIATION.md").is_file()                   # batch still finished
    rec = summary["records"][0]
    assert rec["status"] == "cannot_fix"
    assert "failed" in rec["risk_notes"].lower()


async def test_run_remediate_failsoft_on_unexpected_error(tmp_path: Path, monkeypatch) -> None:
    async def kaboom(**_kw):
        raise ValueError("boom")   # not an AgentRunError -> generic fail-soft branch

    monkeypatch.setattr(remediate_mod, "run_agent", kaboom)
    policy = _write_policy(tmp_path)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=policy)
    finally:
        db.close()
    assert summary["counts"]["cannot_fix"] == 1                 # did not raise


async def test_run_remediate_mixed_batch_counts(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(remediate_mod, "run_agent",
                        _fake_run_agent_factory(captured, PATCH_PAYLOAD))
    # deny CWE-862 (authz) -> guidance; CWE-89 (sqli) -> patched.
    policy = _write_policy(tmp_path, deny=["CWE-862"])
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1", cwe="CWE-89")
        _seed_confirmed_canonical(db, "r1", "f_authz_2", cwe="CWE-862",
                                  vuln_class="missing_authz")
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=policy)
    finally:
        db.close()
    assert summary["counts"] == {"patched": 1, "guidance_only": 1, "cannot_fix": 0}
    assert len(captured) == 1                                   # agent ran only once
    assert (out / "patches" / "f_sqli_1.diff").is_file()
    assert not (out / "patches" / "f_authz_2.diff").exists()


async def test_run_remediate_redacts_secret_in_evidence(tmp_path: Path, monkeypatch) -> None:
    # Denied CWE -> guidance-only (no agent), but the finding's evidence +
    # description still flow into the human report; both must be redacted.
    async def boom(**_kw):
        raise AssertionError("agent must not run")

    monkeypatch.setattr(remediate_mod, "run_agent", boom)
    policy = _write_policy(tmp_path, deny=["CWE-89"])
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(
            db, "r1", "f_sqli_1",
            evidence=f"client = boto3.client('s3', aws_access_key_id='{AWS_KEY}')",
            description=f"Hardcoded AWS key {AWS_KEY} reachable from the SQL path.",
        )
        await run_remediate(_ctx(tmp_path), db, out_dir=out, policy_path=policy)
    finally:
        db.close()

    md = (out / "REMEDIATION.md").read_text()
    js = (out / "remediation.json").read_text()
    assert AWS_KEY not in md and AWS_KEY not in js              # secret never leaks
    assert "[REDACTED-AWS-KEY]" in md                           # masked in evidence
    assert "[REDACTED-AWS-KEY]" in js                           # masked in root_cause


async def test_run_remediate_empty_when_no_confirmed_findings(tmp_path: Path, monkeypatch) -> None:
    async def boom(**_kw):
        raise AssertionError("agent must not run with zero findings")

    monkeypatch.setattr(remediate_mod, "run_agent", boom)
    policy = _write_policy(tmp_path)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=policy)
    finally:
        db.close()
    assert summary["total"] == 0
    assert summary["counts"] == {"patched": 0, "guidance_only": 0, "cannot_fix": 0}
    assert (out / "remediation.json").is_file()                # still emits artifacts


async def test_run_remediate_fail_closed_when_policy_missing(tmp_path: Path, monkeypatch) -> None:
    # Missing policy file -> fail-closed: every finding is guidance-only, the
    # patch agent is never invoked (governance holds even without a policy).
    async def boom(**_kw):
        raise AssertionError("agent must not run under a fail-closed policy")

    monkeypatch.setattr(remediate_mod, "run_agent", boom)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=tmp_path / "nope.yaml")
    finally:
        db.close()
    assert summary["policy_valid"] is False
    assert summary["counts"]["guidance_only"] == 1
    assert summary["counts"]["patched"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI wiring
# ─────────────────────────────────────────────────────────────────────────────

def test_cli_registers_remediate_command() -> None:
    from vash.cli import main
    assert "remediate" in main.commands


# --- generated patches must actually apply --------------------------------

def test_hunk_counts_are_recomputed_from_the_body() -> None:
    """An LLM writing a unified diff gets the header line counts wrong often
    enough to matter: on a real 7-finding run, 4 patches were rejected by
    `git apply` as "corrupt patch", and every one had a header that disagreed
    with the body it introduced. The counts are fully determined by the body,
    so they are recomputed rather than trusted."""
    from vash.stages.remediate import _normalize_hunk_counts
    bad = (
        "--- a/app/notes.py\n"
        "+++ b/app/notes.py\n"
        "@@ -13,6 +13,12 @@\n"          # says 6 old lines; body has 5
        " \n"
        " def read_note(path):\n"
        '     """doc"""\n'
        "-    with open(os.path.join(NOTES_DIR, path)) as fh:\n"
        "-        return fh.read()\n"
        "+    target = os.path.realpath(os.path.join(NOTES_DIR, path))\n"
        "+    with open(target) as fh:\n"
        "+        return fh.read()\n"
    )
    fixed, corrected = _normalize_hunk_counts(bad)
    assert corrected == 1
    assert "@@ -13,5 +13,6 @@" in fixed
    assert "realpath" in fixed                    # body untouched


def test_correct_hunk_counts_are_left_alone() -> None:
    from vash.stages.remediate import _normalize_hunk_counts
    good = (
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n"
        "-x = 1\n"
        "+x = 2\n"
        " y = 3\n"
    )
    fixed, corrected = _normalize_hunk_counts(good)
    assert corrected == 0
    assert fixed.strip() == good.strip()


def test_start_lines_are_never_rewritten() -> None:
    """Counts are derivable from the body; the START line is not — it encodes
    where the hunk applies. Guessing it would silently mangle a patch."""
    from vash.stages.remediate import _normalize_hunk_counts
    fixed, _ = _normalize_hunk_counts(
        "--- a/a.py\n+++ b/a.py\n@@ -42,9 +99,9 @@\n x\n")
    assert "@@ -42,1 +99,1 @@" in fixed


def test_normalisation_never_loses_a_patch_on_weird_input() -> None:
    from vash.stages.remediate import _normalize_hunk_counts
    weird = "not a diff at all\njust prose\n"
    fixed, corrected = _normalize_hunk_counts(weird)
    assert fixed == weird and corrected == 0


def test_apply_check_reports_a_patch_that_does_not_apply(tmp_path) -> None:
    """A patch that cannot be applied is worse than no patch — it looks like a
    fix in the report. It must be reported as failing."""
    import subprocess
    from vash.stages.remediate import _check_patch_applies
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "a.py").write_text("x = 1\ny = 2\n")
    good = "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n-x = 1\n+x = 99\n y = 2\n"
    bad = "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n-NOPE = 1\n+x = 99\n y = 2\n"
    assert _check_patch_applies(good, tmp_path)[0] is True
    assert _check_patch_applies(bad, tmp_path)[0] is False
    assert _check_patch_applies("", tmp_path)[0] is None      # nothing to check


def test_apply_check_reports_a_missing_target_file(tmp_path) -> None:
    """`git apply` works outside a git repo too, so a patch against a file that
    is not there is reported as NOT applying, with the reason — not silently
    passed and not crashed on."""
    from vash.stages.remediate import _check_patch_applies
    applies, detail = _check_patch_applies(
        "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-x\n+y\n", tmp_path)
    assert applies is False
    assert "a.py" in detail


# --- a generated diff must not edit outside the repository -----------------

def test_unsafe_diff_paths_are_detected() -> None:
    """File names in a diff are model output, i.e. untrusted. An absolute path,
    a `..` escape or a drive/UNC prefix would direct the edit OUTSIDE the repo
    under review. `git apply` refuses these, but `patch -p1` and
    `git apply --unsafe-paths` do not — and VASH hands over the file either way.
    (Control adapted from Visa VVAH's diff path-safety guard.)"""
    from vash.stages.remediate import _unsafe_diff_paths
    assert _unsafe_diff_paths("--- a/app/x.py\n+++ b/app/x.py\n") == []
    assert _unsafe_diff_paths("--- /dev/null\n+++ b/app/new.py\n") == []   # legal: new file
    assert _unsafe_diff_paths("--- a/x\n+++ b//etc/passwd\n") == ["/etc/passwd"]
    assert _unsafe_diff_paths(
        "--- a/../../etc/shadow\n+++ b/../../etc/shadow\n") == ["../../etc/shadow"]
    assert _unsafe_diff_paths("--- a/x\n+++ b/C:/Windows/hosts\n") == ["C:/Windows/hosts"]


def test_a_diff_escaping_the_repo_is_withheld_not_written(tmp_path) -> None:
    """The operator still gets the analysis, but not a file they might apply
    with a tool that does not refuse the path."""
    from vash.stages.remediate import _write_patch_and_test
    patches, tests = tmp_path / "patches", tmp_path / "tests"
    patches.mkdir(); tests.mkdir()
    record = {
        "finding_id": "f_evil",
        "status": "patched",
        "patch_diff": "--- a/../../../../tmp/ESCAPED.txt\n"
                      "+++ b/../../../../tmp/ESCAPED.txt\n@@ -0,0 +1 @@\n+pwned\n",
        "security_test": "def test_x(): pass\n",
    }
    _write_patch_and_test(record, patches, tests)
    assert list(patches.iterdir()) == []            # nothing written
    assert record["status"] == "guidance_only"
    assert "unsafe paths" in record["patch_withheld"]


def test_a_safe_diff_is_still_written(tmp_path) -> None:
    from vash.stages.remediate import _write_patch_and_test
    patches, tests = tmp_path / "patches", tmp_path / "tests"
    patches.mkdir(); tests.mkdir()
    record = {
        "finding_id": "f_ok", "status": "patched",
        "patch_diff": "--- a/app/x.py\n+++ b/app/x.py\n@@ -1,1 +1,1 @@\n-a\n+b\n",
        "security_test": "def test_x(): pass\n",
    }
    _write_patch_and_test(record, patches, tests)
    assert (patches / "f_ok.diff").is_file()
    assert record["status"] == "patched"
