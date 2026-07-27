"""Tests for `vash/sandbox.py` — the execution sandbox gate (Phase 4.1).

VASH's decoupled `remediate` / `validate` commands are static: read-only
tools, no Bash, they never execute the target (see `config/stages.yaml`'s
"static-first" comments on those two stages). The one exception is
`remediate --verify`, which runs the generated security test against the
patched and the unpatched copy. This module is the gate that execution MUST
pass: `sandbox.require()` either returns (execution permitted) or raises
`SandboxError` (it may not) — it decides PERMISSION only, it never executes
anything itself.

The verify wiring tests below stub out `verify_patch`: what they assert is
whether the gate lets execution through, not what the runner concludes
(`tests/test_remediate_verify.py` owns that). Stubbing it also keeps this
file's promise that every test here is hermetic — a real verify run would
spawn interpreters.

(The core `vash run` scan pipeline's Hunt/Trace stages are a separate,
pre-existing concern — they intentionally compile/run local PoCs and are
documented in README's "Safety" section; this gate does not touch them.)

All tests here are OFFLINE and hermetic: every test explicitly controls BOTH
sandbox signals via monkeypatch (`VASH_SANDBOX` env + the `/.dockerenv`
marker path) rather than relying on whatever happens to be true of the
machine running the suite — a dev box, a CI runner, or a real container
would otherwise each see different results.

Contracts exercised:
  - is_sandboxed(): True from VASH_SANDBOX truthy, or the dockerenv marker
    present; False otherwise.
  - require(): raises SandboxError with no sandbox + no escape; returns
    silently when sandboxed; returns (with a LOUD warning) when
    allow_no_sandbox=True regardless of sandbox state.
  - run_remediate(verify=True, ...) wiring: the gate runs FIRST in the verify
    branch; a refusal is fail-soft (recorded on the patched record's
    risk_notes, batch still completes, needs_verification stays True, and the
    verifier is never called); a pass (sandbox present, or the
    --dangerously-no-sandbox escape) reaches the verifier, no raise.
  - CLI: `vash remediate` registers `--dangerously-no-sandbox`.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

import vash.stages.remediate as remediate_mod
from vash import sandbox
from vash.config import load_config
from vash.runner import AgentResult
from vash.sandbox import SandboxError, is_sandboxed, require
from vash.stages._common import StageContext
from vash.stages.remediate import VERIFY_ENABLED_MSG, run_remediate
from vash.state import StateDB


def _stub_verifier(calls: list[dict]):
    """Records that the verifier was reached, and executes nothing."""
    def fake_verify_patch(workspace, **kw):
        calls.append(dict(kw, workspace=str(workspace)))
        return {"verdict": "not_attempted", "reason": "stubbed in tests"}
    return fake_verify_patch


@pytest.fixture(autouse=True)
def _hermetic_sandbox_signals(monkeypatch, tmp_path):
    """Every test starts from a known "definitely not sandboxed" baseline:
    VASH_SANDBOX unset, and the dockerenv marker repointed at a path that
    provably does not exist. Individual tests override one or both signals
    as needed. Without this, these tests would be flaky depending on
    whether the host running them happens to set VASH_SANDBOX or is itself
    a container with a real /.dockerenv."""
    monkeypatch.delenv("VASH_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "_DOCKERENV", tmp_path / "no-such-dockerenv")


# ─────────────────────────────────────────────────────────────────────────────
# is_sandboxed()
# ─────────────────────────────────────────────────────────────────────────────

def test_is_sandboxed_false_when_unset_and_no_dockerenv() -> None:
    assert is_sandboxed() is False


def test_is_sandboxed_true_when_env_set(monkeypatch) -> None:
    monkeypatch.setenv("VASH_SANDBOX", "1")
    assert is_sandboxed() is True


@pytest.mark.parametrize("falsy", ["", "0", "false", "False"])
def test_is_sandboxed_false_for_falsy_env_values(monkeypatch, falsy) -> None:
    monkeypatch.setenv("VASH_SANDBOX", falsy)
    assert is_sandboxed() is False


def test_is_sandboxed_true_when_dockerenv_marker_present(monkeypatch, tmp_path) -> None:
    marker = tmp_path / "dockerenv-present"
    marker.write_text("")
    monkeypatch.setattr(sandbox, "_DOCKERENV", marker)
    assert is_sandboxed() is True


# ─────────────────────────────────────────────────────────────────────────────
# require()
# ─────────────────────────────────────────────────────────────────────────────

def test_require_raises_with_no_sandbox_and_no_escape() -> None:
    with pytest.raises(SandboxError, match="VASH_SANDBOX"):
        require()


def test_require_raises_mentions_dangerously_no_sandbox_remedy() -> None:
    with pytest.raises(SandboxError, match="dangerously-no-sandbox"):
        require(allow_no_sandbox=False)


def test_require_returns_when_env_sandboxed(monkeypatch) -> None:
    monkeypatch.setenv("VASH_SANDBOX", "1")
    require()   # must not raise


def test_require_returns_when_dockerenv_present(monkeypatch, tmp_path) -> None:
    marker = tmp_path / "dockerenv-present"
    marker.write_text("")
    monkeypatch.setattr(sandbox, "_DOCKERENV", marker)
    require()   # must not raise


def test_require_returns_with_allow_no_sandbox_and_warns(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="vash.sandbox"):
        require(allow_no_sandbox=True)   # must not raise, even with no sandbox
    assert any(r.levelno >= logging.WARNING for r in caplog.records)
    assert "sandbox" in caplog.text.lower()


def test_require_allow_no_sandbox_wins_even_when_already_sandboxed(monkeypatch) -> None:
    # allow_no_sandbox short-circuits before the is_sandboxed() check —
    # harmless either way, but pins the documented precedence.
    monkeypatch.setenv("VASH_SANDBOX", "1")
    require(allow_no_sandbox=True)   # must not raise


# ─────────────────────────────────────────────────────────────────────────────
# run_remediate wiring — the --verify path must pass through sandbox.require()
# FIRST. Local helpers mirror tests/test_remediate.py's conventions (each
# test file owns its fixtures rather than cross-importing another module).
# ─────────────────────────────────────────────────────────────────────────────

def _write_policy(tmp_path: Path, **over) -> Path:
    base = {
        "schema_version": "1.0",
        "default_action": "allow",
        "deny": [],
        "allow": [],
        "kill_switch": {"env_var": "VASH_REMEDIATE_DISABLE_TEST_SANDBOX",
                        "file": str(tmp_path / ".vash-remediate-off")},
    }
    base.update(over)
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(base))
    return p


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


def _fake_run_agent_factory(payload: dict):
    async def fake_run_agent(*, user_input, artifact_dir, artifact_name, **_kw) -> AgentResult:
        # The patch agent now EDITS files in the disposable workspace and git
        # computes the diff, so a stub must edit to produce one.
        ws = Path(user_input["repo_path"])
        for rel in (user_input.get("editable_files") or []):
            t = ws / rel.split(":", 1)[0]
            t.parent.mkdir(parents=True, exist_ok=True)
            t.write_text("# patched\n" + (t.read_text() if t.is_file() else ""))
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
        "rationale": "confirmed for the purposes of this sandbox-gate test.",
        "validator_confidence": 0.9})
    db.assign_finding_group(fid, f"g_{fid}", True)


def _ctx(tmp_path: Path, run_id: str = "r1") -> StageContext:
    return StageContext(run_id=run_id, repo_path=tmp_path, config=load_config())


async def test_run_remediate_verify_no_sandbox_records_reason_failsoft(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    """No sandbox, no escape: the gate refuses. run_remediate does NOT raise
    (fail-soft) — patch generation is static and already happened — but the
    refusal reason (the SandboxError message) lands on the record, the
    gate-passed log line is never reached, and CRUCIALLY the verifier is never
    called: a refused gate must mean nothing ran."""
    monkeypatch.setattr(remediate_mod, "run_agent", _fake_run_agent_factory(PATCH_PAYLOAD))
    verify_calls: list[dict] = []
    monkeypatch.setattr(remediate_mod, "verify_patch", _stub_verifier(verify_calls))
    policy = _write_policy(tmp_path)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        with caplog.at_level(logging.INFO, logger="vash.stages.remediate"):
            summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                          policy_path=policy, verify=True,
                                          no_sandbox=False)
    finally:
        db.close()

    assert VERIFY_ENABLED_MSG not in caplog.text         # gate refused first
    assert "VASH_SANDBOX" in caplog.text                 # refusal reason logged
    assert verify_calls == []                            # nothing was executed

    rec = summary["records"][0]
    assert rec["status"] == "patched"                    # generation unaffected
    assert rec["needs_verification"] is True              # nothing executed
    assert "VASH_SANDBOX" in rec["risk_notes"]             # reason recorded per-finding
    assert (out / "patches" / "f_sqli_1.diff").is_file()   # static artifact still written
    assert summary["verify_executed"] is False


async def test_run_remediate_verify_dangerously_no_sandbox_reaches_verifier(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    """--dangerously-no-sandbox (no_sandbox=True): the gate passes (with a
    loud warning) and --verify proceeds to the verifier — no raise, no
    fail-soft reason recorded on the finding."""
    monkeypatch.setattr(remediate_mod, "run_agent", _fake_run_agent_factory(PATCH_PAYLOAD))
    verify_calls: list[dict] = []
    monkeypatch.setattr(remediate_mod, "verify_patch", _stub_verifier(verify_calls))
    policy = _write_policy(tmp_path)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        with caplog.at_level(logging.INFO):
            summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                          policy_path=policy, verify=True,
                                          no_sandbox=True)
    finally:
        db.close()

    assert VERIFY_ENABLED_MSG in caplog.text
    assert len(verify_calls) == 1                            # the verifier ran
    rec = summary["records"][0]
    # The stub verdict is not_attempted, which must NOT clear needs_verification.
    assert rec["needs_verification"] is True
    assert rec["risk_notes"] == PATCH_PAYLOAD["risk_notes"]   # untouched by the gate


async def test_run_remediate_verify_env_sandbox_reaches_verifier(
    tmp_path: Path, monkeypatch
) -> None:
    """VASH_SANDBOX=1 (is_sandboxed() alone, no_sandbox=False / default): the
    gate passes without needing the dev escape."""
    monkeypatch.setenv("VASH_SANDBOX", "1")
    monkeypatch.setattr(remediate_mod, "run_agent", _fake_run_agent_factory(PATCH_PAYLOAD))
    verify_calls: list[dict] = []
    monkeypatch.setattr(remediate_mod, "verify_patch", _stub_verifier(verify_calls))
    policy = _write_policy(tmp_path)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=policy, verify=True,
                                      no_sandbox=False)
    finally:
        db.close()

    assert len(verify_calls) == 1
    rec = summary["records"][0]
    assert rec["needs_verification"] is True
    assert rec["risk_notes"] == PATCH_PAYLOAD["risk_notes"]


async def test_run_remediate_no_verify_never_touches_sandbox_gate(
    tmp_path: Path, monkeypatch
) -> None:
    """verify=False (the default): the sandbox gate is not consulted at all
    — no_sandbox/VASH_SANDBOX are irrelevant when --verify wasn't requested —
    and nothing is executed."""
    monkeypatch.setattr(remediate_mod, "run_agent", _fake_run_agent_factory(PATCH_PAYLOAD))
    verify_calls: list[dict] = []
    monkeypatch.setattr(remediate_mod, "verify_patch", _stub_verifier(verify_calls))
    policy = _write_policy(tmp_path)
    out = tmp_path / "out"
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run(str(tmp_path), "r1")
        _seed_confirmed_canonical(db, "r1", "f_sqli_1")
        summary = await run_remediate(_ctx(tmp_path), db, out_dir=out,
                                      policy_path=policy)   # verify defaults False
    finally:
        db.close()

    rec = summary["records"][0]
    assert rec["risk_notes"] == PATCH_PAYLOAD["risk_notes"]   # no gate note added
    assert verify_calls == []                                 # and nothing ran
    assert summary["verify_executed"] is False


# ─────────────────────────────────────────────────────────────────────────────
# CLI wiring
# ─────────────────────────────────────────────────────────────────────────────

def test_cli_remediate_has_dangerously_no_sandbox_flag() -> None:
    from vash.cli import main
    params = {p.name for p in main.commands["remediate"].params}
    assert "no_sandbox" in params
