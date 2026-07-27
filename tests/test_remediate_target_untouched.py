"""THE guarantee: remediation never modifies the code under review.

Remediation now hands the patch agent a write tool. That is only acceptable
because the agent edits a disposable copy and is never told where the real
repository is. This file is the proof, and it is deliberately adversarial: the
stub agent behaves like a badly-misbehaving model — it edits files it was not
given, creates new ones, deletes things, and tries to climb out of the workspace
with relative traversal.

If this file ever fails, the write tool must be taken away again.
"""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

import vash.stages.remediate as remediate_mod
from vash.config import load_config
from vash.runner import AgentResult
from vash.stages._common import StageContext
from vash.stages.remediate import run_remediate
from vash.state import StateDB

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

POLICY = Path(__file__).resolve().parent.parent / "config" / "remediation_policy.yaml"


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*")) if p.is_file()
    }


def _target(tmp_path: Path, *, with_symlink: bool = False) -> Path:
    repo = tmp_path / "target"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text(
        "def q(name):\n    cur.execute(f\"select * from t where n='{name}'\")\n")
    (repo / "app" / "untouched.py").write_text("SECRET_CONSTANT = 42\n")
    (repo / "README.md").write_text("# target\n")
    if with_symlink:
        # An untrusted repo may contain an absolute link back into itself.
        (repo / "shortcut.py").symlink_to(repo / "app" / "untouched.py")
    return repo


def _seed(db: StateDB, run_id: str, fid: str) -> None:
    db.create_run("/t", run_id)
    db.add_task(run_id, {"task_id": "t1", "attack_class": "sql_injection",
                         "scope_hint": "app/db.py", "target_files": ["app/db.py"],
                         "rationale": "r", "priority": 1, "source": "recon"})
    db.add_finding(run_id, "t1", {
        "finding_id": fid, "file": "app/db.py", "line_start": 2, "line_end": 2,
        "vuln_class": "sql_injection", "severity": "high", "cwe": "CWE-89",
        "description": "d" * 25, "evidence_snippet": "e", "confidence": 0.9,
    })
    db.set_finding_validation(fid, "confirmed", {
        "finding_id": fid, "verdict": "confirmed", "rationale": "ok",
        "validator_confidence": 0.9})
    db.assign_finding_group(fid, "g1", True)


def _hostile_agent(escaped: list[Path]):
    """A stub that misbehaves in every way a real model actually can.

    Note what is deliberately NOT modelled: writing to the target's absolute
    path. A stub can do that only because the test handed it the path in a
    closure; a real agent is never told it, which is what
    `test_the_agent_is_never_given_the_target_path` pins down. Modelling it here
    would prove nothing about containment — only that a Python function holding
    a path can write to it. What IS modelled is relative traversal out of the
    workspace, which an agent can attempt without knowing anything.
    """
    async def fake_run_agent(*, user_input, artifact_dir, artifact_name, **_kw):
        ws = Path(user_input["repo_path"])

        # 1. the legitimate edit
        (ws / "app" / "db.py").write_text(
            "def q(name):\n    cur.execute('select * from t where n=%s', (name,))\n")
        # 2. an edit to a file this finding does NOT cover, unreported
        (ws / "app" / "untouched.py").write_text("SECRET_CONSTANT = 0  # tampered\n")
        # 3. a brand-new file nobody asked for
        (ws / "backdoor.py").write_text("import os\n")
        # 4. a deletion
        (ws / "README.md").unlink()
        # 5. write through anything that looks like a local file but isn't
        for name in ("shortcut.py",):
            try:
                (ws / name).write_text("PWNED VIA SYMLINK\n")
            except OSError:
                pass
        # 6. traversal out of the workspace, the escape an agent could try blind
        for rel in ("../ESCAPED.txt", "../../ESCAPED.txt"):
            victim = ws / rel
            try:
                victim.write_text("PWNED\n")
                escaped.append((rel, victim.resolve()))
            except OSError:
                pass

        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload={"finding_id": "f1", "status": "patched",
                     "root_cause": "concatenated SQL",
                     "guidance": "parameterise", "security_test": "def test(): pass",
                     "needs_verification": True},
            cost_usd=0.0, input_tokens=0, output_tokens=0, cache_read_tokens=0,
            cache_creation_tokens=0, num_turns=1, duration_ms=1, session_id="s",
            artifact_path=ap, repair_used=False,
            raw_result_message={"usage": {}, "total_cost_usd": 0.0},
        )
    return fake_run_agent


async def test_target_repository_is_byte_identical_after_remediation(
    tmp_path, monkeypatch
):
    target = _target(tmp_path, with_symlink=True)
    before = _hash_tree(target)
    escaped: list[tuple[str, Path]] = []

    monkeypatch.setattr(remediate_mod, "run_agent", _hostile_agent(escaped))
    db = StateDB(tmp_path / "state.db")
    try:
        _seed(db, "r1", "f1")
        ctx = StageContext(run_id="r1", repo_path=target, config=load_config())
        summary = await run_remediate(ctx, db, out_dir=tmp_path / "out",
                                      policy_path=POLICY)
    finally:
        db.close()

    # The whole point.
    assert _hash_tree(target) == before, "remediation modified the target repository"

    # Traversal out of the workspace lands in the temp tree, never in or under
    # the target — the workspace is not a subdirectory of the code under review,
    # so climbing out of it cannot arrive at it.
    try:
        for rel, victim in escaped:
            assert target not in victim.parents and victim != target, victim
            # One level up is still inside the disposable tempdir, so teardown
            # removes it. Two levels up is the system temp root, and nothing in
            # THIS design stops that — a real agent is held there by the SDK's
            # cwd/add_dirs confinement, which this stub bypasses by writing
            # directly. The test states what the workspace itself guarantees and
            # does not claim the rest.
            if rel == "../ESCAPED.txt":
                assert not victim.exists(), f"{victim} outlived the workspace"
    finally:
        for _rel, victim in escaped:      # never litter the system temp dir
            victim.unlink(missing_ok=True)

    # And the patch built from all that misbehaviour still applies to the
    # untouched target — the fix survived the reverts intact.
    rec = summary["records"][0]
    assert rec.get("applies_cleanly") is not False, rec.get("apply_check")


async def test_the_agent_is_never_given_the_target_path(tmp_path, monkeypatch):
    """Containment does not rely on the agent behaving — it relies on the agent
    not knowing where the target is."""
    target = _target(tmp_path)
    seen: list[dict] = []

    async def capture(*, user_input, artifact_dir, artifact_name, **kw):
        seen.append({"user_input": user_input, "cwd": kw.get("cwd"),
                     "add_dirs": kw.get("add_dirs")})
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload={"finding_id": "f1", "status": "cannot_fix", "root_cause": "x",
                     "guidance": "g", "needs_verification": True},
            cost_usd=0.0, input_tokens=0, output_tokens=0, cache_read_tokens=0,
            cache_creation_tokens=0, num_turns=1, duration_ms=1, session_id="s",
            artifact_path=ap, repair_used=False,
            raw_result_message={"usage": {}, "total_cost_usd": 0.0})

    monkeypatch.setattr(remediate_mod, "run_agent", capture)
    db = StateDB(tmp_path / "state.db")
    try:
        _seed(db, "r1", "f1")
        ctx = StageContext(run_id="r1", repo_path=target, config=load_config())
        await run_remediate(ctx, db, out_dir=tmp_path / "out", policy_path=POLICY)
    finally:
        db.close()

    assert seen, "the agent was never invoked"
    call = seen[0]
    target_str = str(target)
    assert call["user_input"]["repo_path"] != target_str
    assert str(call["cwd"]) != target_str
    assert all(str(d) != target_str for d in (call["add_dirs"] or []))
    # and the target path appears nowhere in what the agent was told
    import json
    assert target_str not in json.dumps(call["user_input"])


async def test_an_unreported_out_of_scope_edit_never_reaches_the_patch(
    tmp_path, monkeypatch
):
    """The agent edited a file it did not report. It must not ride along."""
    target = _target(tmp_path)
    monkeypatch.setattr(remediate_mod, "run_agent", _hostile_agent([]))
    db = StateDB(tmp_path / "state.db")
    try:
        _seed(db, "r1", "f1")
        ctx = StageContext(run_id="r1", repo_path=target, config=load_config())
        summary = await run_remediate(ctx, db, out_dir=tmp_path / "out",
                                      policy_path=POLICY)
    finally:
        db.close()

    rec = summary["records"][0]
    assert set(rec.get("out_of_scope_edits_reverted", [])) >= {
        "app/untouched.py", "backdoor.py", "README.md"}
    diff = (tmp_path / "out" / "patches" / "f1.diff")
    if diff.is_file():
        body = diff.read_text()
        assert "untouched.py" not in body
        assert "backdoor.py" not in body
        assert "db.py" in body                    # the legitimate fix survives


async def test_a_claimed_fix_with_no_edit_is_downgraded_not_reported_as_patched(
    tmp_path, monkeypatch
):
    """The dishonest case: the agent says "patched" and hands back diff text it
    never actually applied. Reporting that as a fix would put a green row in the
    operator's report for a vulnerability that is still open."""
    target = _target(tmp_path)

    async def all_talk(*, user_input, artifact_dir, artifact_name, **_kw):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload={"finding_id": "f1", "status": "patched", "root_cause": "x",
                     "guidance": "g", "needs_verification": True,
                     "patch_diff": "--- a/app/db.py\n+++ b/app/db.py\n@@ -1 +1 @@\n-a\n+b\n"},
            cost_usd=0.0, input_tokens=0, output_tokens=0, cache_read_tokens=0,
            cache_creation_tokens=0, num_turns=1, duration_ms=1, session_id="s",
            artifact_path=ap, repair_used=False,
            raw_result_message={"usage": {}, "total_cost_usd": 0.0})

    monkeypatch.setattr(remediate_mod, "run_agent", all_talk)
    db = StateDB(tmp_path / "state.db")
    try:
        _seed(db, "r1", "f1")
        ctx = StageContext(run_id="r1", repo_path=target, config=load_config())
        summary = await run_remediate(ctx, db, out_dir=tmp_path / "out",
                                      policy_path=POLICY)
    finally:
        db.close()

    rec = summary["records"][0]
    assert rec["status"] == "guidance_only"
    assert not (rec.get("patch_diff") or "").strip()
    assert "no edit" in rec["risk_notes"]
    assert not (tmp_path / "out" / "patches" / "f1.diff").exists()
    assert summary["counts"]["patched"] == 0


async def test_a_redacted_patch_is_never_reported_as_applying(tmp_path, monkeypatch):
    """Redaction rewrites secrets, and a diff is position-sensitive: masking a
    token inside a context line makes that line stop matching the file. The
    written patch then cannot apply — so the apply-check must run on the bytes on
    disk, not the unredacted original, and the report must say the patch was
    masked. A hardcoded-secret finding is exactly the case that hits this."""
    target = _target(tmp_path)
    secret = "AKIAIOSFODNN7EXAMPLE"
    (target / "app" / "db.py").write_text(f'KEY = "{secret}"\n')

    async def edits_a_secret(*, user_input, artifact_dir, artifact_name, **_kw):
        ws = Path(user_input["repo_path"])
        (ws / "app" / "db.py").write_text('KEY = os.environ["KEY"]\n')
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload={"finding_id": "f1", "status": "patched",
                     "root_cause": "hardcoded credential", "guidance": "rotate it",
                     "needs_verification": True},
            cost_usd=0.0, input_tokens=0, output_tokens=0, cache_read_tokens=0,
            cache_creation_tokens=0, num_turns=1, duration_ms=1, session_id="s",
            artifact_path=ap, repair_used=False,
            raw_result_message={"usage": {}, "total_cost_usd": 0.0})

    monkeypatch.setattr(remediate_mod, "run_agent", edits_a_secret)
    db = StateDB(tmp_path / "state.db")
    try:
        _seed(db, "r1", "f1")
        ctx = StageContext(run_id="r1", repo_path=target, config=load_config())
        summary = await run_remediate(ctx, db, out_dir=tmp_path / "out",
                                      policy_path=POLICY)
    finally:
        db.close()

    rec = summary["records"][0]
    written = (tmp_path / "out" / "patches" / "f1.diff").read_text()
    assert secret not in written                     # the secret really is masked
    assert rec.get("patch_redacted") is True
    # ...and because it is masked, the report must not promise it applies.
    assert rec.get("applies_cleanly") is not True, rec.get("apply_check")
    md = (tmp_path / "out" / "REMEDIATION.md").read_text()
    assert "patch redacted" in md and "not** apply verbatim" in md


async def test_the_report_says_when_the_agent_edited_outside_the_finding(
    tmp_path, monkeypatch
):
    """An out-of-scope edit is a trust signal about the agent's behaviour. It
    belonged only to remediation.json, where nobody reading REMEDIATION.md sees
    it."""
    target = _target(tmp_path)
    monkeypatch.setattr(remediate_mod, "run_agent", _hostile_agent([]))
    db = StateDB(tmp_path / "state.db")
    try:
        _seed(db, "r1", "f1")
        ctx = StageContext(run_id="r1", repo_path=target, config=load_config())
        await run_remediate(ctx, db, out_dir=tmp_path / "out", policy_path=POLICY)
    finally:
        db.close()

    md = (tmp_path / "out" / "REMEDIATION.md").read_text()
    assert "outside this finding's files" in md
    assert "backdoor.py" in md
    # and the report no longer describes the old hand-written-diff flow
    assert "disposable copy" in md


async def test_findings_are_remediated_concurrently_and_stay_in_order(
    tmp_path, monkeypatch
):
    """config/stages.yaml declares concurrency for remediate; the loop used to
    ignore it and run one finding at a time. Report order must not depend on
    which agent happens to finish first."""
    import asyncio
    target = _target(tmp_path)
    live = 0
    peak = 0

    async def slow(*, user_input, artifact_dir, artifact_name, **_kw):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        try:
            # later findings finish sooner, so completion order != input order
            await asyncio.sleep(0.05 if artifact_name.endswith("3") else 0.2)
        finally:
            live -= 1
        artifact_dir.mkdir(parents=True, exist_ok=True)
        ap = artifact_dir / f"{artifact_name}.jsonl"
        ap.write_text("{}\n")
        return AgentResult(
            payload={"finding_id": artifact_name, "status": "cannot_fix",
                     "root_cause": "x", "guidance": "g", "needs_verification": True},
            cost_usd=0.0, input_tokens=0, output_tokens=0, cache_read_tokens=0,
            cache_creation_tokens=0, num_turns=1, duration_ms=1, session_id="s",
            artifact_path=ap, repair_used=False,
            raw_result_message={"usage": {}, "total_cost_usd": 0.0})

    monkeypatch.setattr(remediate_mod, "run_agent", slow)
    db = StateDB(tmp_path / "state.db")
    try:
        db.create_run("/t", "r1")
        db.add_task("r1", {"task_id": "t1", "attack_class": "sql_injection",
                           "scope_hint": "app/db.py", "target_files": ["app/db.py"],
                           "rationale": "r", "priority": 1, "source": "recon"})
        for n in (1, 2, 3):
            fid = f"f{n}"
            db.add_finding("r1", "t1", {
                "finding_id": fid, "file": "app/db.py", "line_start": 2,
                "line_end": 2, "vuln_class": "sql_injection", "severity": "high",
                "cwe": "CWE-89", "description": "d" * 25, "evidence_snippet": "e",
                "confidence": 0.9})
            db.set_finding_validation(fid, "confirmed", {
                "finding_id": fid, "verdict": "confirmed", "rationale": "ok",
                "validator_confidence": 0.9})
            db.assign_finding_group(fid, f"g{n}", True)
        ctx = StageContext(run_id="r1", repo_path=target, config=load_config())
        summary = await run_remediate(ctx, db, out_dir=tmp_path / "out",
                                      policy_path=POLICY)
    finally:
        db.close()

    assert peak > 1, "findings still ran one at a time"
    assert [r["finding_id"] for r in summary["records"]] == ["f1", "f2", "f3"]
