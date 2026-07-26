"""The pre-recon provisioning stage (Phase 2 wiring): artifact, agent context,
and the fail-open contract. No Docker — `build=False` is the default path and
the failure cases are injected."""
import json

import pytest

from vash.config import load_config
from vash.orchestrator import _provision_environment
from vash.stages._common import StageContext
from vash.state import StateDB


@pytest.fixture()
def repo(tmp_path):
    d = tmp_path / "target"
    (d / "pkg").mkdir(parents=True)
    (d / "pkg" / "app.py").write_text("x = 1\n")
    (d / "requirements.txt").write_text("requests\n")
    return d


@pytest.fixture()
def db(tmp_path, repo):
    d = StateDB(tmp_path / "state.db")
    d.create_run(str(repo), "r_prov")
    yield d
    d.close()


def _ctx(repo):
    return StageContext(run_id="r_prov", repo_path=repo, config=load_config())


def test_stage_sets_agent_context_and_writes_the_artifact(repo, db):
    ctx = _ctx(repo)
    _provision_environment(ctx, db, build=False)

    assert ctx.project_env is not None
    assert ctx.project_env["primary_language"] == "python"
    assert ctx.project_env["provisioning_status"] == "planned"
    assert "pip" in ctx.project_env["build_systems"]

    out = ctx.results_dir("provision") / "provision.json"
    assert out.exists()
    record = json.loads(out.read_text())
    assert record["status"] == "planned"
    assert "FROM python:" in record["dockerfile"]
    # the full record keeps what the agent summary drops
    assert "attempts" in record and "fingerprint" in record


def test_environment_facts_reach_every_agent_via_extras(repo, db):
    ctx = _ctx(repo)
    assert ctx.extras() == {}                       # nothing before the stage
    _provision_environment(ctx, db, build=False)
    assert ctx.extras()["project_environment"]["primary_language"] == "python"


def test_default_pipeline_path_never_calls_docker(repo, db, monkeypatch):
    """build=False must not construct a Docker client at all."""
    import vash.provision.build as pb

    def _boom(*a, **k):
        raise AssertionError("docker must not be touched when build=False")

    monkeypatch.setattr(pb.SubprocessDocker, "available", _boom)
    _provision_environment(_ctx(repo), db, build=False)


def test_stage_is_fail_open(repo, db, monkeypatch):
    """A provisioning explosion degrades the run, it never aborts it."""
    import vash.provision as prov

    monkeypatch.setattr(prov, "provision_environment",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    ctx = _ctx(repo)
    _provision_environment(ctx, db, build=False)     # must not raise
    assert ctx.project_env is None                   # and stays harmless


def test_artifact_is_registered_in_the_run_db(repo, db):
    _provision_environment(_ctx(repo), db, build=False)
    rows = db._conn.execute(
        "SELECT stage, kind, path FROM artifacts WHERE run_id = ?", ("r_prov",)
    ).fetchall()
    assert [r["stage"] for r in rows] == ["provision"]
    assert rows[0]["kind"] == "provision"
    assert rows[0]["path"].endswith("provision.json")


def test_unrecognised_repo_still_produces_a_harmless_summary(tmp_path, db):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "README.md").write_text("hi\n")
    ctx = StageContext(run_id="r_prov", repo_path=plain, config=load_config())
    _provision_environment(ctx, db, build=False)
    assert ctx.project_env["provisioning_status"] == "skipped"
    assert ctx.project_env["languages"] == []
