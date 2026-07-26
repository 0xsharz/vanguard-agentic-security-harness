"""Phase 2 build/verify/repair loop. Docker is faked — no test in this suite
runs a container."""
from pathlib import Path

import pytest

from vash.provision.build import (
    CommandResult,
    ProvisionResult,
    image_tag_for,
    provision_environment,
)


def _mk(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def _py_repo(tmp_path: Path) -> Path:
    return _mk(tmp_path, {"app.py": "x = 1\n", "requirements.txt": "requests\n"})


class FakeDocker:
    """Scripted docker: `build_results` are returned in order, then the last
    one repeats. Records every Dockerfile it was asked to build."""

    def __init__(self, build_results=None, run_results=None, available=True):
        self.build_results = list(build_results or [CommandResult(0, "ok")])
        self.run_results = list(run_results or [])
        self._available = available
        self.built_dockerfiles: list[str] = []
        self.built_tags: list[str] = []
        self.run_commands: list[str] = []
        self.run_networks: list[str] = []

    def available(self) -> bool:
        return self._available

    def build(self, *, context, dockerfile, tag, timeout):
        self.built_dockerfiles.append(dockerfile)
        self.built_tags.append(tag)
        i = min(len(self.built_dockerfiles) - 1, len(self.build_results) - 1)
        return self.build_results[i]

    def run(self, *, tag, command, workdir, timeout, network):
        self.run_commands.append(command)
        self.run_networks.append(network)
        if not self.run_results:
            return CommandResult(0, "ok")
        return self.run_results.pop(0)


# ---------------------------------------------------------------------------
# the no-Docker default
# ---------------------------------------------------------------------------

def test_build_false_is_the_default_and_never_touches_docker(tmp_path):
    client = FakeDocker()
    r = provision_environment(_py_repo(tmp_path), client=client)
    assert isinstance(r, ProvisionResult)
    assert r.status == "planned"
    assert r.dockerfile and "FROM python:" in r.dockerfile
    assert client.built_dockerfiles == []                # zero docker calls
    assert r.attempts == []


def test_no_known_ecosystem_is_skipped(tmp_path):
    client = FakeDocker()
    r = provision_environment(_mk(tmp_path, {"README.md": "hi\n"}),
                              build=True, client=client)
    assert r.status == "skipped"
    assert client.built_dockerfiles == []


def test_docker_unavailable_skips_fail_open(tmp_path):
    r = provision_environment(_py_repo(tmp_path), build=True,
                              client=FakeDocker(available=False))
    assert r.status == "skipped"
    assert any("docker unavailable" in n for n in r.notes)


# ---------------------------------------------------------------------------
# build + repair
# ---------------------------------------------------------------------------

def test_successful_first_build(tmp_path):
    client = FakeDocker([CommandResult(0, "Successfully built")])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client,
                              verify=False)
    assert r.status == "built"
    assert len(r.attempts) == 1
    assert r.attempts[0].ok and r.attempts[0].repair_rule is None
    assert r.image_tag == image_tag_for(tmp_path)
    assert client.built_tags == [r.image_tag]


def test_failed_build_is_repaired_then_succeeds(tmp_path):
    client = FakeDocker([
        CommandResult(1, "error: command 'gcc' failed with exit status 1"),
        CommandResult(0, "Successfully built"),
    ])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client,
                              verify=False)
    assert r.status == "built"
    assert len(r.attempts) == 2
    assert r.attempts[0].ok is False
    assert r.attempts[1].ok is True
    assert r.attempts[1].repair_rule == "missing_c_toolchain"
    # the SECOND build really was handed the repaired Dockerfile
    assert "build-essential" in client.built_dockerfiles[1]
    assert "build-essential" not in client.built_dockerfiles[0]
    assert any("repair[missing_c_toolchain]" in n for n in r.notes)


def test_repair_ladder_is_bounded_by_max_attempts(tmp_path):
    client = FakeDocker([CommandResult(1, "gcc: command not found")])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client,
                              verify=False, max_attempts=3)
    assert r.status == "failed"
    assert len(r.attempts) == 3
    assert len(client.built_dockerfiles) == 3
    assert any("failed after 3 attempt" in n for n in r.notes)


def test_a_rule_never_fires_twice_across_attempts(tmp_path):
    client = FakeDocker([CommandResult(1, "gcc: command not found")])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client,
                              verify=False, max_attempts=3)
    rules = [a.repair_rule for a in r.attempts if a.repair_rule]
    assert len(rules) == len(set(rules))
    assert rules[0] == "missing_c_toolchain"


def test_build_timeout_is_not_retried(tmp_path):
    client = FakeDocker([CommandResult(124, "…", timed_out=True)])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client,
                              verify=False, max_attempts=3)
    assert r.status == "failed"
    assert len(r.attempts) == 1                          # no repair retry
    assert r.attempts[0].timed_out
    assert any("timed out" in n for n in r.notes)


def test_existing_repo_dockerfile_is_read_not_templated(tmp_path):
    repo = _mk(tmp_path, {
        "app.py": "x=1\n", "requirements.txt": "requests\n",
        "Dockerfile": "FROM python:3.12-slim\nRUN echo mine\n",
    })
    client = FakeDocker([CommandResult(0, "ok")])
    r = provision_environment(repo, build=True, client=client, verify=False)
    assert r.source == "existing"
    assert r.status == "built"
    assert "RUN echo mine" in client.built_dockerfiles[0]


def test_target_repo_is_never_modified(tmp_path):
    """A repaired Dockerfile is fed to `docker build` on stdin — it must never
    be written back into the target tree."""
    repo = _mk(tmp_path, {
        "app.py": "x=1\n", "requirements.txt": "requests\n",
        "Dockerfile": "FROM python:3.11-slim\nRUN pip install -r requirements.txt\n",
    })
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    client = FakeDocker([
        CommandResult(1, "gcc: command not found"),
        CommandResult(0, "ok"),
    ])
    provision_environment(repo, build=True, client=client, verify=False)
    after = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    assert after == before


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def test_verify_runs_deps_then_build_then_test_offline(tmp_path):
    client = FakeDocker([CommandResult(0, "ok")],
                        run_results=[CommandResult(0, "deps"), CommandResult(0, "built"),
                                     CommandResult(0, "tests")])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client)
    assert r.verify is not None and r.verify.ran
    assert r.verify.deps_ok is True
    assert r.verify.build_ok is True and r.verify.test_ok is True
    assert len(client.run_commands) == 3
    assert client.run_commands[0].startswith("[ -f requirements.txt ]")   # deps probe first
    assert client.run_networks == ["none"] * 3           # verification is offline


def test_missing_dependencies_are_reported_even_though_the_image_built(tmp_path):
    """The image can build with `|| true` install steps — the deps probe is
    what stops that being reported as a usable environment."""
    client = FakeDocker([CommandResult(0, "ok")],
                        run_results=[CommandResult(1, "MISSING DEPENDENCIES: requests"),
                                     CommandResult(0, ""), CommandResult(0, "")])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client)
    assert r.status == "built"                           # the image still exists
    assert r.verify.deps_ok is False
    assert any("dependencies are NOT installed" in n and "INCOMPLETE" in n
               for n in r.notes)
    assert "INCOMPLETE" in r.agent_summary()["environment_caveat"]


def test_failed_verify_build_is_flagged_as_incomplete(tmp_path):
    client = FakeDocker([CommandResult(0, "ok")],
                        run_results=[CommandResult(0, ""), CommandResult(1, "ImportError"),
                                     CommandResult(0, "")])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client)
    assert r.status == "built"                           # the image still exists
    assert r.verify.build_ok is False
    assert any("INCOMPLETE" in n for n in r.notes)


def test_verify_is_skipped_for_an_existing_recipe_with_no_known_commands(tmp_path):
    repo = _mk(tmp_path, {"app.py": "1\n", "requirements.txt": "r\n",
                          "Dockerfile": "FROM python:3.11-slim\n"})
    client = FakeDocker([CommandResult(0, "ok")])
    r = provision_environment(repo, build=True, client=client)
    assert r.status == "built"
    assert r.verify is None
    assert client.run_commands == []


# ---------------------------------------------------------------------------
# the agent-facing summary
# ---------------------------------------------------------------------------

def test_agent_summary_is_small_and_carries_no_logs(tmp_path):
    client = FakeDocker([CommandResult(0, "ok" * 5000)])
    r = provision_environment(_py_repo(tmp_path), build=True, client=client,
                              verify=False)
    s = r.agent_summary()
    assert s["primary_language"] == "python"
    assert s["provisioning_status"] == "built"
    assert s["image_tag"] == r.image_tag
    assert "dockerfile" not in s and "attempts" not in s and "notes" not in s
    assert len(str(s)) < 1000


def test_agent_summary_surfaces_an_incomplete_environment(tmp_path):
    # a node repo: its install step (`npm ci || npm install`) is still fatal,
    # so the catch-all rung can soften it. (The pip template already ends in
    # `|| true`, which is why this case uses node.)
    repo = _mk(tmp_path, {"app.js": "1\n", "package.json": "{}"})
    client = FakeDocker([
        CommandResult(1, "totally unrecognised failure"),
        CommandResult(0, "ok"),
    ])
    r = provision_environment(repo, build=True, client=client, verify=False)
    assert r.attempts[1].repair_rule == "soften_install_step"
    assert "INCOMPLETE" in r.agent_summary()["environment_caveat"]


def test_result_is_json_serialisable(tmp_path):
    import json
    r = provision_environment(_py_repo(tmp_path), client=FakeDocker())
    assert json.loads(json.dumps(r.to_dict()))["status"] == "planned"


@pytest.mark.parametrize("name,expected", [
    ("My Repo", "vash-env-my-repo:latest"),
    ("dmcg-src", "vash-env-dmcg-src:latest"),
    ("...", "vash-env-target:latest"),
])
def test_image_tags_are_docker_legal(tmp_path, name, expected):
    assert image_tag_for(tmp_path / name) == expected
