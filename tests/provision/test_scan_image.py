"""The scan image: VASH layered onto the Phase 2 provisioned image, so PoCs
run in the target's own environment. Docker is faked — no test builds an image."""
from pathlib import Path

import pytest

from vash.provision.build import CommandResult
from vash.provision.scan_image import (
    VENV,
    ScanImageResult,
    build_scan_image,
    render_scan_dockerfile,
    scan_image_tag_for,
)


class FakeDocker:
    def __init__(self, result=None, available=True):
        self.result = result or CommandResult(0, "ok")
        self._available = available
        self.contexts: list[Path] = []
        self.dockerfiles: list[str] = []
        self.tags: list[str] = []

    def available(self):
        return self._available

    def build(self, *, context, dockerfile, tag, timeout):
        self.contexts.append(context)
        self.dockerfiles.append(dockerfile)
        self.tags.append(tag)
        return self.result

    def run(self, **kw):                      # pragma: no cover - unused here
        raise AssertionError("scan image build must not run containers")


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def test_layers_on_the_provisioned_image():
    df = render_scan_dockerfile("vash-env-acme:latest")
    assert df.splitlines()[2].startswith("FROM vash-env-acme:latest") or \
        "FROM vash-env-acme:latest" in df


def test_vash_venv_is_never_put_on_path():
    """The load-bearing lesson: if VASH's venv is on PATH, `python3` resolves to
    VASH's interpreter and every Python PoC loses sight of the target's code."""
    df = render_scan_dockerfile("vash-env-acme:latest")
    assert f"ENV PATH={VENV}" not in df
    assert f'PATH={VENV}/bin:$PATH' not in df
    # ...and VASH is therefore invoked by absolute path
    assert f'ENTRYPOINT ["{VENV}/bin/vash"]' in df


def test_ships_the_claude_cli_because_the_sdk_shells_out_to_it():
    df = render_scan_dockerfile("vash-env-acme:latest")
    assert "@anthropic-ai/claude-code" in df
    assert "claude --version" in df           # build-time proof it landed


def test_handles_a_base_image_with_no_usable_python():
    """maven/temurin and golang bases have no python 3.11 — uv supplies one."""
    df = render_scan_dockerfile("maven:3.9-eclipse-temurin-21")
    assert "astral.sh/uv/install.sh" in df
    assert "uv python install 3.11" in df
    assert "python3 -m venv" in df            # the fast path is still preferred


def test_marks_itself_as_a_sandbox():
    assert "ENV VASH_SANDBOX=1" in render_scan_dockerfile("x:1")


def test_installs_the_prompts_and_schemas_vash_needs_at_runtime():
    df = render_scan_dockerfile("x:1")
    for payload in ("vash", "prompts", "schemas", "config"):
        assert f"COPY {payload} ./{payload}" in df


def test_render_is_deterministic():
    assert render_scan_dockerfile("x:1") == render_scan_dockerfile("x:1")


@pytest.mark.parametrize("name,expected", [
    ("vuln-py", "vash-scan-vuln-py:latest"),
    ("My Target", "vash-scan-my-target:latest"),
    ("...", "vash-scan-target:latest"),
])
def test_scan_image_tags_are_docker_legal(tmp_path, name, expected):
    assert scan_image_tag_for(tmp_path / name) == expected


# ---------------------------------------------------------------------------
# building
# ---------------------------------------------------------------------------

def test_build_uses_the_vash_source_as_context_not_the_target(tmp_path):
    """The target is already baked into base_image; what gets installed here is
    VASH itself, so the build context must be the VASH checkout."""
    client = FakeDocker()
    vash_src = tmp_path / "vash-checkout"
    vash_src.mkdir()
    r = build_scan_image(tmp_path / "target", base_image="vash-env-t:latest",
                         client=client, vash_source=vash_src)
    assert r.status == "built"
    assert client.contexts == [vash_src]
    assert client.tags == ["vash-scan-target:latest"]


def test_build_failure_is_fail_soft_and_explains_the_consequence(tmp_path):
    client = FakeDocker(CommandResult(1, "no space left on device"))
    r = build_scan_image(tmp_path / "t", base_image="b:1", client=client)
    assert isinstance(r, ScanImageResult)
    assert r.status == "failed"
    assert r.exit_code == 1
    assert any("toolchain" in n for n in r.notes)   # says what is lost
    assert "no space left" in r.log_tail


def test_docker_unavailable_is_skipped_not_an_error(tmp_path):
    r = build_scan_image(tmp_path / "t", base_image="b:1",
                         client=FakeDocker(available=False))
    assert r.status == "skipped"
    assert client_note(r, "docker unavailable")


def test_result_is_json_serialisable(tmp_path):
    import json
    r = build_scan_image(tmp_path / "t", base_image="b:1", client=FakeDocker())
    assert json.loads(json.dumps(r.to_dict()))["status"] == "built"


def client_note(result, fragment: str) -> bool:
    return any(fragment in n for n in result.notes)


def test_venv_probe_actually_attempts_a_venv_not_just_a_version_check():
    """Debian bases (node:20, golang:1.22) ship a python3.11 whose `venv` is
    broken until python3-venv is installed. A version-only probe took the fast
    path and the build died with 'you need to install the python3-venv
    package' — observed on the real node target."""
    df = render_scan_dockerfile("node:20")
    assert "python3 -m venv /tmp/vash-venv-probe" in df
    probe_at = df.index("/tmp/vash-venv-probe")
    real_at = df.index(f"python3 -m venv {VENV}")
    assert probe_at < real_at            # probe gates the real creation


def test_ships_strace_for_the_compiled_language_observer():
    """A compiled Go binary has no in-process hook, so its only observer is
    syscall-level. strace is absent from every base image we build on — without
    it, Go PoCs run with no observer at all (verified in the real go image)."""
    assert "strace" in render_scan_dockerfile("golang:1.22")


def test_node_setup_guards_on_npm_not_node():
    """The next line runs `npm`, so the guard must test for npm.

    Testing the proxy broke a real build: on a `FROM python:3` (Debian trixie)
    base the nodesource setup script does not support the release, apt fell
    through to Debian's `nodejs` package — which ships npm SEPARATELY — and the
    build died on `npm: not found` with `node` sitting right there satisfying
    the guard.
    """
    from vash.provision.scan_image import _NODE_SETUP
    assert "command -v npm" in _NODE_SETUP
    # a fallback that does not depend on nodesource supporting the distro
    assert "install -y --no-install-recommends npm" in _NODE_SETUP
    # and the image proves all three exist rather than assuming
    assert "npm --version" in _NODE_SETUP
    assert "claude --version" in _NODE_SETUP
