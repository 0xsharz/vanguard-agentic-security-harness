"""Phase 2 provisioning: BUILD the rendered recipe, VERIFY it, REPAIR and retry.

Phase 1 (`fingerprint.py` + `dockerfile.py`) is text-only. This module is the
part that actually talks to Docker:

    fingerprint -> render -> [ docker build -> repair -> retry ]* -> verify

**Isolation stance.** Building a target's environment means running that
target's own build instructions (`npm ci` runs postinstall scripts, `mvn
package` runs plugins). VASH therefore NEVER runs them on the host: every
command issued here executes inside a container, and the verify step runs with
``--network none``, dropped privileges and cpu/memory/pid caps. Provisioning
is additionally **opt-in** (`vash run --provision` / `vash provision --build`)
— it never happens implicitly.

The Docker calls sit behind the small :class:`DockerClient` protocol so the
whole loop — including every repair rung — is unit-tested offline with a fake
client. No test in the suite runs Docker.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

from vash.provision.dockerfile import RenderedRecipe, render_dockerfile
from vash.provision.fingerprint import ProjectFingerprint, fingerprint
from vash.provision.repair import repair_dockerfile

log = logging.getLogger(__name__)

DEFAULT_BUILD_TIMEOUT = 900       # seconds — a cold base-image pull is slow
DEFAULT_VERIFY_TIMEOUT = 600
DEFAULT_MAX_ATTEMPTS = 3          # 1 build + at most 2 repairs
LOG_TAIL_CHARS = 4000             # what we keep of a (possibly huge) build log

# Container resource caps for the verify step. Deliberately modest: verification
# only needs to prove the environment is usable, not to be fast.
VERIFY_MEMORY = "4g"
VERIFY_CPUS = "2"
VERIFY_PIDS = "512"


def _tail(text: str, limit: int = LOG_TAIL_CHARS) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return "...[truncated]...\n" + text[-limit:]


@dataclass
class CommandResult:
    exit_code: int
    log: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class DockerClient(Protocol):
    """Everything this module needs from Docker (fakeable in tests)."""

    def available(self) -> bool: ...

    def build(self, *, context: Path, dockerfile: str, tag: str,
              timeout: int) -> CommandResult: ...

    def run(self, *, tag: str, command: str, workdir: str, timeout: int,
            network: str) -> CommandResult: ...


class SubprocessDocker:
    """The real client: shells out to the `docker` CLI.

    Shelling out (rather than adding the `docker` SDK) keeps the dependency
    set unchanged and matches how VASH already invokes `graphify`.
    """

    def __init__(self, binary: str = "docker") -> None:
        self.binary = binary

    def available(self) -> bool:
        """True only if the CLI exists AND the daemon answers."""
        if shutil.which(self.binary) is None:
            return False
        try:
            p = subprocess.run(
                [self.binary, "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return p.returncode == 0 and bool(p.stdout.strip())

    def _exec(self, argv: list[str], *, timeout: int,
              stdin: str | None = None) -> CommandResult:
        try:
            p = subprocess.run(
                argv, input=stdin, capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "") if isinstance(e.stdout, str) else ""
            err = (e.stderr or "") if isinstance(e.stderr, str) else ""
            return CommandResult(exit_code=124, log=_tail(out + err), timed_out=True)
        except OSError as e:
            return CommandResult(exit_code=127, log=f"{type(e).__name__}: {e}")
        return CommandResult(exit_code=p.returncode, log=_tail(p.stdout + p.stderr))

    def build(self, *, context: Path, dockerfile: str, tag: str,
              timeout: int) -> CommandResult:
        # `-f -` feeds the Dockerfile on stdin, so a repaired Dockerfile is
        # never written into the target repo (the target tree stays read-only).
        return self._exec(
            [self.binary, "build", "--tag", tag, "--file", "-", str(context)],
            timeout=timeout, stdin=dockerfile,
        )

    def run(self, *, tag: str, command: str, workdir: str, timeout: int,
            network: str) -> CommandResult:
        return self._exec(
            [
                self.binary, "run", "--rm",
                "--network", network,
                "--memory", VERIFY_MEMORY,
                "--cpus", VERIFY_CPUS,
                "--pids-limit", VERIFY_PIDS,
                "--security-opt", "no-new-privileges",
                "--workdir", workdir,
                "--entrypoint", "/bin/sh",
                tag, "-c", command,
            ],
            timeout=timeout,
        )


# ---------------------------------------------------------------------------
# result records
# ---------------------------------------------------------------------------

@dataclass
class BuildAttempt:
    attempt: int
    ok: bool
    exit_code: int
    timed_out: bool = False
    # the repair rule applied to produce THIS attempt's Dockerfile
    # (None for the first attempt, which uses the rendered recipe as-is).
    repair_rule: str | None = None
    log_tail: str = ""


@dataclass
class VerifyResult:
    ran: bool = False
    build_ok: bool | None = None
    build_log_tail: str = ""
    test_ok: bool | None = None
    test_log_tail: str = ""
    # dependency-presence probe (see RenderedRecipe.deps_cmd): False means the
    # image built but the target's declared dependencies are NOT installed.
    deps_ok: bool | None = None
    deps_log_tail: str = ""


@dataclass
class ProvisionResult:
    # planned        : recipe rendered, no Docker asked for (the default `vash run`)
    # preprovisioned : already running inside the target's scan image — the
    #                  toolchain and the target's deps are present in THIS container
    # built   : image exists
    # failed  : Docker tried and the repair ladder was exhausted
    # skipped : nothing to build (no known ecosystem / Docker unavailable)
    status: str = "skipped"
    source: str = "none"                 # existing | template | none
    image_tag: str | None = None
    dockerfile: str | None = None
    build_cmd: str | None = None
    test_cmd: str | None = None
    fingerprint: dict = field(default_factory=dict)
    attempts: list[BuildAttempt] = field(default_factory=list)
    verify: VerifyResult | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def agent_summary(self) -> dict:
        """The compact environment facts worth putting in front of an agent.

        Deliberately small (no logs, no Dockerfile) — this rides along in every
        stage's user_input, so it must stay a handful of lines.
        """
        fp = self.fingerprint
        out: dict = {
            "languages": fp.get("languages", []),
            "primary_language": fp.get("primary_language"),
            "build_systems": fp.get("build_systems", []),
            "provisioning_status": self.status,
        }
        if fp.get("version_pins"):
            out["version_pins"] = fp["version_pins"]
        if self.image_tag and self.status == "built":
            out["image_tag"] = self.image_tag
        if self.build_cmd:
            out["build_cmd"] = self.build_cmd
        if self.test_cmd:
            out["test_cmd"] = self.test_cmd
        incomplete = [n for n in self.notes if "INCOMPLETE" in n]
        if incomplete:
            out["environment_caveat"] = incomplete[0]
        return out


# ---------------------------------------------------------------------------
# the provisioning loop
# ---------------------------------------------------------------------------

_TAG_SAFE = re.compile(r"[^a-z0-9_.-]+")


def image_tag_for(repo_path: Path) -> str:
    """A deterministic, Docker-legal tag for a target repo."""
    name = _TAG_SAFE.sub("-", repo_path.name.lower()).strip("-.") or "target"
    return f"vash-env-{name}:latest"


def _recipe_dockerfile(recipe: RenderedRecipe, repo_path: Path) -> tuple[str | None, str | None]:
    """The Dockerfile TEXT for a rendered recipe. For `source="existing"` that
    means reading the target's own file (returned as text, never edited in
    place). Returns (text, error)."""
    if recipe.source == "template":
        return recipe.dockerfile, None
    if recipe.source == "existing" and recipe.path:
        p = repo_path / recipe.path
        try:
            return p.read_text(encoding="utf-8", errors="replace"), None
        except OSError as e:
            return None, f"could not read existing recipe {recipe.path}: {e}"
    return None, "no build recipe to build"


def _verify(client: DockerClient, tag: str, recipe: RenderedRecipe, *,
            timeout: int, network: str, workdir: str) -> VerifyResult:
    """Prove the image is actually usable: the dependency probe first (the
    check that matters for a PoC — are the target's dependencies installed?),
    then the ecosystem's build and test commands. All inside the container,
    offline by default."""
    v = VerifyResult(ran=True)
    if recipe.deps_cmd:
        r = client.run(tag=tag, command=recipe.deps_cmd, workdir=workdir,
                       timeout=timeout, network=network)
        v.deps_ok = r.ok
        v.deps_log_tail = _tail(r.log, 2000)
    if recipe.build_cmd:
        r = client.run(tag=tag, command=recipe.build_cmd, workdir=workdir,
                       timeout=timeout, network=network)
        v.build_ok = r.ok
        v.build_log_tail = _tail(r.log, 2000)
    if recipe.test_cmd:
        r = client.run(tag=tag, command=recipe.test_cmd, workdir=workdir,
                       timeout=timeout, network=network)
        v.test_ok = r.ok
        v.test_log_tail = _tail(r.log, 2000)
    return v


def provision_environment(
    repo_path: Path,
    *,
    build: bool = False,
    client: DockerClient | None = None,
    tag: str | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    verify: bool = True,
    build_timeout: int = DEFAULT_BUILD_TIMEOUT,
    verify_timeout: int = DEFAULT_VERIFY_TIMEOUT,
    verify_network: str = "none",
    fp: ProjectFingerprint | None = None,
) -> ProvisionResult:
    """Fingerprint a repo, render its Dockerfile and (when `build=True`) build,
    repair and verify it.

    `build=False` is the cheap default: pure Phase-1 text work, zero Docker,
    which is what the pipeline runs unless the operator opts in. `build=True`
    executes the target's build instructions — inside a container, never on the
    host (see the module docstring).
    """
    repo_path = Path(repo_path)
    fp = fp or fingerprint(repo_path)
    recipe = render_dockerfile(fp, repo_path)
    result = ProvisionResult(
        source=recipe.source,
        build_cmd=recipe.build_cmd,
        test_cmd=recipe.test_cmd,
        fingerprint=asdict(fp),
        notes=list(recipe.notes),
    )

    dockerfile, err = _recipe_dockerfile(recipe, repo_path)
    if dockerfile is None:
        result.status = "skipped"
        if err:
            result.notes.append(err)
        return result
    result.dockerfile = dockerfile

    if not build:
        # Already running inside the target's scan image (vash-scan-<target>):
        # the toolchain and the target's dependencies are present RIGHT HERE, so
        # reporting "planned" would tell the hunter the opposite of the truth
        # and make it distrust deps_hint's "just import the target".
        preprovisioned = os.environ.get("VASH_SCAN_IMAGE", "").strip()
        if preprovisioned:
            result.status = "preprovisioned"
            result.notes.append(
                f"running inside the target's scan image ({preprovisioned}) — "
                "the target's toolchain and dependencies are already installed "
                "in this container; PoCs can use them directly"
            )
            return result
        result.status = "planned"
        result.notes.append(
            "recipe rendered only — no image built "
            "(`vash provision --build` / `vash run --provision` builds it)"
        )
        return result

    client = client or SubprocessDocker()
    if not client.available():
        result.status = "skipped"
        result.notes.append(
            "docker unavailable (CLI missing or daemon not responding) — "
            "provisioning skipped, the run continues static-only"
        )
        return result

    result.image_tag = tag or image_tag_for(repo_path)
    applied: set[str] = set()
    pending_rule: str | None = None

    for n in range(1, max(1, max_attempts) + 1):
        r = client.build(context=repo_path, dockerfile=dockerfile,
                         tag=result.image_tag, timeout=build_timeout)
        result.attempts.append(BuildAttempt(
            attempt=n, ok=r.ok, exit_code=r.exit_code, timed_out=r.timed_out,
            repair_rule=pending_rule, log_tail=_tail(r.log, 2000),
        ))
        if r.ok:
            result.status = "built"
            break
        if r.timed_out:
            result.notes.append(
                f"build timed out after {build_timeout}s — not retried"
            )
            result.status = "failed"
            break
        if n == max_attempts:
            result.status = "failed"
            result.notes.append(f"build failed after {n} attempt(s)")
            break
        fix = repair_dockerfile(dockerfile, r.log, already_applied=frozenset(applied))
        if fix is None:
            result.status = "failed"
            result.notes.append(
                "build failed and no repair rule matched — see the last attempt log"
            )
            break
        dockerfile = fix.dockerfile
        applied.add(fix.rule)
        pending_rule = fix.rule
        result.dockerfile = dockerfile
        result.notes.append(f"repair[{fix.rule}]: {fix.note}")
        log.info("[provision] build attempt %d failed -> repair %s", n, fix.rule)

    if result.status == "built" and verify and (
            recipe.build_cmd or recipe.test_cmd or recipe.deps_cmd):
        result.verify = _verify(
            client, result.image_tag, recipe,
            timeout=verify_timeout, network=verify_network, workdir="/target",
        )
        if result.verify.deps_ok is False:
            result.notes.append(
                "verify: the target's declared dependencies are NOT installed "
                "in the image — the environment is INCOMPLETE "
                f"({result.verify.deps_log_tail.strip()[:200]})"
            )
        if result.verify.build_ok is False:
            result.notes.append(
                "verify: the ecosystem build command failed inside the image — "
                "the environment may be INCOMPLETE"
            )
    return result
