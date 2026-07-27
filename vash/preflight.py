"""Preflight: prove the run can do what it is about to assume.

`vash.sandbox` answers PERMISSION — "am I allowed to execute target code?"
Nothing answered CAPABILITY — "if I execute it, will it reach the target?" —
and that gap is where this tool's worst failures live, because they are silent.

Every one of them looks like a healthy run:

  * The scan runs in a container that has no javac/go/dotnet, so every
    non-Python PoC dies at `command not found` and the findings quietly become
    static guesses.
  * Provisioning installed the target's dependencies into an image the scan is
    not actually running in, so `import <target>` fails and every PoC proves
    only that a hello-world executed.
  * A build-system misdetection left the image with no dependencies at all
    (a `pyproject.toml` read as poetry, a `uv.lock` never consulted).

In each case the report comes out looking normal. That is the problem: a
security tool that degrades silently is worse than one that fails loudly,
because the operator has no signal to distrust the output.

So this module runs cheap, deterministic checks up front and records what the
run can actually do. It follows the same discipline as the Phase 3 observers:

  * **It never blocks.** A missing capability is reported, not fatal — the run
    may still be worth doing statically, and that is the operator's call.
  * **Unknown is its own answer.** A check that could not be performed reports
    ``None``, never a cheerful ``True``.
  * **What it finds reaches the report**, so "PoC confirmation was impossible
    in this container" is visible next to the findings rather than buried in a
    log nobody reads.

**Execution stance.** The checks that run target code — importing the target
package is target code, since imports execute module-level statements — happen
ONLY when execution is already enabled, which means `sandbox.require()` has
already cleared. With execution off, this module reads the filesystem and runs
`--version` probes of VASH's own toolchain, and touches nothing of the
target's.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from vash.lang.hints import EXT_TO_LANG

log = logging.getLogger(__name__)

# Probes are trivial (`--version`, a single import). Anything slower than this
# is hung, and preflight must never become a reason a run is late.
PROBE_TIMEOUT = 30

# Directories that are never the target's own source.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
              "build", ".tox", "target", "vendor", ".gradle", "site-packages"}

# language -> the executable a PoC in that language needs first. Absent means
# the PoC cannot even start, whatever else is true.
_TOOLCHAIN: dict[str, tuple[str, ...]] = {
    "python": ("python3",),
    "javascript": ("node",),
    "typescript": ("node",),
    "java": ("java", "javac"),
    "go": ("go",),
    "csharp": ("dotnet",),
}


@dataclass(frozen=True)
class Capability:
    """One thing the run may be assuming, and whether it actually holds.

    `ok` is deliberately tri-state. ``None`` means the check could not be
    performed — which is not the same as the capability being present, and must
    never be rendered as though it were.
    """

    name: str
    ok: bool | None
    detail: str
    # What silently degrades when this is False. Written for the operator
    # reading the report, not for the developer reading the code.
    matters_because: str

    @property
    def degraded(self) -> bool:
        return self.ok is False


@dataclass
class PreflightReport:
    execution_enabled: bool
    capabilities: list[Capability] = field(default_factory=list)

    @property
    def degraded(self) -> list[Capability]:
        return [c for c in self.capabilities if c.degraded]

    @property
    def unknown(self) -> list[Capability]:
        return [c for c in self.capabilities if c.ok is None]

    @property
    def poc_confirmation_available(self) -> bool:
        """Can this run actually confirm a finding by executing a PoC?

        The honest headline. False whenever execution is off OR anything the
        PoC path depends on is missing — which is the difference between
        "findings were proven" and "findings are static guesses".
        """
        return self.execution_enabled and not self.degraded

    def as_dict(self) -> dict:
        return {
            "execution_enabled": self.execution_enabled,
            "poc_confirmation_available": self.poc_confirmation_available,
            "degraded": [c.name for c in self.degraded],
            "unknown": [c.name for c in self.unknown],
            "capabilities": [asdict(c) for c in self.capabilities],
        }

    def summary_line(self) -> str:
        if not self.execution_enabled:
            return ("static-only run: no PoC is executed, so no finding here is "
                    "confirmed by execution")
        if self.degraded:
            names = ", ".join(c.name for c in self.degraded)
            return (f"execution is ENABLED but {len(self.degraded)} capability it "
                    f"depends on is missing ({names}) — PoC confirmation will be "
                    f"weak or impossible, and an unproven finding must NOT be "
                    f"read as disproven")
        return "execution enabled and every capability the PoC path needs is present"


def _run(argv: list[str], *, cwd: Path | None = None) -> tuple[int, str]:
    """Run a trivial probe. Never raises; a missing binary is exit 127."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=PROBE_TIMEOUT,
                           cwd=str(cwd) if cwd else None)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, f"{type(e).__name__}: {e}"
    return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()[:400]


def _source_languages(repo_path: Path, limit: int = 4000) -> list[str]:
    """Languages actually present in the target, most common first."""
    counts: dict[str, int] = {}
    seen = 0
    try:
        candidates = repo_path.rglob("*")
    except OSError:
        return []
    for p in candidates:
        if seen >= limit:
            break
        try:
            if not p.is_file():
                continue
            rel = p.relative_to(repo_path).parts
        except (OSError, ValueError):
            continue
        if any(part in _SKIP_DIRS for part in rel):
            continue
        lang = EXT_TO_LANG.get(p.suffix.lower())
        if lang and lang != "web-template":
            counts[lang] = counts.get(lang, 0) + 1
            seen += 1
    return sorted(counts, key=lambda l: (-counts[l], l))


def python_package_candidates(repo_path: Path) -> list[str]:
    """Importable top-level package names this repo plausibly provides.

    Sourced from `src/<pkg>/__init__.py`, `<pkg>/__init__.py`, and the
    distribution name in pyproject.toml (normalised, since `my-pkg` installs as
    `my_pkg`). Best-effort by design: a wrong guess costs one failed import,
    while having no guess at all costs the entire capability check.
    """
    names: list[str] = []

    def add(n: str) -> None:
        n = n.strip().replace("-", "_")
        if n and n.isidentifier() and n not in names and not n.startswith("test"):
            names.append(n)

    for parent in (repo_path / "src", repo_path):
        try:
            entries = sorted(parent.iterdir())
        except OSError:
            continue
        for child in entries:
            try:
                if child.is_dir() and (child / "__init__.py").is_file():
                    if child.name not in _SKIP_DIRS:
                        add(child.name)
            except OSError:
                continue

    pyproject = repo_path / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
            project = data.get("project")
            if isinstance(project, dict) and project.get("name"):
                add(str(project["name"]))
        except (OSError, ValueError, TypeError):
            pass
    return names


def _check_target_readable(repo_path: Path, languages: list[str]) -> Capability:
    if not repo_path.is_dir():
        return Capability("target_readable", False, f"{repo_path} is not a directory",
                          "there is nothing to scan")
    if not languages:
        return Capability(
            "target_readable", False,
            "no files in a language VASH recognises",
            "the hunt has no source to work from, so an empty result would mean "
            "'nothing was looked at', not 'nothing was found'")
    return Capability("target_readable", True,
                      f"languages present: {', '.join(languages[:5])}",
                      "the hunt needs source it can read")


def _check_toolchain(languages: list[str]) -> list[Capability]:
    """One capability per language present: can a PoC in it even start?"""
    out: list[Capability] = []
    for lang in languages:
        tools = _TOOLCHAIN.get(lang)
        if not tools:
            continue                       # a language with no PoC runtime: not a gap
        missing = [t for t in tools if shutil.which(t) is None]
        ok = not missing
        detail = (f"{', '.join(tools)} present" if ok
                  else f"missing: {', '.join(missing)}")
        out.append(Capability(
            f"toolchain_{lang}", ok, detail,
            f"a {lang} PoC cannot compile or run without it, so every {lang} "
            f"finding would fall back to a static guess — and a PoC that never "
            f"ran is NOT evidence the vulnerability is absent"))
    return out


def _check_target_importable(repo_path: Path) -> Capability:
    """THE check that catches a scan running in the wrong container.

    Runs the target's own module-level code, so it is only ever called on the
    execution-enabled path (sandbox already cleared).
    """
    candidates = python_package_candidates(repo_path)
    if not candidates:
        return Capability(
            "target_importable", None,
            "could not determine a top-level package name for this repo",
            "a Python PoC that cannot import the target proves nothing about it")

    tried: list[str] = []
    for name in candidates[:6]:
        code, out = _run(["python3", "-c", f"import {name}"])
        if code == 0:
            return Capability("target_importable", True, f"`import {name}` succeeds",
                              "a PoC can reach the target's real code")
        tried.append(f"{name} ({out.splitlines()[-1][:80] if out else 'failed'})")

    return Capability(
        "target_importable", False,
        "none of " + ", ".join(tried) + " could be imported",
        "the target's dependencies are not installed in THIS container, so "
        "every Python PoC can only prove that a hello-world ran — the exact "
        "silent failure the scan-image design exists to prevent")


def _check_observer(languages: list[str]) -> Capability | None:
    """Is the runtime observer for the primary language usable here?

    Corroboration only — a missing observer weakens evidence, it does not
    invalidate a PoC. Reported as unknown rather than failed for that reason.
    """
    try:
        from vash.lang.poc_runtime import runtime_for
    except Exception:                                # pragma: no cover - import guard
        return None
    rt = runtime_for(languages)
    if rt is None or rt.observer is None:
        return None
    code, _out = _run(["sh", "-c", rt.observer.available_check])
    ok = code == 0
    return Capability(
        f"observer_{rt.observer.name}", True if ok else None,
        "available" if ok else "not available in this container",
        "an observer corroborates that the vulnerable call actually fired; "
        "without it a PoC still stands on its own assertions, so this weakens "
        "evidence rather than invalidating it")


def run_preflight(repo_path: Path, *, execution_enabled: bool) -> PreflightReport:
    """Check what this run can actually do. Never raises, never blocks.

    With `execution_enabled=False` nothing belonging to the target is executed:
    the report simply records that findings will be static.
    """
    repo_path = Path(repo_path)
    report = PreflightReport(execution_enabled=execution_enabled)
    try:
        languages = _source_languages(repo_path)
        report.capabilities.append(_check_target_readable(repo_path, languages))

        if execution_enabled:
            report.capabilities.extend(_check_toolchain(languages))
            if "python" in languages:
                report.capabilities.append(_check_target_importable(repo_path))
            obs = _check_observer(languages)
            if obs is not None:
                report.capabilities.append(obs)
    except Exception as e:                           # pragma: no cover - defensive
        log.warning("[preflight] check failed, continuing: %s", e)
        report.capabilities.append(Capability(
            "preflight_itself", None, f"{type(e).__name__}: {e}",
            "preflight could not complete, so treat its silence as no information"))

    for cap in report.capabilities:
        if cap.degraded:
            log.warning("[preflight] %s: NOT AVAILABLE (%s) — %s",
                        cap.name, cap.detail, cap.matters_because)
        elif cap.ok is None:
            log.info("[preflight] %s: unknown (%s)", cap.name, cap.detail)
    log.info("[preflight] %s", report.summary_line())
    return report
