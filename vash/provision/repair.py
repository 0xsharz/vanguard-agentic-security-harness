"""Deterministic Dockerfile repair (Phase 2).

When `docker build` fails, the build log almost always names the reason in a
recognisable way ("gcc: command not found", "manifest ... not found", "npm ci
can only install with an existing package-lock.json"). This module maps those
signatures to a *small, ordered ladder* of textual Dockerfile edits, so the
provisioning loop can retry without asking an LLM.

Doctrine (same as `taint.py`): **a few high-signal rules beat exhaustive
noise.** Every rule is pure — it takes the Dockerfile text plus the build log
and returns new Dockerfile text (or None when it cannot help). Nothing here
runs Docker, spawns a process, or touches the network, so the whole ladder is
exercised offline by the test suite.

The last rule (`soften_install_step`) is a deliberate catch-all: an imperfect
environment (deps partially installed) is still far more useful to a PoC than
no image at all — but it is recorded as a LOUD note so the operator knows the
environment is incomplete.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from vash.provision.dockerfile import ECOSYSTEM_TEMPLATES

# image name -> the fully-rendered default base ref for that ecosystem. Built
# from the Phase 1 templates so the two never drift: if a target pins a tag
# that does not exist ("node:99"), the repair falls back to the tag VASH
# itself considers known-good.
DEFAULT_BASE_BY_IMAGE: dict[str, str] = {}
for _t in ECOSYSTEM_TEMPLATES.values():
    _ref = _t["base"].format(ver=_t["default_ver"])
    DEFAULT_BASE_BY_IMAGE.setdefault(_ref.rsplit(":", 1)[0], _ref)


@dataclass(frozen=True)
class Repair:
    """One applied repair: the rule that fired and the resulting Dockerfile."""
    rule: str
    dockerfile: str
    note: str


# ---------------------------------------------------------------------------
# text helpers — all pure string surgery on the Dockerfile
# ---------------------------------------------------------------------------

def _lines(dockerfile: str) -> list[str]:
    return dockerfile.splitlines()


def _join(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


def _first_from(lines: list[str]) -> tuple[int, str] | None:
    for i, ln in enumerate(lines):
        m = re.match(r"\s*FROM\s+(\S+)", ln, re.I)
        if m:
            return i, m.group(1)
    return None


def _is_alpine(dockerfile: str) -> bool:
    frm = _first_from(_lines(dockerfile))
    return bool(frm) and "alpine" in frm[1].lower()


def _pkg_install_line(dockerfile: str, debian_pkgs: str, alpine_pkgs: str) -> str:
    if _is_alpine(dockerfile):
        return f"RUN apk add --no-cache {alpine_pkgs}"
    return (
        f"RUN apt-get update && apt-get install -y --no-install-recommends "
        f"{debian_pkgs} && rm -rf /var/lib/apt/lists/*"
    )


def _insert_before_first_run(dockerfile: str, new_line: str) -> str | None:
    """Insert `new_line` immediately before the first RUN (the dependency
    install step). With no RUN at all, append after the FROM block."""
    lines = _lines(dockerfile)
    if new_line in lines:
        return None                       # already present — nothing to do
    for i, ln in enumerate(lines):
        if re.match(r"\s*RUN\s", ln, re.I):
            lines.insert(i, new_line)
            return _join(lines)
    frm = _first_from(lines)
    if frm is None:
        return None
    lines.insert(frm[0] + 1, new_line)
    return _join(lines)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def _fix_base_image(dockerfile: str, log: str) -> tuple[str, str] | None:
    """The pinned base tag does not exist -> fall back to VASH's known-good
    default tag for that image. Only the FIRST FROM is retagged (multi-stage
    targets keep their later stages untouched)."""
    lines = _lines(dockerfile)
    frm = _first_from(lines)
    if frm is None:
        return None
    idx, ref = frm
    image = ref.rsplit(":", 1)[0] if ":" in ref else ref
    default = DEFAULT_BASE_BY_IMAGE.get(image)
    if default is None or default == ref:
        return None                       # unknown image, or already default
    lines[idx] = re.sub(re.escape(ref), default, lines[idx], count=1)
    return _join(lines), f"base image {ref} unavailable -> {default}"


def _fix_c_toolchain(dockerfile: str, log: str) -> tuple[str, str] | None:
    """A native extension needs a C toolchain the slim base image lacks."""
    frm = _first_from(_lines(dockerfile))
    python_base = bool(frm) and frm[1].lower().startswith("python")
    debian = "build-essential" + (" python3-dev" if python_base else "")
    alpine = "build-base" + (" python3-dev" if python_base else "")
    line = _pkg_install_line(dockerfile, debian, alpine)
    out = _insert_before_first_run(dockerfile, line)
    if out is None:
        return None
    return out, "added a C build toolchain for native extensions"


def _fix_missing_git(dockerfile: str, log: str) -> tuple[str, str] | None:
    line = _pkg_install_line(dockerfile, "git ca-certificates", "git ca-certificates")
    out = _insert_before_first_run(dockerfile, line)
    if out is None:
        return None
    return out, "added git (a dependency is fetched from a git URL)"


def _fix_npm_ci(dockerfile: str, log: str) -> tuple[str, str] | None:
    """`npm ci` demands a lockfile the repo does not ship."""
    if "npm ci" not in dockerfile:
        return None
    out = dockerfile.replace("npm ci || npm install", "npm install")
    out = out.replace("npm ci", "npm install")
    if out == dockerfile:
        return None
    return out, "npm ci requires a lockfile the repo lacks -> npm install"


_MISSING_PATH_RE = re.compile(
    r'"/?([^":\s]+)":?\s+not found|COPY failed:.*?stat .*?/([^\s:]+):', re.I
)


def _fix_missing_copy(dockerfile: str, log: str) -> tuple[str, str] | None:
    """A COPY names a path that is not in the build context. Drop that COPY
    (never the whole-repo `COPY . <dst>`, which is the context itself)."""
    m = _MISSING_PATH_RE.search(log)
    if not m:
        return None
    missing = (m.group(1) or m.group(2) or "").strip("/")
    if not missing:
        return None
    base = missing.rsplit("/", 1)[-1]
    kept, dropped = [], []
    for ln in _lines(dockerfile):
        if re.match(r"\s*COPY\s", ln, re.I) and not re.match(r"\s*COPY\s+\.\s", ln, re.I):
            if base and base in ln:
                dropped.append(ln)
                continue
        kept.append(ln)
    if not dropped:
        return None
    return _join(kept), f"dropped COPY of missing context path {missing!r}"


def _soften_install(dockerfile: str, log: str) -> tuple[str, str] | None:
    """Last resort: let the dependency install fail without failing the build.

    A partially-provisioned image still gives a PoC a real interpreter/runtime
    and the target's source — strictly better than no image. The caller
    surfaces the returned note so this is never a silent degradation."""
    lines = _lines(dockerfile)
    for i, ln in enumerate(lines):
        if re.match(r"\s*RUN\s", ln, re.I) and not ln.rstrip().endswith("|| true"):
            lines[i] = ln.rstrip() + " || true"
            return (
                _join(lines),
                "dependency install made non-fatal — the image may be "
                "INCOMPLETE (some dependencies are missing)",
            )
    return None


# Ordered ladder: most specific first, catch-all last. Each entry is
# (rule name, log patterns that arm it, transform). A rule with an empty
# pattern tuple is always armed (the catch-all).
RepairFn = Callable[[str, str], "tuple[str, str] | None"]

REPAIR_RULES: list[tuple[str, tuple[str, ...], RepairFn]] = [
    ("base_image_unavailable", (
        r"manifest for \S+ not found",
        r"manifest unknown",
        r"pull access denied",
        r"failed to resolve source metadata",
        r"not found: name unknown",
        r"no match for platform in manifest",
    ), _fix_base_image),
    ("missing_c_toolchain", (
        r"gcc: (?:command |fatal )?not found",
        r"unable to execute ['\"]?gcc",
        r"command ['\"]gcc['\"] failed",
        r"fatal error: Python\.h",
        r"node-gyp",
        r"linker ['\"`]?cc['\"`]? not found",
        r"make: not found",
        r"error: Microsoft Visual C\+\+",
        r"requires the C compiler",
    ), _fix_c_toolchain),
    ("missing_git", (
        r"git: (?:command )?not found",
        r"['\"]git['\"] is not recognized",
        r"error: can't find ['\"]?git['\"]?",
        r"git executable not found",
    ), _fix_missing_git),
    ("npm_ci_requires_lockfile", (
        r"npm ci` can only install",
        r"can only install with an existing package-lock",
        r"npm ERR! code EUSAGE",
    ), _fix_npm_ci),
    ("missing_copy_path", (
        r"COPY failed",
        r"failed to compute cache key",
        r'"/[^"]+": not found',
    ), _fix_missing_copy),
    # catch-all — always armed, so a build that failed for an unrecognised
    # reason still gets one bounded "best effort" retry.
    ("soften_install_step", (), _soften_install),
]


def _armed(patterns: tuple[str, ...], log: str) -> bool:
    if not patterns:
        return True                        # catch-all
    return any(re.search(p, log, re.I | re.M) for p in patterns)


def repair_dockerfile(
    dockerfile: str, build_log: str, *, already_applied: frozenset[str] = frozenset()
) -> Repair | None:
    """Return the next repair for a failed build, or None when the ladder is
    exhausted.

    Pure: no Docker, no subprocess, no network. A rule fires at most once per
    provisioning attempt sequence (`already_applied` carries the names that
    have fired), which is what bounds the retry loop even though the last rule
    is always armed.
    """
    for name, patterns, fn in REPAIR_RULES:
        if name in already_applied or not _armed(patterns, build_log):
            continue
        out = fn(dockerfile, build_log)
        if out is None:
            continue
        new_dockerfile, note = out
        if new_dockerfile == dockerfile:
            continue                       # no-op edit is not a repair
        return Repair(rule=name, dockerfile=new_dockerfile, note=note)
    return None
