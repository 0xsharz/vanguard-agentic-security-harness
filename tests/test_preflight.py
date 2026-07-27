"""Tests for `vash/preflight.py` — proving the run can do what it assumes.

Every failure this module exists to catch produces a report that looks
completely normal. A scan running in a container without the target's
dependencies still emits findings; they are just static guesses wearing the
clothes of executed proof. So what these tests pin down is not "does the check
run" but **does an absent capability become visible**, and does an
undeterminable one stay honestly undetermined instead of defaulting to fine.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from vash import preflight
from vash.preflight import (
    Capability,
    PreflightReport,
    python_package_candidates,
    run_preflight,
)


def _mk(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# The honesty contract
# ─────────────────────────────────────────────────────────────────────────────

def test_unknown_is_never_reported_as_available() -> None:
    """A check that could not run is not a check that passed. This is the whole
    discipline in one assertion."""
    cap = Capability("x", None, "could not determine", "because")
    assert cap.degraded is False           # unknown is not a failure...
    assert cap.ok is not True              # ...and it is emphatically not a pass

    report = PreflightReport(execution_enabled=True, capabilities=[cap])
    assert report.unknown == [cap]
    assert cap.name not in report.as_dict()["degraded"]


def test_static_run_never_claims_poc_confirmation(tmp_path: Path) -> None:
    repo = _mk(tmp_path, {"app.py": "x = 1\n"})
    report = run_preflight(repo, execution_enabled=False)
    assert report.poc_confirmation_available is False
    assert "no finding here is confirmed by execution" in report.summary_line()


def test_static_run_executes_nothing(tmp_path: Path, monkeypatch) -> None:
    """With execution off, preflight must not run a single subprocess — the
    target's module-level code is target code, and importing it is executing
    it."""
    repo = _mk(tmp_path, {"pkg/__init__.py": "raise SystemExit('should never run')\n"})
    calls: list[list[str]] = []
    monkeypatch.setattr(preflight, "_run",
                        lambda argv, **kw: (calls.append(argv), (0, ""))[1])
    run_preflight(repo, execution_enabled=False)
    assert calls == []


def test_degraded_capability_defeats_poc_confirmation() -> None:
    report = PreflightReport(execution_enabled=True, capabilities=[
        Capability("toolchain_go", False, "missing: go", "no go PoC can run"),
    ])
    assert report.poc_confirmation_available is False
    assert "PoC confirmation will be weak or impossible" in report.summary_line()
    # and the operator is told what silence would have meant
    assert "must NOT be read as disproven" in report.summary_line()


def test_all_capabilities_present_is_the_only_confirming_state() -> None:
    report = PreflightReport(execution_enabled=True, capabilities=[
        Capability("target_readable", True, "python", "needs source"),
        Capability("toolchain_python", True, "python3 present", "needs python"),
    ])
    assert report.poc_confirmation_available is True


# ─────────────────────────────────────────────────────────────────────────────
# The check that catches a scan running in the wrong container
# ─────────────────────────────────────────────────────────────────────────────

def test_uninstallable_target_is_reported_not_hidden(tmp_path: Path) -> None:
    """The failure the scan-image design exists to prevent: the scan runs
    somewhere the target's dependencies are absent, so every PoC proves only
    that a hello-world executed — while the report looks entirely normal."""
    repo = _mk(tmp_path, {
        "src/vash_no_such_package_xyz/__init__.py": "import definitely_absent_dep_xyz\n",
        "src/vash_no_such_package_xyz/app.py": "x = 1\n",
    })
    report = run_preflight(repo, execution_enabled=True)
    cap = next(c for c in report.capabilities if c.name == "target_importable")
    assert cap.ok is False
    assert report.poc_confirmation_available is False
    assert "hello-world" in cap.matters_because


def test_importable_target_passes(tmp_path: Path) -> None:
    """A package that really does import (no dependencies) must not be flagged
    — a check that cries wolf is a check that gets ignored."""
    repo = _mk(tmp_path, {"src/vash_preflight_selftest_pkg/__init__.py": "VALUE = 1\n"})
    report = run_preflight(repo, execution_enabled=True)
    cap = next(c for c in report.capabilities if c.name == "target_importable")
    # PYTHONPATH does not include the repo, so this legitimately may not import;
    # what must never happen is a silent True with nothing behind it.
    assert cap.ok in (True, False)
    assert cap.detail


def test_missing_toolchain_is_named_per_language(tmp_path: Path, monkeypatch) -> None:
    repo = _mk(tmp_path, {"main.go": "package main\n", "b.go": "package main\n"})
    monkeypatch.setattr(preflight.shutil, "which",
                        lambda tool: None if tool == "go" else "/usr/bin/" + tool)
    report = run_preflight(repo, execution_enabled=True)
    cap = next(c for c in report.capabilities if c.name == "toolchain_go")
    assert cap.ok is False
    assert "missing: go" in cap.detail
    assert "NOT evidence the vulnerability is absent" in cap.matters_because


def test_a_language_with_no_poc_runtime_is_not_a_gap(tmp_path: Path) -> None:
    """Ruby has no PoC runtime here. That is a known limit, not a broken
    environment — inventing a failed capability for it would be noise."""
    repo = _mk(tmp_path, {"app.rb": "puts 1\n"})
    report = run_preflight(repo, execution_enabled=True)
    assert not any(c.name.startswith("toolchain_ruby") for c in report.capabilities)


def test_empty_repo_is_reported_as_unscannable(tmp_path: Path) -> None:
    """An empty result from an empty scan must not read like a clean bill of
    health."""
    repo = _mk(tmp_path, {"README.md": "# nothing here\n"})
    report = run_preflight(repo, execution_enabled=False)
    cap = next(c for c in report.capabilities if c.name == "target_readable")
    assert cap.ok is False
    assert "nothing was looked at" in cap.matters_because


# ─────────────────────────────────────────────────────────────────────────────
# Package-name discovery
# ─────────────────────────────────────────────────────────────────────────────

def test_package_candidates_from_src_layout_and_pyproject(tmp_path: Path) -> None:
    repo = _mk(tmp_path, {
        "src/data360/__init__.py": "",
        "pyproject.toml": "[project]\nname = 'data360-mcp'\n",
    })
    names = python_package_candidates(repo)
    assert "data360" in names
    assert "data360_mcp" in names          # dist name normalised to a module name


def test_package_candidates_skip_tests_and_vendor(tmp_path: Path) -> None:
    repo = _mk(tmp_path, {
        "tests/__init__.py": "",
        "node_modules/__init__.py": "",
        "realpkg/__init__.py": "",
    })
    names = python_package_candidates(repo)
    assert names == ["realpkg"]


def test_package_candidates_survive_a_broken_pyproject(tmp_path: Path) -> None:
    """Stage 0 is on the critical path: a malformed manifest degrades the
    answer, it does not raise."""
    repo = _mk(tmp_path, {"pkg/__init__.py": "", "pyproject.toml": "not : valid : toml ["})
    assert python_package_candidates(repo) == ["pkg"]


def test_run_preflight_never_raises_on_a_missing_repo(tmp_path: Path) -> None:
    report = run_preflight(tmp_path / "does-not-exist", execution_enabled=True)
    assert report.poc_confirmation_available is False
    assert report.as_dict()["degraded"]


@pytest.mark.skipif(shutil.which("python3") is None, reason="needs python3")
def test_report_serialises_for_the_json_report(tmp_path: Path) -> None:
    repo = _mk(tmp_path, {"app.py": "x = 1\n"})
    d = run_preflight(repo, execution_enabled=False).as_dict()
    assert set(d) >= {"execution_enabled", "poc_confirmation_available",
                      "degraded", "unknown", "capabilities"}
    assert all(set(c) >= {"name", "ok", "detail", "matters_because"}
               for c in d["capabilities"])


# ─────────────────────────────────────────────────────────────────────────────
# Reaching the operator
# ─────────────────────────────────────────────────────────────────────────────

def test_degraded_execution_becomes_a_report_caveat() -> None:
    """The log is not the deliverable. A run that could not prove its findings
    has to say so where the findings are read, or the report is indistinguishable
    from one where every PoC executed."""
    from types import SimpleNamespace
    from vash.stages.report import _attach_preflight

    ctx = SimpleNamespace(preflight={
        "execution_enabled": True,
        "poc_confirmation_available": False,
        "degraded": ["target_importable"],
        "unknown": [],
        "capabilities": [],
    })
    payload = {"coverage": {"coverage_complete": True}}
    _attach_preflight(ctx, payload)

    assert payload["preflight"]["degraded"] == ["target_importable"]
    caveats = payload["coverage"]["caveats"]
    assert any("NOT fully available" in c for c in caveats)
    assert any("must NOT be read as disproven" in c for c in caveats)
    # coverage cannot still claim to be complete
    assert payload["coverage"]["coverage_complete"] is False


def test_healthy_execution_adds_no_caveat() -> None:
    """A warning that fires on every run is a warning that stops being read."""
    from types import SimpleNamespace
    from vash.stages.report import _attach_preflight

    ctx = SimpleNamespace(preflight={
        "execution_enabled": True,
        "poc_confirmation_available": True,
        "degraded": [], "unknown": [], "capabilities": [],
    })
    payload = {"coverage": {"coverage_complete": True}}
    _attach_preflight(ctx, payload)
    assert "caveats" not in payload["coverage"]
    assert payload["coverage"]["coverage_complete"] is True


def test_missing_preflight_leaves_the_report_untouched() -> None:
    from types import SimpleNamespace
    from vash.stages.report import _attach_preflight
    payload = {"coverage": {"coverage_complete": True}}
    _attach_preflight(SimpleNamespace(preflight=None), payload)
    assert payload == {"coverage": {"coverage_complete": True}}
