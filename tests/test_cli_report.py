"""Tests for vash.cli._render_markdown_report.

Regression coverage for the A2 integration break: report.py's post-hoc
`_attach_variants` (see tests/test_report.py) changed each finding's
`variants` entries from bare finding_id strings to located dicts
({finding_id, file, line_start, line_end, vuln_class}), but this renderer
still did `', '.join(f['variants'])` — a TypeError the first time `vash
report --format md` ran on a report with a deduped sibling. Before this
file, `_render_markdown_report` had zero test coverage, which is why the
break shipped silently.

All OFFLINE: pure function over a hand-built report dict, no StateDB, no
agent/network involved.
"""

from __future__ import annotations

from vash.cli import _render_markdown_report


def _finding(**overrides: object) -> dict:
    """A minimal finding satisfying every field _render_markdown_report
    reads (see schemas/report.schema.json for the full required set)."""
    finding = {
        "finding_id": "f_c",
        "title": "SSRF via unchecked webhook URL",
        "severity": "high",
        "vuln_class": "ssrf",
        "file": "pkg/x.py",
        "line_start": 10,
        "line_end": 12,
        "description": "User-controlled URL is fetched without validation.",
        "evidence": "requests.get(user_url)",
        "trace": {"entry_points": [], "call_chain": []},
        "recommendation": "Validate the URL against an allowlist before fetching.",
    }
    finding.update(overrides)
    return finding


def _report(findings: list[dict]) -> dict:
    return {
        "run_id": "run_1",
        "target": {"repo_path": "/some/repo"},
        "summary": {"total": len(findings), "by_severity": {"high": len(findings)}},
        "findings": findings,
    }


def test_dict_variant_renders_also_at_without_raising() -> None:
    """The exact A2 regression: a located dict variant must render as
    'Also at:' with file:line, not raise TypeError on str.join(dicts)."""
    variant = {
        "finding_id": "f_v", "file": "pkg/y.py", "line_start": 30,
        "line_end": 31, "vuln_class": "ssrf",
    }
    report = _report([_finding(variants=[variant])])

    md = _render_markdown_report(report)

    assert "Also at" in md
    assert "pkg/y.py:30" in md


def test_legacy_string_variant_still_renders() -> None:
    """Defensive dual-shape handling: older/fallback reports may still carry
    bare finding_id strings (schema permits string OR object) — must not
    regress this path while fixing the dict case."""
    report = _report([_finding(variants=["f_v"])])

    md = _render_markdown_report(report)

    assert "Also at" in md
    assert "f_v" in md


def test_no_variants_key_omits_also_at_section() -> None:
    """No `variants` key at all (the common case — most findings have no
    deduped siblings) must not raise and must not print an empty section."""
    report = _report([_finding()])

    md = _render_markdown_report(report)

    assert "Also at" not in md


def test_empty_variants_list_omits_also_at_section() -> None:
    """An explicit empty list (falsy) must behave the same as a missing key."""
    report = _report([_finding(variants=[])])

    md = _render_markdown_report(report)

    assert "Also at" not in md
