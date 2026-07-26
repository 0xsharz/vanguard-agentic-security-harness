"""VVAH/GHSA-style Markdown renderer for an enriched VASH report.

`render_report(report, db=None, run_id=None) -> str` turns the enriched
`report.json` payload (the Task-3 schema shape: top-level
`threat_model`/`scan_metrics`/`verification`, and per-finding
`cvss`/`impact`/`exploit_scenario`/`preconditions`/`how_to_fix`/`poc`/
`variants`/`trace`/`validation`) into a detailed Markdown document that reads
as a peer of a VVAH scan report, with a per-finding GHSA-style advisory block.

Design invariants:

- **Pure & deterministic.** No timestamps, no `Date.now`, no dependence on
  dict-iteration order (severity tallies iterate a fixed order; lists render in
  the order given). Two calls on the same payload are byte-identical.
- **Never drops a section, never crashes.** Every top-level section always
  emits its header; a missing/empty object renders an explicit
  `_Not determined (static run)._` line instead of vanishing. Each section is
  additionally wrapped so a single malformed sub-object degrades to that same
  line rather than taking down the whole document. `render_report` must not
  raise on a minimal `{"run_id", "target", "findings": []}` payload.
- **Post-hoc enrichment lives upstream.** `db`/`run_id` are accepted for
  signature parity with the other attaches; the renderer is pure over the
  already-enriched `report` dict and does not read the DB.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

# The single canonical "we could not determine this in a static run" line. Used
# for any optional field/section that is absent, so nothing is ever silently
# dropped. (The GHSA affected/patched lines use a distinct em-dash phrasing —
# see `_ADVISORY_VERSIONS` — because that is a deliberate advisory statement,
# not a gap.)
NOT_DETERMINED = "_Not determined (static run)._"
_ADVISORY_VERSIONS = "_Not determined — static run._"

_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]

# Verdict labels for the adversarial-verification block — map VASH's internal
# validate verdicts onto the TRUE/FALSE-positive vocabulary a reader expects.
_VERDICT_LABEL = {
    "confirmed": "TRUE_POSITIVE",
    "rejected": "FALSE_POSITIVE",
    "needs_more_info": "NEEDS_MORE_INFO",
}

# A small CWE id -> name table for the common classes VASH emits, so the CWE
# line and Weaknesses block read richly. Absent ids fall back to the bare id +
# link (never a crash, never a wrong invented name).
_CWE_NAMES = {
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command (Command Injection)",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
    "CWE-94": "Improper Control of Generation of Code (Code Injection)",
    "CWE-113": "Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-407": "Inefficient Algorithmic Complexity",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


# ---------------------------------------------------------------------------
# Small formatting primitives.
# ---------------------------------------------------------------------------


def _s(value: Any) -> str:
    """Coerce a value to a stripped display string ('' for None)."""
    if value is None:
        return ""
    return str(value).strip()


def _int(value: Any) -> str:
    """Format an integer with thousands separators, or '' if not numeric."""
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return ""


def _cwe_url(cwe: str) -> str:
    """`CWE-918` -> the canonical MITRE definition URL."""
    num = _s(cwe).replace("CWE-", "").strip()
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def _cwe_label(cwe: str) -> str:
    """`CWE-918` -> `CWE-918: Server-Side Request Forgery (SSRF)` (id-only if unknown)."""
    cwe = _s(cwe)
    name = _CWE_NAMES.get(cwe)
    return f"{cwe}: {name}" if name else cwe


def _fmt_score(score: Any) -> str:
    """CVSS score as a one-decimal string ('9.1', '10.0'); '' if not numeric."""
    try:
        return f"{float(score):.1f}"
    except (TypeError, ValueError):
        return ""


def _fenced(body: str, lang: str = "") -> list[str]:
    """A fenced code block. The body is emitted verbatim (evidence/PoC are
    already redacted upstream by `redact_json`)."""
    return [f"```{lang}", body if body else "", "```"]


def _md_table(headers: list[str], rows: list[list[str]],
              aligns: list[str] | None = None) -> list[str]:
    """Render a GitHub-flavoured Markdown table. `aligns` entries are one of
    'l' (default) or 'r' (right, for numbers)."""
    aligns = aligns or ["l"] * len(headers)
    sep = ["---:" if a == "r" else "---" for a in aligns]
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(sep) + " |"]
    for row in rows:
        out.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return out


def _cell(value: Any) -> str:
    """Sanitise a table cell: single line, pipes escaped."""
    return _s(value).replace("\n", " ").replace("|", "\\|")


# ---------------------------------------------------------------------------
# Top-level orchestration.
# ---------------------------------------------------------------------------


def render_report(report: dict, db: Any = None, run_id: str | None = None) -> str:
    """Render an enriched report dict to a VVAH/GHSA-style Markdown document.

    Pure over `report`; deterministic; never raises on a well-formed-ish dict.
    `db`/`run_id` are accepted for call-site parity and are unused.
    """
    report = report if isinstance(report, dict) else {}
    lines: list[str] = []
    lines += _title(report)
    lines += _section(_summary_section, report, "Summary")
    lines += _section(_scan_metrics_section, report, "Scan Metrics")
    lines += _section(_threat_model_section, report, "Threat Model")
    lines += _section(_verification_section, report, "Verification")
    lines += _section(_findings_section, report, "Findings")
    # Exploit chains are conditional — only emitted when present.
    lines += _safe_optional(_chains_section, report)
    return "\n".join(lines).rstrip() + "\n"


def _section(fn: Callable[[dict], list[str]], report: dict, name: str) -> list[str]:
    """Render one always-present section, fail-soft: any exception degrades to
    the section header + a Not-determined line rather than crashing the doc."""
    try:
        return fn(report)
    except Exception as e:  # never let one section break the whole report
        log.warning("markdown: section %s failed: %s", name, e)
        return ["", f"## {name}", "", NOT_DETERMINED, ""]


def _safe_optional(fn: Callable[[dict], list[str]], report: dict) -> list[str]:
    """Render one conditional section, fail-soft to nothing."""
    try:
        return fn(report)
    except Exception as e:
        log.warning("markdown: optional section failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Title + Summary.
# ---------------------------------------------------------------------------


def _target_name(report: dict) -> str:
    target = report.get("target") or {}
    repo = _s(target.get("repo_path"))
    if repo:
        name = Path(repo).name
        if name:
            return name
    return _s(report.get("run_id")) or "target"


def _title(report: dict) -> list[str]:
    return [f"# Agentic SAST — {_target_name(report)}", ""]


def _summary_section(report: dict) -> list[str]:
    out = ["## Summary", ""]
    target = report.get("target") or {}
    repo = _s(target.get("repo_path"))
    commit = _s(target.get("commit"))
    if repo:
        line = f"**Target:** `{repo}`"
        if commit:
            line += f" (commit `{commit}`)"
        out.append(line)
    run_id = _s(report.get("run_id"))
    if run_id:
        out.append(f"**Run ID:** `{run_id}`")

    summary = report.get("summary") or {}
    total = summary.get("total")
    if total is None:
        total = len(report.get("findings") or [])
    tally = _sev_tally(summary.get("by_severity") or {})
    line = f"**Total findings:** {total}"
    if tally:
        line += f" — {tally}"
    out.append(line)
    out.append("")
    return out


def _sev_tally(by_severity: dict) -> str:
    """`critical: 1, medium: 2` in fixed severity order (deterministic)."""
    parts = [f"{sev}: {by_severity[sev]}" for sev in _SEV_ORDER if by_severity.get(sev)]
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Scan Metrics.
# ---------------------------------------------------------------------------


def _scan_metrics_section(report: dict) -> list[str]:
    out = ["## Scan Metrics", ""]
    m = report.get("scan_metrics")
    if not m:
        out += [NOT_DETERMINED, ""]
        return out

    def bullet(label: str, value: str) -> None:
        out.append(f"- {label}: {value if value else 'Not determined (static run)'}")

    bullet("Files in scope", _int(m.get("files_in_scope")))
    bullet("Files analyzed (unique)", _int(m.get("files_analyzed")))
    cov = m.get("coverage_pct")
    bullet("Coverage", f"{cov:.1f}%" if isinstance(cov, (int, float)) else "")
    dur = m.get("duration_sec")
    bullet("Duration (sec)", _fmt_num(dur))
    cost = m.get("cost_usd")
    bullet("Cost (USD)", f"${cost:.4f}" if isinstance(cost, (int, float)) else "")
    out.append("")

    phases = m.get("tokens_by_phase") or []
    if phases:
        out += ["### Tokens by phase", ""]
        rows = []
        for p in phases:
            rows.append([
                _s(p.get("phase")),
                _int(p.get("input_tokens")),
                _int(p.get("output_tokens")),
                f"${p['cost_usd']:.4f}" if isinstance(p.get("cost_usd"), (int, float)) else "",
            ])
        out += _md_table(
            ["Phase", "Input tokens", "Output tokens", "Cost (USD)"],
            rows, aligns=["l", "r", "r", "r"],
        )
        out.append("")
    return out


def _fmt_num(value: Any) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.1f}"
    return ""


# ---------------------------------------------------------------------------
# Threat Model.
# ---------------------------------------------------------------------------


def _threat_model_section(report: dict) -> list[str]:
    out = ["## Threat Model", ""]
    tm = report.get("threat_model")
    if not tm:
        out += [NOT_DETERMINED, ""]
        return out

    out += ["### System context", ""]
    out += [_s(tm.get("system_context")) or NOT_DETERMINED, ""]

    # Assets table.
    out += ["### Assets", ""]
    assets = tm.get("assets") or []
    if assets:
        rows = [[_s(a.get("name")), _s(a.get("sensitivity")), _s(a.get("description"))]
                for a in assets]
        out += _md_table(["Asset", "Sensitivity", "Description"], rows)
    else:
        out.append(NOT_DETERMINED)
    out.append("")

    # Trust boundaries.
    out += ["### Trust boundaries", ""]
    boundaries = tm.get("trust_boundaries") or []
    if boundaries:
        for b in boundaries:
            name = _s(b.get("name"))
            desc = _s(b.get("description"))
            out.append(f"- **{name}** — {desc}" if name else f"- {desc}")
    else:
        out.append(NOT_DETERMINED)
    out.append("")

    # Ranked threats table.
    out += ["### Ranked threats", ""]
    threats = tm.get("ranked_threats") or []
    if threats:
        rows = [[_s(t.get("rank")), _s(t.get("threat")), _s(t.get("rationale"))]
                for t in threats]
        out += _md_table(["#", "Threat", "Rationale"], rows, aligns=["r", "l", "l"])
    else:
        out.append(NOT_DETERMINED)
    out.append("")

    # Open questions.
    out += ["### Open questions", ""]
    questions = tm.get("open_questions") or []
    if questions:
        out += [f"- {_s(q)}" for q in questions]
    else:
        out.append(NOT_DETERMINED)
    out.append("")
    return out


# ---------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------


def _verification_section(report: dict) -> list[str]:
    out = ["## Verification", ""]
    v = report.get("verification")
    if not v:
        out += [NOT_DETERMINED, ""]
        return out
    out.append(f"- Raw findings (pre-verification): {_s(v.get('raw_findings'))}")
    out.append(f"- True positives (confirmed): {_s(v.get('true_positives'))}")
    out.append(f"- False positives (rejected): {_s(v.get('false_positives'))}")
    out.append(f"- Needs more info: {_s(v.get('needs_more_info'))}")
    out.append(f"- Duplicates collapsed: {_s(v.get('duplicates_collapsed'))}")
    prec = v.get("precision_pct")
    out.append(f"- Verification precision: "
               f"{prec:.1f}%" if isinstance(prec, (int, float)) else "- Verification precision: ")
    out.append("")
    return out


# ---------------------------------------------------------------------------
# Findings.
# ---------------------------------------------------------------------------


def _findings_section(report: dict) -> list[str]:
    findings = report.get("findings") or []
    out = [f"## Findings ({len(findings)})", ""]
    if not findings:
        out += ["_No reachable, confirmed findings._", ""]
        return out
    for idx, f in enumerate(findings, start=1):
        out += _finding_block(idx, f if isinstance(f, dict) else {})
    return out


def _finding_block(idx: int, f: dict) -> list[str]:
    sev = _s(f.get("severity")).upper() or "UNKNOWN"
    title = _s(f.get("title")) or "(untitled finding)"
    out = [f"### {idx}. [{sev}] {title}", ""]
    out += _finding_meta(f)
    out.append("")

    out += ["#### Description", "", _s(f.get("description")) or NOT_DETERMINED, ""]
    out += ["#### Impact", "", _s(f.get("impact")) or NOT_DETERMINED, ""]
    out += ["#### Exploit scenario", "", _s(f.get("exploit_scenario")) or NOT_DETERMINED, ""]
    out += _preconditions(f)
    out += _evidence_and_trace(f)
    out += ["#### How to fix", "",
            _s(f.get("how_to_fix")) or _s(f.get("recommendation")) or NOT_DETERMINED, ""]
    out += _adversarial_verification(f)
    out += _ghsa_block(f)
    out += ["---", ""]
    return out


def _finding_meta(f: dict) -> list[str]:
    """The metadata header lines: Class / CWE (+link) / File / CVSS / Confidence /
    Also-at. Each line ends with two spaces so it hard-wraps in Markdown."""
    out: list[str] = []
    out.append(f"**Class:** {_s(f.get('vuln_class')) or NOT_DETERMINED}  ")
    cwe = _s(f.get("cwe"))
    if cwe:
        out.append(f"**CWE:** {_cwe_label(cwe)} — {_cwe_url(cwe)}  ")
    else:
        out.append(f"**CWE:** {NOT_DETERMINED}  ")

    file = _s(f.get("file"))
    ls, le = f.get("line_start"), f.get("line_end")
    loc = file
    if file and ls is not None:
        loc = f"{file}:{ls}-{le}" if le is not None and le != ls else f"{file}:{ls}"
    out.append(f"**File:** `{loc}`  " if loc else f"**File:** {NOT_DETERMINED}  ")

    out.append(f"**CVSS 3.1:** {_cvss_str(f.get('cvss'))}  ")
    out.append(f"**Confidence:** {_confidence_str(f)}  ")

    also = _also_at(f.get("variants"))
    if also:
        out.append(f"**Also at:** {also}  ")
    return out


def _cvss_str(cvss: Any) -> str:
    if not isinstance(cvss, dict):
        return NOT_DETERMINED
    score = _fmt_score(cvss.get("score"))
    sev = _s(cvss.get("severity")).title()
    vector = _s(cvss.get("vector"))
    if not (score or vector):
        return NOT_DETERMINED
    head = f"**{score}**" if score else ""
    if sev:
        head = f"{head} ({sev})" if head else f"({sev})"
    if vector:
        return f"{head} — `{vector}`" if head else f"`{vector}`"
    return head or NOT_DETERMINED


def _confidence_str(f: dict) -> str:
    """Prefer the validator's confidence (adversarial), else the finding's own."""
    val = f.get("validation")
    if isinstance(val, dict):
        c = val.get("validator_confidence")
        if isinstance(c, (int, float)):
            return f"{c:.2f}"
    c = f.get("confidence")
    if isinstance(c, (int, float)):
        return f"{c:.2f}"
    return "Not determined"


def _also_at(variants: Any) -> str:
    """Render located-sibling references as `file:line` (or the bare finding_id
    when a variant carries no file). Empty string when there are none."""
    if not variants:
        return ""
    locs: list[str] = []
    for v in variants:
        if isinstance(v, dict):
            if v.get("file"):
                locs.append(f"`{_s(v.get('file'))}:{_s(v.get('line_start'))}`")
            else:
                locs.append(f"`{_s(v.get('finding_id'))}`")
        else:
            locs.append(f"`{_s(v)}`")
    return ", ".join(locs)


def _preconditions(f: dict) -> list[str]:
    out = ["#### Preconditions", ""]
    pres = f.get("preconditions")
    if isinstance(pres, list) and pres:
        out += [f"- {_s(p)}" for p in pres]
    else:
        out.append(NOT_DETERMINED)
    out.append("")
    return out


def _evidence_and_trace(f: dict) -> list[str]:
    out: list[str] = []
    evidence = _s(f.get("evidence"))
    if evidence:
        out += ["_Evidence:_", ""]
        out += _fenced(evidence)
        out.append("")
    trace = f.get("trace") or {}
    eps = trace.get("entry_points") or []
    if eps:
        out.append("**Entry points:**")
        for e in eps:
            kind = _s(e.get("kind"))
            location = _s(e.get("location"))
            by = _s(e.get("controllable_by"))
            line = f"- `{kind}` at `{location}`"
            if by:
                line += f" — controllable by {by}"
            out.append(line)
        out.append("")
    chain = trace.get("call_chain") or []
    if chain:
        out.append("**Call chain:**")
        for frame in chain:
            out.append(f"1. `{_s(frame.get('file'))}:{_s(frame.get('line'))}` — "
                       f"`{_s(frame.get('function'))}()`")
        out.append("")
    return out


def _adversarial_verification(f: dict) -> list[str]:
    out = ["#### Adversarial verification", ""]
    val = f.get("validation")
    if not isinstance(val, dict) or not val:
        out += [NOT_DETERMINED, ""]
        return out
    verdict = _s(val.get("verdict"))
    label = _VERDICT_LABEL.get(verdict, verdict.upper() or "UNKNOWN")
    conf = val.get("validator_confidence")
    head = f"**Verdict:** {label}"
    if isinstance(conf, (int, float)):
        head += f" — confidence {conf:.2f}"
    out.append(head)
    rationale = _s(val.get("rationale"))
    if rationale:
        out += ["", rationale]
    out.append("")
    return out


# ---------------------------------------------------------------------------
# GHSA-style advisory sub-block (Advisory metadata + Proof of Concept + Weaknesses).
# ---------------------------------------------------------------------------


def _ghsa_block(f: dict) -> list[str]:
    out = ["#### Advisory", "",
           "_GHSA-style advisory — paste-ready for a GitHub Security Advisory._", ""]
    out.append(f"**Summary** — {_s(f.get('title')) or NOT_DETERMINED}")
    out.append("")
    out.append(f"**Details** — {_s(f.get('description')) or NOT_DETERMINED}")
    out.append("")
    out.append(f"**Impact** — {_s(f.get('impact')) or NOT_DETERMINED}")
    out.append("")
    out.append(f"**Affected versions:** {_ADVISORY_VERSIONS}  ")
    out.append(f"**Patched versions:** {_ADVISORY_VERSIONS}")
    out.append("")
    out += _advisory_references(f)

    # Proof of Concept — its own sub-header so the fenced PoC reads clearly.
    out += ["#### Proof of Concept", ""]
    out += _poc_block(f.get("poc"))
    out.append("")

    # Weaknesses — CWE id + name + MITRE link.
    out += ["#### Weaknesses", ""]
    cwe = _s(f.get("cwe"))
    if cwe:
        out.append(f"- [{_cwe_label(cwe)}]({_cwe_url(cwe)})")
    else:
        out.append(NOT_DETERMINED)
    out.append("")
    return out


def _advisory_references(f: dict) -> list[str]:
    out = ["**References:**"]
    cwe = _s(f.get("cwe"))
    refs: list[str] = []
    if cwe:
        refs.append(f"- {_cwe_url(cwe)}")
    file = _s(f.get("file"))
    if file:
        ls = f.get("line_start")
        loc = f"{file}:{ls}" if ls is not None else file
        refs.append(f"- `{loc}` (source location)")
    if not refs:
        refs.append(f"- {NOT_DETERMINED}")
    out += refs
    out.append("")
    return out


def _poc_block(poc: Any) -> list[str]:
    if not isinstance(poc, dict) or not _s(poc.get("code")):
        return [NOT_DETERMINED]
    lang = _s(poc.get("language"))
    out = _fenced(_s(poc.get("code")), lang)
    succeeded = poc.get("succeeded")
    if isinstance(succeeded, bool):
        status = "executed successfully" if succeeded else "not executed (static run)"
        out.append("")
        out.append(f"_PoC status: {status}._")

    # The observer evidence is the receipt: it records that the dangerous
    # operation was seen to FIRE (a process spawned, a socket opened) and — via
    # the attribution suffix / JFR stack trace — that it fired from the target's
    # own code. Without it a reader has the exploit script but no proof it ran,
    # which is precisely the claim this tool exists to make.
    evidence = poc.get("observer_evidence")
    if isinstance(evidence, list) and evidence:
        out += ["", "**Runtime observer evidence** — the dangerous operation was "
                    "observed as it fired:", ""]
        out += _fenced("\n".join(str(e) for e in evidence[:12]), "text")

    run_output = _s(poc.get("run_output"))
    if run_output and not evidence:
        out += ["", "**PoC output:**", ""]
        out += _fenced(run_output[-1200:], "text")

    notes = _s(poc.get("notes"))
    if notes:
        out += ["", f"_{notes}_"]
    return out


# ---------------------------------------------------------------------------
# Exploit chains (conditional).
# ---------------------------------------------------------------------------


def _chains_section(report: dict) -> list[str]:
    chains = report.get("chains") or []
    if not chains:
        return []
    out = ["## Exploit chains", ""]
    for c in chains:
        c = c if isinstance(c, dict) else {}
        sev = _s(c.get("severity")).upper() or "UNKNOWN"
        title = _s(c.get("title")) or "(untitled chain)"
        out.append(f"### [{sev}] {title}")
        fids = c.get("finding_ids") or []
        if fids:
            out.append(f"**Findings:** {', '.join(_s(x) for x in fids)}")
        out.append("")
        out.append(_s(c.get("narrative")) or NOT_DETERMINED)
        out.append("")
        blocked = c.get("blocked_by_controls") or []
        if blocked:
            out.append(f"**Blocked by controls:** {', '.join(_s(x) for x in blocked)}")
            out.append("")
    return out
