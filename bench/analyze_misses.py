"""Self-tuning miss analysis: locate WHERE the pipeline lost a missed
benchmark CVE (recon / hunt / validate / dedupe / trace), and optionally
suggest a minimal prompt fix for a human to apply.

Adapted from VulnHunter's harness/local_harness/benchmark/analyze_misses.py
(Capital One, Apache License 2.0) -- same "locate the loss phase, then
diagnose it" two-step shape, repointed at `audit`'s stage vocabulary and
structured (DB-backed) findings/recon/trace data instead of free-text scan
logs and results/*.md files:
  - `locate_loss_phase` no longer greps result Markdown files for identifier
    matches; `audit` findings carry structured `file`/`cwe`/`validation_status`/
    `is_canonical` fields and a `traces` table keyed by finding_id, so the
    six loss-phase branches below are answered by direct field checks,
    reusing `bench.scorer.finding_matches_cve`/`score_corpus` rather than a
    fuzzy identifier-grep across scan artifacts.
  - `extract_identifiers`/`search_file_for_identifiers` are ported near-
    verbatim (donor L78-139) -- not used by the deterministic locator below
    (audit's structured data makes free-text search unnecessary there), but
    kept for the optional `--diagnose` layer, to ground its prompt against
    the responsible prompt file's existing text.
  - `DIAGNOSTIC_SYSTEM_PROMPT` is ported near-verbatim (donor L43-68), phase
    names swapped for audit's recon/hunt/validate/dedupe/trace stages and
    prompt paths swapped for this repo's `prompts/NN-stage.md` files.
Full license text: https://www.apache.org/licenses/LICENSE-2.0 (also see
/Users/snatarajan14/VulnHunter/LICENSE).

  Copyright Capital One (VulnHunter contributors) for the adapted shape.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

This is an OFFLINE bench tool, not part of the `audit` pipeline: it reads
scan state (StateDB + ground truth) and SUGGESTS prompt edits for a human to
apply -- it never edits a prompt file itself, never scans, and never touches
`audit/` pipeline code, the C/C++/asan path, or a prompt. Its pure core
(everything below "CLI") makes zero network calls; only `--diagnose` shells
out to `claude -p`, and only when that flag is explicitly passed by a human.

Usage:
    python -m bench.analyze_misses --run-id bench_target_abcd1234
    python -m bench.analyze_misses --run-id ... --diagnose   # optional, needs network
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from audit.state import open_db
from bench.config import AUDIT_REPO_ROOT, AUDIT_STATE_DB, GROUND_TRUTH_DIR, WORK_DIR, atomic_write_json
from bench.scorer import finding_matches_cve, score_corpus

# ---------------------------------------------------------------------------
# Audit-stage prompt map. Every loss phase `locate_loss_phase` can return,
# except "scoring" (a matcher/report-granularity edge case with no single
# responsible prompt -- see branch 6), maps to the prompt file a human
# should look at first. "unknown" is the fallback for that edge case.
# ---------------------------------------------------------------------------

PHASE_TO_PROMPT = {
    "recon": "prompts/01-recon.md",
    "hunt": "prompts/02-hunt.md",
    "validate": "prompts/03-validate.md",
    "dedupe": "prompts/05-dedupe.md",
    "trace": "prompts/06-trace.md",
    "unknown": "prompts/02-hunt.md",
}


# ---------------------------------------------------------------------------
# extract_identifiers / search_file_for_identifiers -- ported from
# VulnHunter near-verbatim (donor L78-139). NOT used by the deterministic
# loss-phase locator below; used only by the optional --diagnose layer.
# ---------------------------------------------------------------------------

_CODE_EXTS = {
    "py", "js", "ts", "jsx", "tsx", "java", "go", "rb", "php", "c", "cpp", "cc",
    "h", "hpp", "cs", "kt", "kts", "scala", "rs", "swift", "m", "mm", "sh",
    "json", "yaml", "yml", "xml", "html", "sql", "tf", "gradle", "properties",
}


def extract_identifiers(description: str) -> list[str]:
    """Extract file paths, function names, and endpoint patterns from free
    text -- a finding/CVE description, a validate rationale, a trace
    rationale, etc."""
    identifiers: list[str] = []

    # A token like `word.word` only counts as a file path if it contains a
    # directory separator or ends in a known code/config extension. Without
    # this filter, prose like "e.g." or version strings like "1.2.3" get
    # mistaken for files and produce spurious loss-phase evidence.
    for candidate in re.findall(r'[\w/.-]+\.\w{1,4}', description):
        ext = candidate.rsplit(".", 1)[-1].lower()
        if "/" in candidate or ext in _CODE_EXTS:
            identifiers.append(candidate)

    function_names = re.findall(r'(?:function|handler|endpoint|method)\s+(\w+)|(\w+)\(\)', description)
    for match in function_names:
        name = match[0] or match[1]
        if name and len(name) > 3:
            identifiers.append(name)

    route_patterns = re.findall(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/[\w/{}\-]+)', description)
    identifiers.extend(route_patterns)

    api_patterns = re.findall(r'/api/[\w/\-{}]+', description)
    identifiers.extend(api_patterns)

    camel_names = re.findall(r'\b[a-z]+(?:[A-Z][a-z]+){1,}\b', description)
    identifiers.extend([n for n in camel_names if len(n) > 5])

    return list(set(identifiers))


def search_file_for_identifiers(filepath: str, identifiers: list[str], context_lines: int = 3) -> list[dict]:
    """Search a file for any of the given identifiers. Return matches with
    context. Used only by the optional --diagnose layer (never by the
    tested pure core)."""
    path = Path(filepath)
    if not path.is_file():
        return []

    lines = path.read_text(errors="replace").splitlines(keepends=True)

    matches = []
    for ident in identifiers:
        # Plain word identifiers (function/variable names) need a word-
        # boundary match so a short name doesn't match unrelated
        # substrings; path/route identifiers keep substring matching.
        if re.fullmatch(r"\w+", ident):
            pattern = re.compile(r"\b" + re.escape(ident) + r"\b", re.IGNORECASE)
            matcher = lambda line, p=pattern: p.search(line) is not None
        else:
            matcher = lambda line, i=ident: i.lower() in line.lower()
        for i, line in enumerate(lines):
            if matcher(line):
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                context = "".join(lines[start:end])
                matches.append({
                    "identifier": ident,
                    "file": filepath,
                    "line": i + 1,
                    "context": context.strip(),
                })
                break
    return matches


# ---------------------------------------------------------------------------
# Deterministic loss-phase locator -- the tested core. Plain data in
# (findings_all/recon_output/traces_by_id are all plain dicts, sourced from
# StateDB by the CLI or hand-built by tests), no I/O, no network.
# ---------------------------------------------------------------------------

def _recon_enumerated_area(cve: dict, recon_output: dict | None) -> bool:
    """True iff any of `cve["file_hint"]`'s substrings appears (case-
    insensitively) in a recon `inputs[]` entry's location/variable/
    entry_point, or a `subsystems[]` entry's path/name."""
    if not recon_output:
        return False
    hints = [h.lower() for h in (cve.get("file_hint") or []) if h]
    if not hints:
        return False

    fields: list[str | None] = []
    for inp in recon_output.get("inputs") or []:
        fields.extend([inp.get("location"), inp.get("variable"), inp.get("entry_point")])
    for sub in recon_output.get("subsystems") or []:
        fields.extend([sub.get("path"), sub.get("name")])

    for field in fields:
        if not field:
            continue
        field_lower = field.lower()
        if any(hint in field_lower for hint in hints):
            return True
    return False


def _rejection_rationale(matches: list[dict]) -> str:
    """Best-effort rejection rationale for a validate false-reject: prefer
    the structured `validation_json.rationale`, fall back to a same-named
    key inside `raw_json`, else a generic note."""
    for f in matches:
        rationale = (f.get("validation_json") or {}).get("rationale")
        if rationale:
            return rationale
    for f in matches:
        rationale = (f.get("raw_json") or {}).get("rationale")
        if rationale:
            return rationale
    return "all matching findings were rejected by validate; no rationale recorded"


def locate_loss_phase(
    cve: dict,
    findings_all: list[dict],
    recon_output: dict | None,
    traces_by_id: dict[str, dict | None],
) -> tuple[str, str]:
    """Determine which audit stage lost `cve`. Returns (phase, evidence).

    `findings_all` is EVERY finding the run produced (any validation_status,
    canonical or not) -- `bench.scorer.finding_matches_cve` narrows it to the
    ones that could plausibly BE this CVE (same CWE-class + a file_hint
    substring in their file path), and the branches below ask, in order,
    which stage is why none of those survived to be scored as a detection.
    """
    matches = [f for f in findings_all if finding_matches_cve(f, cve)]

    # 1/2. Nothing in findings_all even resembles this CVE. Recon is only
    # "at fault" if it never surfaced the area in the first place; if it
    # did, the miss is Hunt's (it had the area but flagged nothing there).
    if not matches:
        if _recon_enumerated_area(cve, recon_output):
            return ("hunt", f"recon enumerated the area but no hunt finding "
                            f"matched class {cve.get('class')}")
        return ("recon", f"no recon input/subsystem references file_hint "
                         f"{cve.get('file_hint')}")

    # 3. A match exists, but Validate rejected every one of them.
    if all(f.get("validation_status") == "rejected" for f in matches):
        return ("validate", _rejection_rationale(matches))

    # 4. A match was confirmed but Dedupe merged it into someone else's
    # canonical group -- it's real, just not the group's spokesperson.
    merged = next(
        (f for f in matches
         if f.get("validation_status") == "confirmed" and not f.get("is_canonical")),
        None,
    )
    if merged is not None:
        return ("dedupe", "confirmed but merged into a canonical group — dedupe over-merged")

    # 5. A match is confirmed + canonical, but Trace marked it (or left it)
    # unreachable.
    for f in matches:
        if f.get("validation_status") == "confirmed" and f.get("is_canonical"):
            trace = traces_by_id.get(f.get("finding_id"))
            if not trace or not trace.get("reachable"):
                evidence = (trace or {}).get("rationale") or "no trace recorded for this finding"
                return ("trace", evidence)

    # 6. confirmed + canonical + reachable, yet still scored missed -- the
    # finding exists and cleared every stage; this is a matcher/report
    # granularity mismatch, not a prompt gap.
    return ("scoring", "finding exists and passed all stages — matcher/report granularity mismatch")


def analyze_misses(
    confirmed: list[dict],
    findings_all: list[dict],
    recon_output: dict | None,
    traces_by_id: dict[str, dict | None],
    expected: list[dict],
) -> list[dict]:
    """For every CVE `bench.scorer.score_corpus` scores as missed, resolve
    its full ground-truth dict and locate the loss phase. Returns one
    analysis dict per miss, in `expected`'s order."""
    missed_ids = score_corpus(confirmed, expected)["cve_missed"]
    by_id = {cve["finding_id"]: cve for cve in expected}

    analyses = []
    for cve_id in missed_ids:
        cve = by_id.get(cve_id)
        if cve is None:
            continue  # defensive: score_corpus only emits ids it read from `expected`
        phase, evidence = locate_loss_phase(cve, findings_all, recon_output, traces_by_id)
        analyses.append({
            "cve_id": cve_id,
            "class": cve.get("class"),
            "cwe": cve.get("cwe"),
            "loss_phase": phase,
            "responsible_prompt": PHASE_TO_PROMPT.get(phase, PHASE_TO_PROMPT["unknown"]),
            "evidence": evidence,
        })
    return analyses


def render_report(analyses: list[dict]) -> str:
    """Render `analyses` as Markdown: a header with counts, a phase
    histogram (so the operator sees the dominant loss stage at a glance),
    then one section per miss. Pure/deterministic -- no timestamps."""
    lines = ["# Miss Analysis", "", f"**Misses analyzed**: {len(analyses)}", ""]

    lines.append("## Loss-phase histogram")
    lines.append("")
    histogram = Counter(a["loss_phase"] for a in analyses)
    if histogram:
        for phase, count in sorted(histogram.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- **{phase}**: {count}")
    else:
        lines.append("- (no misses)")
    lines.append("")

    lines.append("## Misses")
    lines.append("")
    for a in analyses:
        lines.append(f"### {a['cve_id']} ({a.get('class')}, {a.get('cwe')})")
        lines.append("")
        lines.append(f"- **Loss phase**: {a['loss_phase']}")
        lines.append(f"- **Responsible prompt**: {a['responsible_prompt']}")
        lines.append(f"- **Evidence**: {a['evidence']}")
        diag = a.get("diagnostic")
        if diag:
            lines.append(f"- **Root cause** (--diagnose): {diag.get('root_cause', 'unknown')}")
            lines.append(f"- **Suggested change** ({diag.get('change_type', 'unknown')}): "
                         f"{diag.get('suggested_change', '')}")
            lines.append(f"- **FP risk**: {diag.get('false_positive_risk', 'unknown')} — "
                         f"{diag.get('risk_explanation', '')}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Optional --diagnose layer: invokes `claude -p` to suggest a minimal,
# general prompt fix per miss. NEVER called at import time or by the core
# functions above -- only main(), and only when --diagnose is passed. Tests
# never pass --diagnose, so this path is exercised by neither the unit
# tests nor CI; it exists for a human operator to run by hand.
# ---------------------------------------------------------------------------

DIAGNOSTIC_SYSTEM_PROMPT = """You are an expert security-scanner prompt engineer investigating why `audit`, an agentic static-vulnerability pipeline, missed a known CVE in its benchmark corpus.

INVESTIGATION PROCESS:
1. Start with the ground-truth CVE (class, CWE, file-hint substrings, description) to understand exactly what should have been found.
2. Read the pre-analysis loss-phase verdict and its evidence below -- it names the pipeline stage (recon/hunt/validate/dedupe/trace) most likely responsible, but VERIFY it rather than trusting it blindly.
3. Read the responsible prompt file given below to identify the instruction gap that let this miss through.

DIAGNOSIS CONSTRAINTS:
- Identify the ROOT CAUSE in that prompt's instructions.
- Suggest a MINIMAL fix: a single sentence, clause, or bullet-point addition/edit/deletion.
- Be GENERAL: the fix should catch an entire CLASS of similar misses, not just this one CVE.
- Prefer adding to an existing list over restructuring sections.
- Deletions and edits are acceptable if they remove an overly restrictive gate.
- Conciseness is paramount -- prompts must stay small.

Output ONLY valid JSON:
{
  "root_cause": "Why the pipeline missed this -- be specific about which instruction/rule/gate caused the miss",
  "prompt_file": "The primary prompt file to change (e.g. prompts/02-hunt.md)",
  "section_to_change": "Quote the relevant section heading or existing text",
  "suggested_change": "The specific text to add, modify, or delete -- as short and general as possible",
  "change_type": "add|edit|delete",
  "false_positive_risk": "low|medium|high",
  "risk_explanation": "Why this change might or might not introduce false positives"
}"""


def build_diagnostic_prompt(analysis: dict, repo_root: Path) -> str:
    """Build the per-miss investigative prompt. Grounds the request with any
    evidence-derived identifiers already present (or absent) in the
    responsible prompt file, via the ported extract_identifiers/
    search_file_for_identifiers helpers."""
    prompt_rel = analysis["responsible_prompt"]
    prompt_path = repo_root / prompt_rel

    grounding = ""
    identifiers = extract_identifiers(analysis.get("evidence", "") or "")
    if identifiers:
        hits = search_file_for_identifiers(str(prompt_path), identifiers)
        if hits:
            excerpt = "\n".join(f"  - {h['identifier']!r} @ line {h['line']}" for h in hits[:5])
            grounding = f"\n## Evidence identifiers already present in {prompt_rel}\n{excerpt}\n"
        else:
            shown = ", ".join(identifiers[:5])
            grounding = f"\n## None of the evidence's identifiers ({shown}) appear in {prompt_rel} yet.\n"

    return f"""CVE {analysis['cve_id']} was NOT detected. Figure out where the pipeline went wrong.

## Ground Truth CVE
- **ID**: {analysis['cve_id']}
- **Class**: {analysis.get('class')}
- **CWE**: {analysis.get('cwe')}

## Pre-analysis (deterministic; verify against the prompt file rather than trusting blindly)
- **Loss phase**: {analysis['loss_phase']}
- **Evidence**: {analysis['evidence']}
- **Responsible prompt file**: {prompt_rel}
{grounding}
## Investigation
- Read {prompt_path} and identify the instruction gap that let this miss through.

Come up with the minimal change to that prompt to mitigate this gap, as concise and general as possible.
Output ONLY valid JSON as specified in your system prompt."""


def _parse_diagnostic_output(raw_output: str) -> dict:
    text = raw_output.strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return {"root_cause": "failed to parse diagnostic output", "prompt_file": "unknown",
            "section_to_change": text[:500], "suggested_change": "", "change_type": "",
            "false_positive_risk": "unknown", "risk_explanation": ""}


def invoke_diagnostic(analysis: dict, *, model: str, repo_root: Path, timeout: int = 600) -> dict:
    """Shell out to `claude -p` for one miss's diagnosis. Network-requiring;
    only reachable via main()'s --diagnose flag."""
    prompt = build_diagnostic_prompt(analysis, repo_root)
    cmd = [
        "claude", "-p", prompt,
        "--output-format", "text",
        "--model", model,
        "--system-prompt", DIAGNOSTIC_SYSTEM_PROMPT,
        "--allowedTools", "Read", "Bash(grep:*)",
        "--permission-mode", "acceptEdits",
        "--add-dir", str(repo_root / "prompts"),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"root_cause": f"diagnostic timed out after {timeout}s",
                "prompt_file": analysis["responsible_prompt"], "section_to_change": "",
                "suggested_change": "", "change_type": "",
                "false_positive_risk": "unknown", "risk_explanation": ""}
    except FileNotFoundError:
        return {"root_cause": "`claude` CLI not found on PATH",
                "prompt_file": analysis["responsible_prompt"], "section_to_change": "",
                "suggested_change": "", "change_type": "",
                "false_positive_risk": "unknown", "risk_explanation": ""}

    if result.returncode != 0:
        return {"root_cause": f"diagnostic failed: exit {result.returncode}: {result.stderr.strip()[:200]}",
                "prompt_file": analysis["responsible_prompt"], "section_to_change": "",
                "suggested_change": "", "change_type": "",
                "false_positive_risk": "unknown", "risk_explanation": ""}
    return _parse_diagnostic_output(result.stdout)


def run_diagnose(analyses: list[dict], *, model: str, repo_root: Path | None = None) -> list[dict]:
    """Fold a diagnostic suggestion into each analysis. Network-requiring;
    only called from main() under --diagnose."""
    repo_root = repo_root or AUDIT_REPO_ROOT
    return [{**a, "diagnostic": invoke_diagnostic(a, model=model, repo_root=repo_root)} for a in analyses]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _finding_to_dict(f) -> dict:
    """audit.state.Finding -> the plain dict shape locate_loss_phase/
    finding_matches_cve expect. `cwe` is pulled out of raw_json (it isn't a
    real column -- bench.parse_results.load_state_db_findings does the same
    for the same reason)."""
    raw = f.raw_json or {}
    return {
        "finding_id": f.finding_id,
        "file": f.file,
        "cwe": raw.get("cwe"),
        "vuln_class": f.vuln_class,
        "validation_status": f.validation_status,
        "validation_json": f.validation_json,
        "is_canonical": f.is_canonical,
        "raw_json": raw,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Self-tuning miss analysis: locate WHERE the pipeline lost each missed benchmark CVE."
    )
    parser.add_argument("--run-id", required=True, help="audit run_id to analyze (as stored in StateDB).")
    parser.add_argument("--db", type=str, default=None, help="StateDB path (default: bench.config.AUDIT_STATE_DB).")
    parser.add_argument("--ground-truth", type=str, default=None,
                        help="Ground-truth corpus JSON (default: bench/ground_truth/datamodel-code-generator.json).")
    parser.add_argument("--out-json", type=str, default=None, help="Where to write the analyses JSON.")
    parser.add_argument("--out-md", type=str, default=None, help="Where to write the Markdown report.")
    parser.add_argument("--diagnose", action="store_true",
                        help="OPTIONAL, needs network: invoke Claude to suggest a prompt fix per miss.")
    parser.add_argument("--model", type=str, default="claude-sonnet-4-6",
                        help="Model for --diagnose (default: claude-sonnet-4-6).")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    db_path = Path(args.db) if args.db else AUDIT_STATE_DB
    if not db_path.is_file():
        print(f"Error: StateDB not found: {db_path}")
        return 1

    gt_path = Path(args.ground_truth) if args.ground_truth else (GROUND_TRUTH_DIR / "datamodel-code-generator.json")
    expected = json.loads(gt_path.read_text())

    out_json = Path(args.out_json) if args.out_json else (WORK_DIR / "miss_analysis.json")
    out_md = Path(args.out_md) if args.out_md else (WORK_DIR / "MISS_ANALYSIS.md")

    with open_db(db_path) as db:
        findings_rows = db.get_findings(args.run_id)
        findings_all = [_finding_to_dict(f) for f in findings_rows]
        traces_by_id = {f.finding_id: db.get_trace(f.finding_id) for f in findings_rows}
        # "confirmed" for recall-scoring purposes is what the pipeline would
        # actually report: confirmed + canonical (dedupe's spokesperson) +
        # reachable (trace didn't drop it) -- exactly
        # get_reachable_canonical_findings(). A confirmed-but-merged or
        # confirmed-but-unreachable finding must NOT count here, or the
        # "dedupe"/"trace" loss-phase branches above could never fire in
        # practice: the CVE would already read as found by score_corpus.
        confirmed = [_finding_to_dict(f) for f, _tr in db.get_reachable_canonical_findings(args.run_id)]
        recon_output = db.get_recon_output(args.run_id)

    analyses = analyze_misses(confirmed, findings_all, recon_output, traces_by_id, expected)

    if args.diagnose:
        analyses = run_diagnose(analyses, model=args.model)

    atomic_write_json(out_json, analyses)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    with open(out_md, "w") as f:
        f.write(render_report(analyses))

    histogram = Counter(a["loss_phase"] for a in analyses)
    print(f"\n{'='*60}\nMISS ANALYSIS: {len(analyses)} miss(es)\n{'='*60}")
    for phase, count in sorted(histogram.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {phase}: {count}")
    print(f"  JSON: {out_json}")
    print(f"  MD:   {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
