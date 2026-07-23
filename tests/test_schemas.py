"""Validate that representative payloads pass each schema."""

from __future__ import annotations

from pathlib import Path

import pytest

from audit.json_utils import validate_schema

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


HUNT_TASK_OK = {
    "task_id": "t_routes_sqli_1",
    "attack_class": "sql_injection",
    "scope_hint": "GET /lookup reads `name` from query string, passed via f-string into cur.execute() in app.py:30",
    "target_files": ["app.py"],
    "rationale": "Direct format string concatenation of untrusted input.",
    "priority": 1,
    "source": "recon",
}


RECON_OK = {
    "subsystems": [
        {"name": "web", "path": "app.py", "language": "python",
         "purpose": "Flask HTTP handlers"},
    ],
    "architecture": {
        "build_commands": ["pip install -r requirements.txt"],
        "entry_points": [
            {"kind": "http_route", "location": "app.py:lookup", "auth_required": False},
            {"kind": "http_route", "location": "app.py:ping", "auth_required": False},
        ],
        "trust_boundaries": [
            {"name": "http_to_db", "description": "HTTP query string → SQL",
             "source_zone": "anonymous_http", "sink_zone": "sqlite_query"},
        ],
        "external_inputs": [
            {"name": "name", "kind": "http_param", "controllable_by": "anonymous_user"},
        ],
    },
    "initial_tasks": [HUNT_TASK_OK],
}


FINDING_OK = {
    "task_id": "t_routes_sqli_1",
    "findings": [
        {
            "finding_id": "f_t_routes_sqli_1_1",
            "file": "app.py",
            "line_start": 28,
            "line_end": 32,
            "vuln_class": "sql_injection",
            "severity": "high",
            "cwe": "CWE-89",
            "description": "User-controlled `name` is concatenated into an SQL string via f-string and passed to cur.execute() without parameterization.",
            "evidence_snippet": "name = request.args.get('name', '')\nquery = f\"SELECT ... WHERE name = '{name}'\"\ncur.execute(query)",
            "confidence": 0.95,
        }
    ],
    "gaps_observed": [],
}


VALIDATION_OK = {
    "finding_id": "f_t_routes_sqli_1_1",
    "verdict": "confirmed",
    "rationale": "The f-string substitution happens before cur.execute parses any placeholders; no sanitizer between request.args and the query string.",
    "alternative_explanation": "Could have been a parameterized query if `name` were sourced from a trusted internal caller — but it is sourced from request.args, which is attacker-controlled.",
    "validator_confidence": 0.95,
}


TRACE_OK = {
    "finding_id": "f_t_routes_sqli_1_1",
    "reachable": True,
    "confidence": 0.95,
    "rationale": "Single hop: Flask route handler reads request.args directly and passes into the sink.",
    "entry_points": [
        {"kind": "http_route", "location": "app.py:lookup", "auth_required": False,
         "controllable_by": "anonymous_user"}
    ],
    "call_chain": [
        {"file": "app.py", "function": "lookup", "line": 28},
        {"file": "app.py", "function": "lookup", "line": 32, "note": "sink"}
    ],
    "external_inputs": ["name"],
}


REPORT_OK = {
    "run_id": "smoke",
    "target": {"repo_path": "/tmp/vulnerable_app"},
    "summary": {"total": 1, "by_severity": {"high": 1}},
    "findings": [
        {
            "finding_id": "f_t_routes_sqli_1_1",
            "title": "Unauthenticated SQL injection in /lookup via name parameter",
            "severity": "high",
            "vuln_class": "sql_injection",
            "cwe": "CWE-89",
            "file": "app.py",
            "line_start": 28,
            "line_end": 32,
            "description": "User-controlled `name` is interpolated into an SQL string and executed without parameter binding.",
            "evidence": "query = f\"SELECT ... WHERE name = '{name}'\"",
            "trace": {
                "entry_points": [{"kind": "http_route", "location": "app.py:lookup",
                                  "controllable_by": "anonymous_user"}],
                "call_chain": [{"file": "app.py", "function": "lookup", "line": 32}],
            },
            "recommendation": "Use a parameterized query: cur.execute('SELECT ... WHERE name = ?', (name,)).",
        }
    ],
}


@pytest.mark.parametrize(
    "schema_name, payload",
    [
        ("hunt_task", HUNT_TASK_OK),
        ("recon_output", RECON_OK),
        ("finding", FINDING_OK),
        ("validation", VALIDATION_OK),
        ("trace", TRACE_OK),
        ("report", REPORT_OK),
    ],
)
def test_schema_accepts(schema_name: str, payload: dict) -> None:
    errors = validate_schema(payload, SCHEMAS / f"{schema_name}.schema.json")
    assert errors == [], f"{schema_name}: {errors}"


def test_recon_rejects_missing_initial_tasks() -> None:
    bad = {k: v for k, v in RECON_OK.items() if k != "initial_tasks"}
    errors = validate_schema(bad, SCHEMAS / "recon_output.schema.json")
    assert errors, "expected validation error for missing initial_tasks"


def test_validation_rejects_bad_verdict() -> None:
    bad = {**VALIDATION_OK, "verdict": "maybe"}
    errors = validate_schema(bad, SCHEMAS / "validation.schema.json")
    assert errors, "expected validation error for bad verdict enum"


def test_validation_accepts_confirmed_with_cvss_vector() -> None:
    # V4: a confirmed verdict may carry a CVSS 3.1 base vector (+ the
    # pipeline-computed score/rating once Validate has processed it).
    ok = {
        **VALIDATION_OK,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "cvss_rating": "Critical",
    }
    errors = validate_schema(ok, SCHEMAS / "validation.schema.json")
    assert errors == [], errors


def test_validation_rejects_malformed_cvss_vector() -> None:
    bad = {**VALIDATION_OK, "cvss_vector": "not-a-cvss-vector"}
    errors = validate_schema(bad, SCHEMAS / "validation.schema.json")
    assert errors, "expected validation error for malformed cvss_vector"


def test_report_rejects_unknown_severity() -> None:
    bad = {
        **REPORT_OK,
        "findings": [{**REPORT_OK["findings"][0], "severity": "catastrophic"}],
    }
    errors = validate_schema(bad, SCHEMAS / "report.schema.json")
    assert errors, "expected validation error for unknown severity"
