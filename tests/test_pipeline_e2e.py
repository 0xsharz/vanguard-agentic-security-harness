"""End-to-end pipeline test with a fully stubbed SDK.

Drives the real orchestrator (`run_pipeline`) through all 8 stages with
every stage module's `run_agent` monkeypatched to a single canned
dispatcher keyed on `stage=`. NO Claude model call, NO network — proves
the stage wiring (DB reads/writes, task/finding/trace/report plumbing)
is correct end to end, so future prompt/stage changes are
regression-testable offline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import audit.stages._common as common_mod
import audit.stages.dedupe as dedupe_mod
import audit.stages.feedback as feedback_mod
import audit.stages.gapfill as gapfill_mod
import audit.stages.hunt as hunt_mod
import audit.stages.recon as recon_mod
import audit.stages.report as report_mod
import audit.stages.trace as trace_mod
import audit.stages.validate as validate_mod
from audit.config import load_config
from audit.orchestrator import run_pipeline
from audit.runner import AgentResult
from audit.state import StateDB

FIXTURE_REPO = (Path(__file__).parent / "fixtures" / "vulnerable_app").resolve()
RUN_ID = "test_e2e_run"
TASK_ID = "t_web_sqli_1"
FINDING_ID = "t_web_sqli_1-f1"
GROUP_ID = "g_web_sqli_1"

STAGE_MODULES = (
    recon_mod, hunt_mod, validate_mod, gapfill_mod,
    dedupe_mod, trace_mod, feedback_mod, report_mod,
)

# Canned per-stage payloads. recon/hunt/validate are the exact shapes
# given in the task brief; gapfill/dedupe/trace/feedback/report are
# derived from each stage's code (what it actually reads out of
# result.payload) + the matching schemas/*.schema.json (field names,
# required-ness, enums, patterns) so they'd also pass real schema
# validation even though the stub bypasses it.
CANNED: dict[str, dict] = {
    "recon": {
        "subsystems": [{"name": "web", "path": "app.py"}],
        "architecture": {
            "build_commands": [],
            "entry_points": ["app.py"],
            "trust_boundaries": [],
        },
        # F1: attacker-controllable input inventory. `in_name` lives in app.py
        # (matched by the SQLi finding → covered on the first pass). `in_cli`
        # lives elsewhere with an entry point no task scopes → uncovered first,
        # then reconciliation synthesizes a Hunt task naming it and re-reconciles.
        "inputs": [
            {"id": "in_name", "source_type": "HTTP query param",
             "location": "app.py:1", "variable": "name",
             "entry_point": "GET /lookup", "trust_level": "unauthenticated"},
            {"id": "in_cli", "source_type": "CLI arg",
             "location": "manage.py:5", "variable": "--path",
             "entry_point": "import command", "trust_level": "privileged"},
        ],
        "initial_tasks": [
            {
                "task_id": TASK_ID,
                "attack_class": "sql_injection",
                "scope_hint": "app.py",
                "target_files": ["app.py"],
                "rationale": "x",
                "priority": 1,
            }
        ],
    },
    "hunt": {
        "task_id": TASK_ID,
        "gaps_observed": [],
        "findings": [
            {
                "finding_id": FINDING_ID,
                "file": "app.py",
                "line_start": 1,
                "line_end": 2,
                "vuln_class": "sql-injection",
                "severity": "high",
                "description": "sqli",
                "evidence_snippet": "q=...",
                "confidence": 0.9,
            }
        ],
    },
    "validate": {
        "finding_id": FINDING_ID,
        "verdict": "confirmed",
        "rationale": "real",
        "validator_confidence": 0.9,
    },
    # gapfill_output.schema.json requires new_tasks + coverage_analysis.
    # Empty new_tasks makes the orchestrator's gapfill loop exit after
    # one Hunt/Validate/Gapfill iteration.
    "gapfill": {
        "new_tasks": [],
        "coverage_analysis": {
            "light_subsystems": [],
            "unattempted_attack_classes": [],
        },
    },
    # dedupe_output.schema.json: one group, our single confirmed finding
    # is both the sole member and the canonical.
    "dedupe": {
        "groups": [
            {
                "group_id": GROUP_ID,
                "root_cause": "unsanitized request param concatenated into a SQL string",
                "member_finding_ids": [FINDING_ID],
                "canonical_finding_id": FINDING_ID,
            }
        ],
    },
    # trace.schema.json: mark reachable so Feedback/Report pick it up
    # via get_reachable_canonical_findings().
    "trace": {
        "finding_id": FINDING_ID,
        "reachable": True,
        "confidence": 0.9,
        "rationale": "request.args flows unsanitized into cur.execute() with no auth gate",
        "entry_points": [{"kind": "http_route", "location": "app.py:lookup"}],
        "call_chain": [{"file": "app.py", "function": "lookup", "line": 1}],
        "external_inputs": ["name"],
    },
    # feedback_output.schema.json requires new_hunt_tasks. Empty list
    # makes the orchestrator skip the post-Trace Hunt/Validate/Dedupe/
    # Trace re-run and go straight to Report.
    "feedback": {
        "new_hunt_tasks": [],
    },
    # report.schema.json — the final document. run_id/target must match
    # what run_pipeline was invoked with (report.py writes this payload
    # to disk verbatim).
    "report": {
        "run_id": RUN_ID,
        "target": {"repo_path": str(FIXTURE_REPO)},
        "summary": {"total": 1, "by_severity": {"high": 1}},
        "findings": [
            {
                "finding_id": FINDING_ID,
                "title": "SQL injection in app.py",
                "severity": "high",
                "vuln_class": "sql-injection",
                "file": "app.py",
                "line_start": 1,
                "line_end": 2,
                "description": "Unsanitized request parameter is concatenated into a SQL query string.",
                "evidence": "q=...",
                "trace": {
                    "entry_points": [{"kind": "http_route", "location": "app.py:lookup"}],
                    "call_chain": [{"file": "app.py", "function": "lookup", "line": 1}],
                },
                "recommendation": "Use parameterized queries instead of string interpolation.",
            }
        ],
    },
}


@pytest.fixture
def stub_agents(monkeypatch, tmp_path):
    """Monkeypatch every stage module's `run_agent` with one async
    dispatcher keyed on `stage=`, returning a canned AgentResult whose
    `.payload` is CANNED[stage]. Also redirects the results/ and work/
    directories (normally fixed at REPO_ROOT/results, REPO_ROOT/work by
    audit.stages._common) into tmp_path so this test never writes into
    the real checkout.

    Returns the list of stage names actually dispatched through, in
    call order, so the test can assert every stage was really reached.
    """
    monkeypatch.setattr(common_mod, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(common_mod, "WORK", tmp_path / "work")

    calls: list[str] = []

    async def fake_run_agent(*, stage, artifact_dir, artifact_name, **_kwargs) -> AgentResult:
        calls.append(stage)
        payload = json.loads(json.dumps(CANNED[stage]))  # defensive deep copy
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{artifact_name}.jsonl"
        artifact_path.write_text(json.dumps({"kind": "stub", "stage": stage}) + "\n")
        return AgentResult(
            payload=payload,
            cost_usd=0.001,
            input_tokens=10,
            output_tokens=10,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=1,
            duration_ms=1,
            session_id="stub-session",
            artifact_path=artifact_path,
            repair_used=False,
            raw_result_message={
                "usage": {"input_tokens": 10, "output_tokens": 10},
                "total_cost_usd": 0.001,
                "num_turns": 1,
                "duration_ms": 1,
                "session_id": "stub-session",
            },
        )

    for mod in STAGE_MODULES:
        monkeypatch.setattr(mod, "run_agent", fake_run_agent)

    return calls


async def test_pipeline_runs_end_to_end(stub_agents, tmp_path) -> None:
    config = load_config()  # real config/stages.yaml loader — no invented default()
    db = StateDB(tmp_path / "state.db")
    try:
        report_path = await run_pipeline(
            repo_path=FIXTURE_REPO,
            run_id=RUN_ID,
            db=db,
            config=config,
        )

        # 1. The run completed (not aborted/failed).
        run_row = db.get_run(RUN_ID)
        assert run_row is not None
        assert run_row["status"] == "completed"

        # 2. At least one CONFIRMED finding is persisted.
        confirmed = db.get_findings(RUN_ID, validation_status="confirmed")
        assert len(confirmed) == 1
        assert confirmed[0].finding_id == FINDING_ID
        assert confirmed[0].is_canonical is True

        # 3. A report artifact was produced.
        assert report_path.exists()
        report_data = json.loads(report_path.read_text())
        assert report_data["run_id"] == RUN_ID
        assert report_data["summary"]["total"] == 1
        assert len(report_data["findings"]) == 1
        assert report_data["findings"][0]["finding_id"] == FINDING_ID

        # 3a. F1 completeness: both enumerated inputs reached a disposition in
        # the DB (none left NULL) and the resolved ledger is in the report.
        inputs = db.get_inputs(RUN_ID)
        assert len(inputs) == 2
        dispo = {i["id"]: i["disposition"] for i in inputs}
        assert all(v is not None for v in dispo.values()), dispo
        assert dispo["in_name"] == "covered"  # matched by the SQLi finding's file
        assert dispo["in_cli"] == "covered"   # covered after reconcile re-queue
        assert db.get_unresolved_inputs(RUN_ID) == []
        # The uncovered CLI input was re-queued as a reconcile Hunt task.
        rc_tasks = [t for t in db.get_all_tasks(RUN_ID) if t.source == "reconcile"]
        assert [t.task_id for t in rc_tasks] == ["t_rc_1"]
        # The report carries the resolved inventory as a completeness artifact.
        inventory = report_data["input_inventory"]
        assert {e["id"] for e in inventory} == {"in_name", "in_cli"}
        assert all(e["disposition"] == "covered" for e in inventory)

        # 4. Every stage's stub dispatcher was actually invoked — proves
        # the pipeline really reached each of the 8 stages rather than
        # short-circuiting on an empty-input fast path.
        assert set(stub_agents) == {
            "recon", "hunt", "validate", "gapfill",
            "dedupe", "trace", "feedback", "report",
        }
    finally:
        db.close()
