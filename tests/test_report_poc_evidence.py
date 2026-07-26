"""_attach_poc_evidence — the executed-PoC receipt in the delivered report.

VASH's differentiator is that a confirmed finding was PROVEN by running a real
exploit, and (Phase 3) that a runtime observer watched the dangerous operation
fire. That evidence lived only in run state: a live run produced 5 delivered
findings, every one with poc_succeeded=1, and zero observer lines anywhere in
report.json. These tests pin the receipt into the deliverable.
"""
from pathlib import Path

from vash.stages.report import _attach_poc_evidence, _observer_markers
from vash.state import StateDB

OBSERVER_OUT = (
    "[VASH-OBSERVER] hook-armed poc=poc.py pid=475 events=subprocess.Popen,open\n"
    "[VASH-OBSERVER] audit:subprocess.Popen ('/bin/sh', ['-c', 'echo x; id'])\n"
    "HTTP status: 200\n"
    "[VASH-OBSERVER] hook-summary observed=1 subprocess.Popen=1\n"
)


def _seed(db: StateDB, run_id: str, finding_id: str, *, poc: dict | None,
          succeeded: bool = True) -> None:
    db.add_task(run_id, {
        "task_id": "t_1", "attack_class": "command_injection", "scope_hint": "x",
        "target_files": ["app/reports.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })
    finding = {
        "finding_id": finding_id, "file": "app/reports.py",
        "line_start": 7, "line_end": 9, "vuln_class": "command_injection",
        "severity": "critical", "description": "d" * 25, "evidence_snippet": "e",
        "confidence": 0.9,
    }
    if poc is not None:
        finding["poc"] = {**poc, "succeeded": succeeded}
    db.add_finding(run_id, "t_1", finding)


def _db(tmp_path: Path) -> StateDB:
    db = StateDB(tmp_path / "state.db")
    db.create_run("/target", "r1")
    return db


def test_executed_poc_reaches_the_report(tmp_path):
    db = _db(tmp_path)
    try:
        _seed(db, "r1", "f1", poc={
            "language": "python", "code": "import app.reports as r\nr.build_report('x; id')",
            "run_output": OBSERVER_OUT, "notes": "ran under the audit-hook observer",
        })
        payload = {"findings": [{"finding_id": "f1"}]}
        _attach_poc_evidence(db, "r1", payload)

        poc = payload["findings"][0]["poc"]
        assert poc["succeeded"] is True
        assert poc["language"] == "python"
        assert "build_report" in poc["code"]
        assert poc["notes"].startswith("ran under")
        # machine-readable, so a consumer can filter the proven subset
        assert payload["findings"][0]["poc_succeeded"] is True
    finally:
        db.close()


def test_observer_evidence_is_extracted_as_its_own_field(tmp_path):
    """The marker lines ARE the proof — they must survive independently of the
    tail-bounded run_output."""
    db = _db(tmp_path)
    try:
        _seed(db, "r1", "f1", poc={"language": "python", "code": "x = 1",
                                   "run_output": OBSERVER_OUT})
        payload = {"findings": [{"finding_id": "f1"}]}
        _attach_poc_evidence(db, "r1", payload)
        ev = payload["findings"][0]["poc"]["observer_evidence"]
        assert len(ev) == 3
        assert any("audit:subprocess.Popen" in ln for ln in ev)
        assert all(ln.startswith("[VASH-OBSERVER]") for ln in ev)
        assert "HTTP status: 200" not in " ".join(ev)      # non-marker noise dropped
    finally:
        db.close()


def test_a_findings_poc_status_reflects_run_state_not_the_agents_claim(tmp_path):
    """poc.succeeded in raw_json is the hunter's word; the poc_succeeded column
    is what the pipeline recorded. The column wins."""
    db = _db(tmp_path)
    try:
        _seed(db, "r1", "f1", poc={"language": "python", "code": "x = 1"},
              succeeded=False)
        payload = {"findings": [{"finding_id": "f1"}]}
        _attach_poc_evidence(db, "r1", payload)
        assert payload["findings"][0]["poc"]["succeeded"] is False
        assert payload["findings"][0]["poc_succeeded"] is False
    finally:
        db.close()


def test_huge_run_output_is_bounded_but_keeps_the_tail(tmp_path):
    db = _db(tmp_path)
    try:
        noise = "x" * 50_000
        _seed(db, "r1", "f1", poc={"language": "python", "code": "y = 1",
                                   "run_output": noise + "\nTHE-PROOF-LINE"})
        payload = {"findings": [{"finding_id": "f1"}]}
        _attach_poc_evidence(db, "r1", payload)
        out = payload["findings"][0]["poc"]["run_output"]
        assert len(out) <= 2000
        assert "THE-PROOF-LINE" in out                     # the tail is what matters
    finally:
        db.close()


def test_finding_without_a_poc_is_left_alone(tmp_path):
    db = _db(tmp_path)
    try:
        _seed(db, "r1", "f1", poc=None)
        payload = {"findings": [{"finding_id": "f1"}]}
        _attach_poc_evidence(db, "r1", payload)
        assert "poc" not in payload["findings"][0]
    finally:
        db.close()


def test_unknown_finding_id_is_skipped(tmp_path):
    db = _db(tmp_path)
    try:
        payload = {"findings": [{"finding_id": "nope"}]}
        _attach_poc_evidence(db, "r1", payload)
        assert payload["findings"][0] == {"finding_id": "nope"}
    finally:
        db.close()


def test_attach_is_fail_soft(tmp_path, monkeypatch):
    """Report emission is the primary deliverable — an evidence bug must never
    break it."""
    db = _db(tmp_path)
    try:
        monkeypatch.setattr(db, "get_findings",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        payload = {"findings": [{"finding_id": "f1"}]}
        _attach_poc_evidence(db, "r1", payload)          # must not raise
        assert payload == {"findings": [{"finding_id": "f1"}]}
    finally:
        db.close()


def test_observer_marker_extraction_is_bounded():
    many = "\n".join(f"[VASH-OBSERVER] audit:open {i}" for i in range(200))
    assert len(_observer_markers(many)) == 40
    assert _observer_markers("") == []
    assert _observer_markers(None) == []
