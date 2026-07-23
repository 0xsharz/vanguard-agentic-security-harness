"""SQLite-backed run state. JSONL artifacts in results/ are the source of
truth for raw agent output; this DB is the queryable index used for
orchestration, resume, and reporting."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS recon_outputs (
    run_id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    source TEXT NOT NULL,
    attack_class TEXT NOT NULL,
    scope_hint TEXT NOT NULL,
    target_files TEXT NOT NULL,
    rationale TEXT,
    priority INTEGER NOT NULL DEFAULT 3,
    status TEXT NOT NULL DEFAULT 'pending',
    raw_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    file TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    vuln_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    poc_succeeded INTEGER DEFAULT 0,
    confidence REAL,
    raw_json TEXT NOT NULL,
    validation_status TEXT,
    validation_json TEXT,
    group_id TEXT,
    is_canonical INTEGER DEFAULT 0,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS traces (
    finding_id TEXT PRIMARY KEY,
    reachable INTEGER NOT NULL,
    confidence REAL,
    rationale TEXT,
    raw_json TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS chains (
    run_id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS dedupe_groups (
    group_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    canonical_finding_id TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS costs (
    cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ref_id TEXT,
    usd REAL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_creation_tokens INTEGER,
    num_turns INTEGER,
    duration_ms INTEGER,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ref_id TEXT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS inputs (
    input_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    source_type TEXT,
    location TEXT,
    variable TEXT,
    entry_point TEXT,
    trust_level TEXT,
    disposition TEXT,
    disposition_evidence TEXT,
    raw_json TEXT,
    created_at REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_run_status ON tasks(run_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_validation ON findings(validation_status);
CREATE INDEX IF NOT EXISTS idx_findings_group ON findings(group_id);
CREATE INDEX IF NOT EXISTS idx_costs_run_stage ON costs(run_id, stage);
CREATE INDEX IF NOT EXISTS idx_inputs_run ON inputs(run_id);
"""


@dataclass
class Task:
    task_id: str
    run_id: str
    source: str
    attack_class: str
    scope_hint: str
    target_files: list[str]
    rationale: str
    priority: int
    status: str
    raw_json: dict


@dataclass
class Finding:
    finding_id: str
    task_id: str
    run_id: str
    file: str
    line_start: int
    line_end: int
    vuln_class: str
    severity: str
    description: str
    evidence: str
    poc_succeeded: bool
    confidence: float | None
    raw_json: dict
    validation_status: str | None
    validation_json: dict | None
    group_id: str | None
    is_canonical: bool


class StateDB:
    def __init__(self, db_path: Path):
        self.path = db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ---------- runs ----------

    def create_run(self, repo_path: str, run_id: str | None = None) -> str:
        run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"
        self._conn.execute(
            "INSERT INTO runs (run_id, repo_path, started_at, status) VALUES (?, ?, ?, ?)",
            (run_id, repo_path, time.time(), "running"),
        )
        self._conn.commit()
        return run_id

    def finish_run(self, run_id: str, status: str = "completed") -> None:
        self._conn.execute(
            "UPDATE runs SET status = ?, finished_at = ? WHERE run_id = ?",
            (status, time.time(), run_id),
        )
        self._conn.commit()

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    def list_runs(self) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC"
            ).fetchall()
        )

    # ---------- recon ----------

    def save_recon_output(self, run_id: str, payload: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO recon_outputs (run_id, raw_json) VALUES (?, ?)",
            (run_id, json.dumps(payload)),
        )
        self._conn.commit()

    def get_recon_output(self, run_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM recon_outputs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    # ---------- inputs (attacker-controllable input inventory) ----------

    def add_input(self, run_id: str, inp: dict) -> str:
        """Persist one recon-enumerated attacker-controllable input.

        Idempotent (INSERT OR IGNORE on the PK). The stored ``input_id`` is
        namespaced by run so recon-emitted ids like ``in_1`` cannot collide
        across runs that share one ``state.db``. Returns the stored input_id."""
        raw_id = str(inp.get("id") or inp.get("input_id") or "").strip()
        if not raw_id:
            raw_id = uuid.uuid4().hex[:12]
        input_id = raw_id if raw_id.startswith(f"{run_id}:") else f"{run_id}:{raw_id}"
        self._conn.execute(
            """INSERT OR IGNORE INTO inputs
            (input_id, run_id, source_type, location, variable, entry_point,
             trust_level, disposition, disposition_evidence, raw_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)""",
            (
                input_id,
                run_id,
                inp.get("source_type"),
                inp.get("location"),
                inp.get("variable"),
                inp.get("entry_point"),
                inp.get("trust_level"),
                json.dumps(inp),
                time.time(),
            ),
        )
        self._conn.commit()
        return input_id

    def get_inputs(self, run_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM inputs WHERE run_id = ? ORDER BY created_at, input_id",
            (run_id,),
        ).fetchall()
        return [self._row_to_input(r) for r in rows]

    def set_input_disposition(
        self, input_id: str, disposition: str, evidence: str | None = None
    ) -> None:
        self._conn.execute(
            "UPDATE inputs SET disposition = ?, disposition_evidence = ? WHERE input_id = ?",
            (disposition, evidence, input_id),
        )
        self._conn.commit()

    def get_unresolved_inputs(self, run_id: str) -> list[dict]:
        """Inputs that have not yet reached a disposition (disposition IS NULL)."""
        rows = self._conn.execute(
            "SELECT * FROM inputs WHERE run_id = ? AND disposition IS NULL "
            "ORDER BY created_at, input_id",
            (run_id,),
        ).fetchall()
        return [self._row_to_input(r) for r in rows]

    @staticmethod
    def _row_to_input(r: sqlite3.Row) -> dict:
        raw = json.loads(r["raw_json"]) if r["raw_json"] else {}
        return {
            "input_id": r["input_id"],
            "id": raw.get("id", r["input_id"]),
            "source_type": r["source_type"],
            "location": r["location"],
            "variable": r["variable"],
            "entry_point": r["entry_point"],
            "trust_level": r["trust_level"],
            "disposition": r["disposition"],
            "disposition_evidence": r["disposition_evidence"],
        }

    # ---------- tasks ----------

    def add_task(self, run_id: str, task: dict) -> None:
        now = time.time()
        self._conn.execute(
            """INSERT OR IGNORE INTO tasks
            (task_id, run_id, source, attack_class, scope_hint, target_files,
             rationale, priority, status, raw_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)""",
            (
                task["task_id"],
                run_id,
                task.get("source", "recon"),
                task["attack_class"],
                task["scope_hint"],
                json.dumps(task["target_files"]),
                task.get("rationale", ""),
                int(task.get("priority", 3)),
                json.dumps(task),
                now,
                now,
            ),
        )
        self._conn.commit()

    def get_pending_tasks(self, run_id: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? AND status = 'pending' ORDER BY priority, created_at",
            (run_id,),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def get_all_tasks(self, run_id: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? ORDER BY created_at",
            (run_id,),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def update_task_status(self, task_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE tasks SET status = ?, updated_at = ? WHERE task_id = ?",
            (status, time.time(), task_id),
        )
        self._conn.commit()

    def reset_incomplete_tasks(self, run_id: str) -> int:
        """Flip 'running' and 'failed' tasks back to 'pending' so a resumed
        run re-attempts work that was interrupted (quota/crash, left
        'running') or that failed on a transient/quota error (marked
        'failed'). Returns the number of tasks reset."""
        cur = self._conn.execute(
            "UPDATE tasks SET status = 'pending', updated_at = ? "
            "WHERE run_id = ? AND status IN ('running', 'failed')",
            (time.time(), run_id),
        )
        self._conn.commit()
        return cur.rowcount

    @staticmethod
    def _row_to_task(r: sqlite3.Row) -> Task:
        return Task(
            task_id=r["task_id"],
            run_id=r["run_id"],
            source=r["source"],
            attack_class=r["attack_class"],
            scope_hint=r["scope_hint"],
            target_files=json.loads(r["target_files"]),
            rationale=r["rationale"] or "",
            priority=r["priority"],
            status=r["status"],
            raw_json=json.loads(r["raw_json"]),
        )

    # ---------- findings ----------

    def add_finding(self, run_id: str, task_id: str, finding: dict) -> None:
        poc = finding.get("poc") or {}
        self._conn.execute(
            """INSERT OR IGNORE INTO findings
            (finding_id, task_id, run_id, file, line_start, line_end,
             vuln_class, severity, description, evidence, poc_succeeded,
             confidence, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding["finding_id"],
                task_id,
                run_id,
                finding["file"],
                finding["line_start"],
                finding["line_end"],
                finding["vuln_class"],
                finding["severity"],
                finding["description"],
                finding["evidence_snippet"],
                1 if poc.get("succeeded") else 0,
                finding.get("confidence"),
                json.dumps(finding),
            ),
        )
        self._conn.commit()

    def get_findings(self, run_id: str, *, validation_status: str | None = None,
                     canonical_only: bool = False) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE run_id = ?"
        args: list[Any] = [run_id]
        if validation_status is not None:
            sql += " AND validation_status = ?"
            args.append(validation_status)
        if canonical_only:
            sql += " AND is_canonical = 1"
        rows = self._conn.execute(sql, args).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_unvalidated_findings(self, run_id: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? AND validation_status IS NULL",
            (run_id,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def set_finding_validation(self, finding_id: str, status: str, payload: dict) -> None:
        self._conn.execute(
            "UPDATE findings SET validation_status = ?, validation_json = ? WHERE finding_id = ?",
            (status, json.dumps(payload), finding_id),
        )
        self._conn.commit()

    def update_finding_severity(self, finding_id: str, severity: str) -> None:
        """Overwrite a finding's severity. Used by Validate (V4) when a
        confirmed finding's CVSS-vector base score yields a mapped band —
        that band supersedes the hunter's original (LLM-assigned) severity
        as the authoritative value read downstream by report.py (f.severity)."""
        self._conn.execute(
            "UPDATE findings SET severity = ? WHERE finding_id = ?",
            (severity, finding_id),
        )
        self._conn.commit()

    def assign_finding_group(
        self, finding_id: str, group_id: str, is_canonical: bool
    ) -> None:
        self._conn.execute(
            "UPDATE findings SET group_id = ?, is_canonical = ? WHERE finding_id = ?",
            (group_id, 1 if is_canonical else 0, finding_id),
        )
        self._conn.commit()

    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        return Finding(
            finding_id=r["finding_id"],
            task_id=r["task_id"],
            run_id=r["run_id"],
            file=r["file"],
            line_start=r["line_start"],
            line_end=r["line_end"],
            vuln_class=r["vuln_class"],
            severity=r["severity"],
            description=r["description"],
            evidence=r["evidence"],
            poc_succeeded=bool(r["poc_succeeded"]),
            confidence=r["confidence"],
            raw_json=json.loads(r["raw_json"]),
            validation_status=r["validation_status"],
            validation_json=json.loads(r["validation_json"]) if r["validation_json"] else None,
            group_id=r["group_id"],
            is_canonical=bool(r["is_canonical"]),
        )

    # ---------- traces ----------

    def add_trace(self, finding_id: str, payload: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO traces
            (finding_id, reachable, confidence, rationale, raw_json)
            VALUES (?, ?, ?, ?, ?)""",
            (
                finding_id,
                1 if payload.get("reachable") else 0,
                payload.get("confidence"),
                payload.get("rationale", ""),
                json.dumps(payload),
            ),
        )
        self._conn.commit()

    def get_trace(self, finding_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM traces WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    def get_reachable_canonical_findings(self, run_id: str) -> list[tuple[Finding, dict]]:
        out: list[tuple[Finding, dict]] = []
        for f in self.get_findings(run_id, validation_status="confirmed", canonical_only=True):
            tr = self.get_trace(f.finding_id)
            if tr and tr.get("reachable"):
                out.append((f, tr))
        return out

    # ---------- chains (V11: exploit-chain construction) ----------

    def add_chain_analysis(self, run_id: str, payload: dict) -> None:
        """Store the chain-analysis artifact for a run (one per run). The
        chains carry their OWN severity; this does NOT touch per-finding
        severities — V4's CVSS stays per-finding authoritative."""
        self._conn.execute(
            "INSERT OR REPLACE INTO chains (run_id, raw_json) VALUES (?, ?)",
            (run_id, json.dumps(payload)),
        )
        self._conn.commit()

    def get_chain_analysis(self, run_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM chains WHERE run_id = ?", (run_id,)
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    # ---------- dedupe ----------

    def add_dedupe_group(self, run_id: str, group: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO dedupe_groups
            (group_id, run_id, root_cause, canonical_finding_id, raw_json)
            VALUES (?, ?, ?, ?, ?)""",
            (
                group["group_id"],
                run_id,
                group["root_cause"],
                group["canonical_finding_id"],
                json.dumps(group),
            ),
        )
        self._conn.commit()

    # ---------- costs ----------

    def record_cost(
        self,
        run_id: str,
        stage: str,
        ref_id: str | None,
        result_msg: dict,
    ) -> None:
        usage = result_msg.get("usage") or {}
        self._conn.execute(
            """INSERT INTO costs
            (run_id, stage, ref_id, usd, input_tokens, output_tokens,
             cache_read_tokens, cache_creation_tokens, num_turns, duration_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                stage,
                ref_id,
                result_msg.get("total_cost_usd"),
                usage.get("input_tokens"),
                usage.get("output_tokens"),
                usage.get("cache_read_input_tokens"),
                usage.get("cache_creation_input_tokens"),
                result_msg.get("num_turns"),
                result_msg.get("duration_ms"),
                time.time(),
            ),
        )
        self._conn.commit()

    def total_cost(self, run_id: str) -> float:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(usd), 0) AS total FROM costs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return float(row["total"]) if row else 0.0

    # ---------- artifacts ----------

    def add_artifact(
        self, run_id: str, stage: str, ref_id: str | None, kind: str, path: str
    ) -> None:
        self._conn.execute(
            """INSERT INTO artifacts
            (run_id, stage, ref_id, kind, path, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (run_id, stage, ref_id, kind, path, time.time()),
        )
        self._conn.commit()

    # ---------- context manager ----------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


@contextmanager
def open_db(path: Path) -> Iterator[StateDB]:
    db = StateDB(path)
    try:
        yield db
    finally:
        db.close()
