"""Pipeline driver: Recon → (Hunt → Validate → Gapfill)* → Dedupe → Trace
                  → Feedback → (Hunt → Validate → Dedupe → Trace)* → Report
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from audit import stages
from audit.config import HarnessConfig
from audit.graph import GraphQuery, build_or_load
from audit.runner import QuotaExhaustedError
from audit.state import StateDB, Task
from audit.stages._common import StageContext
from audit.taint import build_sink_backward_tasks, build_taint_tasks

log = logging.getLogger(__name__)

# Upper bound on how many uncovered inputs the reconciliation pass will
# re-queue as Hunt tasks in a single run. Keeps the completeness pass bounded
# (a target with hundreds of unreached inputs must not fan out unboundedly).
RECONCILE_CAP = 20


class CostExceeded(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Input reconciliation — the completeness ledger.
#
# After the Hunt/Validate loop, every attacker-controllable input that Recon
# enumerated must reach a disposition. Mirrors VulnHunter's Results-Aggregation
# completeness check ("every input gets a disposition; totals must match"),
# reduced to audit's two-value vocabulary: covered / uncovered.
# ---------------------------------------------------------------------------

# Sensible per-source default attack class for a synthesized reconcile Hunt
# task. Substring-matched against the input's source_type; falls back to a
# broad taint trace.
_RECONCILE_ATTACK_CLASS = [
    ("file upload", "path_traversal"),
    ("file", "path_traversal"),
    ("deserial", "deserialization_pickle"),
    ("pickle", "deserialization_pickle"),
    ("yaml", "deserialization_yaml"),
    ("queue", "deserialization_pickle"),
    ("cookie", "session_tampering"),
    ("header", "header_injection"),
    ("env", "command_injection"),
    ("cli", "command_injection"),
    ("db", "sql_injection"),
    ("sql", "sql_injection"),
]


def _default_attack_class(source_type: str | None) -> str:
    st = (source_type or "").lower()
    for key, cls in _RECONCILE_ATTACK_CLASS:
        if key in st:
            return cls
    return "injection"


def _location_file(location: str | None) -> str:
    """Basename of the file portion of a `file:line` location string."""
    loc = (location or "").strip()
    if not loc:
        return ""
    parts = loc.split(":")
    while len(parts) > 1 and parts[-1].strip().isdigit():
        parts.pop()
    return os.path.basename(":".join(parts)).strip()


def _classify_input(
    inp: dict, finding_basenames: set[str], tasks: list[Task]
) -> tuple[str, str]:
    """Decide an input's disposition. Returns (disposition, evidence).

    Rule (per the F1 brief): an input is **covered** if some finding's file
    matches the input's location file (basename match) OR the input's
    entry_point appears in a task's scope (scope_hint or target_files);
    otherwise **uncovered**.
    """
    loc_base = _location_file(inp.get("location"))
    if loc_base and loc_base in finding_basenames:
        return "covered", f"finding touches {loc_base}"
    entry = (inp.get("entry_point") or "").strip()
    if entry:
        for t in tasks:
            haystack = (t.scope_hint or "") + " " + " ".join(t.target_files or [])
            if entry in haystack:
                return "covered", f"task {t.task_id} scope references '{entry}'"
    return "uncovered", "no finding file or task scope reached this input"


def _synthesize_reconcile_task(inp: dict, n: int) -> dict:
    """One Hunt task that re-queues an uncovered input for a forward trace."""
    iid = inp.get("id") or inp.get("input_id") or f"input_{n}"
    source_type = inp.get("source_type") or "input"
    location = inp.get("location") or "?"
    entry = inp.get("entry_point") or "unknown entry point"
    target = (location.split(":")[0].strip()
              or _location_file(location) or ".")
    return {
        "task_id": f"t_rc_{n}",
        "source": "reconcile",
        "attack_class": _default_attack_class(source_type),
        "scope_hint": (
            f"Completeness reconciliation for uncovered input {iid}: "
            f"{source_type} at {location} (entry point {entry}). Trace this "
            f"attacker-controllable value forward to any dangerous sink."
        ),
        "target_files": [target],
        "rationale": (
            f"Input {iid} ({source_type}) reached no disposition during the "
            f"Hunt/Validate loop; reconciliation re-queues it so every "
            f"enumerated input is traced to a sink or explicitly cleared."
        ),
        "priority": 2,
    }


def _reconcile_pass(db: StateDB, run_id: str) -> tuple[list[dict], list[dict]]:
    """Classify every input once and persist its disposition. Returns
    (covered, uncovered) lists."""
    inputs = db.get_inputs(run_id)
    if not inputs:
        return [], []
    finding_basenames = {os.path.basename(f.file) for f in db.get_findings(run_id)}
    tasks = db.get_all_tasks(run_id)
    covered: list[dict] = []
    uncovered: list[dict] = []
    for inp in inputs:
        disposition, evidence = _classify_input(inp, finding_basenames, tasks)
        db.set_input_disposition(inp["input_id"], disposition, evidence)
        (covered if disposition == "covered" else uncovered).append(inp)
    return covered, uncovered


async def _reconcile_inputs(ctx: StageContext, db: StateDB) -> None:
    """Reconcile every recon-enumerated input to a disposition.

    Bounded (at most RECONCILE_CAP uncovered inputs are re-queued) and
    **fail-open**: any error here is logged and swallowed so a reconciliation
    bug can never abort an otherwise-good run. QuotaExhaustedError is the one
    exception re-raised, to preserve the resumable-abort contract.
    """
    try:
        inputs = db.get_inputs(ctx.run_id)
        if not inputs:
            return
        covered, uncovered = _reconcile_pass(db, ctx.run_id)
        log.info(
            "[%s] reconcile: %d inputs — %d covered, %d uncovered",
            ctx.run_id, len(inputs), len(covered), len(uncovered),
        )
        if not uncovered:
            return

        capped = uncovered[:RECONCILE_CAP]
        for n, inp in enumerate(capped, 1):
            db.add_task(ctx.run_id, _synthesize_reconcile_task(inp, n))
        beyond = max(0, len(uncovered) - RECONCILE_CAP)
        log.info(
            "[%s] reconcile: re-queued %d uncovered inputs as Hunt tasks "
            "(cap=%d; %d left uncovered beyond cap)",
            ctx.run_id, len(capped), RECONCILE_CAP, beyond,
        )

        # Re-run Hunt + Validate ONCE against the reconcile tasks.
        await stages.run_hunt(ctx, db)
        await stages.run_validate(ctx, db)

        # Re-reconcile so the final ledger reflects the extra hunt.
        covered, uncovered = _reconcile_pass(db, ctx.run_id)
        log.info(
            "[%s] reconcile (final): %d covered, %d uncovered",
            ctx.run_id, len(covered), len(uncovered),
        )
    except QuotaExhaustedError:
        raise
    except Exception as e:  # fail-open — reconciliation must never abort a run
        log.warning(
            "[%s] input reconciliation failed (continuing run): %s",
            ctx.run_id, e,
        )


# ---------------------------------------------------------------------------
# Deterministic entry→sink taint chunking (feature V8).
#
# After Recon has enumerated every attacker-controllable input (F1), build the
# code graph and, for each input, walk the real call graph to every dangerous
# sink — emitting ONE narrowly-scoped Hunt task per reachable (input → sink)
# path so the Hunter always sees source AND sink together. Fail-open and gated
# on a trustworthy graph. Mirrors the _reconcile_inputs fail-open pattern.
# ---------------------------------------------------------------------------

def _add_taint_tasks(ctx: StageContext, db: StateDB) -> None:
    """Build the code graph and queue deterministic entry→sink taint tasks.

    **Fail-open**: every error is logged and swallowed — taint chunking must
    NEVER abort a run. **Gated**: a grep-fallback (low-confidence) graph gives
    unreliable reachability, and a graph with no ``calls`` edges cannot carry a
    forward path, so both are skipped (this also keeps the e2e stub green — its
    tiny fixture yields a graph with zero call edges → 0 taint tasks).
    """
    try:
        cache_path = ctx.work_dir("graph") / "graph.json"
        ctx.graph_cache_path = cache_path
        doc = build_or_load(ctx.repo_path, cache_path)
        calls_edges = sum(1 for e in doc.edges if e.kind == "calls")
        if doc.confidence == "low" or calls_edges == 0:
            log.info(
                "[%s] taint: skipped (low-confidence/empty graph: "
                "confidence=%s, calls_edges=%d)",
                ctx.run_id, doc.confidence, calls_edges,
            )
            return
        gq = GraphQuery(doc, ctx.repo_path)
        inputs = db.get_inputs(ctx.run_id)
        if not inputs:
            log.info("[%s] taint: skipped (no enumerated inputs)", ctx.run_id)
            return
        tasks = build_taint_tasks(gq, inputs, ctx.repo_path)
        for t in tasks:
            db.add_task(ctx.run_id, t)
        log.info(
            "[%s] taint: %d entry→sink path tasks (inputs=%d, graph=%d calls edges)",
            ctx.run_id, len(tasks), len(inputs), calls_edges,
        )
    except Exception as e:  # fail-open — taint must never abort a run
        log.warning(
            "[%s] taint chunking failed (continuing run): %s", ctx.run_id, e
        )


# ---------------------------------------------------------------------------
# Sink-backward hunting (feature F3) — the BACKWARD complement of V8's taint.
#
# V8 covers sinks reachable FORWARD from an enumerated input. The recall gap is
# **orphan sinks** — dangerous sinks that NO enumerated input reaches. This step
# queues one backward hunt task per orphan sink (trace through its callers to
# discover the source). Orphans are ``all_sinks − forward_reached``, so these
# tasks are disjoint from V8's by construction — pure new coverage. Fail-open
# and gated exactly like _add_taint_tasks; reuses the graph V8 already cached
# (ctx.graph()) — no rebuild.
# ---------------------------------------------------------------------------

def _add_sink_backward_tasks(ctx: StageContext, db: StateDB) -> None:
    """Queue backward hunt tasks for orphan sinks (dangerous sinks no
    enumerated input reaches forward).

    **Fail-open**: every error is logged and swallowed — sink-backward hunting
    must NEVER abort a run. **Gated**: reuses the graph V8 already built and
    memoized (``ctx.graph()`` — do NOT rebuild); skips a low-confidence graph
    (unreliable reachability) and a graph with no ``calls`` edges (no callers to
    trace backward — also keeps the e2e stub green, whose fixture graph is
    high-confidence with only imports/defines edges).
    """
    try:
        gq = ctx.graph()
        if gq is None or gq.status().get("confidence") == "low":
            return
        if not any(e.kind == "calls" for e in gq._doc.edges):
            log.info(
                "[%s] sink-backward: skipped (graph has no calls edges)", ctx.run_id
            )
            return
        tasks = build_sink_backward_tasks(gq, db.get_inputs(ctx.run_id), ctx.repo_path)
        for t in tasks:
            db.add_task(ctx.run_id, t)
        log.info(
            "[%s] sink-backward: %d orphan-sink audit tasks", ctx.run_id, len(tasks)
        )
    except Exception as e:  # fail-open — sink-backward must never abort a run
        log.warning(
            "[%s] sink-backward failed (continuing run): %s", ctx.run_id, e
        )


async def run_pipeline(
    *,
    repo_path: Path,
    run_id: str,
    db: StateDB,
    config: HarnessConfig,
    max_cost_usd: float | None = None,
    resume: bool = False,
    max_recon_tasks: int | None = None,
    live_target: dict | None = None,
    scope_notes: str | None = None,
) -> Path:
    ctx = StageContext(
        run_id=run_id,
        repo_path=repo_path.resolve(),
        config=config,
        live_target=live_target,
        scope_notes=scope_notes,
    )

    if db.get_run(run_id) is None:
        db.create_run(str(repo_path.resolve()), run_id)
        log.info("[%s] starting fresh pipeline run against %s", run_id, repo_path)
    elif resume:
        # Flip status back to 'running' so subsequent /status calls don't
        # report a stale 'aborted'/'failed' while resume work is ongoing.
        db._conn.execute(  # type: ignore[attr-defined]
            "UPDATE runs SET status = 'running', finished_at = NULL WHERE run_id = ?",
            (run_id,),
        )
        db._conn.commit()  # type: ignore[attr-defined]
        # Re-queue any task left 'running' (interrupted mid-flight by a quota
        # abort or crash) or 'failed' (transient/quota error) so resume
        # actually re-attempts the incomplete work instead of skipping it —
        # Hunt only dispatches 'pending' tasks.
        requeued = db.reset_incomplete_tasks(run_id)
        if requeued:
            log.info("[%s] resume: re-queued %d interrupted/failed tasks", run_id, requeued)
        log.info("[%s] resuming existing run", run_id)
    else:
        raise RuntimeError(
            f"run_id {run_id!r} already exists; pass --resume to continue it."
        )

    def _budget_check(stage_name: str) -> None:
        if max_cost_usd is None:
            return
        spent = db.total_cost(run_id)
        if spent >= max_cost_usd:
            raise CostExceeded(
                f"[{run_id}] budget exhausted before {stage_name}: "
                f"${spent:.4f} >= ${max_cost_usd:.4f}"
            )

    try:
        # ---- Stage 1: Recon ----
        _budget_check("recon")
        recon_kwargs = {} if max_recon_tasks is None else {"max_tasks": max_recon_tasks}
        await stages.run_recon(ctx, db, **recon_kwargs)

        # ---- V8: deterministic entry→sink taint chunking ----
        # Runs after Recon (inputs enumerated) and before the Hunt loop so the
        # Hunter picks up the taint tasks. Fail-open + gated (see helper).
        _add_taint_tasks(ctx, db)

        # ---- F3: sink-backward hunting for orphan sinks ----
        # The BACKWARD complement of V8: for dangerous sinks NO enumerated input
        # reaches, queue a backward audit task. Disjoint from V8 by construction
        # (orphans = all_sinks − forward_reached). Reuses ctx.graph() (no
        # rebuild). Fail-open + gated (see helper).
        _add_sink_backward_tasks(ctx, db)

        # ---- Stages 2-3-4 loop: Hunt → Validate → Gapfill ----
        for i in range(config.gapfill_iterations + 1):
            _budget_check(f"hunt(iter={i})")
            findings_added = await stages.run_hunt(ctx, db, budget_check=_budget_check)
            if findings_added == 0 and i > 0:
                log.info("[%s] no new findings — exiting Hunt/Gapfill loop", run_id)
                break

            _budget_check(f"validate(iter={i})")
            await stages.run_validate(ctx, db)

            if i >= config.gapfill_iterations:
                break  # final iteration: don't gapfill again
            _budget_check(f"gapfill(iter={i})")
            new_tasks = await stages.run_gapfill(ctx, db)
            if new_tasks == 0:
                log.info("[%s] gapfill produced 0 tasks — exiting loop", run_id)
                break

        # ---- Reconciliation: guarantee every enumerated input a disposition ----
        # Runs after the Hunt/Validate loop, before Dedupe. Fail-open and
        # bounded (RECONCILE_CAP); may re-run Hunt+Validate once for uncovered
        # inputs so the final ledger is accurate.
        _budget_check("reconcile")
        await _reconcile_inputs(ctx, db)

        # ---- Stage 5: Dedupe ----
        _budget_check("dedupe")
        await stages.run_dedupe(ctx, db)

        # ---- Stage 6: Trace ----
        _budget_check("trace")
        await stages.run_trace(ctx, db)

        # ---- Stage 7: Feedback (re-runs Hunt/Validate/Dedupe/Trace) ----
        for i in range(config.feedback_iterations):
            _budget_check(f"feedback(iter={i})")
            new_tasks = await stages.run_feedback(ctx, db)
            if new_tasks == 0:
                break
            _budget_check(f"feedback-hunt(iter={i})")
            await stages.run_hunt(ctx, db)
            _budget_check(f"feedback-validate(iter={i})")
            await stages.run_validate(ctx, db)
            _budget_check(f"feedback-dedupe(iter={i})")
            await stages.run_dedupe(ctx, db)
            _budget_check(f"feedback-trace(iter={i})")
            await stages.run_trace(ctx, db)

        # ---- Stage 8: Report ----
        _budget_check("report")
        report_path = await stages.run_report(ctx, db)

        db.finish_run(run_id, "completed")
        log.info(
            "[%s] pipeline complete: total cost $%.4f — report at %s",
            run_id, db.total_cost(run_id), report_path,
        )
        return report_path

    except CostExceeded as e:
        log.error(str(e))
        db.finish_run(run_id, "aborted")
        raise
    except QuotaExhaustedError as e:
        # Subscription quota exhausted — surface clearly; user must wait
        # for the reset window. Run is resumable via --resume once quota
        # returns.
        log.error(
            "[%s] subscription quota exhausted — aborting (resumable with --resume): %s",
            run_id, str(e)[:300],
        )
        db.finish_run(run_id, "aborted")
        raise
    except Exception:
        db.finish_run(run_id, "failed")
        raise
