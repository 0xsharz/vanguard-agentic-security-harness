"""Rich, fail-soft run-progress reporter. Presentation only — every method
swallows its own errors so a display bug can never break the pipeline. Counters
are read from StateDB (authoritative), never recomputed. In a non-TTY (detached/
piped) console it degrades to throttled clean plain lines instead of live bars."""
from __future__ import annotations
import logging, time
from typing import TYPE_CHECKING
from rich.console import Console
from rich.table import Table
if TYPE_CHECKING:
    from vash.state import StateDB
log = logging.getLogger(__name__)

_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
              "low": "cyan", "informational": "dim"}

class RunReporter:
    def __init__(self, console: "Console | None" = None, run_id: str = "",
                 throttle: int = 5) -> None:
        self.console = console or Console()
        self.run_id = run_id
        self.throttle = max(1, throttle)
        self.live = bool(getattr(self.console, "is_terminal", False))
        self._start = time.monotonic()
        self._n = 0

    def stage_start(self, name: str, *, model: str | None = None,
                    count: int | None = None) -> None:
        try:
            bits = [f"[bold]{name.upper()}[/bold]"]
            if model: bits.append(f"[dim]{model}[/dim]")
            if count is not None: bits.append(f"[dim]{count} tasks[/dim]")
            self.console.rule(" · ".join(bits))
        except Exception as e:
            log.debug("reporter.stage_start failed: %s", e)

    def task_done(self, stage: str, *, ok: bool = True, done: int | None = None,
                  total: int | None = None, confirmed: int | None = None,
                  cost: float | None = None) -> None:
        try:
            self._n += 1
            at_end = done is not None and done == total
            if not (self.live or self._n % self.throttle == 0 or at_end):
                return
            parts = [stage]
            if done is not None and total is not None: parts.append(f"{done}/{total}")
            if confirmed is not None: parts.append(f"{confirmed} confirmed")
            if cost is not None: parts.append(f"${cost:.2f}")
            el = int(time.monotonic() - self._start)
            parts.append(f"{el // 60}m{el % 60:02d}s")
            self.console.print("  [dim]·[/dim] " + "  ".join(parts))
        except Exception as e:
            log.debug("reporter.task_done failed: %s", e)

    def finding_confirmed(self, *, severity: str, vuln_class: str, file: str,
                          line: "int | None", confidence: "float | None") -> None:
        try:
            st = _SEV_STYLE.get((severity or "").lower(), "white")
            loc = f"{file}:{line}" if line else file
            c = f" (conf {confidence:.2f})" if isinstance(confidence, (int, float)) else ""
            self.console.print(
                f"  [green]✓[/green] [{st}]{(severity or '?').upper():8}[/{st}] "
                f"{vuln_class:22} [dim]{loc}[/dim]{c}")
        except Exception as e:
            log.debug("reporter.finding_confirmed failed: %s", e)

    def stage_end(self, name: str, **stats) -> None:
        try:
            if stats:
                s = "  ".join(f"{k}={v}" for k, v in stats.items())
                self.console.print(f"  [dim]{name} done — {s}[/dim]")
        except Exception as e:
            log.debug("reporter.stage_end failed: %s", e)

    def run_summary(self, db: "StateDB", run_id: str) -> None:
        try:
            findings = db.get_findings(run_id)
            by_sev: dict[str, int] = {}
            by_status: dict[str, int] = {}
            for f in findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
                vs = getattr(f, "validation_status", None) or "pending"
                by_status[vs] = by_status.get(vs, 0) + 1
            try:
                cost = db.total_cost(run_id)
            except Exception:
                cost = 0.0
            el = int(time.monotonic() - self._start)
            t = Table(title=f"Run {run_id} — summary", show_header=True, header_style="bold")
            t.add_column("metric"); t.add_column("value", justify="right")
            for sev in ("critical", "high", "medium", "low", "informational"):
                if by_sev.get(sev): t.add_row(f"findings · {sev}", str(by_sev[sev]))
            for k in ("confirmed", "rejected", "needs_more_info", "pending"):
                if by_status.get(k): t.add_row(f"validation · {k}", str(by_status[k]))
            t.add_row("total findings", str(len(findings)))
            t.add_row("cost", f"${cost:.2f}")
            t.add_row("duration", f"{el // 60}m{el % 60:02d}s")
            self.console.print(t)
        except Exception as e:
            log.debug("reporter.run_summary failed: %s", e)
