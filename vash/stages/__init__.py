"""One module per pipeline stage. Each exports a single async entry
point invoked by audit.orchestrator."""

from vash.stages.recon import run_recon
from vash.stages.hunt import run_hunt
from vash.stages.validate import run_validate
from vash.stages.gapfill import run_gapfill
from vash.stages.dedupe import run_dedupe
from vash.stages.trace import run_trace
from vash.stages.feedback import run_feedback
from vash.stages.chain import run_chain
from vash.stages.report import run_report
# Decoupled, opt-in command (NOT part of the scan loop) — see vash.cli remediate.
from vash.stages.remediate import run_remediate

__all__ = [
    "run_recon",
    "run_hunt",
    "run_validate",
    "run_gapfill",
    "run_dedupe",
    "run_trace",
    "run_feedback",
    "run_chain",
    "run_report",
    "run_remediate",
]
