"""Deterministic report renderers.

Currently exposes the VVAH/GHSA-style Markdown renderer. The raw
``report.json`` remains the authoritative machine artifact; these renderers
are a human-facing presentation layer over that same enriched payload.
"""

from __future__ import annotations

from vash.reporting.markdown import render_report

__all__ = ["render_report"]
