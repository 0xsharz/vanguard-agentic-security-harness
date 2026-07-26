"""Compliance guard (Task 4.8): verbatim Apache-2.0 ports must retain their
headers, and the NOTICE / LICENSE / license texts must exist.

If someone strips an Apache-2.0 header off a verbatim-ported file, or deletes the
attribution files, this test fails — keeping VASH license-compliant.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Files copied verbatim from Visa VVAH (Apache-2.0) — must keep their header.
APACHE_PORTS = [
    "vash/cvss.py",
    "vash/lang/hints.py",
    "vash/baselines.py",
    "vash/redact.py",
]

APACHE_MARKER = "Licensed under the Apache License, Version 2.0"


def test_verbatim_ports_retain_apache_header():
    for rel in APACHE_PORTS:
        text = (REPO / rel).read_text(encoding="utf-8")
        assert APACHE_MARKER in text, f"{rel} lost its Apache-2.0 header (Apache-2.0 §4 violation)"


def test_attribution_files_exist():
    for rel in ("NOTICE", "LICENSE"):
        assert (REPO / rel).is_file(), f"missing {rel}"


def test_license_texts_present():
    for rel in (
        "licenses/audit-MIT.txt",
        "licenses/VulnHunter-Apache-2.0.txt",
        "licenses/VVAH-Apache-2.0.txt",
    ):
        assert (REPO / rel).is_file(), f"missing {rel}"


def test_notice_credits_all_three_donors():
    notice = (REPO / "NOTICE").read_text(encoding="utf-8").lower()
    for name in ("audit", "vulnhunter", "vvah"):
        assert name in notice, f"NOTICE does not credit {name}"


def test_notice_documents_verbatim_ports():
    """Apache-2.0 §4 requires the attribution to travel with the work. NOTICE is
    the file the licence actually mandates, so the verbatim ports must be named
    there — not only in a convenience document that can be deleted."""
    doc = (REPO / "NOTICE").read_text(encoding="utf-8")
    for rel in APACHE_PORTS:
        assert rel in doc, f"NOTICE omits verbatim port {rel}"
