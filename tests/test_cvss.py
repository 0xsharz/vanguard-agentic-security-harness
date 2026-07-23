"""CVSS 3.1 base-score calculator — ported verbatim from
`~/visa-harness/vvaharness/report/cvss.py` (V4). Pure math, no network."""

from __future__ import annotations

from vash.cvss import rating, score

# FIRST.org worked example: full-impact, network, no-privilege, no-UI bug.
CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Physical access, high complexity, admin privilege, user interaction,
# limited confidentiality impact only.
LOW_VECTOR = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"


def test_score_critical_vector() -> None:
    s = score(CRITICAL_VECTOR)
    assert s == 9.8
    assert rating(s) == "Critical"


def test_score_low_vector() -> None:
    s = score(LOW_VECTOR)
    assert s == 1.6
    assert rating(s) == "Low"


def test_score_unparseable_vector_returns_none() -> None:
    assert score("not a cvss vector") is None
    assert score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None  # bad AV enum
    assert rating(score("garbage")) == "Unknown"


def test_score_absent_vector_returns_none() -> None:
    assert score(None) is None
    assert score("") is None


def test_rating_none_score_is_unknown() -> None:
    assert rating(None) == "Unknown"


def test_rating_zero_score_is_none_band() -> None:
    # All-N impact vector legitimately scores 0.0 — a distinct "None" band,
    # not to be confused with the Python `None` used for "unparseable".
    no_impact_vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
    s = score(no_impact_vector)
    assert s == 0.0
    assert rating(s) == "None"


def test_rating_bands_are_monotonic() -> None:
    assert rating(9.0) == "Critical"
    assert rating(8.9) == "High"
    assert rating(7.0) == "High"
    assert rating(6.9) == "Medium"
    assert rating(4.0) == "Medium"
    assert rating(3.9) == "Low"
