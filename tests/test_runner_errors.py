"""Tests for the API-error classification in runner.py."""

from __future__ import annotations

import pytest

from vash.runner import (
    QuotaExhaustedError,
    TransientAgentError,
    _classify_api_error,
)


@pytest.mark.parametrize("text", [
    "You're out of extra usage · resets 2am (Europe/Rome)",
    "Usage limit reached for the day.",
    "Your plan has no remaining quota.",
    "YOU'RE OUT OF EXTRA USAGE.",
    "You've hit your session limit · resets 5:10am (UTC)",
    "You've hit your session limit · resets 11pm",
])
def test_quota_classified(text: str) -> None:
    label, exc = _classify_api_error(text)
    assert label == "quota_exhausted"
    assert exc is QuotaExhaustedError


@pytest.mark.parametrize("text", [
    "API Error: 529 Overloaded. This is a server-side issue, usually temporary",
    "Server overloaded — please try again",
    "API Error: 503",
    "API Error: 502 Bad Gateway",
    "API Error: 500 Internal Server Error",
    "rate_limit hit",
    "Service temporarily unavailable",
])
def test_transient_classified(text: str) -> None:
    label, exc = _classify_api_error(text)
    assert label == "transient"
    assert exc is TransientAgentError


def test_unknown_is_retryable_but_marked_unclassified() -> None:
    """Still retried (a classification miss should not abort a run), but as a
    DISTINCT type so the retry loop can give it a shorter ladder: an error we
    cannot classify is not evidence that the failure is temporary."""
    from vash.runner import UnclassifiedAgentError
    label, exc = _classify_api_error("some weird new error string")
    assert label == "unknown_api_error"
    assert exc is UnclassifiedAgentError
    assert issubclass(exc, TransientAgentError)   # existing handlers still catch it


def test_empty_error_text_is_unclassified() -> None:
    """The real case: a task failed repeatedly with an EMPTY error message and
    burned the whole backoff ladder (~18 min) on every run, then failed anyway."""
    from vash.runner import UnclassifiedAgentError
    label, exc = _classify_api_error("")
    assert label == "unknown_api_error"
    assert exc is UnclassifiedAgentError


def test_unclassified_errors_get_one_retry_not_the_full_ladder() -> None:
    """Bounds the wasted time: a known-transient error keeps 3 retries, an
    unclassifiable one gets 1. Measured cost of not doing this on a real scan:
    30s + 60s + 120s of backoff per attempt, twice (run + resume), for a task
    that failed identically every single time."""
    from vash.runner import TransientAgentError, UnclassifiedAgentError

    def budget(e, transient_retries=3):
        return 1 if isinstance(e, UnclassifiedAgentError) else transient_retries

    assert budget(UnclassifiedAgentError("")) == 1
    assert budget(TransientAgentError("api error: 529 overloaded")) == 3
