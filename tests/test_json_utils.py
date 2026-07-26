"""Tests for audit.json_utils.extract_json."""

from __future__ import annotations

import pytest

from vash.json_utils import extract_json


def test_plain_json() -> None:
    assert extract_json('{"a": 1}') == {"a": 1}


def test_json_array() -> None:
    assert extract_json("[1, 2, 3]") == [1, 2, 3]


def test_fenced_json() -> None:
    text = 'Sure!\n```json\n{"a": 1}\n```\nDone.'
    assert extract_json(text) == {"a": 1}


def test_fenced_no_language() -> None:
    text = '```\n{"a": 1}\n```'
    assert extract_json(text) == {"a": 1}


def test_prose_with_embedded_json() -> None:
    text = 'Here is my answer: {"a": 1, "b": [1,2]} please use it.'
    assert extract_json(text) == {"a": 1, "b": [1, 2]}


def test_embedded_json_with_braces_in_strings() -> None:
    text = 'preamble {"k": "value with } brace"} epilogue'
    assert extract_json(text) == {"k": "value with } brace"}


def test_empty_raises() -> None:
    with pytest.raises(ValueError):
        extract_json("")


def test_no_json_raises() -> None:
    with pytest.raises(ValueError):
        extract_json("just text, no json here")
