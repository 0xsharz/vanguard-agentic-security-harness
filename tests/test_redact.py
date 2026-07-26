# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for audit.redact.

Offline and deterministic: pure-function string redaction, no network,
no subprocess, no clock. All card numbers below are well-known public
test PANs (e.g. 4111-1111-1111-1111) — not live cardholder data.

Ported verbatim (case-for-case) from ~/visa-harness/tests/test_redact.py
(vvaharness.report.redact), with imports adapted to audit.redact. The
`redact_json` / report-egress sections at the bottom are new for task 4.2
(audit-specific egress at audit/stages/report.py and audit/cli.py).
"""
import json

import pytest

from vash import redact as R
from vash.redact import (
    redact,
    redact_counts,
    redact_tree,
    redact_json,
    _luhn,
    _cc_network,
    _ssn_valid,
)


# ─────────────────────────────────────────────────────────────────────────────
# Low-level validators
# ─────────────────────────────────────────────────────────────────────────────

def test_luhn_accepts_valid_check_digit():
    assert _luhn("4111111111111111") is True
    assert _luhn("378282246310005") is True


def test_luhn_rejects_bad_check_digit():
    # Flip the last digit of a valid card PAN.
    assert _luhn("4111111111111112") is False
    assert _luhn("1234567890123456") is False


def test_cc_network_gates_by_iin():
    assert _cc_network("4111111111111111") is True       # 16-digit PAN, IIN 4
    assert _cc_network("5555555555554444") is True       # Mastercard 51-55
    assert _cc_network("2223003122003222") is True        # Mastercard 2221-2720
    assert _cc_network("378282246310005") is True         # Amex (15 digits)
    # Leading "9" is not assigned to any network IIN.
    assert _cc_network("9000000000000001") is False


def test_cc_network_length_bounds():
    # Below 12 and above 19 digits are rejected outright.
    assert _cc_network("41111") is False
    assert _cc_network("4" + "1" * 19) is False


def test_ssn_valid_gate():
    assert _ssn_valid("078051120") is True
    # area 000 / 666, group 00, serial 0000 are structurally impossible.
    assert _ssn_valid("000051120") is False
    assert _ssn_valid("666051120") is False
    assert _ssn_valid("078001120") is False
    assert _ssn_valid("078050000") is False
    # area 900-999 is the ITIN range (taxpayer IDs) — sensitive PII, so it is
    # ALLOWED through the gate and masked (content guards flag these too).
    assert _ssn_valid("900051120") is True
    assert _ssn_valid("936184524") is True
    assert _ssn_valid("961080047") is True


def test_itin_9xx_is_masked():
    # 9XX-XX-XXXX (ITIN) must be masked, not just SSA-issued SSN areas.
    out = redact("itin 936-18-4524 and 961-08-0047 on file")
    assert "936-18-4524" not in out
    assert "961-08-0047" not in out
    assert redact.last_counts.get("SSN") == 2


@pytest.mark.parametrize(
    "sep_value",
    [
        "078-05-1120",   # dash (baseline)
        "078 05 1120",   # space
        "078.05.1120",   # dot
        "078\t05\t1120", # tab
    ],
)
def test_ssn_separator_variants_masked(sep_value):
    out = redact(f"value {sep_value} here")
    assert sep_value not in out
    assert "[REDACTED-SSN]" in out
    assert redact.last_counts.get("SSN") == 1


@pytest.mark.parametrize(
    "text",
    [
        "ssn=078051120",
        "SSN: 078051120",
        "social_security_number = 078051120",
        "taxpayer-id 078051120",
        "itin: 936184524",          # bare ITIN
    ],
)
def test_keyworded_bare_ssn_masked(text):
    out = redact(text)
    assert "078051120" not in out and "936184524" not in out
    assert "[REDACTED-SSN]" in out
    assert redact.last_counts.get("SSN") == 1
    # the keyword/prefix is preserved (only the 9-digit value is masked)
    assert out.split("[REDACTED-SSN]")[0].strip() != ""


def test_bare_9_digits_without_keyword_not_masked():
    # Precision boundary: a bare 9-digit number with NO SSN/ITIN keyword is an
    # ordinary id/timestamp — must stay untouched (no blanket \d{9} masking).
    for text in ("trace id 123456789 logged", "order 078051120 shipped",
                 "count = 936184524"):
        out = redact(text)
        assert out == text
        assert "SSN" not in redact.last_counts


# ─────────────────────────────────────────────────────────────────────────────
# PAN: Luhn + IIN gating
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "pan",
    [
        "4111111111111111",       # 16-digit PAN
        "4111 1111 1111 1111",    # space-grouped PAN
        "5555555555554444",       # Mastercard
        "378282246310005",        # Amex
    ],
)
def test_valid_pan_is_masked(pan):
    out = redact(f"the card is {pan} on file")
    assert pan.replace(" ", "") not in out.replace(" ", "")
    assert "[REDACTED-PAN]" in out
    assert redact.last_counts.get("PAN") == 1


def test_random_16_digits_not_masked():
    # Luhn-valid but no real network IIN (leading 9) → left untouched.
    assert _luhn("9000000000000001") is True
    text = "trace id 9000000000000001 here"
    out = redact(text)
    assert out == text
    assert "PAN" not in redact.last_counts


def test_non_luhn_pan_not_masked():
    text = "card 4111111111111112 invalid"
    out = redact(text)
    assert out == text
    assert "PAN" not in redact.last_counts


# ─────────────────────────────────────────────────────────────────────────────
# SSN
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_ssn_is_masked():
    out = redact("SSN 078-05-1120 on record")
    assert "078-05-1120" not in out
    assert "[REDACTED-SSN]" in out
    assert redact.last_counts.get("SSN") == 1


def test_invalid_ssn_area_not_masked():
    text = "ref 666-05-1120 ok"
    out = redact(text)
    assert out == text
    assert "SSN" not in redact.last_counts


# ─────────────────────────────────────────────────────────────────────────────
# Cloud / SaaS credential patterns
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "label,secret",
    [
        ("AWS-KEY", "AKIAIOSFODNN7EXAMPLE"),
        ("AWS-KEY", "ASIA" + "A" * 16),
        ("GITHUB-TOKEN", "ghp_" + "a" * 36),
        ("SLACK-TOKEN", "xoxb-" + "1" * 20),
        ("STRIPE-KEY", "sk_live_" + "a" * 24),
        ("STRIPE-KEY", "rk_test_" + "B" * 30),
        ("GOOGLE-API-KEY", "AIza" + "a" * 35),
        ("TWILIO-KEY", "SK" + "0" * 32),
    ],
)
def test_cloud_credential_masked(label, secret):
    out = redact(f"key = {secret} end")
    assert secret not in out
    assert f"[REDACTED-{label}]" in out
    assert redact.last_counts.get(label) == 1


def test_azure_sas_signature_masked():
    out = redact("blob?sig=ABCDabcd1234efgh5678XYZ%2Fpq end")
    assert "[REDACTED-AZURE-SAS]" in out
    assert redact.last_counts.get("AZURE-SAS") == 1


def test_short_aws_lookalike_not_masked():
    # Too few trailing chars to satisfy the AKIA + 16 pattern.
    text = "AKIASHORT end"
    out = redact(text)
    assert out == text
    assert "AWS-KEY" not in redact.last_counts


# ─────────────────────────────────────────────────────────────────────────────
# JWT / Bearer / Basic / private key
# ─────────────────────────────────────────────────────────────────────────────

def test_jwt_masked():
    jwt = "eyJ" + "abcdefghij" + "." + "klmnopqrst" + "." + "uvwxyz0123"
    out = redact(f"Authorization: {jwt}")
    assert jwt not in out
    assert "[REDACTED-JWT]" in out
    assert redact.last_counts.get("JWT") == 1


def test_private_key_block_masked():
    pk = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "ABCDEFGHIJKLMNOP\nQRSTUVWXYZ012345\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = redact(f"embedded:\n{pk}\ntail")
    assert "ABCDEFGHIJKLMNOP" not in out
    assert "[REDACTED-PRIVATE-KEY]" in out
    assert redact.last_counts.get("PRIVATE-KEY") == 1


# ─────────────────────────────────────────────────────────────────────────────
# SECRET value-shape gate
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "text",
    [
        'password: "supersecret"',        # quoted
        "password: hunter2",              # carries a digit
        "secret: abcDEFghi",              # mixed case
        "api_key: aaa-bbb!cc",            # symbol
        "token: " + "a" * 30,             # long opaque token (>=20)
    ],
)
def test_secret_credential_shape_redacted(text):
    out = redact(text)
    assert "[REDACTED-SECRET]" in out
    assert redact.last_counts.get("SECRET") == 1


@pytest.mark.parametrize(
    "text",
    [
        "secret: rotate",        # prose-ambiguous keyword + short lowercase word
        "token: refresh",
        "credential: review",
    ],
)
def test_secret_weak_keyword_plain_word_not_redacted(text):
    out = redact(text)
    assert out == text
    assert "SECRET" not in redact.last_counts


@pytest.mark.parametrize(
    "text",
    [
        "password: correcthorse",       # strong keyword -> value always masked
        "pwd: hunterpw",
        "api_key: supersecret",
        "access_key: accesskeyval",
        "client_secret: clientsecretval",
        "auth_token: authtokenval",
    ],
)
def test_secret_strong_keyword_lowercase_value_redacted(text):
    # An unquoted all-lowercase value after a strong credential keyword is
    # almost always a real secret; the prose carve-out must NOT apply.
    out = redact(text)
    assert "[REDACTED-SECRET]" in out
    assert redact.last_counts.get("SECRET") == 1


@pytest.mark.parametrize(
    "text",
    [
        "password: changeme",
        "password: ${DB_PASS}",
        "secret: <your-secret>",
        "api_key: example",
    ],
)
def test_secret_placeholder_allowlist_not_redacted(text):
    out = redact(text)
    assert out == text
    assert "SECRET" not in redact.last_counts


def test_secret_keeps_keyword_and_quotes_around_mask():
    out = redact('password: "supersecret"')
    # The keyword and the surrounding quotes survive; only the value is masked.
    assert out.startswith("password: ")
    assert out.count('"') == 2
    assert "[REDACTED-SECRET]" in out


def test_secret_backtick_placeholder_not_redacted():
    text = "use `token: ${DB_PASS}` in env"
    out = redact(text)
    assert out == text
    assert "SECRET" not in redact.last_counts


def test_secret_backtick_value_masked_keeps_span_balanced():
    out = redact("password: `hunter2pw`")
    assert "[REDACTED-SECRET]" in out
    assert "hunter2pw" not in out
    assert out.count("`") == 2

@pytest.mark.parametrize(
    "text",
    [
        "superSecret: hunter2pw",
        "myApiKey: abc123def456",
        "dbPassword: s3cr3tvalue",
    ],
)
def test_secret_camelcase_strong_keyword_redacted(text):
    out = redact(text)
    assert "[REDACTED-SECRET]" in out
    assert redact.last_counts.get("SECRET") == 1

@pytest.mark.parametrize(
    "text",
    [
        "secret = (sasl_secret_t *)realloc(p, n);",   # C cast
        "token = parse(input)",                        # function call
        "this.secret = obj.field",                     # member access
    ],
)
def test_secret_code_expression_not_redacted(text):
    out = redact(text)
    assert out == text
    assert "SECRET" not in redact.last_counts


# ── D10: BEARER must not mangle prose ────────────────────────────────────────

@pytest.mark.parametrize(
    "text",
    [
        "HTTP Basic Authentication is supported",
        "uses Bearer authentication for the API",
        "Basic Authorization header",
    ],
)
def test_bearer_prose_not_redacted(text):
    out = redact(text)
    assert out == text
    assert "BEARER" not in redact.last_counts


# ─────────────────────────────────────────────────────────────────────────────
# NUL handling, counts, empty input
# ─────────────────────────────────────────────────────────────────────────────

def test_nul_bytes_stripped_no_indexerror():
    # A literal "\x00<digits>\x00" must not collide with the reinsertion pass.
    out = redact("\x000\x00 hello \x0042\x00 world")
    assert "\x00" not in out
    assert out == "0 hello 42 world"


def test_empty_and_none_passthrough():
    assert redact("") == ""
    assert redact(None) is None


def test_last_counts_aggregates_multiple_hits():
    out = redact("4111111111111111 and 5555555555554444 here")
    assert out.count("[REDACTED-PAN]") == 2
    assert redact.last_counts.get("PAN") == 2


def test_last_counts_reset_between_calls():
    redact("4111111111111111")
    assert redact.last_counts.get("PAN") == 1
    redact("no secrets here at all")
    assert redact.last_counts == {}


def test_clean_text_unchanged():
    text = "This is an ordinary sentence with no secrets."
    out = redact(text)
    assert out == text
    assert redact.last_counts == {}


# ─────────────────────────────────────────────────────────────────────────────
# redact_tree recursion
# ─────────────────────────────────────────────────────────────────────────────

def test_redact_tree_recurses_strings_only():
    tree = {
        "card": "PAN 4111111111111111 here",
        "nested": {"list": ["clean", "ghp_" + "a" * 36]},
        "number": 42,
        "flag": True,
        "none": None,
    }
    out = redact_tree(tree)
    assert "4111111111111111" not in out["card"]
    assert "[REDACTED-PAN]" in out["card"]
    assert out["nested"]["list"][0] == "clean"
    assert "[REDACTED-GITHUB-TOKEN]" in out["nested"]["list"][1]
    # Non-string leaves are passed through untouched.
    assert out["number"] == 42
    assert out["flag"] is True
    assert out["none"] is None


def test_redact_tree_preserves_structure():
    out = redact_tree(["a", ["b", {"c": "d"}], 1])
    assert out == ["a", ["b", {"c": "d"}], 1]


# ── over-match: trailing delimiter / sentence boundary must survive ──────────
def test_secret_does_not_swallow_trailing_period():
    out = redact("token=mysecretvalue9.")
    assert out == "token=[REDACTED-SECRET]."
    assert "mysecretvalue9" not in out


def test_secret_does_not_swallow_trailing_paren_or_sentence():
    out = redact("api_key=abcdef123456) in the call.")
    assert out == "api_key=[REDACTED-SECRET]) in the call."
    assert "abcdef123456" not in out


def test_secret_does_not_swallow_trailing_bracket():
    out = redact("auth_token=abcdefghij]")
    assert out == "auth_token=[REDACTED-SECRET]]"
    assert "abcdefghij" not in out


def test_secret_in_json_object_is_redacted():
    out = redact('config {"token": "abc123def456"}')
    assert "abc123def456" not in out
    assert out.endswith('}')
    assert "[REDACTED-SECRET]" in out


def test_quoted_secret_with_interior_paren_preserved():
    out = redact("password = 'p)ss)word12'")
    assert "p)ss)word12" not in out


def test_prose_carveout_after_weak_keyword_survives():
    assert redact("the secret: management approach") == \
        "the secret: management approach"


def test_strong_keyword_value_always_masked():
    out = redact("password: correcthorse")
    assert "correcthorse" not in out
    assert "[REDACTED-SECRET]" in out


# ─────────────────────────────────────────────────────────────────────────────
# redact_counts: thread-safe variant used for OUTBOUND (prompt / tool) scrubbing
# ─────────────────────────────────────────────────────────────────────────────

def test_redact_counts_returns_text_and_counts():
    text, counts = redact_counts("SSN 078-05-1120 and card 4111111111111111")
    assert "078-05-1120" not in text and "[REDACTED-SSN]" in text
    assert "4111111111111111" not in text and "[REDACTED-PAN]" in text
    assert counts.get("SSN") == 1
    assert counts.get("PAN") == 1


def test_redact_counts_output_matches_redact():
    s = "x 078-05-1120 y ghp_" + "a" * 36 + " z"
    assert redact_counts(s)[0] == redact(s)


def test_redact_counts_does_not_touch_global_last_counts():
    # Prime the shared side-channel, then ensure the thread-safe variant
    # leaves it untouched (so concurrent callers can't corrupt each other).
    redact("078-05-1120")
    before = dict(redact.last_counts)
    redact_counts("4111111111111111 and 5555555555554444")  # two PANs
    assert redact.last_counts == before


def test_redact_counts_empty_and_none():
    assert redact_counts("") == ("", {})
    assert redact_counts(None) == (None, {})


def test_redact_counts_clean_text_zero_counts():
    text, counts = redact_counts("ordinary code: return x + 1")
    assert text == "ordinary code: return x + 1"
    assert counts == {}

def test_redact_is_idempotent_no_double_bracket():
    # Re-redacting already-redacted text must be a no-op (a second pass used to
    # append a stray bracket: `token=[REDACTED-SECRET]]`).
    once = redact("token=supersecretvalue123")
    assert once == "token=[REDACTED-SECRET]"
    assert redact(once) == once
    assert "]]" not in redact(once)


def test_url_userinfo_password_masked_user_preserved():
    out = redact("clone https://x-access-token:ghp_SECRETVALUE123@example.com/o/r.git")
    assert "ghp_SECRETVALUE123" not in out
    assert "x-access-token" in out                 # username/scheme preserved
    assert "[REDACTED-URL-CRED]" in out
    # a host:port URL with no credentials must NOT match
    assert redact("see https://api.example.com:443/v1") \
        == "see https://api.example.com:443/v1"


def test_large_private_key_block_masked():
    # A key body larger than the old 16 KB cap must still be masked (the cap
    # used to fail open and leak the whole block).
    big = ("-----BEGIN RSA PRIVATE KEY-----\n"
           + "A" * 20000 + "\n-----END RSA PRIVATE KEY-----")
    out = redact("key: " + big)
    assert "[REDACTED-PRIVATE-KEY]" in out
    assert "A" * 100 not in out


def test_ssn_unicode_space_separators_masked():
    # NBSP / narrow-no-break separated SSN must mask; a value split across
    # newlines must NOT (avoids matching numbers across table rows).
    assert "[REDACTED-SSN]" in redact("id 078\u00a005\u00a01120 x")
    assert "[REDACTED-SSN]" in redact("id 078\u202f05\u202f1120 x")
    assert "[REDACTED-SSN]" not in redact("078\n05\n1120")


# ═════════════════════════════════════════════════════════════════════════
# NEW for audit task 4.2 — redact_json walker + report-egress cases.
# (audit.redact adds redact_json; VVAH's redact_tree above is unmodified.)
# ═════════════════════════════════════════════════════════════════════════

def test_redact_json_recurses_strings_only():
    tree = {
        "card": "PAN 4111111111111111 here",
        "nested": {"list": ["clean", "ghp_" + "a" * 36]},
        "number": 42,
        "flag": True,
        "none": None,
    }
    out = redact_json(tree)
    assert "4111111111111111" not in out["card"]
    assert "[REDACTED-PAN]" in out["card"]
    assert out["nested"]["list"][0] == "clean"
    assert "[REDACTED-GITHUB-TOKEN]" in out["nested"]["list"][1]
    # Keys + non-string leaves survive untouched.
    assert out["number"] == 42
    assert out["flag"] is True
    assert out["none"] is None


def test_redact_json_preserves_structure():
    out = redact_json(["a", ["b", {"c": "d"}], 1])
    assert out == ["a", ["b", {"c": "d"}], 1]


def test_redact_json_matches_redact_tree():
    # redact_json is the audit-side name used at the report/CLI egress call
    # sites; it must behave identically to the ported redact_tree.
    tree = {"a": "token: supersecretvalue123", "b": [1, 2, "clean"]}
    assert redact_json(tree) == redact_tree(tree)


def test_redact_json_is_a_copy_not_a_mutation():
    tree = {"evidence": "card 4111111111111111 here", "id": "f1"}
    out = redact_json(tree)
    assert out is not tree
    assert tree["evidence"] == "card 4111111111111111 here"  # original untouched
    assert "4111111111111111" not in out["evidence"]


# ── report egress: audit/stages/report.py writes report.json via
#    out_path.write_text(json.dumps(redact_json(payload), indent=2)) ────────

def _report_payload_with_secrets(aws_key: str, pan: str) -> dict:
    """Shape matches audit/stages/report.py's fallback-report / agent-report
    payload (see tests/test_pipeline_e2e.py CANNED['report'] for the
    schema-valid reference shape) — only the `evidence` field carries
    secrets, mirroring a finding that quoted hardcoded credentials."""
    return {
        "run_id": "test_run",
        "target": {"repo_path": "/some/repo"},
        "summary": {"total": 1, "by_severity": {"high": 1}},
        "findings": [
            {
                "finding_id": "f1",
                "title": "Hardcoded AWS key and PAN in app.py",
                "severity": "high",
                "vuln_class": "hardcoded-secret",
                "file": "app.py",
                "line_start": 10,
                "line_end": 12,
                "description": "AWS access key and a card PAN are hardcoded in source.",
                "evidence": f"AWS_KEY = '{aws_key}'\ncard = '{pan}'",
                "trace": {"entry_points": [], "call_chain": []},
                "recommendation": "Remove hardcoded credentials.",
            }
        ],
    }


def test_report_egress_payload_masked_and_still_valid_json(tmp_path):
    """Mirrors the exact call at every out_path.write_text() site in
    audit/stages/report.py: out_path.write_text(json.dumps(redact_json(payload), indent=2)).
    A finding's evidence carries a real-shaped AWS key + Luhn-valid PAN; both
    must be masked in the bytes that hit disk, and the file must still
    round-trip through json.loads."""
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    pan = "4111111111111111"
    payload = _report_payload_with_secrets(aws_key, pan)

    out_path = tmp_path / "report.json"
    out_path.write_text(json.dumps(redact_json(payload), indent=2))

    written = out_path.read_text()
    assert aws_key not in written
    assert pan not in written
    assert "[REDACTED-AWS-KEY]" in written
    assert "[REDACTED-PAN]" in written

    reparsed = json.loads(written)  # must still parse
    assert reparsed["findings"][0]["finding_id"] == "f1"   # non-secret keys intact
    assert reparsed["summary"]["total"] == 1               # numbers intact
    assert aws_key not in reparsed["findings"][0]["evidence"]
    assert pan not in reparsed["findings"][0]["evidence"]


def test_report_egress_redaction_is_idempotent_on_rewrite(tmp_path):
    # Redacting an already-redacted report (e.g. re-running the report stage
    # against a resumed run) must not double-mask or corrupt the JSON.
    payload = _report_payload_with_secrets("AKIAIOSFODNN7EXAMPLE", "4111111111111111")
    once = redact_json(payload)
    twice = redact_json(once)
    assert once == twice
    out_path = tmp_path / "report.json"
    out_path.write_text(json.dumps(twice, indent=2))
    assert "]]" not in out_path.read_text()
    json.loads(out_path.read_text())  # still valid


def test_report_egress_clean_payload_is_a_no_op(tmp_path):
    # Guardrail check: a report with no secrets in it (the common case, and
    # exactly what tests/test_pipeline_e2e.py's stub report looks like) must
    # be unchanged by redact_json — no false positives on ordinary evidence.
    payload = {
        "run_id": "test_e2e_run",
        "target": {"repo_path": "/repo"},
        "summary": {"total": 1, "by_severity": {"high": 1}},
        "findings": [{
            "finding_id": "t_web_sqli_1-f1",
            "title": "SQL injection in app.py",
            "severity": "high",
            "vuln_class": "sql-injection",
            "file": "app.py",
            "line_start": 1,
            "line_end": 2,
            "description": "Unsanitized request parameter is concatenated into a SQL query string.",
            "evidence": "q=...",
            "trace": {"entry_points": [], "call_chain": []},
            "recommendation": "Use parameterized queries instead of string interpolation.",
        }],
    }
    assert redact_json(payload) == payload


def test_build_fallback_report_evidence_is_maskable_by_redact_json():
    """Exercises the REAL audit/stages/report.py fallback-report builder
    (one of the three write sites) rather than a hand-rolled dict, so the
    payload shape it actually produces is proven compatible with
    redact_json — not just a shape lookalike."""
    from types import SimpleNamespace

    from vash.state import Finding
    from vash.stages.report import _build_fallback_report

    finding = Finding(
        finding_id="f1", task_id="t1", run_id="test_run",
        file="app.py", line_start=10, line_end=12,
        vuln_class="hardcoded-secret", severity="high",
        description="Hardcoded AWS key and PAN.",
        evidence="AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\ncard = '4111111111111111'",
        poc_succeeded=False, confidence=0.9, raw_json={},
        validation_status="confirmed", validation_json=None,
        group_id=None, is_canonical=True,
    )
    ctx = SimpleNamespace(run_id="test_run")
    reachable = [(finding, {"entry_points": [], "call_chain": []})]

    report = _build_fallback_report(ctx, None, reachable, {"repo_path": "/repo"}, chains=[])
    redacted = redact_json(report)

    written = json.dumps(redacted, indent=2)
    assert "AKIAIOSFODNN7EXAMPLE" not in written
    assert "4111111111111111" not in written
    assert "[REDACTED-AWS-KEY]" in written
    assert "[REDACTED-PAN]" in written
    reparsed = json.loads(written)
    assert reparsed["findings"][0]["finding_id"] == "f1"
