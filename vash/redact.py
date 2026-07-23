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

"""
Sensitive-data redaction for emitted reports (MD + SARIF).

Applied at the write boundary in the orchestrator (markdown) and
report.enrich.md_to_sarif (SARIF JSON) so card data, PII and credential
material that the model quoted from source never lands in the on-disk
report.

Design goals:
  - High precision (low false-positive): card numbers are Luhn + IIN gated,
    SSNs are area/group/serial gated, generic secrets are keyword-gated.
  - String-in / string-out: callers pass the fully rendered MD or JSON text
    so every field (description, code_snippet, exploit_scenario,
    verifier_reasoning, narrative, …) is covered without enumerating them.
"""
from __future__ import annotations
import re
from typing import Callable


# ─────────────────────────────────────────────────────────────────────────────
# Validators
# ─────────────────────────────────────────────────────────────────────────────

def _luhn(digits: str) -> bool:
    total, odd = 0, True
    for ch in reversed(digits):
        n = int(ch)
        if not odd:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        odd = not odd
    return total % 10 == 0


def _cc_network(digits: str) -> bool:
    """IIN/BIN gate so random Luhn-passing 16-digit ids aren't masked."""
    n = len(digits)
    if n < 12 or n > 19:
        return False
    p1, p2 = digits[0], int(digits[:2])
    p3 = int(digits[:3]) if n >= 3 else -1
    p4 = int(digits[:4]) if n >= 4 else -1
    if n == 15 and p2 in (34, 37):                       # Amex
        return True
    if p1 == "4" and 13 <= n <= 19:                      # Visa
        return True
    if n == 16 and (51 <= p2 <= 55 or 2221 <= p4 <= 2720):  # Mastercard
        return True
    if 16 <= n <= 19 and (p4 == 6011 or p2 == 65 or 644 <= p3 <= 649):  # Discover
        return True
    if 16 <= n <= 19 and 3528 <= p4 <= 3589:             # JCB
        return True
    if 16 <= n <= 19 and p2 == 62:                       # UnionPay
        return True
    if 14 <= n <= 19 and p2 == 36:                       # Diners
        return True
    if 12 <= n <= 19 and p4 in (5018, 5020, 5038, 5893,
                                6304, 6759, 6761, 6762, 6763):  # Maestro
        return True
    if n == 16 and (p3 == 508 or p2 in (81, 82)):        # RuPay
        return True
    return False


def _ssn_valid(d: str) -> bool:
    a, g, s = int(d[:3]), int(d[3:5]), int(d[5:9])
    # Reject only structurally-impossible groupings (area 000/666, group 00,
    # serial 0000). Area 900-999 is intentionally ALLOWED: it is the ITIN range
    # (individual taxpayer IDs, 9XX-XX-XXXX) — sensitive PII that content guards
    # also flag, so mask it rather than let it egress.
    return not (a == 0 or a == 666 or g == 0 or s == 0)


def _bearer_credential(m: re.Match) -> bool:
    """True only when the post-scheme value looks like a real token.

    The BEARER rule matches the literal words ``Bearer``/``Basic`` followed by
    a value; without this guard it also fires on prose such as
    ``HTTP Basic Authentication`` (the value group captures the all-alphabetic
    word ``Authentication``). A genuine bearer/basic credential is base64 or
    otherwise carries at least one non-alphabetic character, so require one in
    the captured value group. Known false-negative: an all-alphabetic 8+ char
    credential is left intact — acceptable versus mangling ordinary prose.
    """
    return any(not c.isalpha() for c in m.group("bv"))

_SECRET_CODE_SHAPE = re.compile(
    r"^\("                 # leading paren / cast:   (sasl_secret_t
    r"|^[A-Za-z_]\w*\("    # function call:          parse(
    r"|^[A-Za-z_]\w*\.\w"  # member access:          obj.field / this.field
)


# ─────────────────────────────────────────────────────────────────────────────
# Patterns  (label, compiled-regex, optional validator(match)->bool)
# ─────────────────────────────────────────────────────────────────────────────

_b64u = r"[A-Za-z0-9_-]"

_PATTERNS: list[tuple[str, re.Pattern, Callable[[re.Match], bool] | None]] = [
    # ── Card / PAN ───────────────────────────────────────────────────────
    ("PAN",
     re.compile(r"(?<![0-9A-Za-z./_-])"
                # \s (Unicode in a str pattern) also matches NBSP/thin/figure
                # space, so a PAN split by those separators isn't bypassed.
                r"(?:\d[\s\-]?){12,18}\d"
                r"(?![0-9A-Za-z./_-])"),
     lambda m: (lambda d: _cc_network(d) and _luhn(d))(re.sub(r"\D", "", m.group(0)))),
    ("CVV",
     re.compile(r"(?i)\b(cvv2?|cvc2?|cid|csc)\b\s*[:=]?\s*\"?(\d{3,4})\"?"),
     None),
    ("TRACK",
     re.compile(r"%B\d{12,19}\^[^?]{2,90}\?"),
     None),

    # ── PII ──────────────────────────────────────────────────────────────
    # Separated SSN/ITIN: NNN-NN-NNNN with '-', '.', tab or single space.
    ("SSN",
     # Separator class includes Unicode spaces (NBSP / thin / narrow-no-break /
     # figure) so an SSN/ITIN split by those isn't bypassed. \n and \r are
     # deliberately excluded to avoid matching three numbers across table rows.
     re.compile(r"(?<!\d)(\d{3})[-.\t \u00a0\u2009\u202f\u2007]"
                r"(\d{2})[-.\t \u00a0\u2009\u202f\u2007](\d{4})(?!\d)"),
     lambda m: _ssn_valid(m.group(1) + m.group(2) + m.group(3))),
    # Keyword-gated BARE 9-digit SSN/ITIN (no separators). Gated on an
    # SSN/ITIN/TIN keyword so we don't mask arbitrary 9-digit ids/timestamps;
    # only the 9-digit value (group 2) is masked, the keyword is preserved.
    ("SSN-CTX",
     re.compile(
         r"(?i)\b(ssn|social[\s_-]*sec(?:urity)?(?:[\s_-]*(?:no|num|number))?"
         r"|itin|tin|taxpayer[\s_-]*id)\b['\"]?\s*[:=#-]?\s*['\"]?"
         r"(?<!\d)(\d{9})(?!\d)"),
     lambda m: _ssn_valid(m.group(2))),

    # ── Cloud / SaaS credentials ────────────────────────────────────────
    ("AWS-KEY",
     re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
     None),
    ("GITHUB-TOKEN",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}"
                r"|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59})\b"),
     None),
    ("SLACK-TOKEN",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
     None),
    ("STRIPE-KEY",
     re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b"),
     None),
    ("GOOGLE-API-KEY",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     None),
    ("AZURE-SAS",
     re.compile(r"(?i)\bsig=[0-9A-Za-z%+/=]{20,}\b"),
     None),
    ("TWILIO-KEY",
     re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     None),

    # ── Bearer / Basic / JWT ────────────────────────────────────────────
    ("JWT",
     re.compile(r"\beyJ" + _b64u + r"{10,}\." + _b64u + r"{10,}\." + _b64u + r"{10,}\b"),
     None),
    ("BEARER",
     re.compile(r"(?i)\b(?:Bearer|Basic)\s+(?P<bv>[A-Za-z0-9+/=._-]{8,})\b"),
     _bearer_credential),

    # ── URL userinfo credential (scheme://user:secret@host) ─────────────
    # Masks ONLY the password component; the scheme + username are preserved.
    # Only fires when an '@' follows, i.e. real userinfo — a host:port URL
    # without credentials never matches.
    ("URL-CRED",
     re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s/@]{1,256})@"),
     None),

    # ── Private-key material ────────────────────────────────────────────
    # Unbounded lazy body between two fixed literal anchors — linear-safe (no
    # catastrophic backtracking). A bounded cap used to FAIL OPEN on large keys
    # (RSA-16384, multi-key bundles), leaving the whole block unmasked.
    ("PRIVATE-KEY",
     re.compile(r"-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[\s\S]*?-{5}END [A-Z ]*PRIVATE KEY-{5}"),
     None),

    # ── Keyword-gated generic secret assignment ─────────────────────────
    ("SECRET",
     re.compile(
         # Leading anchor also accepts a camelCase boundary (a lowercase letter
         # immediately before the keyword) so identifiers like `superSecret`,
         # `myApiKey`, `dbPassword` are recognised, not just `\b`-delimited names.
         r"(?i)(?:\b|(?<=[a-z]))(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?key"
         r"|client[_-]?secret|auth[_-]?token|token|credential)s?\b"
         r"['\"`]?\s*[:=]\s*"           # tolerate a JSON/markdown closing delimiter: "token": / `token`:
         # \x00 excluded so SECRET never re-captures across a placeholder
         # sentinel left by an earlier pattern (e.g. URL-CRED masking the
         # password in `https://x-access-token:…@host`) — which would
         # otherwise swallow the trailing host into a SECRET mask.
         r"(?P<q>['\"`]?)(?P<v>[^\s'\"`,;\x00]{6,256})(?P=q)"),
     lambda m: not re.fullmatch(
         # `\[redacted-...]` makes redact() idempotent: a value that is already
         # a placeholder (e.g. `token=[REDACTED-SECRET]` from a prior pass) is
         # not re-masked — otherwise a second pass appended a stray bracket
         # (`[REDACTED-SECRET]]`).
         r"(?i)\$\{?[A-Z0-9_.]+}?|%[A-Z0-9_]+%|<[^>]+>|\*{3,}|x{3,}"
         r"|\[?redacted]?|\[redacted-[a-z0-9-]+]"
         r"|null|none|true|false|changeme|your[_-]?\w+|placeholder|example",
         m.group("v"))),
]


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def _redact_impl(text: str) -> tuple[str, dict[str, int]]:
    """Core masking pass. Returns (masked_text, counts). Pure / no globals —
    so it is safe to call from concurrent threads (see redact_counts)."""
    # NUL is reserved as the in-band placeholder sentinel below. Strip any
    # NUL bytes already present in the input so a literal "\x00<digits>\x00"
    # sequence in the source text cannot collide with the reinsertion pass
    # and raise IndexError. NUL has no legitimate meaning in a report.
    if "\x00" in text:
        text = text.replace("\x00", "")
    counts: dict[str, int] = {}
    placeholders: list[str] = []
    sentinel = "\x00{}\x00"

    def _mask(label: str, m: re.Match) -> str:
        counts[label] = counts.get(label, 0) + 1
        placeholders.append(f"[REDACTED-{label}]")
        return sentinel.format(len(placeholders) - 1)

    out = text
    for label, rx, validator in _PATTERNS:
        def _sub(m: re.Match, _label=label, _ok=validator) -> str:
            if _ok is not None and not _ok(m):
                return m.group(0)
            if _label == "SECRET":
                v = m.group("v")
                quoted = bool(m.group("q"))
                v_core = v if quoted else (v.rstrip(").}]!?>") or v)
                if len(v_core) < 6:
                    v_core = v
                keyword = re.sub(r"[^a-z]", "", m.group(1).lower())
                strong = {"password", "passwd", "pwd", "apikey",
                          "accesskey", "clientsecret", "authtoken"}
                generic_unquoted = keyword not in strong and not quoted
                # Don't mask prose words (`secret: management`) or code-expression
                # RHS (`secret = (cast)x`, `token = parse(x)`) after a *generic*
                # keyword; strong credential keywords always mask.
                plain_word = (generic_unquoted
                              and v_core.isalpha() and v_core.islower()
                              and len(v_core) < 20)
                code_shape = generic_unquoted and bool(_SECRET_CODE_SHAPE.match(v_core))
                if plain_word or code_shape:
                    return m.group(0)
                head = m.group(0)[: m.start("v") - m.start(0)]
                tail = v[len(v_core):] + m.group(0)[m.end("v") - m.start(0):]
                return head + _mask(_label, m) + tail
            if _label == "CVV":
                return m.group(0)[: m.start(2) - m.start(0)] + _mask(_label, m)
            if _label == "SSN-CTX":
                # Mask only the 9-digit value; keep the keyword/prefix. Emit
                # the canonical "SSN" label so the placeholder and counts match
                # the separated-SSN rule.
                return m.group(0)[: m.start(2) - m.start(0)] + _mask("SSN", m)
            if _label == "URL-CRED":
                # Keep "scheme://user:" (group 1), mask the password (group 2),
                # restore the trailing "@".
                return m.group(1) + _mask(_label, m) + "@"
            return _mask(_label, m)
        out = rx.sub(_sub, out)

    if placeholders:
        def _reinsert(m: re.Match) -> str:
            idx = int(m.group(1))
            # Defensive: an index outside the placeholder range can only come
            # from a sentinel collision; leave such a sequence untouched
            # rather than raising IndexError.
            return placeholders[idx] if 0 <= idx < len(placeholders) else m.group(0)
        out = re.sub(r"\x00(\d+)\x00", _reinsert, out)
    return out, counts


def redact(text: str) -> str:
    """Return `text` with card data, PII and credential material masked.

    Records per-label hit counts on `redact.last_counts` for the caller to
    read afterwards. That side-channel is NOT thread-safe — concurrent callers
    must use `redact_counts()` instead (which returns the counts directly)."""
    if not text:
        return text
    out, counts = _redact_impl(text)
    redact.last_counts = dict(counts)  # type: ignore[attr-defined]
    return out


def redact_counts(text: str) -> tuple[str, dict[str, int]]:
    """Thread-safe variant of `redact()`: returns (masked_text, counts) and
    never touches the shared `redact.last_counts`. Use this from concurrent
    stages (e.g. s4 parallel chunks, the agentic tool loop) where the outbound
    code is scrubbed before it is sent to the model."""
    if not text:
        return text, {}
    return _redact_impl(text)


def redact_tree(obj):
    """Recursively redact every string leaf in a JSON-serialisable structure.

    Use this *before* json.dumps so escaping is handled by the serialiser and
    redaction regexes never see (or corrupt) JSON escape sequences.
    """
    if isinstance(obj, dict):
        return {k: redact_tree(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_tree(v) for v in obj]
    if isinstance(obj, str):
        return redact(obj)
    return obj


# ─────────────────────────────────────────────────────────────────────────────
# audit egress walker — added for audit task 4.2. NOT part of the VVAH port
# above (which ends at redact_tree); this is the audit-side entry point named
# by audit/stages/report.py and audit/cli.py at the report/CLI egress sites.
# Same recursion as redact_tree — kept as a distinct name (rather than an
# alias) so it matches the brief/call sites verbatim and stays independently
# greppable.
# ─────────────────────────────────────────────────────────────────────────────

def redact_json(obj):
    """Recursively redact every string leaf in a JSON-like structure (dict/list/str/other).

    Returns a redacted COPY; keys are left intact (secrets live in values),
    non-str leaves unchanged.
    """
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_json(v) for v in obj]
    return obj
