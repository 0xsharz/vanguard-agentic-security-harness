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
CVSS 3.1 base-score calculator (FIRST.org spec §7).

Given a vector string like
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
returns the 0.0–10.0 base score and the qualitative rating.
"""
from __future__ import annotations
import re

_VECTOR_RE = re.compile(
    r"CVSS:3\.[01]/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/"
    r"UI:(?P<UI>[NR])/S:(?P<S>[UC])/C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])"
)

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup1(x: float) -> float:
    n = int(x * 100000)
    return n / 100000.0 if n % 10000 == 0 else (n // 10000 + 1) / 10.0


def score(vector: str | None) -> float | None:
    """Compute CVSS 3.1 base score from a vector string. Returns None if unparseable."""
    if not vector:
        return None
    m = _VECTOR_RE.search(vector)
    if not m:
        return None
    g = m.groupdict()
    scope_changed = g["S"] == "C"

    iss = 1 - (1 - _CIA[g["C"]]) * (1 - _CIA[g["I"]]) * (1 - _CIA[g["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    pr = (_PR_C if scope_changed else _PR_U)[g["PR"]]
    exploitability = 8.22 * _AV[g["AV"]] * _AC[g["AC"]] * pr * _UI[g["UI"]]

    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _roundup1(base)


def rating(s: float | None) -> str:
    if s is None:
        return "Unknown"
    if s == 0.0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"
