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

"""Coverage-presence guards for detector prompt hints (lang.hints).

These lock the weakness classes that were previously under-covered so a future
refactor can't silently drop them. They assert the guidance TEXT is present —
they do not (and cannot) assert detection quality.
"""
from vash.lang.hints import SPECIALIST_HINTS, LANG_HINTS


def test_logic_bug_covers_indexof_sentinel_idiom():
    body = SPECIALIST_HINTS["logic-bug"]
    assert "indexOf" in body
    assert "== -1" in body


def test_access_control_blocks_hardcoded_constant_idor():
    body = SPECIALIST_HINTS["access-control"]
    assert "HARDCODED" in body
    assert "bounded blast radius" in body


def test_access_control_covers_destructive_bulk_ops():
    body = SPECIALIST_HINTS["access-control"]
    assert "Destructive bulk operations" in body


def test_python_and_java_cover_xpath_injection():
    assert "XPath injection" in LANG_HINTS["python"]
    assert "XPath injection" in LANG_HINTS["java"]
