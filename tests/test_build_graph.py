"""Coverage + integration tests for scripts/build_graph.py.

SKIPPED (whole module) — Task 0.5 scope note:

The upstream file this ports (vulnhunter-fix/tests/test_build_graph.py)
exercises ``scripts/build_graph.py``, a CLI wrapper around
``vulnhunter_fix.graph.build_or_load`` / ``GraphQuery`` that adds
``--findings`` parsing and per-finding ``graph_context/<VULN>.json`` sidecar
emission (VULN-ID regex, sidecar schema, exit code 3 on grep-fallback, etc.).

Task 0.5's brief scopes the port to exactly the 6 graph-package files
(build.py, config.py, fallback.py, schema.py, query.py, __init__.py) now
living at audit/graph/ — it does not include a ``scripts/`` CLI layer, and
audit has no equivalent script or ``_skill_bootstrap`` shim to import. All
9 tests in the original file (test_builds_graph_to_cache,
test_repo_root_not_a_dir, test_sidecar_emission, test_sidecar_list_shape,
test_sidecar_single_finding, test_findings_missing_file,
test_findings_bad_json, test_findings_wrong_shape,
test_finding_without_id_skipped) depend on that script via
``importlib.util.spec_from_file_location(... SCRIPTS / "build_graph.py")``.

This is VulnHunter-only infra outside this port's scope (not a silent drop):
when a CLI/sidecar layer is built on top of audit.graph in a later task,
port this file for real against that new script and remove this skip.
"""

from __future__ import annotations

import pytest

pytest.skip(
    "scripts/build_graph.py (the CLI + sidecar-emission wrapper this file "
    "tests) is out of scope for Task 0.5, which only ports the audit.graph "
    "package itself; no equivalent script exists yet in audit/. See module "
    "docstring for detail — port for real once that CLI layer is built.",
    allow_module_level=True,
)
