"""Repo-kind -> OWASP/CWE baseline checklist (feature V10).

Ported machinery: `_BASELINES`, `_repo_kind`, `_baseline_block`, the
classifier regexes. These tests lock the checklist text (verbatim from
VVAH's s2_threatmodel.py) and the classification logic. `classify_and_baseline`
is the new evidence-gathering adapter — tested against tiny on-disk fixture
repos built in `tmp_path` (no network, no live scan).
"""
from __future__ import annotations

from pathlib import Path

import audit.baselines as baselines_mod
from audit.baselines import (
    _BASELINES,
    _baseline_block,
    _repo_kind,
    classify_and_baseline,
)


def _ev(**over) -> dict:
    base = {
        "all_files": [],
        "manifests": [],
        "entry_points": [],
        "api_artefacts": [],
        "primary_language": "",
        "languages": [],
    }
    base.update(over)
    return base


# ---- _repo_kind (pure classifier over a synthetic `ev` dict) --------------

def test_repo_kind_defaults_to_library_with_no_signal() -> None:
    assert _repo_kind(_ev()) == {"library"}


def test_repo_kind_web_api_from_framework_manifest_regex() -> None:
    ev = _ev(manifests=[("requirements.txt", "Flask==2.0.1\ngunicorn\n")])
    assert _repo_kind(ev) == {"web-api"}


def test_repo_kind_web_api_from_api_artefact() -> None:
    ev = _ev(api_artefacts=["openapi.yaml"])
    assert _repo_kind(ev) == {"web-api"}


def test_repo_kind_web_api_from_network_entry_point() -> None:
    ev = _ev(entry_points=[("network", None, "", "")])
    assert _repo_kind(ev) == {"web-api"}


def test_repo_kind_native_from_language() -> None:
    ev = _ev(primary_language="c-cpp", languages=[("c-cpp", 5), ("python", 1)])
    assert _repo_kind(ev) == {"native"}


def test_repo_kind_mobile_from_androidmanifest_file() -> None:
    ev = _ev(all_files=["app/src/main/AndroidManifest.xml"])
    assert _repo_kind(ev) == {"mobile"}


def test_repo_kind_mobile_from_manifest_package_reference() -> None:
    ev = _ev(manifests=[("build.gradle", "applicationId 'com.android.example'\n")])
    assert _repo_kind(ev) == {"mobile"}


def test_repo_kind_iac_from_terraform_file() -> None:
    ev = _ev(all_files=["infra/main.tf"])
    assert _repo_kind(ev) == {"iac"}


def test_repo_kind_iac_from_helm_chart() -> None:
    ev = _ev(all_files=["charts/app/Chart.yaml"])
    assert _repo_kind(ev) == {"iac"}


def test_repo_kind_can_return_multiple_kinds() -> None:
    ev = _ev(
        manifests=[("requirements.txt", "flask\n")],
        all_files=["infra/main.tf"],
    )
    assert _repo_kind(ev) == {"web-api", "iac"}


def test_repo_kind_all_files_key_optional() -> None:
    """`all_files` is the one adapted key (was `ctx.all_files`) — a caller
    that omits it entirely must not crash, just skip the file-name checks."""
    ev = {
        "manifests": [], "entry_points": [], "api_artefacts": [],
        "primary_language": "", "languages": [],
    }
    assert _repo_kind(ev) == {"library"}


# ---- _baseline_block (checklist renderer) ---------------------------------

def test_baseline_block_mode_none_returns_empty() -> None:
    assert _baseline_block(_ev(), "none") == (set(), "")


def test_baseline_block_mode_owasp_forces_web_api_regardless_of_evidence() -> None:
    ev = _ev(primary_language="c-cpp", languages=[("c-cpp", 9)])
    kinds, text = _baseline_block(ev, "owasp")
    assert kinds == {"web-api"}
    assert "OWASP A01" in text


def test_baseline_block_auto_with_no_evidence_still_renders_library_block() -> None:
    # "library" is _repo_kind's fallback and always has _BASELINES entries,
    # so mode=auto with zero evidence still renders a non-empty block.
    kinds, text = _baseline_block(_ev(), "auto")
    assert kinds == {"library"}
    assert text


def test_baseline_block_empty_text_when_classified_kind_has_no_checklist_entries(
    monkeypatch,
) -> None:
    """Ported defensive branch: if a classified kind has no `_BASELINES`
    entry (unreachable via the current classifier's own kind set, but a real
    branch in the ported `_baseline_block`), the text is empty while `kinds`
    is still reported."""
    monkeypatch.setattr(baselines_mod, "_BASELINES", {})
    kinds, text = _baseline_block(_ev(), "auto")
    assert kinds == {"library"}
    assert text == ""


def test_baseline_block_checklist_items_are_verbatim() -> None:
    """Lock a couple of exact strings from each ported checklist so a future
    refactor can't silently reword or drop them."""
    assert _BASELINES["web-api"][0] == (
        "OWASP A01 Broken Access Control (IDOR, path traversal, forced "
        "browsing, privilege escalation)"
    )
    assert _BASELINES["native"][0] == "CWE-119/787 Buffer overflow (stack/heap write OOB)"
    assert _BASELINES["mobile"][0] == (
        "OWASP M1 Improper Credential Usage (hardcoded keys, token leakage)"
    )
    assert _BASELINES["iac"][0] == (
        "Over-permissive IAM / RBAC (wildcard actions, cluster-admin bindings)"
    )
    assert _BASELINES["library"][-1] == "ReDoS / algorithmic-complexity DoS"

    _, text = _baseline_block(_ev(primary_language="c-cpp", languages=[("c-cpp", 1)]), "auto")
    assert "CWE-119/787 Buffer overflow (stack/heap write OOB)" in text
    assert "CWE-78 OS command injection via system()/exec()" in text


def test_baseline_block_wording_ranks_and_omits() -> None:
    """The injected instruction text itself (reused verbatim in the Recon
    prompt's wording)."""
    _, text = _baseline_block(_ev(api_artefacts=["openapi.yaml"]), "auto")
    assert "rank" in text
    assert "matching surface" in text
    assert "otherwise omit silently" in text


# ---- classify_and_baseline (evidence-gathering adapter, real filesystem) --

def test_classify_and_baseline_web_api_repo(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("Flask==2.0.1\n")
    (tmp_path / "app.py").write_text("from flask import Flask\n")

    kinds, text = classify_and_baseline(tmp_path)
    assert kinds == {"web-api"}
    assert "OWASP A03 Injection" in text
    assert "OWASP A10 Server-Side Request Forgery" in text


def test_classify_and_baseline_native_c_repo(tmp_path: Path) -> None:
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")
    (tmp_path / "Makefile").write_text("all:\n\tgcc -o app main.c\n")

    kinds, text = classify_and_baseline(tmp_path)
    assert kinds == {"native"}
    assert "CWE-119" in text
    assert "CWE-416 Use-after-free / double-free" in text


def test_classify_and_baseline_library_fallback(tmp_path: Path) -> None:
    (tmp_path / "utils.py").write_text("def helper():\n    pass\n")

    kinds, text = classify_and_baseline(tmp_path)
    assert kinds == {"library"}
    assert "ReDoS" in text


def test_classify_and_baseline_openapi_artefact_triggers_web_api(tmp_path: Path) -> None:
    (tmp_path / "openapi.yaml").write_text("openapi: 3.0.0\ninfo:\n  title: x\n")

    kinds, _text = classify_and_baseline(tmp_path)
    assert kinds == {"web-api"}


def test_classify_and_baseline_excludes_git_directory(tmp_path: Path) -> None:
    """A `.tf` file living under `.git/` must not flip the repo to `iac`."""
    (tmp_path / "utils.py").write_text("def helper():\n    pass\n")
    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    (git_dir / "sneaky.tf").write_text("resource {}\n")

    kinds, _text = classify_and_baseline(tmp_path)
    assert kinds == {"library"}


def test_classify_and_baseline_mode_none(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask\n")
    assert classify_and_baseline(tmp_path, mode="none") == (set(), "")


def test_classify_and_baseline_mode_owasp_overrides_repo_kind(tmp_path: Path) -> None:
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")
    kinds, text = classify_and_baseline(tmp_path, mode="owasp")
    assert kinds == {"web-api"}
    assert "OWASP A01" in text


def test_classify_and_baseline_missing_repo_path_degrades_gracefully() -> None:
    """Best-effort contract: a nonexistent path must not raise."""
    kinds, text = classify_and_baseline("/no/such/path/for/audit/tests")
    assert kinds == {"library"}
    assert "ReDoS" in text
