"""Deterministic Dockerfile repair ladder (Phase 2). Pure text surgery —
no Docker, no subprocess, no network."""
from vash.provision.repair import (
    DEFAULT_BASE_BY_IMAGE,
    REPAIR_RULES,
    repair_dockerfile,
)

NODE_DF = (
    "FROM node:99\n"
    "WORKDIR /target\n"
    "COPY . /target\n"
    "RUN npm ci\n"
)

PY_DF = (
    "FROM python:3.11-slim\n"
    "WORKDIR /target\n"
    "COPY . /target\n"
    "RUN pip install -r requirements.txt\n"
)


def test_bad_base_tag_falls_back_to_known_good_default():
    log = "ERROR: failed to solve: node:99: manifest for node:99 not found"
    r = repair_dockerfile(NODE_DF, log)
    assert r is not None
    assert r.rule == "base_image_unavailable"
    assert "FROM node:20" in r.dockerfile
    assert "node:99" not in r.dockerfile
    # the rest of the file is untouched
    assert "RUN npm ci" in r.dockerfile


def test_default_base_map_is_built_from_the_phase1_templates():
    assert DEFAULT_BASE_BY_IMAGE["node"] == "node:20"
    assert DEFAULT_BASE_BY_IMAGE["python"] == "python:3.11-slim"
    assert DEFAULT_BASE_BY_IMAGE["golang"] == "golang:1.22"


def test_base_already_default_is_not_repaired_by_that_rule():
    df = NODE_DF.replace("node:99", "node:20")
    r = repair_dockerfile(df, "manifest for node:20 not found")
    # falls through to the catch-all rather than a no-op retag
    assert r is not None and r.rule == "soften_install_step"


def test_missing_c_toolchain_inserts_build_essential_before_install():
    log = "  gcc: command not found\n  error: command 'gcc' failed"
    r = repair_dockerfile(PY_DF, log)
    assert r is not None and r.rule == "missing_c_toolchain"
    lines = r.dockerfile.splitlines()
    apt = next(i for i, ln in enumerate(lines) if "apt-get install" in ln)
    pip = next(i for i, ln in enumerate(lines) if "pip install" in ln)
    assert apt < pip                                    # inserted BEFORE the install
    assert "build-essential" in lines[apt]
    assert "python3-dev" in lines[apt]                  # python base -> headers too


def test_missing_c_toolchain_uses_apk_on_alpine():
    df = PY_DF.replace("python:3.11-slim", "python:3.11-alpine")
    r = repair_dockerfile(df, "fatal error: Python.h: No such file or directory")
    assert r is not None and r.rule == "missing_c_toolchain"
    assert "apk add --no-cache" in r.dockerfile
    assert "apt-get" not in r.dockerfile


def test_missing_git_adds_git():
    r = repair_dockerfile(PY_DF, "error: git: not found while cloning dependency")
    assert r is not None and r.rule == "missing_git"
    assert "git" in r.dockerfile


def test_npm_ci_without_lockfile_becomes_npm_install():
    log = "npm ERR! code EUSAGE\nnpm ci` can only install with an existing package-lock.json"
    r = repair_dockerfile(NODE_DF, log)
    assert r is not None and r.rule == "npm_ci_requires_lockfile"
    assert "npm install" in r.dockerfile
    assert "npm ci" not in r.dockerfile


def test_missing_copy_path_is_dropped_but_context_copy_is_kept():
    df = (
        "FROM python:3.11-slim\n"
        "WORKDIR /target\n"
        "COPY . /target\n"
        "COPY extras/config.yaml /etc/config.yaml\n"
        "RUN pip install -e .\n"
    )
    log = 'failed to compute cache key: "/extras/config.yaml": not found'
    r = repair_dockerfile(df, log)
    assert r is not None and r.rule == "missing_copy_path"
    assert "extras/config.yaml" not in r.dockerfile
    assert "COPY . /target" in r.dockerfile             # the context COPY survives


def test_unrecognised_failure_falls_through_to_the_catch_all():
    r = repair_dockerfile(PY_DF, "some entirely unrecognised build explosion")
    assert r is not None and r.rule == "soften_install_step"
    assert "|| true" in r.dockerfile
    assert "INCOMPLETE" in r.note                       # degradation is never silent


def test_already_applied_rules_do_not_fire_twice():
    log = "gcc: command not found"
    first = repair_dockerfile(PY_DF, log)
    assert first is not None and first.rule == "missing_c_toolchain"
    second = repair_dockerfile(first.dockerfile, log,
                               already_applied=frozenset({"missing_c_toolchain"}))
    assert second is not None and second.rule != "missing_c_toolchain"


def test_ladder_exhausts_and_returns_none():
    applied = frozenset(name for name, _, _ in REPAIR_RULES)
    assert repair_dockerfile(PY_DF, "anything", already_applied=applied) is None


def test_repair_never_mutates_the_input_dockerfile():
    before = PY_DF
    repair_dockerfile(PY_DF, "gcc: command not found")
    assert PY_DF == before
