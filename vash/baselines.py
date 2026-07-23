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
Repo-kind classifier -> minimum-baseline OWASP/CWE checklist.

Ported from VVAH's `vvaharness/pipeline/stages/s2_threatmodel.py` (the
threat-model stage's baseline machinery): `_BASELINES` (the checklist text,
kept verbatim), `_repo_kind` (classifier), `_baseline_block` (checklist
renderer), and the classifier regexes/sets `_WEB_FW_RX` / `_NATIVE_LANGS`.

VVAH's `_repo_kind`/`_baseline_block` read evidence out of an `ev` dict plus
a `ctx: ContextPackage` (VVAH's s1-mapped context object — file list, entry
points, primary language, etc., built by an earlier pipeline stage). audit
has neither `ctx` nor a pre-built `ev`, so `classify_and_baseline()` below is
a new adapter: it walks the on-disk repo directly and assembles the same
small `ev` dict shape those two functions read (folding `ctx.all_files` into
`ev["all_files"]`, since that was the only piece `_repo_kind` ever read off
`ctx`), then calls them. Everything else — the checklist text and the
classification logic/regexes — is unchanged from upstream.

Used by Recon: `baseline_text` is injected into the recon agent's
`user_input` as `"baseline"` so task coverage isn't limited to what
git-history mining surfaces (see prompts/01-recon.md).
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from vash.lang.hints import detect_languages


# ─────────────────────────────────────────────────────────────────────────────
# Repo-kind classifier -> minimum-baseline checklist
# (ported from VVAH s2_threatmodel.py; checklist text + regexes verbatim)
# ─────────────────────────────────────────────────────────────────────────────

_WEB_FW_RX = re.compile(
    r"\b(spring|express|fastify|koa|hapi|nest|next|nuxt|django|flask|fastapi|"
    r"tornado|rails|sinatra|laravel|symfony|gin-gonic|echo|fiber|actix|axum|"
    r"asp\.net|ktor|micronaut|quarkus|vertx|play-framework)\b", re.IGNORECASE)

_NATIVE_LANGS = {"c", "cpp", "c++", "c-cpp", "c/c++", "rust", "objective-c", "objc"}

_BASELINES: dict[str, tuple[str, ...]] = {
    "web-api": (
        "OWASP A01 Broken Access Control (IDOR, path traversal, forced browsing, privilege escalation)",
        "OWASP A02 Cryptographic Failures (weak/missing crypto, plaintext secrets/transport)",
        "OWASP A03 Injection (SQL/NoSQL/OS/LDAP/template/header)",
        "OWASP A04 Insecure Design (missing rate-limit, trust-boundary assumptions)",
        "OWASP A05 Security Misconfiguration (default creds, debug on, permissive CORS)",
        "OWASP A07 Identification & Authentication Failures (weak session, missing MFA, JWT flaws)",
        "OWASP A08 Software & Data Integrity Failures (unsafe deserialization, unsigned updates)",
        "OWASP A10 Server-Side Request Forgery",
        "XSS (reflected / stored / DOM)",
        "CSRF / state-changing GET",
    ),
    "mobile": (
        "OWASP M1 Improper Credential Usage (hardcoded keys, token leakage)",
        "OWASP M3 Insecure Authentication/Authorization",
        "OWASP M5 Insecure Communication (no cert pinning, cleartext traffic)",
        "OWASP M8 Security Misconfiguration (exported components, debuggable build)",
        "OWASP M9 Insecure Data Storage (world-readable prefs, unencrypted DB)",
    ),
    "native": (
        "CWE-119/787 Buffer overflow (stack/heap write OOB)",
        "CWE-416 Use-after-free / double-free",
        "CWE-190 Integer overflow leading to undersized allocation",
        "CWE-134 Format-string",
        "CWE-362 TOCTOU / race condition",
        "CWE-78 OS command injection via system()/exec()",
    ),
    "iac": (
        "Over-permissive IAM / RBAC (wildcard actions, cluster-admin bindings)",
        "Public network exposure (0.0.0.0/0 ingress, hostNetwork, public S3/bucket)",
        "Secrets committed in plaintext / env",
        "Privileged or root containers, missing securityContext",
        "Disabled TLS / unencrypted storage classes",
    ),
    "library": (
        "Injection via untrusted caller input (SQL/OS/path)",
        "Unsafe deserialization (pickle/yaml.load/XMLDecoder/ObjectInputStream)",
        "Path traversal in file-handling APIs",
        "ReDoS / algorithmic-complexity DoS",
    ),
}


def _repo_kind(ev: dict) -> set[str]:
    """Classify a repo into 0+ kinds from evidence gathered in `ev` (see
    `classify_and_baseline`). Adapted from VVAH's `_repo_kind(ev, ctx)`:
    `ctx.all_files` is now read as `ev["all_files"]`; all classification
    logic and regexes are unchanged."""
    kinds: set[str] = set()
    all_files = [f.lower() for f in ev.get("all_files", ())]
    manifest_text = "\n".join(body for _, body in ev["manifests"])

    if (any(k == "network" for k, *_ in ev["entry_points"])
            or ev["api_artefacts"]
            or _WEB_FW_RX.search(manifest_text)):
        kinds.add("web-api")

    if (any(f.endswith(("androidmanifest.xml", "info.plist", "podfile"))
            for f in all_files)
            or re.search(r"\bcom\.android\b", manifest_text)):
        kinds.add("mobile")

    if any(f.endswith((".tf", ".hcl", "chart.yaml", "values.yaml",
                       "kustomization.yaml", "kustomization.yml"))
           for f in all_files):
        kinds.add("iac")

    langs = {(ev["primary_language"] or "").lower(),
             *(l.lower() for l, _ in ev["languages"])}
    if langs & _NATIVE_LANGS:
        kinds.add("native")

    return kinds or {"library"}


def _baseline_block(ev: dict, mode: str) -> tuple[set[str], str]:
    """Render the checklist block for the classified repo kind(s). Adapted
    from VVAH's `_baseline_block(ev, ctx, mode)`: the `ctx` param is dropped
    (it only ever flowed through to `_repo_kind`); text and logic unchanged."""
    if mode == "none":
        return set(), ""
    kinds = {"web-api"} if mode == "owasp" else _repo_kind(ev)
    seen: set[str] = set()
    items: list[str] = []
    for k in sorted(kinds):
        for it in _BASELINES.get(k, ()):
            if it not in seen:
                seen.add(it)
                items.append(it)
    if not items:
        return kinds, ""
    body = "\n".join(f"  - {it}" for it in items)
    return kinds, (
        f"\nMINIMUM BASELINE for repo kind {{{', '.join(sorted(kinds))}}} — rank "
        f"each against THIS codebase; emit a threat ONLY if a matching surface "
        f"exists in the evidence above, otherwise omit silently:\n{body}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Evidence-gathering adapter (new — audit has no VVAH ctx/ev)
# ─────────────────────────────────────────────────────────────────────────────

_MANIFEST_CANDIDATES = (
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    "setup.py", "pyproject.toml", "requirements.txt",
    "go.mod", "Cargo.toml", "Gemfile", "composer.json",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
)

_API_SURFACE_GLOBS = (
    "*openapi*.y*ml", "*openapi*.json",
    "*.proto", "*.graphql", "*.graphqls",
)

_MANIFEST_CAP_CHARS = 4000


def _read_capped(p: Path, cap_chars: int = _MANIFEST_CAP_CHARS) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:cap_chars]
    except OSError:
        return ""


def classify_and_baseline(repo_path: str | Path, mode: str = "auto") -> tuple[set[str], str]:
    """Best-effort adapter: gather the minimal evidence `_repo_kind`/
    `_baseline_block` need straight off disk, then call them.

    Gathers: the repo's file list (`.git` excluded), languages (via
    `audit.lang.hints.detect_languages`, already ported for Hunt in V9),
    manifest text (a fixed set of common manifest filenames, read if
    present), API-contract artefacts (OpenAPI/proto/GraphQL globs), and a
    lightweight network-entry-point signal (Dockerfile `EXPOSE` / compose
    `ports:`, reused from the manifest text already read — no extra pass).

    Returns (kinds, baseline_text) — see `_baseline_block`. Never raises for
    a missing/unreadable `repo_path`: with no evidence gathered, `_repo_kind`
    still degrades to `{"library"}` (unless `mode == "none"`). The Recon
    wireup (`audit/stages/recon.py`) additionally guards this call with
    try/except per the "best-effort; empty string if it errors" contract.
    """
    root = Path(repo_path)

    all_files: list[str] = []
    if root.is_dir():
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(root)
            if ".git" in rel.parts:
                continue
            all_files.append(rel.as_posix())

    languages = detect_languages(all_files, repo_root=root)
    primary_language = languages[0] if languages else ""

    manifests: list[tuple[str, str]] = []
    for name in _MANIFEST_CANDIDATES:
        p = root / name
        if p.is_file():
            manifests.append((name, _read_capped(p)))
    manifest_text = "\n".join(body for _, body in manifests)

    # `_repo_kind` only checks for ANY entry point with kind == "network", so
    # one synthetic tuple is enough — no extra file-content pass needed.
    entry_points: list[tuple] = []
    if (re.search(r"^\s*EXPOSE\s+\d", manifest_text, re.MULTILINE)
            or "ports:" in manifest_text):
        entry_points.append(("network", None, "", ""))

    api_artefacts = [
        rel for rel in all_files
        if any(fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(rel.lower(), g)
               for g in _API_SURFACE_GLOBS)
    ]

    ev = {
        "all_files": all_files,
        "primary_language": primary_language,
        "languages": [(lang, 1) for lang in languages],
        "manifests": manifests,
        "entry_points": entry_points,
        "api_artefacts": api_artefacts,
    }

    return _baseline_block(ev, mode)
