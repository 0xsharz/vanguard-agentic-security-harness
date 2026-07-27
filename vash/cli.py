"""Click-based CLI: auth-check, run, status, report."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.table import Table

from vash.auth import AuthError, configure_auth


def _allow_api_key_from_env_or_flag(flag: bool) -> bool:
    """A user may opt into api_key mode via --allow-api-key OR via
    AUDIT_ALLOW_API_KEY=1 in the env. Either is sufficient."""
    if flag:
        return True
    return os.environ.get("AUDIT_ALLOW_API_KEY", "").strip() not in ("", "0", "false", "False")
from vash.config import load_config
from vash.orchestrator import CostExceeded, run_pipeline
from vash.redact import redact_json
from vash.sandbox import SandboxError
from vash.stages._common import StageContext
from vash.stages.remediate import run_remediate
from vash.stages.revalidate import DEFAULT_MIN_CONFIDENCE, run_revalidate
from vash.state import StateDB

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = REPO_ROOT / "state.db"
RESULTS_ROOT = REPO_ROOT / "results"
DEFAULT_POLICY_PATH = REPO_ROOT / "config" / "remediation_policy.yaml"

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True,
                              show_path=False, markup=False)],
    )


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="DEBUG logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """VASH — Vanguard Agentic Security Harness: static-first vulnerability discovery agent."""
    ctx.ensure_object(dict)
    _setup_logging(verbose)


@main.command("auth-check")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "(also via AUDIT_ALLOW_API_KEY=1).")
def auth_check(allow_api_key: bool) -> None:
    """Verify Claude Code auth is configured correctly."""
    allow = _allow_api_key_from_env_or_flag(allow_api_key)
    try:
        status = configure_auth(allow_api_key=allow)
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        sys.exit(2)
    if status.auth_mode == "oauth_token":
        console.print("[green]OK[/green] using CLAUDE_CODE_OAUTH_TOKEN")
    elif status.auth_mode == "api_key":
        console.print(
            "[green]OK[/green] using ANTHROPIC_API_KEY (metered Anthropic API billing)"
        )
    elif status.auth_mode == "keychain_login":
        console.print(
            f"[green]OK[/green] using stored login from {status.credentials_file}"
        )
    elif status.auth_mode == "macos_keychain_login":
        console.print(
            "[green]OK[/green] using macOS Keychain-backed Claude Code login"
        )
    elif status.auth_mode == "gateway":
        console.print(
            f"[green]OK[/green] using LLM gateway at {status.gateway_base_url} "
            "(ANTHROPIC_AUTH_TOKEN)"
        )
        if status.gateway_model:
            console.print(f"          ANTHROPIC_MODEL={status.gateway_model}")
    if status.api_key_scrubbed:
        console.print("[yellow]scrubbed[/yellow] ANTHROPIC_API_KEY removed from env "
                      "(it would have outranked the active auth mode)")
    if status.auth_token_scrubbed:
        console.print("[yellow]scrubbed[/yellow] ANTHROPIC_AUTH_TOKEN removed from env "
                      "(no gateway base URL set — leaving it would outrank subscription)")
    console.print(f"claude CLI: {status.claude_cli_path} ({status.claude_cli_version})")


@main.command("run")
@click.option("--repo", "repo", required=True, type=click.Path(exists=True, file_okay=False),
              help="Path to the target source-code repo.")
@click.option("--run-id", default=None, help="Run identifier (default: random).")
@click.option("--resume", is_flag=True, help="Resume an existing run-id.")
@click.option("--max-cost-usd", default=None, type=float,
              help="Abort if cumulative cost crosses this threshold.")
@click.option("--max-concurrency", default=None, type=int,
              help="Cap every stage's concurrency to this (cost containment).")
@click.option("--max-recon-tasks", default=None, type=int,
              help="Cap the number of initial Hunt tasks Recon may emit.")
@click.option("--target-url", default=None,
              help="Optional: URL of a live deployment the agents can hit "
                   "to confirm findings (e.g. http://server.local:8888).")
@click.option("--target-creds", "target_creds", multiple=True,
              metavar="KEY=VALUE",
              help="Credentials for the live target. Repeat the flag for "
                   "each KEY=VALUE pair (e.g. --target-creds email=admin@x "
                   "--target-creds password=...).")
@click.option("--scope-notes", "scope_notes_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Optional: path to a text file with target-specific scope "
                   "rules / exclusions; passed verbatim to every stage.")
@click.option("--dynamic-validation", is_flag=True, default=False,
              help="Enable the executed-PoC (sandboxed) validation stage. Default: "
                   "static-only. Requires a sandbox (Docker/VASH_SANDBOX=1) or "
                   "--dangerously-no-sandbox.")
@click.option("--dangerously-no-sandbox", "no_sandbox", is_flag=True, default=False,
              help="DEV ONLY: allow --dynamic-validation to run PoCs without an active "
                   "sandbox, with a loud warning. Unsafe on untrusted targets.")
@click.option("--provision", is_flag=True, default=False,
              help="Build the target's environment image (docker build + verify "
                   "+ deterministic repair) before the scan. Requires Docker. "
                   "Runs the TARGET's own build instructions — inside a "
                   "container, never on the host. Without this flag the "
                   "pipeline still fingerprints the repo and renders a "
                   "Dockerfile, but builds nothing.")
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Override config/stages.yaml.")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "(also via AUDIT_ALLOW_API_KEY=1).")
def run(repo: str, run_id: str | None, resume: bool, max_cost_usd: float | None,
        max_concurrency: int | None, max_recon_tasks: int | None,
        target_url: str | None, target_creds: tuple[str, ...],
        scope_notes_path: str | None,
        dynamic_validation: bool, no_sandbox: bool, provision: bool,
        config_path: str | None,
        allow_api_key: bool) -> None:
    """Run the full 9-stage pipeline against a target repo.

    Stages: recon → hunt → validate → gapfill → dedupe → trace → feedback →
    chain → report, preceded by a deterministic provisioning step that
    fingerprints the repo (and, with --provision, builds its environment).
    """
    allow = _allow_api_key_from_env_or_flag(allow_api_key)
    try:
        configure_auth(allow_api_key=allow)
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        sys.exit(2)

    config = load_config(Path(config_path)) if config_path else load_config()
    if max_concurrency is not None:
        config.cap_concurrency(max_concurrency)
        console.print(f"[cyan]capped concurrency to {max_concurrency} across all stages[/cyan]")

    if provision:
        console.print("[cyan]provisioning enabled:[/cyan] the target's own build "
                      "instructions will run inside a container (never on this host)")

    # Live-target plumbing — agents will receive {"url": ..., "credentials": {...}}
    # in their user_input when set.
    live_target: dict | None = None
    if target_url:
        creds: dict[str, str] = {}
        for kv in target_creds:
            if "=" not in kv:
                console.print(f"[red]invalid --target-creds {kv!r} — expected KEY=VALUE[/red]")
                sys.exit(2)
            k, _, v = kv.partition("=")
            creds[k.strip()] = v.strip()
        live_target = {"url": target_url, "credentials": creds}
        console.print(f"[cyan]live target:[/cyan] {target_url} (creds: {sorted(creds)})")
    elif target_creds:
        console.print("[yellow]--target-creds without --target-url is ignored[/yellow]")

    scope_notes: str | None = None
    if scope_notes_path:
        scope_notes = Path(scope_notes_path).read_text()
        console.print(f"[cyan]scope notes loaded:[/cyan] {scope_notes_path} ({len(scope_notes)} chars)")

    run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"
    repo_path = Path(repo).resolve()

    db = StateDB(DB_PATH)
    try:
        report = asyncio.run(run_pipeline(
            repo_path=repo_path,
            run_id=run_id,
            db=db,
            config=config,
            max_cost_usd=max_cost_usd,
            resume=resume,
            max_recon_tasks=max_recon_tasks,
            live_target=live_target,
            scope_notes=scope_notes,
            dynamic_validation=dynamic_validation,
            allow_no_sandbox=no_sandbox,
            provision=provision,
        ))
        console.print(f"[green]done[/green] run_id={run_id} report={report}")
        # Note: the per-stage run summary is already printed by
        # ctx.reporter.run_summary(db, run_id) inside run_pipeline (F2/Task 2's
        # RunReporter) — no separate summary render needed here (previously
        # _print_run_summary duplicated it; removed, see review Fix 4).
    except CostExceeded as e:
        console.print(f"[yellow]aborted[/yellow] {e}")
        sys.exit(3)
    except SandboxError as e:
        console.print(f"[red]dynamic validation refused:[/red] {e}")
        sys.exit(2)
    except Exception as e:
        console.print(f"[red]failed[/red] {type(e).__name__}: {e}")
        raise
    finally:
        db.close()


@main.command("provision")
@click.option("--repo", "repo", required=True,
              type=click.Path(exists=True, file_okay=False),
              help="Path to the target source-code repo.")
@click.option("--build", is_flag=True, default=False,
              help="Actually run `docker build` (plus verify + deterministic "
                   "repair retries). Without it this only fingerprints the "
                   "repo and prints the Dockerfile it WOULD build.")
@click.option("--tag", default=None,
              help="Image tag to build (default: vash-env-<repo-name>:latest).")
@click.option("--max-attempts", default=3, type=int,
              help="Build attempts, including repair retries (default: 3).")
@click.option("--no-verify", is_flag=True, default=False,
              help="Skip running the ecosystem's build/test command inside the "
                   "built image.")
@click.option("--verify-network", default="none",
              type=click.Choice(["none", "bridge"]),
              help="Container network for the verify step (default: none — "
                   "verification runs offline).")
@click.option("--scan-image", is_flag=True, default=False,
              help="Also build the SCAN image (vash-scan-<repo>): VASH layered "
                   "on top of the target's provisioned image, so PoCs run with "
                   "the target's own toolchain and dependencies. Without it the "
                   "scan runs in the generic sandbox, where a Java/Go PoC has "
                   "no compiler and a Python PoC cannot import the target. "
                   "Implies --build.")
@click.option("--out", "out_path", default=None, type=click.Path(),
              help="Write the full provisioning record as JSON here.")
def provision_cmd(repo: str, build: bool, tag: str | None, max_attempts: int,
                  no_verify: bool, verify_network: str, scan_image: bool,
                  out_path: str | None) -> None:
    """Fingerprint a repo and render (optionally build) its environment image.

    Decoupled + offline by default — no LLM, no cost, no network: it reads the
    repo's manifests and prints the Dockerfile VASH would build. With --build it
    runs `docker build`, retries with a deterministic repair ladder when the
    build fails, then verifies the image by running the ecosystem's build/test
    command inside it.

    Safety: --build executes the TARGET's own build instructions (npm postinstall
    scripts, maven plugins, ...). Those always run inside a container — never on
    this host — and the verify step additionally runs with no network and
    dropped privileges.
    """
    from vash.provision import provision_environment
    from vash.provision.scan_image import build_scan_image

    repo_path = Path(repo).resolve()
    # --scan-image is only meaningful once the target image exists.
    build = build or scan_image
    result = provision_environment(
        repo_path, build=build, tag=tag, max_attempts=max_attempts,
        verify=not no_verify, verify_network=verify_network,
    )

    fp = result.fingerprint
    console.print(f"[bold]repo:[/bold] {repo_path}")
    console.print(f"[bold]languages:[/bold] {', '.join(fp.get('languages') or []) or '-'} "
                  f"(primary: {fp.get('primary_language') or '-'})")
    console.print(f"[bold]build systems:[/bold] "
                  f"{', '.join(fp.get('build_systems') or []) or '-'}")
    if fp.get("version_pins"):
        console.print(f"[bold]version pins:[/bold] {fp['version_pins']}")
    console.print(f"[bold]recipe source:[/bold] {result.source}")

    if result.dockerfile:
        console.print("\n[dim]--- Dockerfile ---[/dim]")
        # markup=False: a Dockerfile (and a repair note) may contain
        # [brackets], which Rich would otherwise swallow as markup tags.
        console.print(result.dockerfile.rstrip(), markup=False, highlight=False)
        console.print("[dim]------------------[/dim]\n")

    for a in result.attempts:
        state = "[green]ok[/green]" if a.ok else f"[red]exit {a.exit_code}[/red]"
        via = f" (after repair: {a.repair_rule})" if a.repair_rule else ""
        console.print(f"build attempt {a.attempt}: {state}{via}")
    for note in result.notes:
        console.print("[yellow]note:[/yellow] " + escape(note))

    v = result.verify
    if v and v.ran:
        if v.deps_ok is not None:
            console.print(f"verify deps:  {'[green]ok[/green]' if v.deps_ok else '[red]MISSING[/red]'}")
        if v.build_ok is not None:
            console.print(f"verify build: {'[green]ok[/green]' if v.build_ok else '[red]FAILED[/red]'}")
        if v.test_ok is not None:
            console.print(f"verify test:  {'[green]ok[/green]' if v.test_ok else '[yellow]failed[/yellow]'}")

    color = {"built": "green", "planned": "cyan",
             "failed": "red", "skipped": "yellow"}.get(result.status, "white")
    console.print(f"\n[{color}]status: {result.status}[/{color}]"
                  + (f" — image {result.image_tag}" if result.status == "built" else ""))

    scan = None
    if scan_image:
        if result.status != "built":
            console.print("[yellow]--scan-image skipped:[/yellow] the target "
                          "image was not built, so there is nothing to layer on")
        else:
            console.print("\nbuilding scan image (VASH + the target's environment)...")
            scan = build_scan_image(repo_path, base_image=result.image_tag)
            for note in scan.notes:
                console.print("[yellow]note:[/yellow] " + escape(note))
            if scan.status == "built":
                console.print(f"[green]scan image: {scan.tag}[/green]")
                console.print("run the scan with it: "
                              f"docker run --rm -e CLAUDE_CODE_OAUTH_TOKEN "
                              f"-v <target>:/target:ro {scan.tag} "
                              "run --repo /target --dynamic-validation")
            else:
                console.print(f"[red]scan image {scan.status}[/red]")
                # Without the log the operator cannot act on the failure — the
                # notes only say what was lost, not why.
                if scan.log_tail:
                    console.print("[dim]--- last lines of the build log ---[/dim]")
                    console.print(escape(scan.log_tail[-1200:]),
                                  markup=False, highlight=False)

    if out_path:
        payload = result.to_dict()
        if scan is not None:
            payload["scan_image"] = scan.to_dict()
        Path(out_path).write_text(json.dumps(payload, indent=2))
        console.print(f"record: {out_path}")

    if result.status == "failed" or (scan is not None and scan.status == "failed"):
        sys.exit(1)


@main.command("status")
@click.option("--run-id", default=None)
def status(run_id: str | None) -> None:
    """Show pipeline status: tasks, findings, traces, cost."""
    db = StateDB(DB_PATH)
    try:
        if run_id is None:
            _show_runs_table(db)
            return
        run = db.get_run(run_id)
        if run is None:
            console.print(f"[red]unknown run_id {run_id!r}[/red]")
            sys.exit(1)
        _show_run_detail(db, run_id)
    finally:
        db.close()


@main.command("report")
@click.option("--run-id", required=True)
@click.option("--format", "fmt", type=click.Choice(["json", "md"]), default="json")
def report(run_id: str, fmt: str) -> None:
    """Print (or generate) the final report."""
    db = StateDB(DB_PATH)
    try:
        report_path = RESULTS_ROOT / run_id / "report" / "report.json"
        if not report_path.exists():
            console.print(f"[red]no report at {report_path}[/red]")
            sys.exit(1)
        # Belt-and-suspenders: audit/stages/report.py already redacts before
        # writing report.json, but this CLI is itself an egress point (it
        # prints findings/evidence to stdout for a human/CI to read), so
        # redact again here too. redact_json is idempotent, so re-redacting
        # an already-redacted report is a no-op.
        payload = redact_json(json.loads(report_path.read_text()))
        if fmt == "json":
            click.echo(json.dumps(payload, indent=2))
        else:
            # Task 4: the VVAH/GHSA-style renderer. report.json (the json
            # path above) stays the authoritative raw artifact — this is a
            # human-facing presentation over the same enriched payload.
            from vash.reporting.markdown import render_report
            click.echo(render_report(payload, db, run_id))
    finally:
        db.close()


@main.command("remediate")
@click.option("--run-id", required=True, help="Remediate a prior run's confirmed findings.")
@click.option("--repo", "repo", default=None,
              type=click.Path(exists=True, file_okay=False),
              help="Target repo (default: the path recorded for the run).")
@click.option("--policy", "policy_path", default=None, type=click.Path(),
              help="Remediation policy YAML (default: config/remediation_policy.yaml).")
@click.option("--out", "out_dir", default=None, type=click.Path(),
              help="Output dir (default: results/<run-id>/remediation).")
@click.option("--verify", is_flag=True, default=False,
              help="NOT YET IMPLEMENTED — running the generated security tests "
                   "is still deferred, so this flag verifies NOTHING today and "
                   "patches stay needs_verification. All it exercises is the "
                   "execution-sandbox gate (requires VASH_SANDBOX=1, or "
                   "--dangerously-no-sandbox; a refusal is fail-soft).")
@click.option("--dangerously-no-sandbox", "no_sandbox", is_flag=True, default=False,
              help="DEV ONLY: bypass the --verify execution-sandbox gate "
                   "(vash.sandbox.require) with a loud warning instead of an "
                   "active sandbox. Unsafe against any target you don't "
                   "already trust — never use this in CI or against "
                   "untrusted source. No effect without --verify.")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "(also via AUDIT_ALLOW_API_KEY=1).")
def remediate(run_id: str, repo: str | None, policy_path: str | None,
              out_dir: str | None, verify: bool, no_sandbox: bool,
              allow_api_key: bool) -> None:
    """Generate static, policy-gated root-cause patches + security tests for a
    prior run's confirmed findings. Decoupled + opt-in — NOT part of `vash run`.

    Reads the existing run's DB, enforces the VVAH policy gate (fail-closed)
    BEFORE any patch agent, and writes diffs/tests/REMEDIATION.md (all redacted).
    The patch agent EDITS a disposable copy of the repo and `git diff` computes
    the diff, so patches are valid by construction; your working tree is never
    modified and nothing is executed. Patches are marked needs_verification:
    --verify does NOT yet run the generated tests (deferred), it only exercises
    the execution-sandbox gate (vash.sandbox.require).
    """
    allow = _allow_api_key_from_env_or_flag(allow_api_key)
    try:
        configure_auth(allow_api_key=allow)
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        sys.exit(2)

    db = StateDB(DB_PATH)
    try:
        run = db.get_run(run_id)
        if run is None:
            console.print(f"[red]unknown run_id {run_id!r}[/red]")
            sys.exit(1)
        repo_path = Path(repo).resolve() if repo else Path(run["repo_path"])
        policy = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
        out = Path(out_dir) if out_dir else (RESULTS_ROOT / run_id / "remediation")
        config = load_config()
        ctx = StageContext(run_id=run_id, repo_path=repo_path, config=config)

        if verify:
            if no_sandbox:
                console.print("[yellow]--dangerously-no-sandbox[/yellow] set: "
                              "--verify will bypass the execution sandbox gate "
                              "with a loud warning — DEV ONLY, unsafe against "
                              "untrusted source. Note that no test is run either "
                              "way: real test execution is still DEFERRED, so "
                              "nothing gets verified.")
            else:
                console.print("[yellow]--verify requested[/yellow] — gated by "
                              "the execution sandbox: requires VASH_SANDBOX=1 "
                              "(or --dangerously-no-sandbox) or it's refused "
                              "fail-soft. Real test execution itself remains "
                              "DEFERRED either way.")

        summary = asyncio.run(run_remediate(
            ctx, db, out_dir=out, policy_path=policy, verify=verify,
            no_sandbox=no_sandbox,
        ))
        c = summary["counts"]
        if not summary["policy_valid"]:
            console.print("[yellow]policy invalid/missing — fail-closed: "
                          "all findings guidance-only[/yellow]")
        console.print(
            f"[green]remediation done[/green] run_id={run_id} — "
            f"patched={c['patched']} guidance_only={c['guidance_only']} "
            f"cannot_fix={c['cannot_fix']} (of {summary['total']})"
        )
        console.print(f"artifacts: {summary['out_dir']}")
    except Exception as e:
        console.print(f"[red]failed[/red] {type(e).__name__}: {e}")
        raise
    finally:
        db.close()


@main.command("validate")
@click.option("--run-id", required=True,
              help="Independently re-verify a prior run's confirmed findings.")
@click.option("--repo", "repo", default=None,
              type=click.Path(exists=True, file_okay=False),
              help="Target repo (default: the path recorded for the run).")
@click.option("--model", default=None,
              help="Override the model used for the second opinion (default: "
                   "config/stages.yaml's revalidate stage model — deliberately "
                   "a different tier than the scan's own Validate stage).")
@click.option("--min-confidence", "min_confidence", default=DEFAULT_MIN_CONFIDENCE,
              type=int,
              help="Confidence gate (0-10): a 'validated' verdict below this "
                   f"is downgraded to needs_review (default: {DEFAULT_MIN_CONFIDENCE}).")
@click.option("--out", "out_dir", default=None, type=click.Path(),
              help="Output dir (default: results/<run-id>/revalidation).")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "(also via AUDIT_ALLOW_API_KEY=1).")
def validate(run_id: str, repo: str | None, model: str | None,
            min_confidence: int, out_dir: str | None, allow_api_key: bool) -> None:
    """Independently re-verify a prior run's confirmed findings — a fresh,
    read-only second opinion (VVAH s6 stance) that actively tries to reach
    the OPPOSITE verdict before agreeing with the scan. Decoupled + opt-in —
    NOT part of `vash run`.

    Reads the existing run's DB, NEVER mutates it, and writes
    revalidation.json / REVALIDATION.md (redacted) with a per-finding verdict
    and any DISAGREEMENTS with the scan — the overturned false positives the
    second opinion caught.
    """
    allow = _allow_api_key_from_env_or_flag(allow_api_key)
    try:
        configure_auth(allow_api_key=allow)
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        sys.exit(2)

    db = StateDB(DB_PATH)
    try:
        run = db.get_run(run_id)
        if run is None:
            console.print(f"[red]unknown run_id {run_id!r}[/red]")
            sys.exit(1)
        repo_path = Path(repo).resolve() if repo else Path(run["repo_path"])
        out = Path(out_dir) if out_dir else (RESULTS_ROOT / run_id / "revalidation")
        config = load_config()
        ctx = StageContext(run_id=run_id, repo_path=repo_path, config=config)

        summary = asyncio.run(run_revalidate(
            ctx, db, out_dir=out, model=model, min_confidence=min_confidence,
        ))
        c = summary["counts"]
        console.print(
            f"[green]revalidation done[/green] run_id={run_id} — "
            f"validated={c['validated']} failed(OVERTURNED)={c['failed']} "
            f"needs_review={c['needs_review']} (of {summary['total']})"
        )
        if summary["overturned_finding_ids"]:
            console.print(
                "[yellow]OVERTURNED[/yellow] (false positives caught): "
                + ", ".join(summary["overturned_finding_ids"])
            )
        console.print(f"artifacts: {summary['out_dir']}")
    except Exception as e:
        console.print(f"[red]failed[/red] {type(e).__name__}: {e}")
        raise
    finally:
        db.close()


def _show_runs_table(db: StateDB) -> None:
    runs = db.list_runs()
    t = Table(title="runs", show_lines=False)
    t.add_column("run_id")
    t.add_column("repo")
    t.add_column("status")
    t.add_column("cost ($)")
    for r in runs:
        t.add_row(r["run_id"], r["repo_path"], r["status"],
                  f"{db.total_cost(r['run_id']):.4f}")
    console.print(t)


def _show_run_detail(db: StateDB, run_id: str) -> None:
    tasks = db.get_all_tasks(run_id)
    findings = db.get_findings(run_id)
    confirmed = [f for f in findings if f.validation_status == "confirmed"]
    canonical = [f for f in confirmed if f.is_canonical]
    reachable = db.get_reachable_canonical_findings(run_id)

    t = Table(title=f"run {run_id}", show_lines=False)
    t.add_column("metric"); t.add_column("count")
    t.add_row("tasks (total)", str(len(tasks)))
    t.add_row("tasks (pending)", str(sum(1 for x in tasks if x.status == "pending")))
    t.add_row("tasks (done)", str(sum(1 for x in tasks if x.status == "done")))
    t.add_row("tasks (failed)", str(sum(1 for x in tasks if x.status == "failed")))
    t.add_row("findings (raw)", str(len(findings)))
    t.add_row("findings (confirmed)", str(len(confirmed)))
    t.add_row("findings (canonical)", str(len(canonical)))
    t.add_row("findings (reachable)", str(len(reachable)))
    t.add_row("total cost ($)", f"{db.total_cost(run_id):.4f}")
    console.print(t)


if __name__ == "__main__":
    main()
