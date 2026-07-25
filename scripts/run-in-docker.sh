#!/usr/bin/env bash
# Run a VASH scan inside the execution sandbox (container), opted into executed-PoC
# validation. Execution requires BOTH: --dynamic-validation (passed below) AND an
# active sandbox — /.dockerenv inside this container makes vash.sandbox.is_sandboxed()
# True, satisfying the second precondition. Together they let Hunt execute
# per-candidate PoCs for zero-false-positive confirmation — safely isolated from your
# host. (Default `vash run`, without --dynamic-validation, is static-only even here.)
#
# Auth: your host may log in via the macOS Keychain, which CANNOT cross into a
# Linux container. Provide a container-passable credential first:
#     claude setup-token            # prints a CLAUDE_CODE_OAUTH_TOKEN
#     export CLAUDE_CODE_OAUTH_TOKEN=...   # (or export ANTHROPIC_API_KEY=...)
#
# Usage:
#     ./scripts/run-in-docker.sh <target-dir> [run-id] [extra vash run args...]
# Example (the benchmark, cost-bounded):
#     ./scripts/run-in-docker.sh .bench-targets/dmcg-src dmcg-exec \
#         --max-cost-usd 20 --max-concurrency 4
set -euo pipefail

TARGET="${1:?usage: run-in-docker.sh <target-dir> [run-id] [vash run args...]}"
RUN_ID="${2:-docker-run}"
if [ "$#" -ge 2 ]; then shift 2; else shift "$#"; fi

if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -z "${ANTHROPIC_API_KEY:-}" ] && [ -z "${ANTHROPIC_AUTH_TOKEN:-}" ]; then
  echo "ERROR: no credential in env. Run 'claude setup-token' and export CLAUDE_CODE_OAUTH_TOKEN," >&2
  echo "       or export ANTHROPIC_API_KEY. The Keychain login does not cross into the container." >&2
  exit 2
fi

TARGET_ABS="$(cd "$TARGET" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/results"

echo "[run-in-docker] building vash:latest ..."
docker build -t vash:latest "$ROOT"

echo "[run-in-docker] scanning $TARGET_ABS  (run-id=$RUN_ID)  in the sandbox ..."
docker run --rm -it \
  -e CLAUDE_CODE_OAUTH_TOKEN="${CLAUDE_CODE_OAUTH_TOKEN:-}" \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
  -e ANTHROPIC_AUTH_TOKEN="${ANTHROPIC_AUTH_TOKEN:-}" \
  -v "$TARGET_ABS":/target:ro \
  -v "$ROOT/results":/app/results \
  vash:latest run --repo /target --run-id "$RUN_ID" --dynamic-validation "$@"

echo "[run-in-docker] done — report at results/$RUN_ID/report.json"
