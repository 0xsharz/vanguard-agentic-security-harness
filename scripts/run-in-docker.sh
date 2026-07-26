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
# sqlite lives on the host so `vash status` / `vash report --run-id` work after
# the container exits (and so a --resume can pick the run back up).
touch "$ROOT/state.db"

# Prefer the target's SCAN image when one exists: it is the provisioned target
# environment with VASH layered on, so a PoC has the target's own toolchain and
# dependencies. The generic vash:latest has neither — no javac/java/mvn/go/
# dotnet, and none of the target's libraries — so PoCs there can only ever
# prove Python-shaped findings. Tag must match provision.scan_image.
TARGET_NAME="$(basename "$TARGET_ABS" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9_.-]\{1,\}/-/g' -e 's/^[-.]*//' -e 's/[-.]*$//')"
SCAN_IMAGE="vash-scan-${TARGET_NAME:-target}:latest"

if docker image inspect "$SCAN_IMAGE" >/dev/null 2>&1; then
  IMAGE="$SCAN_IMAGE"
  echo "[run-in-docker] using the target's scan image: $SCAN_IMAGE"
  echo "[run-in-docker]   PoCs run with the target's own toolchain + dependencies."
else
  IMAGE="vash:latest"
  echo "[run-in-docker] NOTE: no scan image found for this target ($SCAN_IMAGE)."
  echo "[run-in-docker]   Falling back to the generic sandbox. PoCs will NOT have the"
  echo "[run-in-docker]   target's toolchain or dependencies, so executed-PoC"
  echo "[run-in-docker]   confirmation will be weak or impossible for non-Python targets."
  echo "[run-in-docker]   Build one first with:"
  echo "[run-in-docker]       vash provision --repo \"$TARGET_ABS\" --scan-image"
  echo "[run-in-docker] building vash:latest ..."
  docker build -t vash:latest "$ROOT"
fi

echo "[run-in-docker] scanning $TARGET_ABS  (run-id=$RUN_ID)  in the sandbox ..."
docker run --rm -it \
  -e CLAUDE_CODE_OAUTH_TOKEN="${CLAUDE_CODE_OAUTH_TOKEN:-}" \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
  -e ANTHROPIC_AUTH_TOKEN="${ANTHROPIC_AUTH_TOKEN:-}" \
  -v "$TARGET_ABS":/target:ro \
  -v "$ROOT/results":/app/results \
  -v "$ROOT/state.db":/app/state.db \
  "$IMAGE" run --repo /target --run-id "$RUN_ID" --dynamic-validation "$@"

echo "[run-in-docker] done — report at results/$RUN_ID/report.json"
