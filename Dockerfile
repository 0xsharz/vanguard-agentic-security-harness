# VASH execution sandbox — runs the scan inside a container so PoC execution is
# isolated from the host. Inside a container `/.dockerenv` exists, so
# `vash.sandbox.is_sandboxed()` returns True and the runner grants Bash to Hunt
# (executed-PoC confirmation). On a bare host VASH auto-degrades to static.
#
# Build:  docker build -t vash:latest .
# Run:    docker run --rm -it \
#           -e CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN" \
#           -v /abs/path/to/target:/target:ro \
#           -v "$PWD/results":/app/results \
#           vash:latest run --repo /target --run-id my-run --max-cost-usd 20
FROM python:3.11-slim

# git: recon read-only history mining. build-essential + curl: graphify / native wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first (cache layer), then the package.
COPY pyproject.toml README.md ./
COPY vash ./vash
COPY prompts ./prompts
COPY schemas ./schemas
COPY config ./config
COPY bench ./bench
COPY licenses ./licenses
COPY NOTICE LICENSE ./
RUN pip install --no-cache-dir -e .

# Belt-and-suspenders: mark the sandbox explicitly (in addition to /.dockerenv).
ENV VASH_SANDBOX=1
# The scan target is mounted read-only at /target; results persist via a mount at /app/results.
ENTRYPOINT ["vash"]
CMD ["--help"]
