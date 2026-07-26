# vulnerable-demo — a deliberately insecure target

> ⚠️ **This code is intentionally vulnerable. Do not deploy it, copy it into a
> real project, or run it on a network you care about.** It exists so VASH has
> something honest to be demonstrated against.

38 lines, two real bugs, and a couple more the code has by accident:

| | |
|---|---|
| `notes.py::export_note` | builds a shell command by string concatenation → **command injection** |
| `notes.py::read_note` | joins user input onto a base path → **path traversal** |
| `server.py` | no authentication, single-threaded, no timeouts |

## Reproduce the run in the README

```bash
# 1. build the target's environment, then layer VASH on top of it
vash provision --repo ./examples/vulnerable-demo --scan-image

# 2. scan it, with exploits actually executing inside that environment
docker run --rm -e CLAUDE_CODE_OAUTH_TOKEN \
  -v "$PWD/examples/vulnerable-demo":/target:ro \
  vash-scan-vulnerable-demo:latest \
  run --repo /target --run-id demo --dynamic-validation

# 3. turn the confirmed findings into patches + security tests
vash remediate --run-id demo --repo ./examples/vulnerable-demo
```

The output of exactly this run is committed as
[`docs/example-report.md`](../../docs/example-report.md) and
[`docs/example-remediation.md`](../../docs/example-remediation.md).

Results vary between runs — the hunt is stochastic, and a scan costs real money
(this one was ~$10 and 22 minutes). Both planted bugs were found and rated
critical, along with five the target genuinely has.
