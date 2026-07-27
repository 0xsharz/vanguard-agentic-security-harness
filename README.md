<div align="center">

# 🛡️ VASH — Vanguard Agentic Security Harness

**An agentic vulnerability scanner that doesn't just flag what _looks_ exploitable — it builds the target's environment, runs a real exploit inside it, and watches the vulnerability fire.**

[![License](https://img.shields.io/badge/license-MIT%20%2B%20Apache--2.0-blue)](#-license)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](#-install)
[![Tests](https://img.shields.io/badge/tests-825%20passing-brightgreen)](#-project-structure)
[![Powered by Claude](https://img.shields.io/badge/powered%20by-Claude%20Agent%20SDK-D97757)](https://www.anthropic.com)
[![Static-first](https://img.shields.io/badge/mode-static--first%20%2B%20executed--PoC-6E56CF)](#-static-vs-dynamic-validation)

</div>

---

Most scanners hand you a list of things that *look* wrong and leave the triage to you. VASH is built around a harder question: **can this actually be exploited?** Answering it takes four steps, and it does all four:

1. **Hunt broadly.** Many narrowly-scoped agents, each chasing one attack class in one place, over a real AST call-graph — not one prompt asked to "find bugs".
2. **Build somewhere to prove it.** A Java exploit needs a JDK and the target's classpath; a Python one needs its dependencies. VASH fingerprints the repo and **provisions the target's own environment**, then runs the scan inside it.
3. **Run the exploit.** Every candidate gets a real proof-of-concept, executed in an isolated container. Findings that don't reproduce are dropped.
4. **Watch it fire.** A script exiting `0` proves nothing. VASH instruments the runtime and records the dangerous operation as it happens — `subprocess.Popen`, `jdk.ProcessStart`, an `execve` — **attributed to the line of target code that caused it**.

The last two are the difference between *"an LLM thinks this is a bug"* and *"here is the command that ran, and here is the line that ran it."*

And when it can't answer, it says so: a missing compiler is reported as a missing compiler, not as "not vulnerable" — see [Honest by construction](#-honest-by-construction).

It runs on your **Claude Pro/Max subscription** through the official Claude Code Agent SDK — no API key required — and is safe by default: on a bare host it never executes anything belonging to the target.

```bash
vash run --repo ./my-project                       # static analysis (safe by default)
vash run --repo ./my-project --dynamic-validation  # + sandboxed executed-PoC confirmation
```

## 📖 Table of contents

- [Why VASH](#-why-vash) · [Highlights](#-highlights) · [How it works](#-how-it-works) · [Install](#-install) · [Quickstart](#-quickstart)
- [See it run](#-see-it-run) · [Commands](#-commands) · [The report](#-the-report) · [Static vs dynamic](#-static-vs-dynamic-validation) · [Proving it, per language](#-proving-it-per-language) · [Honest by construction](#-honest-by-construction) · [Project structure](#-project-structure)
- [Configuration & cost](#-configuration--cost) · [Results](#-results) · [License](#-license)

---

## 🎯 Why VASH

A single "find bugs in this code" prompt produces noise: plausible-sounding findings, with no way to tell which are real. VASH attacks that directly, on a pipeline modeled on Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) research:

| Principle | What VASH does |
|---|---|
| **Many narrow agents** | Each hunter chases *one* attack class in *one* scoped location — not one exhaustive agent. |
| **Deliberate disagreement** | A differently-modeled Validate agent adversarially tries to **disprove** every finding by re-reading the code. |
| **Reachability as the gate** | A Trace stage proves an attacker-controlled input can actually reach the sink — unreachable "bugs" are dropped. |
| **Feedback loops** | A confirmed pattern in one file automatically seeds hunts for the same pattern everywhere else. |
| **Executed-PoC confirmation** | *VASH's differentiator.* In dynamic mode it runs a real exploit per candidate in a sandbox and keeps only what fires — every delivered finding is exploit-verified, not statically guessed. |
| **A real environment to prove it in** | The scan runs *inside* the target's own provisioned image, so a PoC has the toolchain and dependencies it needs. Without this, a Java PoC dies at `command not found` and a Python one can't import the code it is attacking. |
| **Silence is never success** | An unexamined file, a failed hunt task, a missing observer and an incomplete environment are all reported as such. A gap that isn't disclosed reads as a clean bill of health. |

## ✨ Highlights

- 🧠 **9-stage agentic pipeline** — recon → hunt → validate → gapfill → dedupe → trace → feedback → chain → report, over a deterministic AST **call-graph spine**.
- 🎯 **Executed-PoC confirmation** — opt-in `--dynamic-validation` runs each PoC in an isolated sandbox; on a bare host VASH stays **100% static** and never executes untrusted code.
- 🔬 **Runtime observers** — a PoC that exits 0 proves nothing. VASH watches the process while the exploit runs and records the dangerous operation *as it fires*, attributed to the line that caused it: a PEP-578 audit hook (Python), a `--require` preload (JS/TS), JFR (Java), syscall tracing (Go, C#). See [Proving it, per language](#-proving-it-per-language).
- 🌐 **Multi-language, all the way to the proof** — VASH *finds* bugs in Python, JS/TS, Java, Go, C#, Ruby, PHP, C/C++, web templates and IaC — and for the first five it also **builds the target's environment and proves the bug by running an exploit inside it**.
- 🔗 **Exploit-chain synthesis** — stitches individual findings into end-to-end attack chains.
- 📊 **Professional reporting** — a detailed, advisory-grade Markdown report (threat model, CVSS + vectors, exploit scenarios, adversarial-verification verdicts, and paste-ready GitHub-Security-Advisory blocks) alongside a machine-readable `report.json`.
- 📟 **Rich live logging** — per-stage progress, running cost, and a per-finding confirmation feed; degrades to clean plain lines when run detached.
- 🛠️ **Decoupled commands** — `run` (scan), `remediate` (static patches), `validate` (independent second opinion), `provision` (build the target's environment).
- 💳 **Subscription-native** — driven by Claude Pro/Max via the Agent SDK; optional metered API-key and OpenRouter/gateway support.

## 🔍 How it works

VASH maps the repository into a call-graph, fans out many narrowly-scoped hunters, adversarially validates each finding, proves reachability, and (optionally) confirms by execution — then writes the report.

<p align="center">
  <img src="docs/pipeline.svg" alt="The VASH pipeline: recon → hunt → validate → gapfill → dedupe → trace → feedback → chain → report, with a feedback loop from feedback back to hunt, all running over a deterministic AST call-graph spine that feeds taint analysis and sink-backward hunting." width="100%">
</p>

| # | Stage | Tier | Purpose |
|---|---|---|---|
| 1 | **Recon** | Opus | Map the repo; emit narrowly-scoped hunt tasks + a completeness inventory of every untrusted input. |
| 2 | **Hunt** | Sonnet | One attack class per agent; hunts statically, then (dynamic mode) writes and **runs** a PoC in the target's own runtime, under a [runtime observer](#-proving-it-per-language). |
| 3 | **Validate** | Opus | Adversarial re-read on a *different* model — tries to **disprove** each finding. |
| 4 | **Gapfill** | Sonnet | Re-queue under-covered areas until coverage is complete. |
| 5 | **Dedupe** | Sonnet | Cluster findings by root cause; keep one canonical per distinct file. |
| 6 | **Trace** | Opus | Prove attacker-controlled input reaches the sink (reachability gate). |
| 7 | **Feedback** | Sonnet | Seed fresh hunts from confirmed patterns; re-run the loop. |
| 8 | **Chain** | Sonnet | Synthesize multi-finding exploit chains. |
| 9 | **Report** | Sonnet | Emit `report.json` (raw) + a detailed `report.md` (advisory-grade). |

> A deterministic **graphify** call-graph feeds taint analysis (entry → sink) and sink-backward hunting, so agents reason over real data-flow, not guesses. Models are per-stage configurable.

## 📦 Install

**Requirements:** Python 3.11+, Node.js (for the bundled Claude CLI), and a Claude Pro/Max subscription (or an Anthropic API key).

```bash
git clone https://github.com/0xsharz/vanguard-agentic-security-harness.git
cd vanguard-agentic-security-harness
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Authenticate (uses your Claude subscription — no API key needed)
claude login
vash auth-check
```

## 🚀 Quickstart

```bash
# 1. Scan a repo (static — safe by default)
vash run --repo ./target-project --run-id my-first-scan

# 2. Read the report
vash report --run-id my-first-scan --format md    # detailed Markdown
#   raw JSON + report.md are also written under results/<run-id>/report/

# 3. (optional) Confirm findings by execution, inside a sandbox
docker build -t vash:latest .
./scripts/run-in-docker.sh ./target-project my-scan-dyn   # runs with --dynamic-validation

# 4. (optional, decoupled) generate patches / a second opinion
vash remediate --run-id my-first-scan
vash validate  --run-id my-first-scan
```

## 📸 See it run

A 38-line target with two real bugs — a shell command built by string
concatenation, and a path joined straight onto user input. It lives in
[`examples/vulnerable-demo/`](examples/vulnerable-demo) so you can reproduce
this run yourself:

```python
# app/notes.py
def export_note(name):
    cmd = "note2pdf --title " + name            # attacker controls `name`
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def read_note(path):
    with open(os.path.join(NOTES_DIR, path)) as fh:   # attacker controls `path`
        return fh.read()
```

**1 — build the target's environment**, so an exploit has a real runtime to run in:

```bash
vash provision --repo ./examples/vulnerable-demo --scan-image
```

<p align="center"><img src="docs/screenshots/provision.svg" alt="vash provision fingerprints the repo, renders a Dockerfile, builds and verifies the image, then layers VASH on top of it" width="100%"></p>

**2 — scan it, with exploits actually running** inside that environment:

```bash
docker run --rm -e CLAUDE_CODE_OAUTH_TOKEN \
  -v ./examples/vulnerable-demo:/target:ro vash-scan-vulnerable-demo:latest \
  run --repo /target --dynamic-validation
```

<p align="center"><img src="docs/screenshots/scan.svg" alt="The hunt stage dispatching narrowly-scoped tasks, each with a per-language PoC recipe and the python-audit-hook observer, followed by the validation feed confirming findings" width="100%"></p>

Note `observer=python-audit-hook` on each task — that is the runtime instrumentation
being attached before the exploit runs.

**3 — the result.** Both planted bugs found and rated critical, plus five more the
target genuinely has (no auth on the sink, unbounded reads, a routing bug), and two
exploit chains:

<p align="center"><img src="docs/screenshots/summary.svg" alt="Run summary table: 10 findings, all 10 confirmed by adversarial validation, 4 critical" width="100%"></p>

| Delivered | | |
|---|---|---|
| `CWE-78` command injection | `app/notes.py:7` | critical |
| `CWE-22` path traversal | `app/notes.py:14` | critical |
| `CWE-306` missing authentication | `app/notes.py:7` | high |
| `CWE-400` denial of service ×3 | `notes.py:9,16` · `server.py:20` | high / medium |
| `CWE-697` routing logic error | `app/server.py:9` | medium |

**Every one carries `poc_succeeded=true`** — an exploit was written, executed in the
container, and observed. 22 minutes, $10.33.

📎 **[The full report →](docs/example-report.md)** · **[the remediation for it →](docs/example-remediation.md)** — threat model, per-finding
advisory blocks, the exploit code, and the observer lines showing each dangerous
operation as it fired:

```text
[VASH-OBSERVER] audit:subprocess.Popen ('/bin/sh', ['-c', 'note2pdf --title x; echo VASH_PWNED_MARKER; …'])
    <- from /target/app/notes.py:10 in export_note
```


## 🖥️ Commands

### `vash run` — the scan

```bash
vash run --repo PATH [options]
```

| Flag | Description |
|---|---|
| `--repo PATH` | **(required)** Path to the target source repo. |
| `--run-id TEXT` | Run identifier (default: random). Reuse with `--resume`. |
| `--resume` | Resume an existing run — re-queues interrupted/failed tasks. |
| `--dynamic-validation` | **Enable the executed-PoC (sandboxed) validation stage.** Default is static-only. Requires a sandbox (`Docker`/`VASH_SANDBOX=1`) or `--dangerously-no-sandbox`. |
| `--dangerously-no-sandbox` | DEV ONLY — allow `--dynamic-validation` to run PoCs without a sandbox, with a loud warning. Never use on untrusted targets. |
| `--max-cost-usd FLOAT` | Abort if cumulative cost crosses this threshold. |
| `--max-concurrency INT` | Cap every stage's concurrency (cost/rate containment). |
| `--max-recon-tasks INT` | Cap the number of initial hunt tasks recon may emit. |
| `--target-url URL` | Optional live deployment the agents may hit to confirm findings. |
| `--target-creds K=V` | Credentials for the live target (repeatable). |
| `--scope-notes FILE` | Target-specific scope rules / exclusions, passed to every stage. |
| `--provision` | Build the target's environment image before the scan (`docker build` + verify + deterministic repair). Requires Docker. Runs the **target's own** build instructions — inside a container, never on the host. Without it the pipeline still fingerprints the repo and renders a Dockerfile, but builds nothing. |
| `--config PATH` | Override `config/stages.yaml` (models, concurrency, iterations). |
| `--allow-api-key` | Honor `ANTHROPIC_API_KEY` for metered billing. |

### `vash report` — read the results

```bash
vash report --run-id ID --format md     # detailed advisory-grade Markdown
vash report --run-id ID --format json   # raw machine-readable report
```

### `vash remediate` — static patch generation *(decoupled, opt-in)*

Generates policy-gated, root-cause patches for the confirmed findings, plus a security
test for each. **Your repository is never modified and never executed.**

```bash
vash remediate --run-id ID [--repo PATH] [--policy FILE] [--out DIR]
```

**How the patch is made.** Asking a model to *type out* a unified diff is asking it to do
arithmetic on line numbers, and it gets it wrong: on one real run `git apply` rejected
4 of 7 patches over miscounted hunk headers and context that didn't match. So VASH
doesn't ask. The agent **edits files, and `git diff` computes the patch** — which makes
it valid by construction.

Editing needs somewhere safe to edit, and that is never your code:

```
   your repository  ──copy──▶  disposable workspace  ──git diff──▶  patch
   (read-only, untouched)      (the agent edits HERE)                  │
                                        │                              ▼
                                        └──── destroyed ────▶  results/…/patches/
```

Three independent things keep that true, none of which rely on the model behaving:

1. **The agent is never told where your repository is.** Its working directory is the
   copy; the real path appears nowhere in its input.
2. **`git status` is the ground truth, not the agent's account of itself.** Every file it
   actually touched is compared against the files the finding covers, and anything else
   is reverted before the patch is built — so an unreported edit can't ride along inside it.
3. **The workspace is deleted afterwards**, on success, on failure, and on exception.

The agent still gets no shell: editing a file is not executing it. Each patch is checked
with `git apply --check` against your real tree (a read-only operation) and reported as
applying or not — and a finding the agent *claimed* to fix without making an edit is
downgraded to guidance rather than reported as patched.

By default the agent still gets no shell and nothing is executed, so every patch is
marked `needs_verification`. **`--verify`** (opt-in, and gated by the same execution
sandbox as PoC running) is what clears it: the generated security test is run twice
inside the disposable copy — once against the patch, once against the restored
baseline — and only a test that is **RED without the fix and GREEN with it** counts
as verified. A test that passes without the patch doesn't exercise the bug, and says
so.

The honest part is the third outcome. The copy carries your source but not your
installed dependencies, so a test can fail at `import` for reasons that have nothing
to do with the vulnerability — and an import error misread as a failing test would
report *every* such project as proven vulnerable. Those are separated at the runner
level and reported as `not_attempted`, which is stated in the report as evidence for
neither side. Python and JavaScript tests are run; other languages are reported
`not_attempted` rather than guessed at.

If a patch touches a secret, the written `.diff` is redacted — which means it will
not apply verbatim. The report says so per finding rather than letting the
apply-check vouch for bytes that were never written.

> **📎 [Read a real one →](docs/example-remediation.md)** — the remediation for the demo
> scan above: 7 findings, 7 patches, 7 tests. The command-injection fix replaces
> `shell=True` string concatenation with an argv list; the path-traversal fix resolves
> and containment-checks the path rather than filtering `../`.

### `vash validate` — independent second opinion *(decoupled, opt-in)*

Re-verifies a prior run's confirmed findings with a fresh, adversarial pass.

```bash
vash validate --run-id ID [--repo PATH] [--model NAME] [--min-confidence FLOAT]
```

### `vash provision` — build the target's environment *(decoupled, opt-in)*

Fingerprints the repo (languages, build systems, version pins, existing recipes) and renders the Dockerfile VASH would build. Offline and free by default — no LLM, no network, no cost. With `--build` it runs `docker build`, retries through a **deterministic repair ladder** when the build fails, then verifies the image from the inside.

```bash
vash provision --repo PATH                       # print the fingerprint + Dockerfile (no build)
vash provision --repo PATH --build               # build + verify, repairing failures
vash provision --repo PATH --scan-image          # ...and layer VASH on top (see below)
vash provision --repo PATH --build --out rec.json
```

| Flag | Description |
|---|---|
| `--build` | Actually run `docker build` (+ verify + repair retries). |
| `--scan-image` | Also build `vash-scan-<repo>` — VASH layered on the target's image, so PoCs run with the target's own toolchain and dependencies. Implies `--build`. |
| `--tag TEXT` | Image tag (default `vash-env-<repo-name>:latest`). |
| `--max-attempts INT` | Build attempts including repair retries (default 3). |
| `--no-verify` | Skip running the ecosystem's build/test command inside the image. |
| `--verify-network` | Container network for verification: `none` (default) or `bridge`. |
| `--out PATH` | Write the full provisioning record (attempts, repairs, logs) as JSON. |

**Repair ladder** — the build log is matched against a small set of high-signal signatures, each mapped to one textual Dockerfile edit, applied at most once: unavailable base tag → known-good default; missing C toolchain → `build-essential`/`build-base`; missing `git`; `npm ci` without a lockfile → `npm install`; a `COPY` of a path absent from the context; and finally a catch-all that makes the dependency install non-fatal. The repaired Dockerfile is fed to `docker build` on **stdin** — the target tree is never written to.

**Verification is honest**: an image that builds is not necessarily usable, so verify runs a dependency-presence probe *before* the build/test commands. If the target's declared dependencies are not actually installed, the result is reported as `INCOMPLETE` rather than success.

#### The scan image — where executed PoCs actually run

Proving a vulnerability means *running* an exploit against the target. That needs the target's compiler and its libraries — and the generic sandbox has neither: no `javac`, `java`, `mvn`, `go`, `dotnet` or `strace`, and none of the target's packages. A Java PoC there dies at `command not found`; a Python PoC cannot import the code it is attacking.

So `--scan-image` inverts the layering — **VASH is installed into the target's own environment**:

```
vash-env-<target>      the target's environment (Phase: provisioning)
        │
        └── + VASH + node + the claude CLI   →   vash-scan-<target>
```

```bash
vash provision --repo ./target --scan-image        # build it once
./scripts/run-in-docker.sh ./target my-run         # picks it up automatically
```

`run-in-docker.sh` uses `vash-scan-<target>` when it exists and tells you what is lost when it does not, rather than silently degrading. Two details that are load-bearing: VASH lives in its own virtualenv that is deliberately **not** on `PATH` (otherwise `python3` would resolve to VASH's interpreter and every Python PoC would lose sight of the target), and bases without a usable Python — Maven, Go — get a private 3.11 via `uv`.

### `vash status` / `vash auth-check`

```bash
vash status --run-id ID       # tasks, findings, traces, cost
vash auth-check               # verify Claude Code auth is configured
```

## 📄 The report

> **📎 [Read a real one →](docs/example-report.md)** — the complete, unedited report from the scan above, including the runtime observer evidence for each finding.

Every run writes a raw, machine-readable **`report.json`** and a detailed, advisory-grade **`report.md`**. The Markdown report is deterministic and structured like a professional pentest deliverable:

- **Summary** & severity tally
- **Scan Metrics** — files in scope/analyzed, coverage %, cost, tokens-by-phase
- **Threat Model** — system context, assets, trust boundaries, ranked threats, open questions
- **Verification** — raw findings → true/false positives, duplicates collapsed, precision
- **Findings** — each with CWE (+ MITRE link), **CVSS 3.1 score & vector**, confidence, "Also at" co-located sites, Description / Impact / **Exploit scenario** / Preconditions / evidence / **How to fix** / **Adversarial-verification verdict**
- **GHSA advisory sub-block** per finding — Summary / Details / Proof of Concept / Weaknesses / References, ready to paste into a GitHub Security Advisory
- **Exploit chains** — end-to-end attack paths across findings

## 🔒 Static vs dynamic validation

VASH is **static-first**. Its core safety invariant is enforced in one place: the agent runner strips the `Bash` tool — so **nothing from the target ever executes** — unless dynamic validation is explicitly enabled *and* an isolation sandbox is active.

```
execution_enabled = --dynamic-validation  AND  (inside a sandbox  OR  --dangerously-no-sandbox)
```

| Mode | Command | Behavior |
|---|---|---|
| **Static** (default) | `vash run --repo …` | Pure reasoning + call-graph taint. Never runs target code — safe on untrusted repos. |
| **Dynamic** | `vash run --repo … --dynamic-validation` *(in Docker/`VASH_SANDBOX=1`)* | Writes & runs a real PoC per candidate in the sandbox; keeps only what fires. |
| **Refused** | `--dynamic-validation` on a bare host | **Fails fast** with a clear remedy — never silently executes on the host. |

**`vash remediate --verify`** is the third path that executes anything, and it passes the same gate (`sandbox.require()`): with no sandbox and no `--dangerously-no-sandbox` it is refused fail-soft — the static patches are still delivered, and nothing runs. What it executes is the security test VASH generated, inside the disposable copy of your repo, never in your working tree.

**Provisioning** (`--provision` / `vash provision --build`) is the one other path that runs target-authored instructions — a target's build is its own code (`npm ci` runs postinstall scripts, `mvn package` runs plugins). It is opt-in, and every command it issues executes **inside a container, never on the host**; the verify step additionally runs with `--network none`, `no-new-privileges` and cpu/memory/pid caps. Fingerprinting and Dockerfile rendering (the default, flagless path) are pure text analysis and execute nothing.

## 🔬 Proving it, per language

Running an exploit is only half the job. A proof-of-concept that exits `0` proves
nothing — the sink may have swallowed an exception, or the script may never have
reached the target's code at all. So when VASH executes a PoC it also **watches the
process** and records the dangerous operation *as it happens*.

| Language | How the PoC is built and run | What watches it | What it records |
|---|---|---|---|
| **Python** | run directly | PEP-578 audit hook (`sys.addaudithook`) | `subprocess`, `open`, `socket.connect`, `exec`, `pickle` — below the Python API, so a C extension or pickle gadget cannot slip past |
| **JavaScript / TypeScript** | `node` (TS compiles first) | `--require` preload | `child_process`, `fs`, `net`, `http` — CommonJS **and** ESM |
| **Java** | `javac` + the target's real classpath | Java Flight Recorder | `jdk.ProcessStart` / `SocketWrite` / `FileWrite`, **with a stack trace** |
| **Go** | `go build`, then trace the binary | `strace` | `execve`, `openat`, `connect` |
| **C#** | `dotnet build` against the target assembly | `strace` | same syscall boundary |

### Evidence names the code that caused it

A marker on its own only says *"a process started"* — innocent code does that too.
Every marker therefore carries the frame that caused it:

```
[VASH-OBSERVER] audit:subprocess.Popen ('/bin/sh', ['-c', 'echo …; id'])
    <- from /target/app/reports.py:7 in build_report
```

That attribution is what makes it evidence. If it names **your PoC** instead of the
target, the PoC called the sink directly and proved nothing about the target — and
the report says so rather than quietly counting it as a win.

### Two rules that keep it honest

- **An observer is corroboration, never a verdict.** If its tooling is missing (no
  `jfr` in a JRE-only image, no `SYS_PTRACE` under Docker's default seccomp), the PoC
  still runs unwrapped and the finding stands on its own evidence. *Absence of observer
  output is never treated as proof the bug is not real.*
- **A missing toolchain is not a failed exploit.** If `javac` isn't there, that is an
  environment limitation, not a verdict — the finding keeps its severity and is marked
  `needs_poc` for a later run. Without this rule a missing compiler would silently
  delete real findings.

### The environment the exploit runs in

Compiling a Java PoC needs a JDK and the target's classpath; importing a Python target
needs its dependencies. So `vash provision --scan-image` layers VASH **on top of the
target's own provisioned image** — the container that hunts becomes the container the
target needs:

```
vash-env-<target>          the target's environment (toolchain + dependencies)
        └── + VASH         →  vash-scan-<target>     ← the scan runs in here
```

`./scripts/run-in-docker.sh` picks that image up automatically, and tells you what is
lost if you haven't built one rather than silently degrading.


## 🧭 Honest by construction

A scanner that quietly skips something and reports nothing looks exactly like a
scanner that checked and found nothing clean. VASH treats that as a bug class of
its own, so each of these is enforced in code and covered by tests:

| Situation | What a naive tool does | What VASH does |
|---|---|---|
| A hunt task dies (API error, timeout) | Report the rest; coverage looks complete | Reports `tasks_failed`, marks coverage **not complete**, and states *"absence of a finding in those areas is not evidence that none exists"* |
| The file sweep hits its cap | Silently truncate | Discloses how many eligible files were **not** swept |
| The observer's tooling is missing | Treat "no evidence" as "not vulnerable" | Runs the PoC unwrapped and keeps the finding; **absence of observer output is never a verdict** |
| The language toolchain is absent | The PoC fails → drop the finding | A missing `javac` is an *environment limitation*, not a failed exploit. The finding keeps its severity and is flagged for a later run |
| The environment built but deps didn't install | Report "built ✅" | Probes for the target's dependencies and reports the environment **INCOMPLETE** |
| A PoC calls the sink directly | Count it as proof | The evidence names the PoC instead of the target — so it's visible that the exploit **bypassed** the code under test |

None of this makes the tool look better in a demo. It's here because the opposite —
a confident report over a partial scan — is how a security tool does real damage.


## 🗂️ Project structure

```
vash/
├── vash/                    # the package
│   ├── cli.py               # Click CLI entry point
│   ├── orchestrator.py      # pipeline driver (the 9 stages)
│   ├── runner.py            # agent runner + the Bash safety gate
│   ├── sandbox.py           # execution sandbox gate (static-first invariant)
│   ├── progress.py          # RunReporter — rich, fail-soft live logging
│   ├── taint.py             # deterministic entry→sink taint analysis
│   ├── provision/           # fingerprint → render Dockerfile → build/verify/repair
│   │                        #   + scan_image.py (VASH inside the target's env)
│   ├── lang/poc_runtime.py  # per-language PoC recipes + runtime observers
│   ├── lang/observers/      # the audit hook / node preload assets
│   ├── graph_context.py     # call-graph queries feeding the hunters
│   ├── state.py             # SQLite run state (findings, tasks, cost)
│   ├── stages/              # recon, hunt, validate, gapfill, dedupe,
│   │                        #   trace, feedback, chain, report, remediate
│   └── reporting/markdown.py# advisory-grade Markdown report renderer
├── prompts/                 # one system prompt per stage
├── schemas/                 # JSON Schemas — every agent output is validated
├── config/stages.yaml       # per-stage model, concurrency, iterations
├── bench/                   # CVE-recall benchmark harness + ground truth
├── scripts/run-in-docker.sh # sandboxed (executed-PoC) runner
├── tests/                   # 825 offline tests
├── Dockerfile               # the isolation sandbox image
├── NOTICE / licenses/       # third-party attribution + licence texts
└── docs/                    # design specs & benchmark write-ups
```

## ⚙️ Configuration & cost

- **Models** are per-stage in `config/stages.yaml` (Opus for recon/validate/trace, Sonnet elsewhere by default) — tune cost vs depth freely.
- **Containment:** `--max-cost-usd` (hard budget ceiling), `--max-concurrency`, and `--max-recon-tasks` bound every run; runs are **resumable** (`--resume`) after an interruption or budget stop.
- **Providers:** subscription by default; `--allow-api-key`/`ANTHROPIC_API_KEY` for metered billing, or an OpenRouter/gateway base-URL for non-Anthropic models.

## 📈 Results

### 🎯 `swagger-typescript-api` ≤ 13.12.1 — blind scan recovered **all 6 disclosed CVEs (100%)**

Given only the source — no hints, no advisories — VASH independently surfaced confirmed findings corresponding to **every one of the six CVEs** later disclosed in `swagger-typescript-api` and fixed in **13.12.2**. Each survived VASH's adversarial validation stage. All six share one root cause: attacker-controlled OpenAPI spec content reaching code-generation sinks without TypeScript-context escaping.

| Disclosed CVE | Class | VASH |
|---|---|:---:|
| [CVE-2026-54662](https://github.com/advisories/GHSA-hqj5-cw9f-rx67) | RCE — `fetch` client `baseUrl` | ✅ |
| [CVE-2026-54661](https://github.com/advisories/GHSA-38c3-wv3c-v3xj) | RCE — `axios` client `baseUrl` | ✅ |
| [CVE-2026-54666](https://github.com/advisories/GHSA-w284-33mx-6g9v) | RCE — OpenAPI path template | ✅ |
| [CVE-2026-54664](https://github.com/advisories/GHSA-5f94-x226-ccpm) | RCE — enum string values | ✅ |
| [CVE-2026-54660](https://github.com/advisories/GHSA-h754-fxp7-88wx) | Credential exfiltration — remote `$ref` | ✅ |
| [CVE-2026-54663](https://github.com/advisories/GHSA-x36r-4347-pm5x) | SSRF — remote `$ref` | ✅ |

VASH surfaced **29 findings; 12 survived adversarial validation** — the six above plus additional plausibly-novel issues (prototype pollution, ReDoS, YAML deserialization, path traversal). *Recall is mapped by vulnerability sink/class against the disclosed advisories.*

### 📊 `datamodel-code-generator` 0.55.0 — scored against published CVE ground truth

Deterministically scored by the `bench/` harness (50 Python files + 20 Jinja2 templates, **11 in-version CVEs**):

| Run | Delivered recall | Findings | Cost / time | Basis |
|---|:---:|:---:|---|---|
| **Docker, executed-PoC** | **5/11 (45%)** | 25 (+3 chains) | ~$88 / ~3.5 hr | every finding exploit-verified |
| **Host, static** | **5/11 (45%)** | 25 (+5 chains) | ~$103 / ~2.5 hr | static hunt |

- **5/11 per run, 6/11 union.** Two independent runs each delivered 5/11; across both, VASH covered **6 distinct CVEs**. The hunt is stochastic — a given run trades one codegen CVE for another — so added iterations reliably land 6/11.
- **Template files count.** `CVE-2026-54654` is a `.jinja2` code-generation bug: it only surfaces if the sweep treats templates as source, which VASH does.
- **Executed-PoC buys confidence.** In the Docker run, every one of the 25 delivered findings had a PoC that fired in the sandbox.

*Reproducible via the `bench/` harness and its CVE ground truth.*

## 📜 License

VASH is released under the **MIT License** — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## ⚠️ Responsible use

VASH is a defensive security tool for **authorized** testing of code you own or are permitted to assess. Dynamic mode executes proof-of-concept exploits — run it only inside the provided sandbox, and never point it at systems you don't have permission to test.

