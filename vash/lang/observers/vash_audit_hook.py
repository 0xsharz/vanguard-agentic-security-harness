#!/usr/bin/env python3
"""PEP-578 audit-hook observer for Python PoCs.

    python3 vash_audit_hook.py python3 poc.py [args...]
    python3 vash_audit_hook.py poc.py [args...]

Installs a `sys.addaudithook` hook, then runs the PoC through `runpy` in the
same interpreter. Every security-relevant CPython audit event the PoC triggers
(process spawn, file open, socket connect, exec/compile, pickle/marshal load)
is printed to **stderr** with a distinctive marker prefix, so the Hunt agent
can tell "the script exited 0" apart from "the vulnerable behaviour actually
fired". Exit code and stdout of the PoC are passed through unchanged.

**Why an audit hook and not a wrapper library.** Audit events are raised by
CPython itself, below the Python API, so they fire no matter how the target
reaches the sink — `os.system`, a C extension calling `subprocess`, a pickle
gadget chain. A monkey-patched module can be bypassed; an audit hook cannot
(hooks can never be removed once added, by design).

**Noise control, and why it matters.** The interpreter raises `open`,
`compile` and `exec` constantly just to *start* — importing modules, reading
`.py` files, compiling the PoC. Reporting those would produce evidence that
proves nothing, so this hook (a) arms itself only once the PoC is about to
run, (b) drops events attributable to loading the PoC itself, (c) drops
`open` of code files and of anything under the interpreter's own prefix, and
(d) caps each event type. The bias is deliberate: a missed event costs a
weaker proof, a fabricated event costs a false finding.

**Honesty.** This observer is OPTIONAL instrumentation. If it is not used, or
its output is empty, that says nothing about whether the vulnerability
reproduced — read the PoC's own assertions. The `hook-armed` banner line
exists precisely so "the observer never ran" is distinguishable from "the
observer ran and saw nothing".
"""
from __future__ import annotations

import os
import re
import runpy
import sys

MARKER = "[VASH-OBSERVER]"

# Audit events worth reporting. Chosen for "an attacker got something to
# happen" value, not completeness — see the noise-control note above.
WATCHED_EVENTS = (
    "subprocess.Popen",     # every subprocess.* API funnels through this
    "os.system",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "os.startfile",
    "open",                 # io.open / builtins.open / os.open
    "socket.connect",
    "socket.getaddrinfo",
    "urllib.Request",
    "exec",                 # raised by both exec() and eval()
    "compile",
    "pickle.find_class",    # the pickle RCE primitive
    "marshal.load",
    "marshal.loads",
    "ctypes.dlopen",
)

# Events the import system raises constantly just to load a module (reading
# and unmarshalling .pyc, exec'ing module bodies, compiling namedtuple
# accessors). They stay in WATCHED_EVENTS — a PoC that unmarshals attacker
# bytes is exactly what we want to see — but they are dropped when the call
# came from inside the import machinery. The high-value events
# (subprocess/os/socket/pickle) are NEVER filtered this way.
_IMPORT_NOISY_EVENTS = ("open", "exec", "compile", "marshal.load", "marshal.loads")

MAX_PER_EVENT = 25

# `open` of these is almost always the import system, not the PoC.
_CODE_SUFFIXES = (".py", ".pyc", ".pyo", ".pyi", ".so", ".pyd", ".dll", ".egg")

# how far up the stack to look for the import machinery
_FRAME_SCAN_LIMIT = 60

_state = {"armed": False, "reentrant": False, "poc": None}
_counts: dict[str, int] = {}


def _noise_roots() -> tuple[str, ...]:
    roots = [sys.prefix, sys.base_prefix]
    try:
        roots.append(os.path.dirname(os.__file__ or ""))
    except Exception:  # pragma: no cover - defensive
        pass
    return tuple(os.path.normcase(r) for r in roots if r)


_NOISE_ROOTS = _noise_roots()


def _emit(line: str) -> None:
    """Write a marker line. Never raises: instrumentation must not be able to
    break the PoC (stderr can be closed during interpreter shutdown)."""
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def _short(value: object, limit: int = 200) -> str:
    try:
        text = repr(value)
    except Exception:
        return "<unrepresentable>"
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def _is_poc(path: object) -> bool:
    poc = _state["poc"]
    if not poc or not isinstance(path, str):
        return False
    try:
        return os.path.normcase(os.path.abspath(path)) == poc
    except Exception:
        return False


def _boring_open(path: object) -> bool:
    if not isinstance(path, str):
        return False                       # an int fd — keep it, it is unusual
    norm = os.path.normcase(path)
    if norm.endswith(_CODE_SUFFIXES):
        return True
    return any(norm.startswith(root) for root in _NOISE_ROOTS)


def _in_import_machinery() -> bool:
    """True when the current call is being made *by* an import.

    Walking the stack is the only reliable discriminator: there is no
    "import finished" audit event, so a depth counter cannot work, and the
    noisy events (`marshal.loads` of a .pyc, `exec` of a module body,
    `compile` of a namedtuple accessor) look identical to the real thing
    from their arguments alone.
    """
    try:
        frame = sys._getframe(1)
    except Exception:
        return False
    depth = 0
    while frame is not None and depth < _FRAME_SCAN_LIMIT:
        name = frame.f_code.co_filename
        if "importlib" in name or "zipimport" in name:
            return True
        frame = frame.f_back
        depth += 1
    return False


def _hook(event: str, args: tuple) -> None:
    if not _state["armed"] or _state["reentrant"]:
        return
    if event not in WATCHED_EVENTS:
        return
    _state["reentrant"] = True             # our own formatting must not recurse
    try:
        if event in _IMPORT_NOISY_EVENTS and _in_import_machinery():
            return
        if event == "open":
            path = args[0] if args else None
            if _is_poc(path) or _boring_open(path):
                return
        elif event == "compile":
            if len(args) > 1 and _is_poc(args[1]):
                return                     # runpy compiling the PoC itself
        elif event == "exec":
            code = args[0] if args else None
            if _is_poc(getattr(code, "co_filename", None)):
                return                     # runpy exec'ing the PoC itself
        seen = _counts[event] = _counts.get(event, 0) + 1
        if seen > MAX_PER_EVENT:
            if seen == MAX_PER_EVENT + 1:
                _emit(f"{MARKER} audit:{event} <further occurrences suppressed>")
            return
        _emit(f"{MARKER} audit:{event} {_short(args)}")
    except Exception:
        pass
    finally:
        _state["reentrant"] = False


_ENV_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)


def _apply_env_assignments(argv: list[str]) -> list[str]:
    """Consume leading `NAME=VALUE` tokens and apply them to this process.

    The runtime's own deps_hint tells the agent to reach the target with
    `PYTHONPATH=/target python3 poc.py`. The shell only treats `NAME=VALUE` as
    an assignment at the START of a command, so once that command is spliced
    after `python3 <hook>` the assignment arrives here as a plain argv token —
    the wrapper would then treat "PYTHONPATH=/target" as the script name and
    exit 2 WITHOUT EVER RUNNING THE POC, which reads downstream as "the
    observer saw nothing". Applying it here keeps the documented invocation
    working, and because it is applied before the PoC is loaded, the PoC sees
    the intended import path.
    """
    out = list(argv)
    while out:
        m = _ENV_ASSIGN.match(out[0])
        if not m:
            break
        name, value = m.group(1), m.group(2)
        os.environ[name] = value
        if name == "PYTHONPATH":
            # sys.path was already built from the inherited environment, so
            # setting os.environ alone would be too late for this process.
            for part in reversed(value.split(os.pathsep)):
                if part and part not in sys.path:
                    sys.path.insert(0, part)
        _emit(f"{MARKER} env {name}={value}")
        out.pop(0)
    return out


def _strip_interpreter(argv: list[str]) -> list[str]:
    """Drop a leading `python3 [-u ...]` so the wrapper can be spliced in front
    of a plain run command (`python3 vash_audit_hook.py <run_cmd>`)."""
    out = list(argv)
    while out:
        head = out[0]
        base = os.path.basename(head).lower()
        if base.startswith("python") or base in ("py", "py.exe"):
            out.pop(0)
            continue
        if head in ("-u", "-B", "-E", "-s", "-S", "-I", "-q"):
            out.pop(0)
            continue
        break
    return out


def main(argv: list[str]) -> int:
    # Order matters: `PYTHONPATH=/target python3 poc.py` puts the assignment
    # first, and a `python3` may follow it.
    cmd = _strip_interpreter(_apply_env_assignments(argv))
    if not cmd or cmd[0].startswith("-"):
        _emit(f"{MARKER} usage: vash_audit_hook.py [python3] <poc.py> [args...] "
              "(only the script form is observable; `-c` / `-m` are not)")
        return 2

    script = cmd[0]
    if not os.path.isfile(script):
        _emit(f"{MARKER} error: no such PoC script: {script}")
        return 2

    _state["poc"] = os.path.normcase(os.path.abspath(script))
    sys.argv = [script] + cmd[1:]
    sys.addaudithook(_hook)
    _state["armed"] = True
    _emit(f"{MARKER} hook-armed poc={script} pid={os.getpid()} "
          f"events={','.join(WATCHED_EVENTS)}")

    code = 0
    try:
        runpy.run_path(script, run_name="__main__")
    except SystemExit as exc:
        if isinstance(exc.code, int):
            code = exc.code
        elif exc.code is not None:
            _emit(f"{MARKER} poc-exit {_short(exc.code)}")
            code = 1
    finally:
        _state["armed"] = False
        total = sum(_counts.values())
        detail = " ".join(f"{k}={v}" for k, v in sorted(_counts.items())) or "none"
        _emit(f"{MARKER} hook-summary observed={total} {detail} "
              "(no events observed is NOT proof the vulnerability did not fire)")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
