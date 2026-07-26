import pytest
from vash import sandbox
from vash.runner import _gate_tools


@pytest.mark.parametrize("dyn,sb,nosb,expected", [
    (False, False, False, False),   # no flag -> static even if... n/a
    (False, True,  False, False),   # no flag -> static even in sandbox
    (True,  True,  False, True),    # flag + sandbox -> dynamic
    (True,  False, True,  True),    # flag + dev escape -> dynamic
    (True,  True,  True,  True),
])
def test_resolve_execution_enabled(monkeypatch, dyn, sb, nosb, expected):
    monkeypatch.setattr(sandbox, "is_sandboxed", lambda: sb)
    assert sandbox.resolve_execution(dynamic_validation=dyn, allow_no_sandbox=nosb) is expected

def test_resolve_execution_fail_fast(monkeypatch):
    monkeypatch.setattr(sandbox, "is_sandboxed", lambda: False)
    with pytest.raises(sandbox.SandboxError):
        sandbox.resolve_execution(dynamic_validation=True, allow_no_sandbox=False)

def test_gate_strips_bash_when_static():
    assert _gate_tools(["Read", "Bash", "Grep"], False, "hunt") == ["Read", "Grep"]

def test_gate_keeps_bash_when_dynamic():
    assert _gate_tools(["Read", "Bash", "Grep"], True, "hunt") == ["Read", "Bash", "Grep"]

def test_gate_noop_without_bash():
    assert _gate_tools(["Read", "Grep"], False, "recon") == ["Read", "Grep"]
