"""Auth setup tests — env scrubbing + the auth modes.

Modes: gateway, api_key (opt-in), oauth_token, keychain_login,
macos_keychain_login.

The api_key mode requires the caller to pass `allow_api_key=True` to
configure_auth(). Without it, ANTHROPIC_API_KEY is scrubbed in favor of
subscription auth, matching the original "subscription only" behavior.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from vash import auth as auth_mod
from vash.auth import AuthError, configure_auth


def _empty_env(tmp_path: Path) -> Path:
    p = tmp_path / ".env"
    p.write_text("")
    return p


def _require_claude_cli() -> None:
    if shutil.which("claude") is None:
        pytest.skip("claude CLI not installed")


def _clear_all_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wipe every env var that influences auth-mode selection."""
    for var in (
        "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)

def _force_non_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force tests that expect no implicit local login fallback to run as Linux."""
    monkeypatch.setattr(auth_mod.platform, "system", lambda: "Linux")

# ---------- absence ----------


def test_missing_everything_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _clear_all_auth_env(monkeypatch)
    _force_non_macos(monkeypatch)
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    with pytest.raises(AuthError, match="No auth available"):
        configure_auth(env_file=_empty_env(tmp_path))


def test_missing_claude_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "fake-test-token")
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(AuthError, match="claude.*CLI"):
        configure_auth(env_file=_empty_env(tmp_path))


# ---------- default behavior (allow_api_key=False, preserves upstream) ----------


def test_default_scrubs_api_key_with_oauth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Default behavior: ANTHROPIC_API_KEY is scrubbed even when OAuth is
    present. Subscription auth wins. Matches upstream evilsocket/audit."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "fake-test-token")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-be-deleted")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path))
    assert status.auth_mode == "oauth_token"
    assert status.api_key_scrubbed is True
    assert "ANTHROPIC_API_KEY" not in os.environ


def test_default_scrubs_api_key_even_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Default behavior: ANTHROPIC_API_KEY alone (no other auth, no opt-in)
    is scrubbed and yields AuthError with a hint about --allow-api-key."""
    _clear_all_auth_env(monkeypatch)
    _force_non_macos(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-be-deleted")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    _require_claude_cli()
    with pytest.raises(AuthError, match="--allow-api-key"):
        configure_auth(env_file=_empty_env(tmp_path))
    # And the key was scrubbed before the raise.
    assert "ANTHROPIC_API_KEY" not in os.environ


def test_oauth_token_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """OAuth token alone selects oauth_token mode."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "fake-test-token")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path))
    assert status.auth_mode == "oauth_token"
    assert status.api_key_scrubbed is False


def test_keychain_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _clear_all_auth_env(monkeypatch)
    creds = tmp_path / "creds.json"
    creds.write_text("{}")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", creds)
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path))
    assert status.auth_mode == "keychain_login"
    assert status.credentials_file == creds

def test_macos_keychain_login_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """On macOS, Claude Code /login credentials live in the macOS Keychain,
    not in ~/.claude/.credentials.json. Allow this path through preflight so
    the Claude Agent SDK can use the active first-party login."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    monkeypatch.setattr(auth_mod.platform, "system", lambda: "Darwin")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path))
    assert status.auth_mode == "macos_keychain_login"
    assert status.credentials_file is None


# ---------- opt-in api_key mode ----------


def test_api_key_mode_opt_in(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """ANTHROPIC_API_KEY with allow_api_key=True selects api_key mode
    and leaves the key in the env so the SDK can use it."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-fake")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path), allow_api_key=True)
    assert status.auth_mode == "api_key"
    assert status.api_key_scrubbed is False
    # CRITICAL: the key MUST still be in the env so the SDK can use it
    assert os.environ.get("ANTHROPIC_API_KEY") == "sk-ant-api03-fake"


def test_api_key_outranks_oauth_when_opted_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With allow_api_key=True, ANTHROPIC_API_KEY wins over
    CLAUDE_CODE_OAUTH_TOKEN. Matches SDK precedence (rung 3 > rung 5)."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-fake")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "fake-oauth-token")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path), allow_api_key=True)
    assert status.auth_mode == "api_key"
    assert os.environ.get("ANTHROPIC_API_KEY") == "sk-ant-api03-fake"


def test_api_key_scrubs_stale_auth_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """In api_key mode, a stale ANTHROPIC_AUTH_TOKEN must be scrubbed
    so it can't outrank the API key (rung 2 > rung 3)."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-fake")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "stale-token-must-go")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path), allow_api_key=True)
    assert status.auth_mode == "api_key"
    assert status.auth_token_scrubbed is True
    assert "ANTHROPIC_AUTH_TOKEN" not in os.environ
    assert os.environ.get("ANTHROPIC_API_KEY") == "sk-ant-api03-fake"


def test_allow_api_key_with_no_key_falls_back_to_oauth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Passing allow_api_key=True without setting ANTHROPIC_API_KEY is
    a no-op — falls through to subscription auth normally."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "fake-test-token")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path), allow_api_key=True)
    assert status.auth_mode == "oauth_token"


# ---------- gateway mode ----------


def test_gateway_mode_openrouter(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When ANTHROPIC_BASE_URL points at a non-anthropic host AND
    ANTHROPIC_AUTH_TOKEN is set, leave the gateway env intact and
    don't scrub the token."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://openrouter.ai/api")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "or-sk-xxx")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "should-be-deleted")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path))
    assert status.auth_mode == "gateway"
    assert status.gateway_base_url == "https://openrouter.ai/api"
    assert status.api_key_scrubbed is True
    assert status.auth_token_scrubbed is False
    # CRITICAL: the gateway token MUST still be in the env so the SDK can use it
    assert os.environ.get("ANTHROPIC_AUTH_TOKEN") == "or-sk-xxx"
    assert os.environ.get("ANTHROPIC_BASE_URL") == "https://openrouter.ai/api"
    assert "ANTHROPIC_API_KEY" not in os.environ


def test_gateway_beats_api_key_even_when_opted_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Gateway mode outranks api_key mode even with allow_api_key=True.
    Mirrors SDK precedence (ANTHROPIC_AUTH_TOKEN at rung 2 > API key at 3)."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://openrouter.ai/api")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "or-sk-xxx")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-fake")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path), allow_api_key=True)
    assert status.auth_mode == "gateway"
    assert status.api_key_scrubbed is True
    assert "ANTHROPIC_API_KEY" not in os.environ


def test_gateway_mode_requires_both_url_and_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A base URL without a token doesn't trigger gateway mode."""
    _clear_all_auth_env(monkeypatch)
    _force_non_macos(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://openrouter.ai/api")
    monkeypatch.setattr(auth_mod, "CREDENTIALS_PATH", tmp_path / "no_creds.json")
    _require_claude_cli()
    with pytest.raises(AuthError):
        configure_auth(env_file=_empty_env(tmp_path))


def test_anthropic_base_url_does_not_trigger_gateway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A base URL pointing AT anthropic.com is normal — not gateway mode.
    Subscription scrubbing should still happen for the auth token."""
    _clear_all_auth_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "should-be-scrubbed")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "fake-token")
    _require_claude_cli()
    status = configure_auth(env_file=_empty_env(tmp_path))
    assert status.auth_mode == "oauth_token"
    assert status.auth_token_scrubbed is True
    assert "ANTHROPIC_AUTH_TOKEN" not in os.environ
