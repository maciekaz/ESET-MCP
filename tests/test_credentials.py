"""Unit tests for credential parsing and resolvers (no network)."""
from __future__ import annotations

import base64

import pytest

from eset_mcp.credentials import (
    BasicAuthCredentialResolver,
    CredentialResolverError,
    Credentials,
    EnvCredentialResolver,
    normalize_region,
    parse_basic_auth_header,
    request_credentials,
)

# ─── parse_basic_auth_header ─────────────────────────────────────────────────

def _basic(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def test_parse_basic_auth_happy_path() -> None:
    user, pw = parse_basic_auth_header(_basic("alice", "s3cr3t"))
    assert (user, pw) == ("alice", "s3cr3t")


def test_parse_basic_auth_unicode_password() -> None:
    user, pw = parse_basic_auth_header(_basic("user", "pa$$wörd!#@"))
    assert (user, pw) == ("user", "pa$$wörd!#@")


def test_parse_basic_auth_password_with_colon() -> None:
    # ESET allows colons in passwords; only the first colon separates user and pass.
    user, pw = parse_basic_auth_header(_basic("u", "a:b:c"))
    assert (user, pw) == ("u", "a:b:c")


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer abc",
        "Basic",
        "Basic !!!notbase64!!!",
        "Basic " + base64.b64encode(b"no-colon").decode(),
        "Basic " + base64.b64encode(b":nopass").decode(),
        "Basic " + base64.b64encode(b"nouser:").decode(),
    ],
)
def test_parse_basic_auth_malformed_rejected(header: str) -> None:
    with pytest.raises(CredentialResolverError):
        parse_basic_auth_header(header)


# ─── normalize_region ────────────────────────────────────────────────────────

def test_normalize_region_default_when_missing() -> None:
    assert normalize_region(None, "eu") == "eu"
    assert normalize_region("", "us") == "us"


def test_normalize_region_normalizes_case_and_whitespace() -> None:
    assert normalize_region(" US ", "eu") == "us"


def test_normalize_region_rejects_unknown() -> None:
    with pytest.raises(CredentialResolverError):
        normalize_region("antarctica", "eu")


# ─── Resolvers ───────────────────────────────────────────────────────────────

def test_env_resolver_always_returns_same_creds() -> None:
    class FakeSettings:
        user = "env-user"
        password = "env-pass"
        region = "eu"

    r = EnvCredentialResolver(FakeSettings())  # type: ignore[arg-type]
    creds = r.resolve()
    assert creds == Credentials("env-user", "env-pass", "eu")
    # Resolves to the same identity object every time — important for the
    # client pool cache to hit consistently in env mode.
    assert r.resolve() is creds


def test_basic_resolver_reads_contextvar() -> None:
    r = BasicAuthCredentialResolver(default_region="eu")
    creds = Credentials("alice", "s3cr3t", "us")
    token = request_credentials.set(creds)
    try:
        assert r.resolve() == creds
    finally:
        request_credentials.reset(token)


def test_basic_resolver_raises_when_contextvar_empty() -> None:
    r = BasicAuthCredentialResolver(default_region="eu")
    # Defensive — ensure the var is empty (it should be by default).
    token = request_credentials.set(None)
    try:
        with pytest.raises(CredentialResolverError):
            r.resolve()
    finally:
        request_credentials.reset(token)


def test_credentials_cache_key_distinct_per_field() -> None:
    a = Credentials("alice", "x", "eu")
    a_same = Credentials("alice", "x", "eu")
    a_diff_pw = Credentials("alice", "rotated-pw", "eu")
    b = Credentials("bob", "x", "eu")
    c = Credentials("alice", "x", "us")
    assert a.cache_key() == a_same.cache_key()
    # Password rotation forces a new client — we don't want stale tokens
    # served after an account password change.
    assert a.cache_key() != a_diff_pw.cache_key()
    assert a.cache_key() != b.cache_key()
    assert a.cache_key() != c.cache_key()
    # The key never contains the raw password.
    assert "x" not in a.cache_key()
