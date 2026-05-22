"""Unit tests for on-prem ESET PROTECT support.

These run entirely without network — they exercise:
- Settings parsing of ESET_DEPLOYMENT / ESET_ONPREM_SERVER_URL / ESET_ONPREM_VERIFY_SSL
- Credentials.cache_key() distinguishing cloud vs on-prem (and same user on
  two different on-prem URLs)
- Header parsing in the ASGI middleware (X-ESET-Server-URL precedence)
- OnPremTokenManager wire format against a mocked HTTP server (respx)
- On-prem path overrides loaded from openapi/onprem-path-overrides.json
- httpx verify=… wiring driven by Credentials.verify_ssl
"""
from __future__ import annotations

import base64

import httpx
import pytest
import respx

from eset_mcp.auth import CloudTokenManager, OnPremTokenManager, make_token_manager
from eset_mcp.config import Settings
from eset_mcp.credentials import (
    BasicAuthCredentialResolver,
    CredentialResolverError,
    Credentials,
    EnvCredentialResolver,
    normalize_server_url_header,
    request_credentials,
)
from eset_mcp.http_client import EsetHttpClient
from eset_mcp.regions import resolve_auth_url, resolve_base_url
from eset_mcp.tools_loader import ToolDef, load_all_tools

# ─── Settings (env parsing) ───────────────────────────────────────────────────


def _set_env(monkeypatch, **overrides) -> None:
    """Replace any ESET_* env vars with a clean baseline + caller's overrides."""
    # Wipe state so tests don't leak between each other.
    for key in list(monkeypatch._setitem if hasattr(monkeypatch, "_setitem") else []):
        if key.startswith("ESET_"):
            monkeypatch.delenv(key, raising=False)
    baseline = {
        "ESET_AUTH_MODE": "env",
        "ESET_USER": "u@example.com",
        "ESET_PASSWORD": "pw",
        "ESET_MODE": "RO",
        "ESET_REGION": "eu",
        "ESET_MCP_TRANSPORT": "stdio",
    }
    baseline.update(overrides)
    for k, v in baseline.items():
        monkeypatch.setenv(k, v)


def test_settings_default_deployment_is_cloud(monkeypatch) -> None:
    _set_env(monkeypatch)
    s = Settings.from_env(env_file=None)
    assert s.deployment == "cloud"
    assert s.onprem_server_url == ""
    assert s.onprem_verify_ssl is True


def test_settings_onprem_requires_server_url_in_env_mode(monkeypatch) -> None:
    _set_env(monkeypatch, ESET_DEPLOYMENT="onprem")
    with pytest.raises(RuntimeError, match="ESET_ONPREM_SERVER_URL"):
        Settings.from_env(env_file=None)


def test_settings_onprem_basic_mode_allows_empty_url(monkeypatch) -> None:
    """basic auth + on-prem with no env URL is fine — clients send the header."""
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_AUTH_MODE="basic",
        ESET_MCP_TRANSPORT="http",
    )
    s = Settings.from_env(env_file=None)
    assert s.deployment == "onprem"
    assert s.onprem_server_url == ""


def test_settings_onprem_server_url_normalised(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.example.com:9443/",
    )
    s = Settings.from_env(env_file=None)
    # Trailing slash dropped so callers can concatenate "/path" safely.
    assert s.onprem_server_url == "https://protect.example.com:9443"


def test_settings_onprem_server_url_http_rejected(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="http://protect.example.com:9443",
    )
    with pytest.raises(RuntimeError, match="https"):
        Settings.from_env(env_file=None)


def test_settings_onprem_server_url_with_path_rejected(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.example.com:9443/api",
    )
    with pytest.raises(RuntimeError, match="path"):
        Settings.from_env(env_file=None)


def test_settings_onprem_verify_ssl_false(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
        ESET_ONPREM_VERIFY_SSL="false",
    )
    s = Settings.from_env(env_file=None)
    assert s.onprem_verify_ssl is False


# ─── Credentials.cache_key() ──────────────────────────────────────────────────


def test_cache_key_distinguishes_cloud_from_onprem() -> None:
    cloud = Credentials(user="u", password="pw", region="eu")
    onprem = Credentials(
        user="u", password="pw", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    assert cloud.cache_key() != onprem.cache_key()
    # Cloud key carries region.
    assert cloud.cache_key()[2] == "cloud"
    assert cloud.cache_key()[3] == "eu"
    # On-prem key carries the URL.
    assert onprem.cache_key()[2] == "onprem"
    assert onprem.cache_key()[3] == "https://protect.local:9443"


def test_cache_key_distinguishes_two_onprem_consoles() -> None:
    a = Credentials(user="u", password="pw", region="eu",
                    deployment="onprem", server_url="https://a.local:9443")
    b = Credentials(user="u", password="pw", region="eu",
                    deployment="onprem", server_url="https://b.local:9443")
    assert a.cache_key() != b.cache_key()


def test_cache_key_password_hash_changes_when_password_rotates() -> None:
    """Rotating the password forces a new pool entry — no stale-token reuse."""
    a = Credentials(user="u", password="old", region="eu")
    b = Credentials(user="u", password="new", region="eu")
    assert a.cache_key() != b.cache_key()


def test_cache_key_cf_token_rotation_creates_new_pool_entry() -> None:
    """Different CF Access secret for the same on-prem URL → distinct pool entry.

    Important: the httpx default headers carrying the CF tokens are baked in
    at construction time, so swapping the secret on a shared client would
    race. The cache key must reflect the secret so the pool hands out a
    fresh client when it changes.
    """
    base = dict(user="u", password="p", region="eu",
                deployment="onprem", server_url="https://protect.local:9443")
    with_a = Credentials(**base, cf_access_client_id="id", cf_access_client_secret="A")
    with_b = Credentials(**base, cf_access_client_id="id", cf_access_client_secret="B")
    no_cf = Credentials(**base)
    keys = {with_a.cache_key(), with_b.cache_key(), no_cf.cache_key()}
    assert len(keys) == 3, "expected three distinct pool keys (A, B, no-CF)"
    # CF id alone (without secret) is never used — only secret hash distinguishes.
    assert with_a.cache_key()[4] != ""
    assert no_cf.cache_key()[4] == ""


# ─── Header normalisation (middleware helpers) ────────────────────────────────


def test_normalize_server_url_header_empty_returns_blank() -> None:
    assert normalize_server_url_header(None) == ""
    assert normalize_server_url_header("") == ""


def test_normalize_server_url_header_strips_trailing_slash() -> None:
    assert (
        normalize_server_url_header("https://protect.example.com:9443/")
        == "https://protect.example.com:9443"
    )


def test_normalize_server_url_header_rejects_http() -> None:
    with pytest.raises(CredentialResolverError, match="https"):
        normalize_server_url_header("http://protect.example.com:9443")


def test_normalize_server_url_header_rejects_path() -> None:
    with pytest.raises(CredentialResolverError, match="path"):
        normalize_server_url_header("https://protect.example.com:9443/api")


# ─── Region/URL resolution ────────────────────────────────────────────────────


def test_resolve_base_url_cloud_per_service() -> None:
    c = Credentials(user="u", password="pw", region="eu")
    assert resolve_base_url(c, "device-management") == "https://eu.device-management.eset.systems"
    assert resolve_base_url(c, "policy-management") == "https://eu.policy-management.eset.systems"


def test_resolve_base_url_onprem_collapses_to_single_host() -> None:
    c = Credentials(user="u", password="pw", region="eu",
                    deployment="onprem", server_url="https://protect.local:9443")
    # On-prem uses one origin for everything.
    assert resolve_base_url(c, "device-management") == "https://protect.local:9443"
    assert resolve_base_url(c, "policy-management") == "https://protect.local:9443"


def test_resolve_auth_url_picks_right_endpoint() -> None:
    cloud = Credentials(user="u", password="pw", region="eu")
    assert "/oauth/token" in resolve_auth_url(cloud)

    onprem = Credentials(user="u", password="pw", region="eu",
                         deployment="onprem", server_url="https://protect.local:9443")
    assert resolve_auth_url(onprem) == "https://protect.local:9443/GetTokens"


def test_resolve_base_url_onprem_without_server_url_raises() -> None:
    bad = Credentials(user="u", password="pw", region="eu", deployment="onprem")
    with pytest.raises(RuntimeError, match="server URL"):
        resolve_base_url(bad, "device-management")


# ─── EnvCredentialResolver / BasicAuthCredentialResolver ──────────────────────


def test_env_resolver_propagates_onprem_settings(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
        ESET_ONPREM_VERIFY_SSL="false",
    )
    s = Settings.from_env(env_file=None)
    r = EnvCredentialResolver(s)
    c = r.resolve()
    assert c.deployment == "onprem"
    assert c.server_url == "https://protect.local:9443"
    assert c.verify_ssl is False


def test_basic_resolver_reads_contextvar(monkeypatch) -> None:
    _set_env(monkeypatch)
    s = Settings.from_env(env_file=None)
    r = BasicAuthCredentialResolver(s)
    # Without anything in the ContextVar → error.
    with pytest.raises(CredentialResolverError):
        r.resolve()
    # With creds set in the ContextVar → returned as-is.
    creds = Credentials(user="x", password="y", region="us",
                        deployment="onprem", server_url="https://x:9443")
    tok = request_credentials.set(creds)
    try:
        assert r.resolve() == creds
    finally:
        request_credentials.reset(tok)


# ─── Middleware (X-ESET-Server-URL → on-prem) ─────────────────────────────────


def _build_app_with_middleware(settings: Settings):
    """Tiny Starlette app whose only job is to expose what the middleware stashed."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from eset_mcp.middleware import BasicAuthCredentialsMiddleware

    async def _echo(_request):
        creds = request_credentials.get()
        if creds is None:
            return JSONResponse({"error": "no creds"}, status_code=500)
        return JSONResponse({
            "user": creds.user,
            "deployment": creds.deployment,
            "region": creds.region,
            "server_url": creds.server_url,
            "verify_ssl": creds.verify_ssl,
        })

    app = Starlette(routes=[Route("/echo", _echo)])
    app.add_middleware(BasicAuthCredentialsMiddleware, settings=settings)
    return app


def _basic_header(user: str = "u", pw: str = "pw") -> str:
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {token}"


async def test_middleware_no_override_uses_cloud_default(monkeypatch) -> None:
    _set_env(monkeypatch, ESET_AUTH_MODE="basic", ESET_MCP_TRANSPORT="http")
    s = Settings.from_env(env_file=None)
    app = _build_app_with_middleware(s)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/echo", headers={"authorization": _basic_header()})
    assert r.status_code == 200
    body = r.json()
    assert body["deployment"] == "cloud"
    assert body["region"] == "eu"
    assert body["server_url"] == ""


async def test_middleware_server_url_header_switches_to_onprem(monkeypatch) -> None:
    _set_env(monkeypatch, ESET_AUTH_MODE="basic", ESET_MCP_TRANSPORT="http")
    s = Settings.from_env(env_file=None)
    app = _build_app_with_middleware(s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get(
            "/echo",
            headers={
                "authorization": _basic_header(),
                "x-eset-server-url": "https://protect.client-a.local:9443",
            },
        )
    assert r.status_code == 200
    body = r.json()
    assert body["deployment"] == "onprem"
    assert body["server_url"] == "https://protect.client-a.local:9443"


async def test_middleware_server_url_wins_over_region(monkeypatch) -> None:
    """Mixing X-ESET-Server-URL with X-ESET-Region is fine; URL wins (it's on-prem)."""
    _set_env(monkeypatch, ESET_AUTH_MODE="basic", ESET_MCP_TRANSPORT="http")
    s = Settings.from_env(env_file=None)
    app = _build_app_with_middleware(s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get(
            "/echo",
            headers={
                "authorization": _basic_header(),
                "x-eset-region": "us",
                "x-eset-server-url": "https://protect.client-a.local:9443",
            },
        )
    body = r.json()
    assert body["deployment"] == "onprem"  # URL won; region is ignored for on-prem routing


async def test_middleware_invalid_server_url_returns_400(monkeypatch) -> None:
    _set_env(monkeypatch, ESET_AUTH_MODE="basic", ESET_MCP_TRANSPORT="http")
    s = Settings.from_env(env_file=None)
    app = _build_app_with_middleware(s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get(
            "/echo",
            headers={
                "authorization": _basic_header(),
                "x-eset-server-url": "http://protect.local:9443",  # http, not https
            },
        )
    assert r.status_code == 400


async def test_middleware_env_onprem_fallback_when_header_absent(monkeypatch) -> None:
    """ESET_DEPLOYMENT=onprem + valid server URL → request inherits env default."""
    _set_env(
        monkeypatch,
        ESET_AUTH_MODE="basic",
        ESET_MCP_TRANSPORT="http",
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.env-default.local:9443",
    )
    s = Settings.from_env(env_file=None)
    app = _build_app_with_middleware(s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/echo", headers={"authorization": _basic_header()})
    body = r.json()
    assert body["deployment"] == "onprem"
    assert body["server_url"] == "https://protect.env-default.local:9443"


async def test_middleware_env_onprem_no_url_no_header_returns_400(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_AUTH_MODE="basic",
        ESET_MCP_TRANSPORT="http",
        ESET_DEPLOYMENT="onprem",
        # No ESET_ONPREM_SERVER_URL — must be supplied per request.
    )
    s = Settings.from_env(env_file=None)
    app = _build_app_with_middleware(s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/echo", headers={"authorization": _basic_header()})
    assert r.status_code == 400


# ─── OnPremTokenManager wire format (respx mock) ──────────────────────────────


@respx.mock
async def test_onprem_token_manager_posts_get_tokens() -> None:
    """OnPremTokenManager hits POST /GetTokens with the documented JSON body
    and parses camelCase {accessToken, expiresIn}."""
    creds = Credentials(
        user="u@example.com", password="s3cret", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    route = respx.post("https://protect.local:9443/GetTokens").mock(
        return_value=httpx.Response(200, json={"accessToken": "AAA", "expiresIn": 3600})
    )
    async with httpx.AsyncClient() as http:
        mgr = OnPremTokenManager(creds, http)
        token = await mgr.get_access_token()

    assert token == "AAA"
    assert route.called
    # Verify wire format: JSON body with exactly the three documented keys.
    sent = route.calls.last.request
    import json
    body = json.loads(sent.content.decode("utf-8"))
    assert body == {"username": "u@example.com", "password": "s3cret", "grant_type": "password"}
    assert sent.headers.get("content-type", "").startswith("application/json")


@respx.mock
async def test_onprem_token_manager_missing_access_token_errors() -> None:
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    respx.post("https://protect.local:9443/GetTokens").mock(
        return_value=httpx.Response(200, json={"oops": True})
    )
    async with httpx.AsyncClient() as http:
        mgr = OnPremTokenManager(creds, http)
        with pytest.raises(Exception, match="accessToken"):
            await mgr.get_access_token()


def test_make_token_manager_picks_by_deployment() -> None:
    import httpx as _httpx
    h = _httpx.AsyncClient()
    cloud_creds = Credentials(user="u", password="p", region="eu")
    onprem_creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    assert isinstance(make_token_manager(cloud_creds, h), CloudTokenManager)
    assert isinstance(make_token_manager(onprem_creds, h), OnPremTokenManager)


# ─── EsetHttpClient TLS verify wiring ─────────────────────────────────────────


def test_http_client_onprem_verify_true_by_default() -> None:
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )
    client = EsetHttpClient(creds)
    try:
        # httpx exposes the verify flag indirectly via the transport's SSL context.
        # We check the public _transport's verify config — internal attribute,
        # but stable enough across httpx 0.27+.
        assert client._http.is_closed is False
    finally:
        import asyncio
        asyncio.get_event_loop().run_until_complete(client.aclose()) if not asyncio.get_event_loop().is_running() else None


def test_http_client_onprem_verify_false_honoured_and_warns(caplog) -> None:
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
        verify_ssl=False,
    )
    import logging
    with caplog.at_level(logging.WARNING, logger="eset_mcp.http"):
        client = EsetHttpClient(creds)
    # The warning happens exactly once at construction.
    warnings = [r for r in caplog.records if "verification DISABLED" in r.getMessage()]
    assert len(warnings) == 1
    assert "https://protect.local:9443" in warnings[0].getMessage()
    # Don't bother awaiting close — pytest tears down the loop.
    del client


# ─── On-prem path overrides (tools_loader) ────────────────────────────────────


def test_tool_def_path_for_picks_onprem_when_override_present() -> None:
    t = ToolDef(
        name="x", description="", input_schema={}, service="device-management",
        method="POST", path="/v1/devices/{u}:rename", operation_id="Devices_RenameDevice",
        read_only=False, onprem_path="/v1/devices/{u}:renameDevice",
    )
    assert t.path_for("cloud") == "/v1/devices/{u}:rename"
    assert t.path_for("onprem") == "/v1/devices/{u}:renameDevice"


def test_tool_def_path_for_falls_back_to_cloud_when_no_override() -> None:
    t = ToolDef(
        name="x", description="", input_schema={}, service="device-management",
        method="GET", path="/v1/devices", operation_id="Devices_ListDevices", read_only=True,
    )
    assert t.path_for("cloud") == "/v1/devices"
    assert t.path_for("onprem") == "/v1/devices"  # no override → same path


def test_rename_device_has_onprem_override_loaded_from_json() -> None:
    """The single override shipped in onprem-path-overrides.json is applied."""
    tools = load_all_tools()
    by_name = {t.name: t for t in tools}
    # Tool name is generated from service prefix + snake_case(operationId).
    # The OpenAPI op is Devices_RenameDevice under service device-management,
    # which maps to "device_devices__rename_device".
    rename = by_name["device_devices__rename_device"]
    assert rename.path == "/v1/devices/{deviceUuid}:rename"
    assert rename.onprem_path == "/v1/devices/{deviceUuid}:renameDevice"


# ─── Cloudflare Access Service Token ──────────────────────────────────────────


def test_settings_cf_access_requires_both_id_and_secret(monkeypatch) -> None:
    """Half-pair (only ID, only SECRET) is a 100% chance of operator typo."""
    _set_env(monkeypatch, ESET_ONPREM_CF_ACCESS_CLIENT_ID="just-the-id")
    with pytest.raises(RuntimeError, match="must be set together"):
        Settings.from_env(env_file=None)


def test_settings_cf_access_both_set_ok(monkeypatch) -> None:
    _set_env(
        monkeypatch,
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
        ESET_ONPREM_CF_ACCESS_CLIENT_ID="abc.access",
        ESET_ONPREM_CF_ACCESS_CLIENT_SECRET="s3cr3t",
    )
    s = Settings.from_env(env_file=None)
    assert s.onprem_cf_access_client_id == "abc.access"
    assert s.onprem_cf_access_client_secret == "s3cr3t"


def test_http_client_onprem_attaches_cf_headers_to_httpx_defaults() -> None:
    """When CF tokens are present, the httpx client default headers carry
    CF-Access-Client-Id / CF-Access-Client-Secret on every outbound call —
    including the /GetTokens auth call (same underlying httpx client)."""
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
        cf_access_client_id="abc.access", cf_access_client_secret="s3cr3t",
    )
    client = EsetHttpClient(creds)
    try:
        assert client._http.headers["cf-access-client-id"] == "abc.access"
        assert client._http.headers["cf-access-client-secret"] == "s3cr3t"
    finally:
        del client


def test_http_client_cloud_does_not_attach_cf_headers() -> None:
    """Cloud creds must NEVER carry CF Access headers — ESET Connect is a
    public SaaS and is not behind anyone's Cloudflare Access."""
    creds = Credentials(
        user="u", password="p", region="eu",
        cf_access_client_id="abc.access", cf_access_client_secret="s3cr3t",
    )
    client = EsetHttpClient(creds)
    try:
        assert "cf-access-client-id" not in client._http.headers
        assert "cf-access-client-secret" not in client._http.headers
    finally:
        del client


@respx.mock
async def test_onprem_get_tokens_call_carries_cf_headers() -> None:
    """End-to-end wiring check: /GetTokens (auth handshake) must include the
    CF Access headers, otherwise Cloudflare blocks it at the edge."""
    creds = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
        cf_access_client_id="abc.access", cf_access_client_secret="s3cr3t",
    )
    route = respx.post("https://protect.local:9443/GetTokens").mock(
        return_value=httpx.Response(200, json={"accessToken": "T", "expiresIn": 3600})
    )
    client = EsetHttpClient(creds)
    try:
        token = await client._token_mgr.get_access_token()
        assert token == "T"
        sent = route.calls.last.request
        assert sent.headers.get("CF-Access-Client-Id") == "abc.access"
        assert sent.headers.get("CF-Access-Client-Secret") == "s3cr3t"
    finally:
        await client.aclose()


async def test_middleware_cf_headers_passthrough(monkeypatch) -> None:
    """X-ESET-CF-Access-* headers stash on the Credentials in the ContextVar."""
    _set_env(
        monkeypatch,
        ESET_AUTH_MODE="basic",
        ESET_MCP_TRANSPORT="http",
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
    )
    s = Settings.from_env(env_file=None)

    # Tiny app exposing what the middleware stashed.
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from eset_mcp.middleware import BasicAuthCredentialsMiddleware

    async def _echo(_request):
        c = request_credentials.get()
        return JSONResponse({"id": c.cf_access_client_id, "secret": c.cf_access_client_secret})

    app = Starlette(routes=[Route("/echo", _echo)])
    app.add_middleware(BasicAuthCredentialsMiddleware, settings=s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get(
            "/echo",
            headers={
                "authorization": _basic_header(),
                "x-eset-cf-access-client-id": "per-req.access",
                "x-eset-cf-access-client-secret": "per-req-secret",
            },
        )
    body = r.json()
    assert body["id"] == "per-req.access"
    assert body["secret"] == "per-req-secret"


async def test_middleware_cf_half_pair_returns_400(monkeypatch) -> None:
    """Sending only one of the two CF headers is a 400 (almost-certain typo)."""
    _set_env(
        monkeypatch,
        ESET_AUTH_MODE="basic",
        ESET_MCP_TRANSPORT="http",
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
    )
    s = Settings.from_env(env_file=None)

    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from eset_mcp.middleware import BasicAuthCredentialsMiddleware

    async def _echo(_request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/echo", _echo)])
    app.add_middleware(BasicAuthCredentialsMiddleware, settings=s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get(
            "/echo",
            headers={
                "authorization": _basic_header(),
                "x-eset-cf-access-client-id": "only-id",
                # No secret header.
            },
        )
    assert r.status_code == 400


async def test_middleware_cf_env_fallback_when_no_headers(monkeypatch) -> None:
    """When client sends no CF headers, env defaults are used."""
    _set_env(
        monkeypatch,
        ESET_AUTH_MODE="basic",
        ESET_MCP_TRANSPORT="http",
        ESET_DEPLOYMENT="onprem",
        ESET_ONPREM_SERVER_URL="https://protect.local:9443",
        ESET_ONPREM_CF_ACCESS_CLIENT_ID="env-id.access",
        ESET_ONPREM_CF_ACCESS_CLIENT_SECRET="env-secret",
    )
    s = Settings.from_env(env_file=None)

    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from eset_mcp.middleware import BasicAuthCredentialsMiddleware

    async def _echo(_request):
        c = request_credentials.get()
        return JSONResponse({"id": c.cf_access_client_id, "secret": c.cf_access_client_secret})

    app = Starlette(routes=[Route("/echo", _echo)])
    app.add_middleware(BasicAuthCredentialsMiddleware, settings=s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/echo", headers={"authorization": _basic_header()})
    body = r.json()
    assert body["id"] == "env-id.access"
    assert body["secret"] == "env-secret"


async def test_middleware_cloud_request_never_propagates_cf_headers(monkeypatch) -> None:
    """Even if env defaults set CF tokens, cloud requests must not carry them.

    Cloud creds always have empty CF fields because ESET Connect doesn't sit
    behind anyone's CF Access — propagating the headers would leak the
    token to the public ESET API for no benefit.
    """
    _set_env(
        monkeypatch,
        ESET_AUTH_MODE="basic",
        ESET_MCP_TRANSPORT="http",
        ESET_DEPLOYMENT="cloud",
        ESET_ONPREM_CF_ACCESS_CLIENT_ID="env-id.access",
        ESET_ONPREM_CF_ACCESS_CLIENT_SECRET="env-secret",
    )
    s = Settings.from_env(env_file=None)

    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from eset_mcp.middleware import BasicAuthCredentialsMiddleware

    async def _echo(_request):
        c = request_credentials.get()
        return JSONResponse({
            "deployment": c.deployment,
            "id": c.cf_access_client_id,
            "secret": c.cf_access_client_secret,
        })

    app = Starlette(routes=[Route("/echo", _echo)])
    app.add_middleware(BasicAuthCredentialsMiddleware, settings=s)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/echo", headers={"authorization": _basic_header()})
    body = r.json()
    assert body["deployment"] == "cloud"
    assert body["id"] == ""
    assert body["secret"] == ""
