"""Synthetic canaries, failure state machines and connection policy boundaries."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import socket
import sys
import time
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, quote

import httpcore
import httpx
import pytest

from audits.test_security_boundaries import (
    AUTH_URL,
    GROUP_TOOL,
    GROUPS_URL,
    SECRET,
    memory_client,
    mock_auth,
    settings,
)
from eset_mcp.auth import Token
from eset_mcp.client_pool import ClientPool
from eset_mcp.config import _normalize_server_url, _parse_metrics_path, _parse_origins
from eset_mcp.credentials import Credentials
from eset_mcp.egress import GuardedBackend
from eset_mcp.errors import EsetApiError
from eset_mcp.http_client import EsetHttpClient
from eset_mcp.observability.logging import _JsonFormatter, _TextFormatter
from eset_mcp.security import clean_output, path_segment, secret_scope
from eset_mcp.transport import parse_retry_after


@pytest.mark.parametrize("variant", ["access_token", "refreshToken", "Authorization", "CLIENT-secret", "Set-Cookie", "api_key", "CF-Access-Client-Id"])
def test_recursive_structural_redaction(variant):
    output = clean_output({"records": [{"metadata": {variant: SECRET}}], "nextPageToken": "keep-cursor", "enabled": False})
    assert SECRET not in json.dumps(output)
    assert output["nextPageToken"] == "keep-cursor" and output["enabled"] is False


@pytest.mark.parametrize("formatter", [_JsonFormatter, _TextFormatter])
def test_logs_filter_known_values_in_message_exception_and_nested_payload(formatter):
    with secret_scope() as secrets:
        secrets.add(SECRET)
        try:
            raise RuntimeError("upstream opaque diagnostic " + SECRET)
        except RuntimeError:
            record = logging.LogRecord("audit", logging.ERROR, __file__, 1, "diagnostic %s", (SECRET,), sys.exc_info())
        record.payload = {"nested": [{"opaque": SECRET, "password": "UNKNOWN_PASSWORD"}]}
        output = formatter().format(record)
        assert SECRET not in output and "UNKNOWN_PASSWORD" not in output


def test_known_values_encodings_and_independent_secret_scopes():
    secret = 'CANARY &+ąć"\\'
    with secret_scope() as secrets:
        secrets.add(secret)
        values = [secret, quote(secret, safe=""), base64.b64encode(secret.encode()).decode(), json.dumps(secret)[1:-1]]
        assert all(clean_output("prefix " + value + " suffix") == "prefix [REDACTED] suffix" for value in values)
    assert clean_output(secret) == secret


def test_credentials_token_settings_reprs_never_include_passwords():
    assert SECRET not in repr(Credentials("u", SECRET, "eu", cf_access_client_secret=SECRET))
    assert SECRET not in repr(Token(SECRET, SECRET, 1))
    assert SECRET not in repr(settings(password=SECRET, onprem_cf_access_client_secret=SECRET))


@pytest.mark.parametrize("status", [200, 400, 401, 403, 404, 429, 500, 503])
async def test_api_canary_never_crosses_full_model_boundary(status, monkeypatch, offline):
    monkeypatch.setattr("eset_mcp.transport.asyncio.sleep", AsyncMock())
    mock_auth(offline)
    offline.get(GROUPS_URL).respond(status, headers={"request-id": SECRET}, json={
        "deviceGroups": [{"uuid": "safe", "opaque": SECRET, "token": "UNKNOWN_ACCESS_TOKEN"}],
    })
    async with memory_client() as client:
        result = await client.call_tool(GROUP_TOOL, {})
    serialized = result.model_dump_json()
    assert SECRET not in serialized and "UNKNOWN_ACCESS_TOKEN" not in serialized
    assert result.is_error == (status != 200)


@pytest.mark.parametrize("arguments", [{"pageSize": "wrong"}, {"surprise": SECRET}, {"fields": SECRET}])
async def test_invalid_schema_never_reaches_api(arguments, offline):
    async with memory_client() as client:
        result = await client.call_tool(GROUP_TOOL, arguments)
    assert result.is_error and not offline.calls


@pytest.mark.parametrize("value", ["..", ".", "a/b", "a\\b", "%2e%2e", "%252e%252e", "%2FGetTokens", "a?b", "a#b", "a\rb", "a\x00b"])
async def test_path_injection_rejected_without_authentication(value, offline):
    async with memory_client() as client:
        result = await client.call_tool("device_full_profile", {"deviceUuid": value})
    assert result.is_error and not offline.calls


def test_path_segment_preserves_ids_and_encodes_safe_special_characters():
    assert path_segment("A-a_12.3~") == "A-a_12.3~"
    assert path_segment("urządzenie 1:2") == "urz%C4%85dzenie%201%3A2"


@pytest.mark.parametrize("url", ["http://host", "https://u:p@host", "https://host/path", "https://host?token=x", "https://host#x", "https://host:0", "https://host:65536", "https://host:abc", "https://host\\@evil", "https://ho\nst", "https://%31%32%37.0.0.1", "https://[fe80::1%25lo0]"])
def test_origin_normalization_rejects_ambiguous_authorities(url):
    with pytest.raises(RuntimeError):
        _normalize_server_url(url)


def test_origin_normalization_and_per_user_configuration():
    assert _normalize_server_url("https://PrOtEcT.Example.:443/") == "https://protect.example"
    assert _normalize_server_url("https://[2001:db8::1]:9443") == "https://[2001:db8::1]:9443"
    assert _parse_origins('{"u":["https://PROTECT.example:443/"]}') == {"u": ("https://protect.example",)}
    for value in ['{"*":["https://host"]}', '[]', '{"u":"https://host"}']:
        with pytest.raises(RuntimeError):
            _parse_origins(value)


@pytest.mark.parametrize("path", ["/", "/mcp", "/mcp/", "/MCP", "/mcp/other", "/metrics/../mcp", "//metrics", "/metrics?x"])
def test_metrics_route_cannot_bypass_mcp_auth(path):
    with pytest.raises(RuntimeError):
        _parse_metrics_path(path)


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "::ffff:127.0.0.1", "::"])
def test_special_networks_denied_by_default(ip):
    assert not GuardedBackend(()).allows(ip)


def test_private_network_and_explicit_cidr_policy():
    assert GuardedBackend(()).allows("10.1.2.3")
    assert GuardedBackend(("127.0.0.1/32",)).allows("127.0.0.1")
    assert not GuardedBackend(("10.1.0.0/16",)).allows("10.2.0.1")


async def test_dns_validated_once_then_ip_pinned(monkeypatch):
    backend = GuardedBackend(())
    dns = AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 9443))])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", dns)
    backend._backend = AsyncMock()
    await backend.connect_tcp("protect.invalid", 9443, timeout=5)
    dns.assert_awaited_once()
    assert backend._backend.connect_tcp.await_args.args == ("10.1.2.3", 9443)


async def test_mixed_dns_answers_fail_closed_before_connect(monkeypatch):
    backend = GuardedBackend(())
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 9443)) for ip in ("10.1.2.3", "169.254.169.254")]))
    backend._backend = AsyncMock()
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("protect.invalid", 9443)
    backend._backend.connect_tcp.assert_not_awaited()


@pytest.mark.parametrize("deployment,style", [("cloud", "legacy"), ("onprem", "legacy"), ("onprem", "v13")])
async def test_authentication_202_429_preserves_exact_login_request(deployment, style, monkeypatch, offline):
    monkeypatch.setattr("eset_mcp.transport.asyncio.sleep", AsyncMock())
    creds = Credentials("user+ąć", "p&= +", "eu", deployment=deployment,
                        server_url="https://protect.invalid", onprem_auth_style=style)
    url = AUTH_URL if deployment == "cloud" else "https://protect.invalid/GetTokens"
    payload = {"access_token": "ACCESS", "expires_in": 3600} if deployment == "cloud" else {"accessToken": "ACCESS", "expiresIn": 3600}
    route = offline.post(url).mock(side_effect=[httpx.Response(202, headers={"response-id": "pending"}),
                                               httpx.Response(429, headers={"Retry-After": "0"}),
                                               httpx.Response(202), httpx.Response(200, json=payload)])
    async with EsetHttpClient(creds) as client:
        assert await client._token_mgr.get_access_token() == "ACCESS"
    requests = [c.request for c in route.calls]
    assert len(requests) == 4
    assert all((r.url, r.method, r.content) == (requests[0].url, "POST", requests[0].content) for r in requests)
    assert all(r.headers["response-id"] == "pending" for r in requests[1:])
    if deployment == "cloud":
        assert parse_qs(requests[0].content.decode())["password"] == [creds.password]
    else:
        body = json.loads(requests[0].content)
        assert body == {"username": creds.user, "password": creds.password,
                        **({"grantType": "PASSWORD"} if style == "v13" else {"grant_type": "password"})}


@pytest.mark.parametrize("deployment", ["cloud", "onprem"])
async def test_refresh_invalid_grant_falls_back_once_and_preserves_later_refresh(deployment, offline):
    creds = Credentials("u", "pw", "eu", deployment=deployment, server_url="https://protect.invalid", onprem_auth_style="v13")
    cloud = deployment == "cloud"
    url = AUTH_URL if cloud else "https://protect.invalid/GetTokens"
    access, refresh, expiry = ("access_token", "refresh_token", "expires_in") if cloud else ("accessToken", "refreshToken", "expiresIn")
    route = offline.post(url).mock(side_effect=[httpx.Response(400, json={"error": "invalid_grant"}),
                                               httpx.Response(200, json={access: "NEW", refresh: "NEW_REFRESH", expiry: 3600}),
                                               httpx.Response(200, json={access: "NEWER", expiry: 3600})])
    async with EsetHttpClient(creds) as client:
        manager = client._token_mgr
        manager._token = Token("OLD", "OLD_REFRESH", time.time() - 1)
        assert await manager.get_access_token() == "NEW"
        assert await manager.force_refresh(rejected_token="NEW") == "NEWER"
        assert manager._token.refresh_token == "NEW_REFRESH"
    if cloud:
        bodies = [parse_qs(c.request.content.decode(), keep_blank_values=True) for c in route.calls]
        assert [b["grant_type"][0] for b in bodies] == ["refresh_token", "password", "refresh_token"]
    else:
        bodies = [json.loads(c.request.content) for c in route.calls]
        assert [b["grantType"] for b in bodies] == ["REFRESH_TOKEN", "PASSWORD", "REFRESH_TOKEN"]


async def test_fifty_rejected_fresh_tokens_cause_one_renewal(offline):
    route = offline.post(AUTH_URL).respond(200, json={"access_token": "NEW", "expires_in": 3600})
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        client._token_mgr._token = Token("OLD", None, time.time() + 3600)
        result = await asyncio.gather(*(client._token_mgr.force_refresh("OLD") for _ in range(50)))
    assert result == ["NEW"] * 50
    assert route.call_count == 1


@pytest.mark.parametrize("payload", [{}, [], {"access_token": ""}, {"access_token": "A\r\nB"},
                                     {"access_token": "A", "expires_in": 0}, {"access_token": "A", "expires_in": True},
                                     {"access_token": "A", "expires_in": "nan"}, {"access_token": "A", "refresh_token": {"token": SECRET}}])
async def test_malformed_auth_never_becomes_cached_token(payload, offline):
    offline.post(AUTH_URL).respond(200, json=payload)
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        with pytest.raises(EsetApiError) as exc:
            await client._token_mgr.get_access_token()
        assert client._token_mgr._token is None
    assert SECRET not in str(exc.value)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
@pytest.mark.parametrize("failure", [500, "timeout", "connection"])
async def test_mutations_not_replayed_after_ambiguous_failure(method, failure, offline):
    mock_auth(offline)
    route = offline.request(method, GROUPS_URL)
    if failure == 500:
        route.respond(500, text=SECRET)
    else:
        error = httpx.ReadTimeout if failure == "timeout" else httpx.ConnectError
        route.mock(side_effect=error(SECRET))
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        with pytest.raises(EsetApiError) as exc:
            await client.request(method, "device-management", "/v1/device_groups", json={"name": "fixture"})
    assert route.call_count == 1
    assert SECRET not in str(exc.value)


async def test_polling_can_refresh_and_rate_limit_without_changing_mutation(monkeypatch, offline):
    monkeypatch.setattr("eset_mcp.transport.asyncio.sleep", AsyncMock())
    auth = offline.post(AUTH_URL).respond(200, json={"access_token": "NEW", "expires_in": 3600})
    route = offline.post(GROUPS_URL).mock(side_effect=[httpx.Response(202, headers={"response-id": "pending"}),
                                                     httpx.Response(401), httpx.Response(429, headers={"Retry-After": "0"}),
                                                     httpx.Response(200, json={"ok": True})])
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        client._token_mgr._token = Token("OLD", None, time.time() + 3600)
        assert await client.request("POST", "device-management", "/v1/device_groups", query={"a": "x &+"}, json={"a": [1, False]}) == {"ok": True}
    assert auth.call_count == 1
    requests = [c.request for c in route.calls]
    assert len(requests) == 4
    assert all((r.method, r.url, r.content) == (requests[0].method, requests[0].url, requests[0].content) for r in requests)
    assert all(r.headers["response-id"] == "pending" for r in requests[1:])
    assert [r.headers["authorization"] for r in requests] == ["Bearer OLD", "Bearer OLD", "Bearer NEW", "Bearer NEW"]


@pytest.mark.parametrize("status,body", [(204, ""), (200, "not json"), (302, SECRET), (202, "")])
async def test_empty_invalid_redirect_and_missing_pending_id(status, body, offline):
    mock_auth(offline)
    route = offline.get(GROUPS_URL).respond(status, text=body, headers={"Location": "https://unapproved.invalid"})
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        if status == 204:
            assert await client.request("GET", "device-management", "/v1/device_groups") == {}
        else:
            with pytest.raises(EsetApiError):
                await client.request("GET", "device-management", "/v1/device_groups")
    assert route.call_count == 1


async def test_retry_after_beyond_budget_fails_without_early_retry(offline):
    mock_auth(offline)
    route = offline.get(GROUPS_URL).respond(429, headers={"Retry-After": "3600"})
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        with pytest.raises(EsetApiError) as exc:
            await client.request("GET", "device-management", "/v1/device_groups")
    assert exc.value.status == 504 and route.call_count == 1


@pytest.mark.parametrize("raw,expected", [("nan", None), ("inf", None), ("-1", None), ("bad", None), ("0.25", .25), ("120", 120)])
def test_retry_after_safe_numeric_values(raw, expected):
    assert parse_retry_after(raw) == expected


async def test_leased_client_survives_eviction_and_shutdown():
    pool = ClientPool(settings(), max_clients=1)
    async with pool.acquire(Credentials("first", "pw", "eu")) as leased:
        await pool.get(Credentials("second", "pw", "eu"))
        await asyncio.sleep(0)
        assert not leased._http.is_closed
        await pool.close()
        assert not leased._http.is_closed
    await pool.close()
    assert leased._http.is_closed
    with pytest.raises(RuntimeError):
        await pool.get(Credentials("first", "pw", "eu"))


async def test_cancellation_releases_retired_client():
    pool = ClientPool(settings(), max_clients=1)
    ready = asyncio.Event()
    held = []

    async def work():
        async with pool.acquire(Credentials("first", "pw", "eu")) as client:
            held.append(client)
            ready.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(work())
    await ready.wait()
    await pool.get(Credentials("second", "pw", "eu"))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await pool.close()
    assert held[0]._http.is_closed and not pool._leases and not pool._retired


async def test_composite_failure_remains_error_when_body_is_capped(offline):
    mock_auth(offline)
    offline.get("https://eu.device-management.eset.systems/v1/devices/missing").respond(403, text=SECRET)
    async with memory_client(response_bytes_max=1) as client:
        result = await client.call_tool("device_full_profile", {"deviceUuid": "missing"})
    assert result.is_error and SECRET not in result.model_dump_json()


async def test_permitted_other_origin_never_inherits_default_cf_token(offline):
    from audits.test_mcp_2026 import app_client, call
    from audits.test_security_boundaries import basic

    route = offline.post("https://permitted.invalid/GetTokens").respond(200, json={"accessToken": "SECOND_ACCESS", "expiresIn": 3600})
    offline.get("https://permitted.invalid/v1/device_groups").respond(200, json={"deviceGroups": []})
    async with app_client(onprem_server_url="https://default.invalid", onprem_cf_access_client_id="default-id",
                          onprem_cf_access_client_secret=SECRET,
                          onprem_origins={"audit-user": ("https://permitted.invalid",)}) as (client, _):
        _, result = await call(client, "modern", {"Authorization": basic("audit-user"), "X-ESET-Server-URL": "https://permitted.invalid"},
                               "tools/call", {"name": GROUP_TOOL, "arguments": {}})
        assert not result["result"].get("isError")
    assert route.call_count == 1
    assert all("cf-access-client-secret" not in c.request.headers for c in offline.calls)
