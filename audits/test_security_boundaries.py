"""Regression tests for reproduced baseline flaws (now required to pass).

Original results and immutable business contracts remain in audits/.
All tokens, passwords, tenant names and upstream responses here are synthetic.
"""
from __future__ import annotations

import base64
import json
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp import Client
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from eset_mcp.__main__ import _serve_http
from eset_mcp.auth import Token
from eset_mcp.client_pool import ClientPool
from eset_mcp.config import Settings
from eset_mcp.credentials import (
    BasicAuthCredentialResolver,
    Credentials,
    EnvCredentialResolver,
    request_credentials,
)
from eset_mcp.http_client import EsetHttpClient
from eset_mcp.middleware import BasicAuthCredentialsMiddleware
from eset_mcp.observability.logging import _JsonFormatter, _TextFormatter
from eset_mcp.server import build_server
from eset_mcp.tools_loader import load_all_tools

SECRET = "AUDIT_ONLY_SECRET_8932"
AUTH_URL = "https://eu.business-account.iam.eset.systems/oauth/token"
GROUPS_URL = "https://eu.device-management.eset.systems/v1/device_groups"
GROUP_TOOL = next(t.name for t in load_all_tools() if t.path == "/v1/device_groups" and t.method == "GET")
AUTH_TOOL = "auth_o_auth__token"


def settings(**overrides):
    # Deliberately bypass Settings.from_env and all .env discovery.
    return replace(Settings(
        user="audit-user", password="audit-password", mode="RO", region="eu",
        transport="http", http_host="127.0.0.1", http_port=8765,
        log_level="WARNING", auth_mode="env", response_bytes_max=100000,
        deployment="cloud", onprem_server_url="", onprem_verify_ssl=True,
        onprem_cf_access_client_id="", onprem_cf_access_client_secret="",
        log_format="text", metrics_enabled=False, metrics_path="/metrics", http_allowed_hosts=("audit",),
    ), **overrides)


def mock_auth(offline):
    return offline.post(AUTH_URL).respond(200, json={
        "access_token": SECRET, "refresh_token": "AUDIT_ONLY_REFRESH", "expires_in": 3600,
    })


@asynccontextmanager
async def memory_client(**overrides):
    config = settings(**overrides)
    pool = ClientPool(config)
    try:
        server = build_server(config, pool, EnvCredentialResolver(config))
        async with Client(server, cache=None) as client:
            yield client
    finally:
        await pool.close()


async def test_authentication_not_in_model_catalog():
    async with memory_client(mode="RW") as client:
        catalog = await client.list_tools()
    assert AUTH_TOOL not in {tool.name for tool in catalog.tools}


async def test_ro_blocks_auth_tool_without_upstream_request(offline):
    async with memory_client() as client:
        result = await client.call_tool(AUTH_TOOL, {})
    assert result.is_error
    assert "Invalid tool" in result.content[0].text
    assert not offline.calls


async def test_error_body_never_returns_token(offline):
    mock_auth(offline)
    offline.get(GROUPS_URL).respond(400, json={"diagnostic": f"Bearer {SECRET}"})
    async with memory_client() as client:
        result = await client.call_tool(GROUP_TOOL, {})
    assert SECRET not in result.model_dump_json()


async def test_success_body_never_returns_token(offline):
    mock_auth(offline)
    offline.get(GROUPS_URL).respond(200, json={"deviceGroups": [{
        "uuid": "audit-group", "metadata": {"accessToken": SECRET},
    }]})
    async with memory_client() as client:
        result = await client.call_tool(GROUP_TOOL, {})
    assert SECRET not in result.model_dump_json()


async def test_composite_error_never_returns_token(offline):
    mock_auth(offline)
    offline.get("https://eu.device-management.eset.systems/v1/devices/audit-device").respond(
        400, json={"diagnostic": SECRET},
    )
    async with memory_client() as client:
        result = await client.call_tool("device_full_profile", {"deviceUuid": "audit-device"})
    assert SECRET not in result.model_dump_json()


async def test_upstream_error_sets_is_error(offline):
    mock_auth(offline)
    offline.get(GROUPS_URL).respond(403, json={"message": "permission denied"})
    async with memory_client() as client:
        result = await client.call_tool(GROUP_TOOL, {})
    assert result.is_error


async def test_401_replaces_rejected_unexpired_token(offline):
    route = offline.post(AUTH_URL).respond(200, json={"access_token": "NEW", "expires_in": 3600})
    seen = []

    def reply(request):
        seen.append(request.headers["authorization"])
        if request.headers["authorization"] == "Bearer OLD":
            return httpx.Response(401, json={"message": "revoked"})
        return httpx.Response(200, json={"deviceGroups": []})

    offline.get(GROUPS_URL).mock(side_effect=reply)
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        client._token_mgr._token = Token("OLD", None, time.time() + 3600)
        try:
            await client.request("GET", "device-management", "/v1/device_groups")
        except Exception:
            pass  # Assert the actual wire behavior below, not an incidental exception.
    assert route.call_count == 1, f"refresh calls={route.call_count}, authorization sequence={seen}"
    assert seen == ["Bearer OLD", "Bearer NEW"]


@pytest.mark.parametrize("formatter", [_JsonFormatter, _TextFormatter])
def test_log_nested_values_are_sanitized(formatter):
    record = logging.LogRecord("audit", logging.WARNING, __file__, 1, "upstream failure", (), None)
    record.payload = {"authorization": f"Bearer {SECRET}"}
    assert SECRET not in formatter().format(record)


async def test_unapproved_origin_does_not_receive_default_cf_secret(offline):
    config = settings(auth_mode="basic", onprem_cf_access_client_id="audit-cf-id",
                      onprem_cf_access_client_secret=SECRET)
    captured = []

    def upstream(request):
        captured.append(request)
        return httpx.Response(200, json={"accessToken": "AUDIT_ONLY_ONPREM", "expiresIn": 3600})

    offline.post("https://unapproved.invalid/GetTokens").mock(side_effect=upstream)

    async def handler(request):
        async with EsetHttpClient(request_credentials.get()) as client:
            await client._token_mgr.get_access_token()
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/probe", handler)])
    app.add_middleware(BasicAuthCredentialsMiddleware, settings=config)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://audit") as client:
        await client.get("/probe", headers={
            "Authorization": basic("arbitrary", "not-an-eset-password"),
            "X-ESET-Server-URL": "https://unapproved.invalid",
        })
    assert not any(SECRET in str(request.headers) for request in captured)


def basic(user, password="audit-password"):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


@asynccontextmanager
async def production_http_app(monkeypatch):
    import uvicorn
    config = settings(auth_mode="basic")
    pool = ClientPool(config)
    server = build_server(config, pool, BasicAuthCredentialResolver(config))
    captured = {}

    class CaptureServer:
        def __init__(self, config):
            captured["app"] = config.app

        async def serve(self):
            pass

    monkeypatch.setattr(uvicorn, "Server", CaptureServer)
    try:
        await _serve_http(config, server)
        app = captured["app"]
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://audit") as client:
                yield client
    finally:
        await pool.close()


def rpc(response):
    assert response.status_code == 200, response.text
    if response.headers["content-type"].startswith("application/json"):
        return response.json()
    return json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith("data: ")))


async def initialize(client, user, region):
    headers = {"Authorization": basic(user), "X-ESET-Region": region,
               "Accept": "application/json, text/event-stream"}
    response = await client.post("/mcp/", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "offline-audit", "version": "1"},
        },
    })
    rpc(response)
    headers["Mcp-Session-Id"] = response.headers["mcp-session-id"]
    headers["Mcp-Protocol-Version"] = "2025-11-25"
    await client.post("/mcp/", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    return headers


async def test_http_session_cannot_be_reused_as_another_principal(monkeypatch):
    async with production_http_app(monkeypatch) as client:
        headers = await initialize(client, "tenant-a", "eu")
        headers.update({"Authorization": basic("tenant-b"), "X-ESET-Region": "us"})
        response = await client.post("/mcp/", headers=headers, json={
            "jsonrpc": "2.0", "id": 2, "method": "resources/read",
            "params": {"uri": "eset://config/region"},
        })
    assert response.status_code in (401, 403), f"status={response.status_code}, response={response.text}"


async def test_http_distinct_sessions_keep_regions_separate(monkeypatch):
    async with production_http_app(monkeypatch) as client:
        a = await initialize(client, "tenant-a", "eu")
        b = await initialize(client, "tenant-b", "us")
        for headers, expected in [(a, "eu"), (b, "us")]:
            response = await client.post("/mcp/", headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "resources/read",
                "params": {"uri": "eset://config/region"},
            })
            assert rpc(response)["result"]["contents"][0]["text"] == expected


async def test_http_tool_cannot_use_session_creators_account(monkeypatch, offline):
    auth = mock_auth(offline)
    groups = offline.get(GROUPS_URL).respond(200, json={"deviceGroups": [{"owner": "tenant-a"}]})
    async with production_http_app(monkeypatch) as client:
        headers = await initialize(client, "tenant-a", "eu")
        headers["Authorization"] = basic("tenant-b", "invalid-password")
        response = await client.post("/mcp/", headers=headers, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": GROUP_TOOL, "arguments": {}},
        })
    if response.status_code == 200:
        # Explicit evidence: the backend login used A despite HTTP credentials B.
        assert auth.call_count == 1 and groups.call_count == 1
        from urllib.parse import parse_qs
        sent = parse_qs(auth.calls.last.request.content.decode())
        assert sent["username"] == ["tenant-a"], sent
    assert response.status_code in (401, 403), response.text


async def test_onprem_auth_uses_documented_grant_type(offline):
    route = offline.post("https://protect.invalid:9443/GetTokens").respond(
        200, json={"accessToken": "AUDIT_ONLY", "refreshToken": "AUDIT_ONLY_REFRESH", "expiresIn": 3600},
    )
    async with EsetHttpClient(Credentials("u", "p", "eu", deployment="onprem",
                                         server_url="https://protect.invalid:9443", onprem_auth_style="v13")) as client:
        await client._token_mgr.get_access_token()
    body = json.loads(route.calls.last.request.content)
    assert body.get("grantType") == "PASSWORD", body
    assert "grant_type" not in body


async def test_202_poll_preserves_method_query_body_and_response_id(monkeypatch, offline):
    mock_auth(offline)
    monkeypatch.setattr("eset_mcp.transport.asyncio.sleep", AsyncMock())
    route = offline.post("https://eu.automation.eset.systems/v1/tasks").mock(side_effect=[
        httpx.Response(202, headers={"response-id": "audit-pending"}),
        httpx.Response(202), httpx.Response(200, json={"uuid": "audit-job"}),
    ])
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        result = await client.request("POST", "automation", "/v1/tasks",
                                      query={"filter": "name eq 'a b'"}, json={"name": "audit"})
    assert result == {"uuid": "audit-job"}
    requests = [call.request for call in route.calls]
    assert len(requests) == 3
    assert all(r.method == requests[0].method and r.url == requests[0].url and
               r.content == requests[0].content for r in requests)
    assert all(r.headers["response-id"] == "audit-pending" for r in requests[1:])


async def test_429_preserves_request_and_honors_retry_after(monkeypatch, offline):
    mock_auth(offline)
    sleep = AsyncMock()
    monkeypatch.setattr("eset_mcp.transport.asyncio.sleep", sleep)
    route = offline.get(GROUPS_URL).mock(side_effect=[
        httpx.Response(429, headers={"Retry-After": "0.01"}),
        httpx.Response(200, json={"deviceGroups": []}),
    ])
    async with EsetHttpClient(Credentials("u", "p", "eu")) as client:
        await client.request("GET", "device-management", "/v1/device_groups", query={"pageSize": 3})
    assert route.call_count == 2
    assert route.calls[0].request.url == route.calls[1].request.url
    sleep.assert_awaited_once_with(0.01)
