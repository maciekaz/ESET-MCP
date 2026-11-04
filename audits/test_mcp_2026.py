"""Independent JSON-RPC wire probes, not an SDK client talking to itself."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest

from audits.capture_legacy import PAYLOAD, wire
from audits.test_security_boundaries import basic, rpc, settings
from eset_mcp.__main__ import create_http_app
from eset_mcp.client_pool import ClientPool
from eset_mcp.credentials import BasicAuthCredentialResolver
from eset_mcp.server import build_server
from eset_mcp.tools_loader import load_all_tools

BASELINE = json.loads(Path(__file__).with_name("legacy_execution.json").read_text())
VERSION = "2026-07-28"


def modern(method, params=None, *, version=VERSION):
    params = dict(params or {})
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "raw-offline-probe", "version": "1"},
    }
    headers = {"MCP-Protocol-Version": version, "MCP-Method": method,
               "Accept": "application/json, text/event-stream"}
    if "name" in params or "uri" in params:
        headers["MCP-Name"] = params.get("name", params.get("uri"))
    return headers, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


@asynccontextmanager
async def app_client(**overrides):
    config = settings(auth_mode="basic", **overrides)
    pool = ClientPool(config)
    app = create_http_app(config, build_server(config, pool, BasicAuthCredentialResolver(config)))
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://audit") as client:
                yield client, pool
    finally:
        await pool.close()


async def legacy_session(client, headers):
    response = await client.post("/mcp/", headers={**headers, "Accept": "application/json, text/event-stream"}, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "independent-legacy-probe", "version": "1"},
        },
    })
    assert rpc(response)["result"]["protocolVersion"] == "2025-11-25"
    headers = {**headers, "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-11-25", "MCP-Session-Id": response.headers["mcp-session-id"]}
    response = await client.post("/mcp/", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response.status_code == 202
    return headers


async def call(client, era, headers, method, params=None):
    if era == "modern":
        routing, body = modern(method, params)
    else:
        routing, body = {}, {"jsonrpc": "2.0", "id": 2, "method": method, "params": params or {}}
    response = await client.post("/mcp/", headers={**headers, **routing}, json=body)
    return response, rpc(response)


@pytest.mark.parametrize("era", ["legacy", "modern"])
@pytest.mark.parametrize("deployment", ["cloud", "onprem"])
async def test_all_101_calls_match_executed_original_server(era, deployment, offline):
    """Full MCP->validation->mapping->auth->HTTP->model path, 404 calls total."""
    cases = [c for c in BASELINE["cases"] if c["deployment"] == deployment and c.get("kind") != "composite"]
    assert len(cases) == 101
    requests = []

    def upstream(request):
        requests.append(wire(request))
        if request.url.path == "/oauth/token":
            return httpx.Response(200, json={"access_token": "fixture-access", "refresh_token": "fixture-refresh", "expires_in": 3600})
        if request.url.path == "/GetTokens":
            return httpx.Response(200, json={"accessToken": "fixture-access", "expiresIn": 3600})
        return httpx.Response(200, json=PAYLOAD)

    offline.route().mock(side_effect=upstream)
    async with app_client(mode="RW", deployment=deployment, onprem_server_url="https://protect.invalid:9443",
                          onprem_cf_access_client_id="fixture-cf-id", onprem_cf_access_client_secret="fixture-cf-secret") as (client, _):
        headers = {"Authorization": basic("fixture-user", "fixture-password")}
        if era == "legacy":
            headers = await legacy_session(client, headers)
        for case in cases:
            requests.clear()
            response, result = await call(client, era, headers, "tools/call", {"name": case["name"], "arguments": case["arguments"]})
            assert not result["result"].get("isError"), (case["name"], result)
            assert result["result"]["content"] == case["content"], case["name"]
            assert requests == case["requests"], case["name"]
            assert response.headers["cache-control"] == "no-store"
            if era == "modern":
                assert result["result"]["resultType"] == "complete"
                assert "mcp-session-id" not in response.headers


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_ro_hides_and_blocks_all_54_writes(era, offline):
    writes = [t for t in load_all_tools() if not t.read_only]
    assert len(writes) == 54
    async with app_client() as (client, _):
        headers = {"Authorization": basic("audit-user")}
        if era == "legacy":
            headers = await legacy_session(client, headers)
        _, catalog = await call(client, era, headers, "tools/list")
        assert len(catalog["result"]["tools"]) == 51  # 47 raw reads + 4 composites
        for tool in writes:
            _, result = await call(client, era, headers, "tools/call", {"name": tool.name, "arguments": {}})
            assert result["result"]["isError"]
            assert "RW" in result["result"]["content"][0]["text"]
    assert not offline.calls


async def test_modern_discovery_private_cache_and_request_metadata(offline):
    async with app_client() as (client, _):
        headers = {"Authorization": basic("audit-user")}
        _, discovery = await call(client, "modern", headers, "server/discover")
        assert VERSION in str(discovery["result"])
        for method, params in [("tools/list", {}), ("resources/list", {}), ("prompts/list", {}),
                               ("resources/read", {"uri": "eset://config/region"})]:
            _, result = await call(client, "modern", headers, method, params)
            assert result["result"]["cacheScope"] == "private"
            assert result["result"]["ttlMs"] == 0
        for user, region in [("tenant-a", "eu"), ("tenant-b", "us"), ("tenant-a", "de")]:
            _, result = await call(client, "modern", {"Authorization": basic(user), "X-ESET-Region": region},
                                   "resources/read", {"uri": "eset://config/region"})
            assert result["result"]["contents"][0]["text"] == region
    assert not offline.calls


@pytest.mark.parametrize("fault", ["version", "method", "name", "missing_meta", "missing_capabilities", "origin", "host", "auth", "body_size", "duplicate_version"])
async def test_modern_rejections_before_upstream(fault, offline):
    async with app_client() as (client, _):
        headers, body = modern("tools/call", {"name": "device_devices__list_devices", "arguments": {}})
        headers["Authorization"] = basic("audit-user")
        if fault == "version":
            headers, body = modern("tools/list", version="2099-01-01")
            headers["Authorization"] = basic("audit-user")
        elif fault == "method":
            headers["MCP-Method"] = "resources/list"
        elif fault == "name":
            headers["MCP-Name"] = "auth_o_auth__token"
        elif fault == "missing_meta":
            del body["params"]["_meta"]
        elif fault == "missing_capabilities":
            del body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
        elif fault == "origin":
            headers["Origin"] = "https://unapproved.invalid"
        elif fault == "host":
            headers["Host"] = "unapproved.invalid"
        elif fault == "auth":
            del headers["Authorization"]
        elif fault == "body_size":
            body["padding"] = "x" * (4 * 1024 * 1024 + 1)
        elif fault == "duplicate_version":
            headers = [*headers.items(), ("MCP-Protocol-Version", "2025-11-25")]
        response = await client.post("/mcp/", headers=headers, json=body)
        assert 400 <= response.status_code < 500, (fault, response.text)
        if fault == "version":
            assert response.json()["error"]["code"] == -32022
    assert not offline.calls


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_concurrent_requests_do_not_share_credentials_or_tokens(era, offline):
    from urllib.parse import parse_qs

    from audits.test_security_boundaries import GROUP_TOOL

    def upstream(request):
        if request.url.path == "/oauth/token":
            user = parse_qs(request.content.decode())["username"][0]
            return httpx.Response(200, json={"access_token": "ACCESS_" + user, "expires_in": 3600})
        # Deliberate opaque echo tests both isolation and request-local token redaction.
        user = request.headers["authorization"].removeprefix("Bearer ACCESS_")
        return httpx.Response(200, json={"owner": user, "echo": "ACCESS_" + user})

    offline.route().mock(side_effect=upstream)
    async with app_client() as (client, _):
        async def tenant(index):
            user = f"tenant-{index}"
            headers = {"Authorization": basic(user), "X-ESET-Region": "eu" if index % 2 else "us"}
            if era == "legacy":
                headers = await legacy_session(client, headers)
            _, result = await call(client, era, headers, "tools/call", {"name": GROUP_TOOL, "arguments": {}})
            payload = json.loads(result["result"]["content"][0]["text"])
            assert payload == {"owner": user, "echo": "[REDACTED]"}
            return payload["owner"]
        assert len(set(await asyncio.gather(*(tenant(i) for i in range(40))))) == 40


@pytest.mark.parametrize("era", ["legacy", "modern"])
@pytest.mark.parametrize("deployment", ["cloud", "onprem"])
async def test_composites_match_original_pagination_fanout_sorting(era, deployment, monkeypatch, offline):
    from audits.composite_fixture import FixedDateTime, composite_reply
    from audits.test_security_boundaries import GROUP_TOOL

    monkeypatch.setattr("eset_mcp.composite_tools.datetime", FixedDateTime)
    cases = [c for c in BASELINE["cases"] if c["deployment"] == deployment and c.get("kind") == "composite"]
    assert len(cases) == 4
    requests = []

    def upstream(request):
        requests.append(wire(request))
        if request.url.path == "/oauth/token":
            return httpx.Response(200, json={"access_token": "fixture-access", "expires_in": 3600})
        if request.url.path == "/GetTokens":
            return httpx.Response(200, json={"accessToken": "fixture-access", "expiresIn": 3600})
        return httpx.Response(200, json=composite_reply(request))

    offline.route().mock(side_effect=upstream)
    async with app_client(mode="RW", deployment=deployment, onprem_server_url="https://protect.invalid:9443",
                          onprem_cf_access_client_id="fixture-cf-id", onprem_cf_access_client_secret="fixture-cf-secret") as (client, _):
        headers = {"Authorization": basic("fixture-user", "fixture-password")}
        if era == "legacy":
            headers = await legacy_session(client, headers)
        await call(client, era, headers, "tools/call", {"name": GROUP_TOOL, "arguments": {}})
        for case in cases:
            requests.clear()
            _, result = await call(client, era, headers, "tools/call", {"name": case["name"], "arguments": case["arguments"]})
            assert not result["result"].get("isError"), case["name"]
            assert result["result"]["content"] == case["content"], case["name"]
            assert sorted(requests, key=json.dumps) == sorted(case["requests"], key=json.dumps), case["name"]
            payload = json.loads(result["result"]["content"][0]["text"])
            if case["name"] == "latest_detections":
                assert [d["uuid"] for d in payload["detections"]] == ["new", "older"]
            if case["name"] == "incident_full_context":
                assert len(payload["devices"]) == len(payload["detections"]) == 10
                assert payload["truncated"] == {"devices": True, "detections": True}
            if case["name"] == "eset_search":
                assert payload["total"] == 8 and all(v == 3 for v in payload["scanned"].values())


@pytest.mark.parametrize("change", ["user", "password", "region", "deployment", "origin", "cf_id", "cf_secret"])
async def test_legacy_session_binding_rejects_all_connection_identity_changes(change, offline):
    onprem = change in {"origin", "cf_id", "cf_secret"}
    async with app_client(onprem_server_url="https://default.invalid", onprem_cf_access_client_id="initial-cf-id",
                          onprem_cf_access_client_secret="initial-cf-secret",
                          onprem_origins={"audit-user": ("https://other.invalid",)}) as (client, _):
        headers = {"Authorization": basic("audit-user")}
        if onprem:
            headers["X-ESET-Server-URL"] = "https://default.invalid"
        headers = await legacy_session(client, headers)
        if change == "user":
            headers["Authorization"] = basic("other-user")
        elif change == "password":
            headers["Authorization"] = basic("audit-user", "rotated-password")
        elif change == "region":
            headers["X-ESET-Region"] = "us"
        elif change in {"origin", "deployment"}:
            headers["X-ESET-Server-URL"] = "https://other.invalid"
        else:
            headers["X-ESET-CF-Access-Client-Id"] = "changed-id" if change == "cf_id" else "initial-cf-id"
            headers["X-ESET-CF-Access-Client-Secret"] = "changed-secret" if change == "cf_secret" else "initial-cf-secret"
        response = await client.post("/mcp/", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert response.status_code == 403
    assert not offline.calls


async def test_modern_does_not_reuse_legacy_session_identity(offline):
    async with app_client() as (client, _):
        headers = await legacy_session(client, {"Authorization": basic("user-a")})
        headers.update(Authorization=basic("user-b"), **{"X-ESET-Region": "us"})
        _, result = await call(client, "modern", headers, "resources/read", {"uri": "eset://config/region"})
        assert result["result"]["contents"][0]["text"] == "us"
    assert not offline.calls


@pytest.mark.parametrize("header", ["Authorization", "X-ESET-Region", "X-ESET-Server-URL", "X-ESET-CF-Access-Client-Secret", "MCP-Session-Id"])
async def test_duplicate_credential_headers_rejected(header, offline):
    async with app_client() as (client, _):
        headers, body = modern("tools/list")
        headers["Authorization"] = basic("audit-user")
        headers[header] = headers.get(header, "first")
        response = await client.post("/mcp/", headers=[*headers.items(), (header, "other")], json=body)
        assert response.status_code == 400
    assert not offline.calls


@pytest.mark.parametrize("version", ["legacy", "2026-07-28"])
async def test_real_sdk2_http_client_handles_endpoint_redirect_and_results(version, offline):
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    from audits.test_security_boundaries import GROUP_TOOL, GROUPS_URL, mock_auth

    mock_auth(offline)
    offline.get(GROUPS_URL).respond(200, json={"deviceGroups": [{"uuid": "sdk2-http"}]})
    async with asyncio.timeout(10), app_client() as (raw_client, _):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=raw_client._transport.app),
                                     headers={"Authorization": basic("audit-user")}) as http_client:
            transport = streamable_http_client("http://audit/mcp", http_client=http_client)
            async with Client(transport, mode=version, cache=None) as client:
                assert len((await client.list_tools()).tools) == 51
                result = await client.call_tool(GROUP_TOOL, {})
                assert not result.is_error
                assert json.loads(result.content[0].text)["deviceGroups"][0]["uuid"] == "sdk2-http"
                assert (await client.read_resource("eset://config/region")).contents[0].text == "eu"
