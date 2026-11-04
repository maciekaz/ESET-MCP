"""Run ONLY with the archived original source and MCP v1 baseline environment.

Usage: PYTHONPATH=/path/to/legacy-source python audits/capture_legacy.py output.json
Does not read .env; every upstream exchange is intercepted by RESPX.
"""
from __future__ import annotations

import asyncio
import json
import sys
from importlib.metadata import version
from pathlib import Path

import httpx
import respx
from jsonschema import Draft202012Validator

from eset_mcp.client_pool import ClientPool
from eset_mcp.config import Settings
from eset_mcp.credentials import EnvCredentialResolver
from eset_mcp.server import build_server
from eset_mcp.tools_loader import load_all_tools

BASE_COMMIT = "442dcadadcfde802cf0b7ccb1955438ed20fcf15"
PAYLOAD = {"items": [{"uuid": "fixture-1", "displayName": "Próba & < >", "enabled": True}],
           "totalSize": 1, "nextPageToken": "cursor-next-page"}


def sample(schema, depth=0):
    if "enum" in schema:
        return schema["enum"][0]
    kind = schema.get("type", "object")
    if kind == "object":
        return {k: sample(v, depth + 1) for k, v in schema.get("properties", {}).items()
                if k != "fields" and not v.get("readOnly") and
                (depth < 3 or k in schema.get("required", []))}
    if kind == "array":
        return [sample(schema.get("items", {}), depth + 1)]
    if kind in {"integer", "number"}:
        return max(schema.get("minimum", 1), 1)
    if kind == "boolean":
        return True
    if kind == "null":
        return None
    if schema.get("format") == "date-time":
        return "2026-09-01T12:00:00Z"
    return "fixture-value"


def wire(request):
    return {"method": request.method, "url": str(request.url),
            "headers": {k: request.headers[k] for k in
                        ("authorization", "accept", "content-type", "cf-access-client-id", "cf-access-client-secret")
                        if k in request.headers},
            "body": request.content.decode()}


async def capture():
    from composite_fixture import COMPOSITE_CASES, FixedDateTime, composite_reply
    from mcp.shared.memory import create_connected_server_and_client_session

    import eset_mcp
    import eset_mcp.composite_tools
    assert eset_mcp.__version__ == "1.0.3" and version("mcp") == "1.27.1", "Use the immutable legacy checkout/environment"
    eset_mcp.composite_tools.datetime = FixedDateTime

    cases = []
    for deployment in ("cloud", "onprem"):
        settings = Settings(user="fixture-user", password="fixture-password", mode="RW", region="eu",
                            transport="stdio", http_host="127.0.0.1", http_port=8765, log_level="WARNING",
                            auth_mode="env", response_bytes_max=100000, deployment=deployment,
                            onprem_server_url="https://protect.invalid:9443", onprem_verify_ssl=True,
                            onprem_cf_access_client_id="fixture-cf-id", onprem_cf_access_client_secret="fixture-cf-secret",
                            log_format="text", metrics_enabled=False, metrics_path="/metrics")
        pool = ClientPool(settings)
        requests = []
        state = {"composite": False}

        def reply(request, requests=requests, state=state):
            requests.append(wire(request))
            if request.url.path == "/oauth/token":
                return httpx.Response(200, json={"access_token": "fixture-access", "refresh_token": "fixture-refresh", "expires_in": 3600})
            if request.url.path == "/GetTokens":
                return httpx.Response(200, json={"accessToken": "fixture-access", "expiresIn": 3600})
            return httpx.Response(200, json=composite_reply(request) if state["composite"] else PAYLOAD)

        try:
            with respx.mock(assert_all_called=False) as router:
                router.route().mock(side_effect=reply)
                server = build_server(settings, pool, EnvCredentialResolver(settings))
                async with create_connected_server_and_client_session(server) as client:
                    await client.initialize()
                    for tool in load_all_tools():
                        if tool.service == "business-account":
                            continue
                        arguments = sample(tool.input_schema)
                        Draft202012Validator(tool.input_schema).validate(arguments)
                        requests.clear()
                        result = await client.call_tool(tool.name, arguments)
                        assert not result.isError, (tool.name, result)
                        cases.append({"deployment": deployment, "name": tool.name, "arguments": arguments,
                                      "requests": list(requests), "content": [c.model_dump(by_alias=True, exclude_none=True) for c in result.content]})
                    state["composite"] = True
                    for name, arguments in COMPOSITE_CASES:
                        requests.clear()
                        result = await client.call_tool(name, arguments)
                        assert not result.isError, (name, result)
                        cases.append({"kind": "composite", "deployment": deployment, "name": name, "arguments": arguments,
                                      "requests": list(requests), "content": [c.model_dump(by_alias=True, exclude_none=True) for c in result.content]})
        finally:
            await pool.close()
    return {"source_commit": BASE_COMMIT, "source_mcp": "1.27.1", "cases": cases}


if __name__ == "__main__":
    output = asyncio.run(capture())
    Path(sys.argv[1]).write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
