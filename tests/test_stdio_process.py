"""Independent JSON-lines clients against a real CLI subprocess, both eras."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CANARIES = ("STDIO_PASSWORD", "STDIO_ACCESS", "STDIO_REFRESH", "STDIO_CF_SECRET")


@pytest.mark.parametrize("era", ["legacy", "modern"])
@pytest.mark.parametrize("deployment", ["cloud", "onprem"])
@pytest.mark.parametrize("mode", ["RO", "RW"])
async def test_cli_stdio_compatibility_and_secret_boundary(era, deployment, mode):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ESET_")}
    env.update(PYTHON_DOTENV_DISABLED="1", PYTHONPATH=str(ROOT),
               ESET_USER="stdio-user", ESET_PASSWORD="STDIO_PASSWORD", ESET_MODE=mode,
               ESET_AUTH_MODE="env", ESET_MCP_TRANSPORT="stdio", ESET_DEPLOYMENT=deployment,
               ESET_ONPREM_SERVER_URL="https://protect.invalid:9443", ESET_LOG_LEVEL="DEBUG",
               ESET_MCP_LOG_FORMAT="json", ESET_ONPREM_CF_ACCESS_CLIENT_ID="stdio-cf-id",
               ESET_ONPREM_CF_ACCESS_CLIENT_SECRET="STDIO_CF_SECRET")
    child = await asyncio.create_subprocess_exec(sys.executable, str(ROOT / "tests/stdio_fixture_server.py"),
                                                env=env, cwd=ROOT, limit=4 * 1024 * 1024, stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    logs = asyncio.create_task(child.stderr.read())
    messages = []
    index = 0

    async def send(method, params=None, *, notification=False):
        nonlocal index
        index += 1
        params = dict(params or {})
        if era == "modern":
            params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                               "io.modelcontextprotocol/clientCapabilities": {},
                               "io.modelcontextprotocol/clientInfo": {"name": "independent-stdio", "version": "1"}}
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            request["id"] = index
        child.stdin.write(json.dumps(request).encode() + b"\n")
        await child.stdin.drain()
        if notification:
            return None
        while True:
            line = await asyncio.wait_for(child.stdout.readline(), timeout=15)
            assert line, "CLI exited before its response"
            messages.append(line.decode())
            result = json.loads(line)  # stdout must contain only JSON-RPC
            if result.get("id") == index:
                return result

    try:
        if era == "legacy":
            reply = await send("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                               "clientInfo": {"name": "legacy-stdio", "version": "1"}})
            assert reply["result"]["protocolVersion"] == "2025-11-25"
            await send("notifications/initialized", notification=True)
        else:
            reply = await send("server/discover")
            assert "2026-07-28" in str(reply["result"])
        reply = await send("tools/list")
        assert len(reply["result"]["tools"]) == (51 if mode == "RO" else 105)
        assert "auth_o_auth__token" not in {t["name"] for t in reply["result"]["tools"]}
        reply = await send("tools/call", {"name": "device_device_groups__list_groups", "arguments": {"pageSize": 3}})
        assert not reply["result"].get("isError")
        assert json.loads(reply["result"]["content"][0]["text"]) == {"items": [{"uuid": "stdio-fixture", "echo": "[REDACTED]"}]}
        reply = await send("tools/call", {"name": "device_devices__rename_device",
                                          "arguments": {"deviceUuid": "device-1", "body": {"displayName": "renamed"}}})
        assert bool(reply["result"].get("isError")) == (mode == "RO")
        reply = await send("resources/read", {"uri": "eset://config/deployment"})
        assert deployment in reply["result"]["contents"][0]["text"]
        reply = await send("prompts/get", {"name": "audit_inactive_devices", "arguments": {"days": "30"}})
        assert "30 days" in reply["result"]["messages"][0]["content"]["text"]
    finally:
        child.stdin.close()
        try:
            await asyncio.wait_for(child.wait(), 10)
        except TimeoutError:
            child.kill()
            await child.wait()
        diagnostic = (await logs).decode()
    assert child.returncode == 0, diagnostic
    output = "".join(messages) + diagnostic
    assert all(secret not in output for secret in CANARIES)
