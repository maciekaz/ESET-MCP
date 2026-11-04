"""Compatibility probe: run with MCP 1.27.1, pass the new server's Python path.

No real API requests: the new server runs stdio_fixture_server.py.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    root = Path(__file__).resolve().parents[1]
    for deployment in ("cloud", "onprem"):
        env = {k: v for k, v in os.environ.items() if not k.startswith("ESET_")}
        env.update(PYTHON_DOTENV_DISABLED="1", PYTHONPATH=str(root), ESET_USER="stdio-user",
                   ESET_PASSWORD="STDIO_PASSWORD", ESET_AUTH_MODE="env", ESET_MODE="RW",
                   ESET_MCP_TRANSPORT="stdio", ESET_DEPLOYMENT=deployment,
                   ESET_ONPREM_SERVER_URL="https://protect.invalid:9443", ESET_LOG_LEVEL="WARNING",
                   ESET_ONPREM_CF_ACCESS_CLIENT_ID="stdio-cf-id", ESET_ONPREM_CF_ACCESS_CLIENT_SECRET="STDIO_CF_SECRET")
        params = StdioServerParameters(command=sys.argv[1], args=[str(root / "tests/stdio_fixture_server.py")], env=env)
        async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
            initialized = await client.initialize()
            assert initialized.protocolVersion == "2025-11-25"
            catalog = await client.list_tools()
            assert len(catalog.tools) == 105
            for name, arguments in [("device_device_groups__list_groups", {}),
                                    ("device_devices__rename_device", {"deviceUuid": "device-1", "body": {"displayName": "new"}})]:
                result = await client.call_tool(name, arguments)
                assert not result.isError, result
                assert "STDIO_ACCESS" not in result.model_dump_json()
            assert len((await client.list_resources()).resources) == 5
            assert len((await client.list_prompts()).prompts) == 3
            assert "30 days" in (await client.get_prompt("audit_inactive_devices", {"days": "30"})).messages[0].content.text
        print(json.dumps({"deployment": deployment, "client": "mcp-1.27.1", "server": "mcp-2.3.0", "status": "passed"}))


if __name__ == "__main__":
    asyncio.run(main())
