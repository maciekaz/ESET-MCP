"""RO mode behaviour:

  1. RW tools are HIDDEN from the catalog (not advertised by list_tools).
  2. A direct call to a hard-coded RW tool name (one the agent shouldn't even
     know about, but might from prior tool listings or hard-coded scripts) is
     still rejected before any HTTP request goes out - defence in depth.
"""
from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.ro


async def test_ro_hides_rw_tool_from_catalog(mcp_session) -> None:
    """Architectural decision (2026-05): RO catalog should not contain RW tools at all."""
    assert os.getenv("ESET_MODE", "RO").upper() == "RO", \
        "This test only makes sense in RO mode - set ESET_MODE=RO in .env."

    async with mcp_session() as client:
        tools = await client.list_tools()
    names = {t.name for t in tools.tools}
    assert "device_devices__move_device" not in names, (
        "RW tool 'device_devices__move_device' must NOT appear in the RO catalog."
    )


async def test_ro_blocks_direct_rw_call_defence_in_depth(mcp_session) -> None:
    """Even if a client somehow knows the RW tool name, the gate must refuse it."""
    async with mcp_session() as client:
        result = await client.call_tool(
            "device_devices__move_device",
            arguments={"deviceUuid": "00000000-0000-0000-0000-000000000000", "body": {}},
        )
    text = result.content[0].text
    assert "RO" in text and "RW" in text, \
        f"Block message should mention RO/RW; got: {text!r}"
