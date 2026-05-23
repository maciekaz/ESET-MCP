"""Test "MCP vs docs": every OpenAPI operation MUST be backed by exactly one tool.

This is the safety net required by the project directive - after large changes
it ensures nothing has vanished and nothing extra has appeared compared with
the official ESET specification.
"""
from __future__ import annotations

import json
from importlib import resources

import pytest

from eset_mcp.tools_loader import load_all_tools

pytestmark = pytest.mark.ro


def _count_operations_in_specs() -> int:
    total = 0
    pkg = resources.files("eset_mcp") / "openapi"
    for entry in sorted(pkg.iterdir()):
        if entry.suffix != ".json":
            continue
        spec = json.loads(entry.read_text(encoding="utf-8"))
        for _, ops in spec.get("paths", {}).items():
            for m in ops:
                if m.lower() in {"get", "post", "put", "patch", "delete"}:
                    total += 1
    return total


def test_one_tool_per_openapi_operation() -> None:
    tools = load_all_tools()
    spec_op_count = _count_operations_in_specs()
    assert len(tools) == spec_op_count, (
        f"Tool count ({len(tools)}) != OpenAPI operation count ({spec_op_count}). "
        "Something is drifting from the API documentation."
    )


def test_tool_names_are_unique() -> None:
    tools = load_all_tools()
    names = [t.name for t in tools]
    assert len(names) == len(set(names)), f"Duplicates: {sorted({n for n in names if names.count(n) > 1})}"


def test_every_tool_has_inputschema() -> None:
    for t in load_all_tools():
        assert t.input_schema.get("type") == "object", f"{t.name}: object schema missing"
        # `properties` may be empty (e.g. /oauth/token without query params),
        # but the key must exist.
        assert "properties" in t.input_schema, f"{t.name}: properties key missing"
