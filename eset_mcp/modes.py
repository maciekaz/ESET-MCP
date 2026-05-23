"""RO/RW gate - independent of the API account's permissions.

Pattern: every tool has a `read_only: bool` flag. When the server runs in RO mode,
invoking a tool with `read_only=False` raises ModeForbiddenError *before* any
HTTP request goes out.

In RO mode the RW tools remain visible in the catalog (the agent can see they
exist), but invocation fails with a clear message.
"""
from __future__ import annotations

from .config import Mode
from .errors import ModeForbiddenError


def check_mode_allows(tool_mode_required: Mode, server_mode: Mode, tool_name: str) -> None:
    """Raise ModeForbiddenError if the tool requires RW but the server is in RO."""
    if tool_mode_required == "RW" and server_mode == "RO":
        raise ModeForbiddenError(tool_name=tool_name)
