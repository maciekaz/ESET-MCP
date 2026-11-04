"""Synthetic upstream only; run the real CLI entry point in a child process."""
from __future__ import annotations

import json
import socket
from urllib.parse import parse_qs

import httpx

from eset_mcp.__main__ import main


def no_network(*args, **kwargs):
    raise AssertionError("The stdio fixture must not open network connections")


socket.socket.connect = no_network
socket.socket.connect_ex = no_network
socket.getaddrinfo = no_network
_original_init = httpx.AsyncClient.__init__


def upstream(request):
    if request.url.path == "/oauth/token":
        assert parse_qs(request.content.decode())["password"] == ["STDIO_PASSWORD"]
        return httpx.Response(200, json={"access_token": "STDIO_ACCESS", "refresh_token": "STDIO_REFRESH", "expires_in": 3600})
    if request.url.path == "/GetTokens":
        assert json.loads(request.content)["password"] == "STDIO_PASSWORD"
        assert request.headers["CF-Access-Client-Secret"] == "STDIO_CF_SECRET"
        return httpx.Response(200, json={"accessToken": "STDIO_ACCESS", "expiresIn": 3600})
    assert request.headers["Authorization"] == "Bearer STDIO_ACCESS"
    return httpx.Response(200, json={"items": [{"uuid": "stdio-fixture", "echo": "STDIO_ACCESS"}]})


def fixture_init(self, *args, **kwargs):
    kwargs["transport"] = httpx.MockTransport(upstream)
    return _original_init(self, *args, **kwargs)


httpx.AsyncClient.__init__ = fixture_init
main()
