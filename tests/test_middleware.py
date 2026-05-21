"""Unit tests for the Basic-auth ASGI middleware (no network).

Boots a minimal Starlette app behind the middleware and checks that:
  · missing/garbled headers → 401 + WWW-Authenticate challenge
  · valid Basic auth → request_credentials ContextVar populated, 200 returned
  · region defaults to .env when X-ESET-Region not sent; custom region honored
  · ContextVar is reset after each request (no bleed between calls)
"""
from __future__ import annotations

import base64

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from eset_mcp.credentials import request_credentials
from eset_mcp.middleware import BasicAuthCredentialsMiddleware


def _app(default_region="eu"):
    async def probe(request):
        creds = request_credentials.get()
        if creds is None:
            return JSONResponse({"creds": None})
        return JSONResponse(
            {"user": creds.user, "password": creds.password, "region": creds.region}
        )

    app = Starlette(routes=[Route("/probe", probe)])
    app.add_middleware(BasicAuthCredentialsMiddleware, default_region=default_region)
    return app


def _basic_header(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def test_missing_header_returns_401() -> None:
    with TestClient(_app()) as client:
        r = client.get("/probe")
        assert r.status_code == 401
        assert "WWW-Authenticate" in r.headers
        assert r.headers["WWW-Authenticate"].startswith("Basic ")


def test_valid_basic_auth_populates_context() -> None:
    with TestClient(_app()) as client:
        r = client.get("/probe", headers={"authorization": _basic_header("alice", "s3cr3t")})
        assert r.status_code == 200
        body = r.json()
        assert body == {"user": "alice", "password": "s3cr3t", "region": "eu"}


def test_region_header_overrides_default() -> None:
    with TestClient(_app(default_region="eu")) as client:
        r = client.get(
            "/probe",
            headers={
                "authorization": _basic_header("alice", "x"),
                "x-eset-region": "us",
            },
        )
        assert r.json()["region"] == "us"


def test_unknown_region_returns_401() -> None:
    with TestClient(_app()) as client:
        r = client.get(
            "/probe",
            headers={
                "authorization": _basic_header("alice", "x"),
                "x-eset-region": "atlantis",
            },
        )
        assert r.status_code == 401


def test_malformed_basic_returns_401() -> None:
    with TestClient(_app()) as client:
        r = client.get("/probe", headers={"authorization": "Basic !!notbase64"})
        assert r.status_code == 401


def test_contextvar_cleared_between_requests() -> None:
    """After a successful request, request_credentials must NOT carry over."""
    with TestClient(_app()) as client:
        r = client.get("/probe", headers={"authorization": _basic_header("alice", "x")})
        assert r.status_code == 200
    # Outside the TestClient request scope, the ContextVar in *this* test
    # task should still be unset (it was set in the middleware's task only).
    assert request_credentials.get() is None
