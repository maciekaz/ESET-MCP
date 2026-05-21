"""ASGI middleware for per-request credential injection (basic-auth mode).

When the server runs with ``ESET_AUTH_MODE=basic``, every request to /mcp
MUST carry an ``Authorization: Basic <base64(user:password)>`` header. The
client may also send ``X-ESET-Region`` to point at a non-default region.

The middleware:

1. Rejects the request with HTTP 401 if the header is missing or malformed.
2. Sets the request-scoped :data:`eset_mcp.credentials.request_credentials`
   ContextVar so the MCP handlers (running inside the same task) can read
   the per-request credentials.
3. Resets the ContextVar after the request finishes, so credentials never
   bleed between concurrent requests.

We intentionally keep this as a thin Starlette ``BaseHTTPMiddleware``: it
runs once per request, before MCP's StreamableHTTPSessionManager dispatches
into the JSON-RPC layer.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from .config import Region
from .credentials import (
    CredentialResolverError,
    Credentials,
    normalize_region,
    parse_basic_auth_header,
    request_credentials,
)

# Realm name shown in the WWW-Authenticate challenge. Anything goes; clients
# don't usually display it, but it tells operators what they're hitting.
_REALM = "ESET-MCP"


class BasicAuthCredentialsMiddleware(BaseHTTPMiddleware):
    """Require Basic auth on every HTTP request and stash creds in a ContextVar."""

    def __init__(self, app: ASGIApp, *, default_region: Region):
        super().__init__(app)
        self._default_region = default_region

    async def dispatch(self, request: Request, call_next) -> Response:
        auth_header = request.headers.get("authorization", "")
        region_header = request.headers.get("x-eset-region")

        try:
            user, password = parse_basic_auth_header(auth_header)
            region = normalize_region(region_header, self._default_region)
        except CredentialResolverError as e:
            return JSONResponse(
                status_code=401,
                content={"error": str(e)},
                headers={"WWW-Authenticate": f'Basic realm="{_REALM}", charset="UTF-8"'},
            )

        creds = Credentials(user=user, password=password, region=region)
        token = request_credentials.set(creds)
        try:
            return await call_next(request)
        finally:
            request_credentials.reset(token)
