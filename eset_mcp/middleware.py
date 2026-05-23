"""ASGI middleware for per-request credential injection (basic-auth mode).

When the server runs with ``ESET_AUTH_MODE=basic``, every request to /mcp
MUST carry an ``Authorization: Basic <base64(user:password)>`` header. The
client may also send:

- ``X-ESET-Region``     - override the default cloud region.
- ``X-ESET-Server-URL`` - switch the request to an on-prem PROTECT console
  (e.g. ``https://protect.example.com:9443``). Presence of this header takes
  precedence over ``X-ESET-Region``: the request is dispatched as on-prem
  regardless of region, and the X-ESET-Region value (if any) is ignored.

When neither override header is set, the credentials inherit the server's
configured defaults (``ESET_DEPLOYMENT``, ``ESET_REGION``,
``ESET_ONPREM_SERVER_URL``, ``ESET_ONPREM_VERIFY_SSL``).

The middleware:

1. Rejects the request with HTTP 401 if Basic auth is missing or malformed.
2. Rejects with HTTP 400 if X-ESET-Server-URL or X-ESET-Region is malformed.
3. Sets the request-scoped :data:`eset_mcp.credentials.request_credentials`
   ContextVar so the MCP handlers (running inside the same task) can read
   the per-request credentials.
4. Resets the ContextVar after the request finishes, so credentials never
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

from .config import Settings
from .credentials import (
    CredentialResolverError,
    Credentials,
    normalize_region,
    normalize_server_url_header,
    parse_basic_auth_header,
    request_credentials,
)

# Realm name shown in the WWW-Authenticate challenge. Anything goes; clients
# don't usually display it, but it tells operators what they're hitting.
_REALM = "ESET-MCP"


class BasicAuthCredentialsMiddleware(BaseHTTPMiddleware):
    """Require Basic auth on every HTTP request and stash creds in a ContextVar.

    ``skip_paths`` lets specific routes bypass auth entirely - used for the
    Prometheus ``/metrics`` endpoint, which carries no secrets and is
    expected to be reachable by scrapers that can't speak Basic auth.
    Protect those routes at the network layer instead.
    """

    def __init__(self, app: ASGIApp, *, settings: Settings, skip_paths: tuple[str, ...] = ()):
        super().__init__(app)
        self._settings = settings
        self._skip_paths = tuple(skip_paths)

    async def dispatch(self, request: Request, call_next) -> Response:
        # Routes the operator opted out of auth for (e.g. /metrics).
        if self._skip_paths and request.url.path in self._skip_paths:
            return await call_next(request)
        auth_header = request.headers.get("authorization", "")
        region_header = request.headers.get("x-eset-region")
        server_url_header = request.headers.get("x-eset-server-url")
        # Cloudflare Access Service Token (optional). Per-request override of
        # the env defaults. Both values must be sent together; mixing one
        # header with the env default is an obvious foot-gun, so we treat
        # half-pair input as an explicit "use env" (a missing pair is
        # validated at .env load time).
        cf_id_header = request.headers.get("x-eset-cf-access-client-id")
        cf_secret_header = request.headers.get("x-eset-cf-access-client-secret")

        try:
            user, password = parse_basic_auth_header(auth_header)
        except CredentialResolverError as e:
            return JSONResponse(
                status_code=401,
                content={"error": str(e)},
                headers={"WWW-Authenticate": f'Basic realm="{_REALM}", charset="UTF-8"'},
            )

        try:
            # On-prem header (if provided) wins over X-ESET-Region. We still
            # normalise the region for the fallback path (env default) so the
            # ContextVar always carries a valid Region value even on on-prem
            # credentials (it's just unused there).
            override_url = normalize_server_url_header(server_url_header)
            region = normalize_region(region_header, self._settings.region)
        except CredentialResolverError as e:
            return JSONResponse(status_code=400, content={"error": str(e)})

        # CF Service Token: a complete pair in the headers wins; otherwise
        # fall back to the env defaults. A half-pair in the headers is a
        # 400 (the operator clearly meant to override but typoed).
        if cf_id_header or cf_secret_header:
            if not (cf_id_header and cf_secret_header):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": (
                            "X-ESET-CF-Access-Client-Id and "
                            "X-ESET-CF-Access-Client-Secret must be sent together."
                        )
                    },
                )
            cf_id = cf_id_header.strip()
            cf_secret = cf_secret_header.strip()
        else:
            cf_id = self._settings.onprem_cf_access_client_id
            cf_secret = self._settings.onprem_cf_access_client_secret

        if override_url:
            # Per-request on-prem override.
            creds = Credentials(
                user=user,
                password=password,
                region=region,  # carried for completeness; unused for on-prem
                deployment="onprem",
                server_url=override_url,
                verify_ssl=self._settings.onprem_verify_ssl,
                cf_access_client_id=cf_id,
                cf_access_client_secret=cf_secret,
            )
        elif self._settings.deployment == "onprem":
            # Env default is on-prem and the client didn't override.
            if not self._settings.onprem_server_url:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": (
                            "Server is configured for on-prem (ESET_DEPLOYMENT=onprem) "
                            "but ESET_ONPREM_SERVER_URL is empty and the request did "
                            "not provide an X-ESET-Server-URL header."
                        )
                    },
                )
            creds = Credentials(
                user=user,
                password=password,
                region=region,
                deployment="onprem",
                server_url=self._settings.onprem_server_url,
                verify_ssl=self._settings.onprem_verify_ssl,
                cf_access_client_id=cf_id,
                cf_access_client_secret=cf_secret,
            )
        else:
            # Cloud path (env default + no per-request on-prem override).
            # CF tokens are intentionally NOT propagated to cloud credentials -
            # ESET Connect is a public SaaS, never behind anyone's CF Access.
            creds = Credentials(
                user=user,
                password=password,
                region=region,
                deployment="cloud",
            )

        token = request_credentials.set(creds)
        try:
            return await call_next(request)
        finally:
            request_credentials.reset(token)
