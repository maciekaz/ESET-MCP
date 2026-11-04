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
3. Authorizes the destination and binds legacy sessions to connection identity.
4. Stores credentials in request.scope for the SDK handler's explicit request.
   The ContextVar is only a compatibility hook for direct middleware users;
   session tasks may inherit stale context, so handlers must not use it.

We intentionally keep this as a thin Starlette ``BaseHTTPMiddleware``: it
runs once per request, before MCP's StreamableHTTPSessionManager dispatches
into the JSON-RPC layer.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import OrderedDict

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
    """Require Basic auth on every HTTP request and attach scoped credentials.

    ``skip_paths`` lets specific routes bypass auth entirely - used for the
    Prometheus ``/metrics`` endpoint, which carries no secrets and is
    expected to be reachable by scrapers that can't speak Basic auth.
    Protect those routes at the network layer instead.
    """

    def __init__(self, app: ASGIApp, *, settings: Settings, skip_paths: tuple[str, ...] = ()):
        super().__init__(app)
        self._settings = settings
        self._skip_paths = tuple(skip_paths)
        self._binding_key = secrets.token_bytes(32)
        self._sessions: OrderedDict[str, tuple[bytes, float]] = OrderedDict()

    async def dispatch(self, request: Request, call_next) -> Response:
        # Routes the operator opted out of auth for (e.g. /metrics).
        if self._skip_paths and request.url.path.rstrip("/") in self._skip_paths:
            return await call_next(request)
        if any(len(request.headers.getlist(name)) > 1 for name in (
            "authorization", "x-eset-region", "x-eset-server-url", "mcp-session-id",
            "x-eset-cf-access-client-id", "x-eset-cf-access-client-secret",
        )):
            return JSONResponse(status_code=400, content={"error": "Duplicate credential or routing headers"})
        auth_header = request.headers.get("authorization", "")
        region_header = request.headers.get("x-eset-region")
        server_url_header = request.headers.get("x-eset-server-url")
        # Cloudflare Access Service Token (optional). Per-request override of
        # the env defaults. Both values must be sent together; mixing one
        # header with an env default is forbidden: a half pair is rejected.
        # The complete env pair is used only for the configured default origin.
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

        default_url = self._settings.onprem_server_url
        allowed = getattr(self._settings, "onprem_origins", {}).get(user, ())
        if override_url and override_url != default_url and override_url not in allowed:
            return JSONResponse(status_code=403, content={"error": "On-prem origin is not authorized for this user."})

        # CF Service Token: a complete pair in the headers wins; otherwise
        # fall back to the env defaults. A half-pair in the headers is a
        # 400 (the operator clearly meant to override but typoed).
        if cf_id_header or cf_secret_header:
            if not (cf_id_header and cf_id_header.strip() and cf_secret_header and cf_secret_header.strip()):
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
        elif not override_url or override_url == default_url:
            cf_id = self._settings.onprem_cf_access_client_id
            cf_secret = self._settings.onprem_cf_access_client_secret
        else:
            # Never send the server's own CF credentials to a different origin.
            cf_id = cf_secret = ""

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
                onprem_auth_style=getattr(self._settings, "onprem_auth_style", "legacy"),
                allowed_networks=getattr(self._settings, "onprem_networks", ()),
                ca_bundle=getattr(self._settings, "ca_bundle", ""),
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
                onprem_auth_style=getattr(self._settings, "onprem_auth_style", "legacy"),
                allowed_networks=getattr(self._settings, "onprem_networks", ()),
                ca_bundle=getattr(self._settings, "ca_bundle", ""),
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
                ca_bundle=getattr(self._settings, "ca_bundle", ""),
            )

        binding = hmac.digest(self._binding_key, repr(creds.cache_key()).encode(), hashlib.sha256)
        session_id = request.headers.get("mcp-session-id")
        if request.headers.get("mcp-protocol-version") == "2026-07-28":
            session_id = None  # modern requests have no protocol-level session
        if session_id:
            stored = self._sessions.get(session_id)
            if stored is None or time.monotonic() > stored[1] or not hmac.compare_digest(stored[0], binding):
                return JSONResponse(status_code=403, content={"error": "Session does not belong to these credentials. Reconnect."})
            self._sessions.move_to_end(session_id)
            self._sessions[session_id] = (binding, time.monotonic() + 1800)

        # The SDK carries this exact request to the handler, independently of
        # which task created a legacy session. Never resolve production calls
        # from the session task's inherited ContextVar.
        request.scope["eset.credentials"] = creds
        token = request_credentials.set(creds)
        try:
            response = await call_next(request)
            new_session = response.headers.get("mcp-session-id")
            if new_session and response.status_code == 200:
                self._sessions[new_session] = (binding, time.monotonic() + 1800)
                self._sessions.move_to_end(new_session)
                while len(self._sessions) > 1000:
                    self._sessions.popitem(last=False)
            if session_id and request.method == "DELETE" and response.status_code < 400:
                self._sessions.pop(session_id, None)
            response.headers["Cache-Control"] = "no-store"
            return response
        finally:
            request_credentials.reset(token)
