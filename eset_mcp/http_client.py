"""Thin wrapper around httpx - auth header, 202 polling, 429 retry, error mapping.

Rules from the ESET Connect docs:
- 202 Accepted = pending; poll with `response-id` header, up to 10 minutes.
- 429 Too Many Requests = rate limit (10 req/s); exponential backoff, max 3 tries.
- 401 = token expired; one forced refresh + retry.
- 5xx = a single retry for GET/HEAD only; mutations are never blindly replayed.

This class is *credentials-bound*: a single client owns one OAuth session for
one ESET account (cloud) or one PROTECT console (on-prem). In multi-tenant
mode the :class:`ClientPool` keeps one instance per pool key.

For on-prem credentials the underlying httpx client honours
``creds.verify_ssl`` (default True) - operators of intranet deployments with
self-signed certs opt out via ``ESET_ONPREM_VERIFY_SSL=false``. A single
WARNING is logged at construction time when verification is disabled so
the operator notices it once, without log spam on every request.
"""
from __future__ import annotations

import logging
import ssl
import time
from typing import Any

import httpx

from .auth import TokenManagerProto, make_token_manager
from .credentials import Credentials
from .egress import OnPremTransport
from .errors import EsetApiError
from .observability import log_event
from .regions import resolve_base_url
from .security import remember_secrets
from .transport import parse_retry_after, response_json, send_request

_LOG = logging.getLogger("eset_mcp.http")

# Per-request socket timeout. Generous because ESET list endpoints can take
# several seconds on large tenants and 202-pending polls are accounted for
# separately (see _PENDING_POLL_BUDGET_S).
_REQUEST_TIMEOUT_S = 120

# Total budget for the business request, including polling and retry waits.
_PENDING_POLL_BUDGET_S = 600.0


class EsetHttpClient:
    """High-level HTTP client for the ESET Connect API or an on-prem PROTECT console.

    One instance == one auth session for one ESET account (cloud) or one
    on-prem console. Use directly when you have fixed credentials; in
    multi-tenant mode go through :class:`ClientPool`.

    Usage:
        async with EsetHttpClient(credentials) as client:
            data = await client.request("GET", "device-management", "/v1/device_groups")

    Or, for pool-managed lifetime:
        client = EsetHttpClient(credentials)
        try:
            data = await client.request(...)
        finally:
            await client.aclose()
    """

    def __init__(self, credentials: Credentials):
        self._creds = credentials
        # TLS verification is configurable only for on-prem (which routinely
        # ships with self-signed certs). Cloud credentials always verify.
        verify = True if credentials.deployment == "cloud" else credentials.verify_ssl
        if verify and credentials.ca_bundle:
            verify = ssl.create_default_context(cafile=credentials.ca_bundle)
        if credentials.deployment == "onprem" and not verify:
            _LOG.warning(
                "TLS certificate verification DISABLED for on-prem server %s - "
                "set ESET_ONPREM_VERIFY_SSL=true once the console cert is trusted.",
                credentials.server_url,
            )
        # Cloudflare Access Service Token (on-prem only). When set, every
        # request - including the POST /GetTokens auth call - carries the
        # CF-Access-Client-Id / CF-Access-Client-Secret headers so the
        # Cloudflare Access edge lets the request through to the origin.
        default_headers: dict[str, str] = {}
        if (
            credentials.deployment == "onprem"
            and credentials.cf_access_client_id
            and credentials.cf_access_client_secret
        ):
            default_headers["CF-Access-Client-Id"] = credentials.cf_access_client_id
            default_headers["CF-Access-Client-Secret"] = credentials.cf_access_client_secret
            _LOG.info(
                "Cloudflare Access Service Token attached for on-prem server %s",
                credentials.server_url,
            )
        self._http = httpx.AsyncClient(
            timeout=_REQUEST_TIMEOUT_S,
            follow_redirects=False,
            verify=verify,
            headers=default_headers or None,
            trust_env=False,
            transport=OnPremTransport(verify=verify, networks=credentials.allowed_networks)
            if credentials.deployment == "onprem" else None,
        )
        self._token_mgr: TokenManagerProto = make_token_manager(credentials, self._http)

    @property
    def credentials(self) -> Credentials:
        return self._creds

    async def __aenter__(self) -> EsetHttpClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def request(
        self,
        method: str,
        service: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        json: Any | None = None,
        _retry_after_401: bool = True,
    ) -> dict[str, Any] | list[Any]:
        """Execute a request, handle 202/401/429/5xx, return the body as JSON.

        ``path`` is the *template* path from the OpenAPI spec (with
        ``{placeholder}`` segments already substituted by the caller). We
        intentionally do NOT log the substituted URL - it can reveal device
        UUIDs and other tenant data. Logs carry only method, service and
        status, with a local duration.
        """
        # Tool dispatch may only issue business requests. Token endpoints stay
        # private to the token managers, even if a caller bypasses the catalog.
        from urllib.parse import unquote
        decoded = unquote(path)
        if (service == "business-account" or not path.startswith("/") or
                path.startswith("//") or any(c in decoded for c in "?#\\\r\n\x00") or
                any(part in {".", ".."} for part in decoded.split("/")) or
                decoded.rstrip("/").lower() in {"/gettokens", "/oauth/token"}):
            raise EsetApiError(400, "Invalid business API path.")
        url = resolve_base_url(self._creds, service) + path
        remember_secrets(self._creds.password, self._creds.cf_access_client_secret)
        token = await self._token_mgr.get_access_token()
        remember_secrets(token)

        async def refresh() -> str:
            renewed = await self._token_mgr.force_refresh(rejected_token=token)
            remember_secrets(renewed)
            return renewed

        started = time.monotonic()
        resp = await send_request(
            self._http, method, url, deployment=self._creds.deployment,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            refresh=refresh if _retry_after_401 else None,
            budget=_PENDING_POLL_BUDGET_S, params=query, json=json,
        )
        log_event(
            _LOG, "http_request_complete",
            deployment=self._creds.deployment, method=method, service=service,
            status=resp.status_code, duration_ms=int((time.monotonic() - started) * 1000),
        )
        return response_json(resp)

    async def paginate(
        self,
        service: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        page_size: int = 1000,
        items_key: str | None = None,
    ):
        """Async generator iterating over all pages (pageToken/nextPageToken).

        items_key: the response field that holds the list (e.g. "deviceGroups").
        If None - yields whole pages instead of items.
        """
        page_token = ""
        while True:
            q = dict(query or {})
            q["pageSize"] = page_size
            if page_token:
                q["pageToken"] = page_token
            page = await self.request("GET", service, path, query=q)
            if items_key and isinstance(page, dict):
                for item in page.get(items_key, []) or []:
                    yield item
            else:
                yield page
            page_token = (page.get("nextPageToken") if isinstance(page, dict) else "") or ""
            if not page_token:
                return


# Compatibility aliases for direct users of the old module helpers.
_parse_json = response_json
_parse_retry_after = parse_retry_after
