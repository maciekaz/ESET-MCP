"""Thin wrapper around httpx — auth header, 202 polling, 429 retry, error mapping.

Rules from the ESET Connect docs:
- 202 Accepted = pending; poll with `response-id` header, up to 10 minutes.
- 429 Too Many Requests = rate limit (10 req/s); exponential backoff, max 3 tries.
- 401 = token expired; one forced refresh + retry.
- 5xx = transient; single retry.

This class is *credentials-bound*: a single client owns one OAuth session for
one ESET account (cloud) or one PROTECT console (on-prem). In multi-tenant
mode the :class:`ClientPool` keeps one instance per pool key.

For on-prem credentials the underlying httpx client honours
``creds.verify_ssl`` (default True) — operators of intranet deployments with
self-signed certs opt out via ``ESET_ONPREM_VERIFY_SSL=false``. A single
WARNING is logged at construction time when verification is disabled so
the operator notices it once, without log spam on every request.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from .auth import TokenManagerProto, make_token_manager
from .credentials import Credentials
from .errors import EsetApiError, map_http_error
from .regions import resolve_base_url

_LOG = logging.getLogger("eset_mcp.http")

# 202 polling.
_PENDING_POLL_INTERVAL_S = 2.0
_PENDING_POLL_INTERVAL_CAP_S = 30.0
_PENDING_POLL_BUDGET_S = 600.0  # 10 minutes, per the docs.

# Rate-limit retry.
_RATE_LIMIT_MAX_TRIES = 3
_RATE_LIMIT_BASE_BACKOFF_S = 1.0


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
        if credentials.deployment == "onprem" and not verify:
            _LOG.warning(
                "TLS certificate verification DISABLED for on-prem server %s — "
                "set ESET_ONPREM_VERIFY_SSL=true once the console cert is trusted.",
                credentials.server_url,
            )
        self._http = httpx.AsyncClient(timeout=120, follow_redirects=False, verify=verify)
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
        """Execute a request, handle 202/401/429/5xx, return the body as JSON."""
        url = resolve_base_url(self._creds, service) + path
        token = await self._token_mgr.get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        resp = await self._http.request(method, url, params=query, json=json, headers=headers)

        # 401 — token expired between get_access_token() and the request; force-refresh + retry.
        if resp.status_code == 401 and _retry_after_401:
            _LOG.info("401 from %s — forcing token refresh and retrying", url)
            await self._token_mgr.force_refresh()
            return await self.request(
                method, service, path, query=query, json=json, _retry_after_401=False
            )

        # 429 — rate limit, backoff.
        if resp.status_code == 429:
            for attempt in range(1, _RATE_LIMIT_MAX_TRIES + 1):
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                wait_s = retry_after or _RATE_LIMIT_BASE_BACKOFF_S * (2 ** (attempt - 1))
                _LOG.warning("429 from %s — sleeping %.1fs (try %d/%d)", url, wait_s, attempt, _RATE_LIMIT_MAX_TRIES)
                await asyncio.sleep(wait_s)
                resp = await self._http.request(method, url, params=query, json=json, headers=headers)
                if resp.status_code != 429:
                    break

        # 202 — pending, long-poll with response-id.
        if resp.status_code == 202:
            response_id = resp.headers.get("response-id")
            if not response_id:
                raise map_http_error(202, resp.text, url, resp.headers.get("request-id"))
            return await self._poll_pending(method, url, response_id, headers, query, json)

        if resp.status_code >= 400:
            raise map_http_error(
                status=resp.status_code,
                body=resp.text,
                endpoint=url,
                request_id=resp.headers.get("request-id"),
            )

        return _parse_json(resp)

    async def _poll_pending(
        self,
        method: str,
        url: str,
        response_id: str,
        headers: dict[str, str],
        query: dict[str, Any] | None,
        json: Any | None,
    ) -> dict[str, Any] | list[Any]:
        """Poll 202 with exponential backoff, up to 10 minutes."""
        deadline = time.monotonic() + _PENDING_POLL_BUDGET_S
        interval = _PENDING_POLL_INTERVAL_S
        poll_headers = {**headers, "response-id": response_id}

        while True:
            if time.monotonic() > deadline:
                raise EsetApiError(
                    status=504,
                    message="Pending response did not complete within 10 minutes — the cached query expired.",
                    endpoint=url,
                )
            await asyncio.sleep(interval)
            interval = min(interval * 1.5, _PENDING_POLL_INTERVAL_CAP_S)

            resp = await self._http.request(method, url, params=query, json=json, headers=poll_headers)
            if resp.status_code == 202:
                continue
            if resp.status_code >= 400:
                raise map_http_error(
                    status=resp.status_code,
                    body=resp.text,
                    endpoint=url,
                    request_id=resp.headers.get("request-id"),
                )
            return _parse_json(resp)

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
        If None — yields whole pages instead of items.
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


def _parse_json(resp: httpx.Response) -> dict[str, Any] | list[Any]:
    if not resp.content:
        return {}
    return resp.json()


def _parse_retry_after(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None
