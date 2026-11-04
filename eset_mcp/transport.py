"""Bounded ESET request lifecycle shared by authentication and business APIs."""
from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx

from .errors import EsetApiError, map_http_error
from .observability import inc_http_retry

PENDING_BUDGET_S = 600.0
POLL_INTERVAL_S = 2.0


def parse_retry_after(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        try:
            date = parsedate_to_datetime(raw)
            if date.tzinfo is None:
                date = date.replace(tzinfo=UTC)
            value = (date - datetime.now(UTC)).total_seconds()
        except (ValueError, OverflowError, TypeError):
            return None
    return value if math.isfinite(value) and value >= 0 else None


async def send_request(
    http: httpx.AsyncClient, method: str, url: str, *, deployment: str,
    headers: dict[str, str], timeout: float = 120, budget: float = PENDING_BUDGET_S,
    refresh: Callable[[], Awaitable[str]] | None = None, **kwargs,
) -> httpx.Response:
    """Keep method/URL/body/query identical during cached 202 polling.

    A rejected request may renew auth once. Only GET/HEAD may retry 5xx;
    transport failures are never replayed because their outcome is unknown.
    """
    headers = dict(headers)
    rate_retries = 0
    server_retries = 0
    auth_retried = False
    poll_interval = POLL_INTERVAL_S
    deadline = time.monotonic() + budget
    try:
        async with asyncio.timeout(budget):
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                response = await http.request(method, url, headers=headers,
                                              timeout=min(timeout, remaining), **kwargs)
                status = response.status_code
                if status == 401 and refresh is not None and not auth_retried:
                    auth_retried = True
                    headers["Authorization"] = f"Bearer {await refresh()}"
                    inc_http_retry(deployment=deployment, status="401")
                    continue
                if status == 429 and rate_retries < 3:
                    delay = parse_retry_after(response.headers.get("Retry-After"))
                    if delay is None:
                        delay = 2 ** rate_retries
                    rate_retries += 1
                    inc_http_retry(deployment=deployment, status="429")
                elif status == 202:
                    if "response-id" not in headers:
                        response_id = response.headers.get("response-id")
                        if not response_id or any(ord(c) < 32 for c in response_id):
                            raise EsetApiError(502, "Pending response is missing a valid response-id.")
                        headers["response-id"] = response_id
                    delay = poll_interval
                    poll_interval = min(poll_interval * 1.5, 30.0)
                elif status >= 500 and method.upper() in {"GET", "HEAD"} and server_retries < 1:
                    server_retries += 1
                    inc_http_retry(deployment=deployment, status=str(status))
                    delay = 1.0
                else:
                    return response
                if delay >= deadline - time.monotonic():
                    raise TimeoutError
                await asyncio.sleep(delay)
    except (TimeoutError, httpx.TimeoutException):
        raise EsetApiError(504, "ESET request exceeded its time budget; outcome may be unknown.") from None
    except httpx.RequestError:
        raise EsetApiError(502, "ESET connection failed; check the endpoint, network and TLS configuration.") from None


def response_json(response: httpx.Response):
    if not 200 <= response.status_code < 300:
        raise map_http_error(response.status_code, "", "", None)
    if not response.content:
        return {}
    try:
        return response.json()
    except (ValueError, UnicodeError):
        raise EsetApiError(502, "ESET returned an invalid JSON response.") from None
