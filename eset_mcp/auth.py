"""OAuth2 password grant + automatic token refresh.

The access token is valid for 1h (per ESET docs). We refresh proactively
5 minutes before expiry to avoid a race during long-running tool calls.

A TokenManager is tied to one set of credentials (one ESET account in one
region). In multi-tenant mode each pooled :class:`EsetHttpClient` owns its
own TokenManager — tokens never leak between tenants.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from .credentials import Credentials
from .errors import map_http_error
from .regions import auth_url

# Safety margin — refresh the token N seconds before its nominal expiry.
_REFRESH_MARGIN_S = 300


@dataclass
class Token:
    access_token: str
    refresh_token: str | None
    expires_at: float  # epoch seconds

    def expired_or_expiring(self, margin: int = _REFRESH_MARGIN_S) -> bool:
        return time.time() >= self.expires_at - margin


class TokenManager:
    """Holds a single token for one set of credentials; refreshes proactively and on 401."""

    def __init__(self, credentials: Credentials, http: httpx.AsyncClient):
        self._creds = credentials
        self._http = http
        self._token: Token | None = None
        self._lock = asyncio.Lock()

    async def get_access_token(self) -> str:
        """Return a valid access_token, refreshing it if expired or expiring soon."""
        async with self._lock:
            if self._token is None or self._token.expired_or_expiring():
                await self._refresh_locked()
            assert self._token is not None
            return self._token.access_token

    async def force_refresh(self) -> str:
        """Force a refresh — used after a 401 from the server."""
        async with self._lock:
            await self._refresh_locked()
            assert self._token is not None
            return self._token.access_token

    async def _refresh_locked(self) -> None:
        """Internal — must be called while holding _lock."""
        # If we have a refresh_token and it has not fully expired, use it.
        # Otherwise — fall back to the password grant.
        if self._token and self._token.refresh_token and not self._token.expired_or_expiring(margin=0):
            data = {
                "grant_type": "refresh_token",
                "refresh_token": self._token.refresh_token,
            }
        else:
            data = {
                "grant_type": "password",
                "username": self._creds.user,
                "password": self._creds.password,
                "refresh_token": "",
            }

        url = auth_url(self._creds.region)
        resp = await self._http.post(
            url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if resp.status_code != 200:
            raise map_http_error(
                status=resp.status_code,
                body=resp.text,
                endpoint=url,
                request_id=resp.headers.get("request-id"),
            )

        payload = resp.json()
        self._token = Token(
            access_token=payload["access_token"],
            refresh_token=payload.get("refresh_token"),
            expires_at=time.time() + int(payload.get("expires_in", 3600)),
        )
