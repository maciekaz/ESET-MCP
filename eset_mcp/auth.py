"""OAuth2 password grant + automatic token refresh.

Two token managers, one per deployment kind:

- :class:`CloudTokenManager` - ESET Connect cloud. Standard OAuth2 password
  grant against ``/oauth/token``, snake_case response, supports refresh
  tokens. Refreshes proactively 5 minutes before expiry.

- :class:`OnPremTokenManager` - ESET PROTECT on-prem console. Bespoke
  ``POST /GetTokens`` endpoint with a JSON body and a **camelCase** response
  (``accessToken`` / ``expiresIn``). No refresh-token flow exists; on expiry
  the full username+password handshake is repeated. Refreshes 60 seconds
  before expiry (matching the reference client behaviour).

A token manager is tied to one set of credentials (one ESET account in one
region OR one on-prem console). In multi-tenant mode each pooled
:class:`EsetHttpClient` owns its own manager - tokens never leak between
tenants.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Protocol

import httpx

from .credentials import Credentials
from .errors import map_http_error
from .observability import inc_token_refresh, log_event
from .regions import resolve_auth_url

_LOG = logging.getLogger("eset_mcp.auth")

# Safety margin - refresh the token N seconds before its nominal expiry.
# Cloud uses 5 min (1h tokens, plenty of headroom); on-prem mirrors the
# reference TypeScript client at 60 s.
_REFRESH_MARGIN_CLOUD_S = 300
_REFRESH_MARGIN_ONPREM_S = 60

# Auth handshake should respond in <1 s; 30 s covers TLS + slow links and
# matches httpx's default for short-lived control calls.
_AUTH_REQUEST_TIMEOUT_S = 30


@dataclass
class Token:
    access_token: str
    refresh_token: str | None
    expires_at: float  # epoch seconds


class TokenManagerProto(Protocol):
    """Minimal interface required by :class:`EsetHttpClient`."""

    async def get_access_token(self) -> str: ...
    async def force_refresh(self) -> str: ...


class _TokenManagerBase:
    """Shared bookkeeping: token cache + per-instance refresh lock."""

    _refresh_margin_s: int = _REFRESH_MARGIN_CLOUD_S

    def __init__(self, credentials: Credentials, http: httpx.AsyncClient):
        self._creds = credentials
        self._http = http
        self._token: Token | None = None
        self._lock = asyncio.Lock()

    def _expired_or_expiring(self, *, margin: int | None = None) -> bool:
        if self._token is None:
            return True
        m = self._refresh_margin_s if margin is None else margin
        return time.time() >= self._token.expires_at - m

    async def get_access_token(self) -> str:
        async with self._lock:
            if self._expired_or_expiring():
                reason = "initial" if self._token is None else "proactive"
                await self._refresh_locked()
                self._record_refresh(reason)
            assert self._token is not None
            return self._token.access_token

    async def force_refresh(self) -> str:
        async with self._lock:
            # Coalesce: under a 401 burst (e.g. cloud-side token revoked),
            # N concurrent requests all call force_refresh(). The first
            # one re-auths; subsequent ones acquire the lock, see that
            # the cached token is fresh (just minted), and return it
            # without re-auth. Otherwise we'd do N identical OAuth
            # handshakes back-to-back.
            if not self._expired_or_expiring():
                assert self._token is not None
                return self._token.access_token
            await self._refresh_locked()
            self._record_refresh("forced_401")
            assert self._token is not None
            return self._token.access_token

    def _record_refresh(self, reason: str) -> None:
        """Emit metric + log entry for a successful token refresh."""
        inc_token_refresh(deployment=self._creds.deployment, reason=reason)
        log_event(
            _LOG, "token_refresh",
            deployment=self._creds.deployment,
            reason=reason,
            user=self._creds.user,
        )

    async def _refresh_locked(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


class CloudTokenManager(_TokenManagerBase):
    """OAuth2 password / refresh grant against the ESET Connect cloud."""

    _refresh_margin_s = _REFRESH_MARGIN_CLOUD_S

    async def _refresh_locked(self) -> None:
        # If we have a refresh_token and it has not fully expired, use it.
        # Otherwise - fall back to the password grant.
        if self._token and self._token.refresh_token and not self._expired_or_expiring(margin=0):
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

        url = resolve_auth_url(self._creds)
        resp = await self._http.post(
            url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=_AUTH_REQUEST_TIMEOUT_S,
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


# Backwards-compatible alias - older imports / tests reference TokenManager.
TokenManager = CloudTokenManager


class OnPremTokenManager(_TokenManagerBase):
    """Token manager for on-prem ESET PROTECT consoles.

    Wire format (verified against Fenrindale/eset-protect-mcp's reference
    TypeScript client, which talks to ESET PROTECT On-Prem 13.0+):

        POST {server_url}/GetTokens
        Content-Type: application/json

        {"username": "...", "password": "...", "grant_type": "password"}

    Successful response (HTTP 200):

        {"accessToken": "...", "expiresIn": 3600}

    Note: response keys are **camelCase**, unlike the cloud's snake_case.
    There is no refresh-token field - on expiry we re-send the password.
    """

    _refresh_margin_s = _REFRESH_MARGIN_ONPREM_S

    async def _refresh_locked(self) -> None:
        url = resolve_auth_url(self._creds)
        body = {
            "username": self._creds.user,
            "password": self._creds.password,
            "grant_type": "password",
        }
        resp = await self._http.post(
            url,
            json=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=_AUTH_REQUEST_TIMEOUT_S,
        )
        if resp.status_code != 200:
            raise map_http_error(
                status=resp.status_code,
                body=resp.text,
                endpoint=url,
                request_id=resp.headers.get("request-id"),
            )

        payload = resp.json()
        access = payload.get("accessToken")
        if not access:
            raise map_http_error(
                status=resp.status_code,
                body=f"On-prem /GetTokens response missing accessToken: {resp.text}",
                endpoint=url,
                request_id=resp.headers.get("request-id"),
            )
        expires_in = int(payload.get("expiresIn", 3600))
        self._token = Token(
            access_token=access,
            refresh_token=None,  # on-prem has no refresh-token flow
            expires_at=time.time() + expires_in,
        )


def make_token_manager(credentials: Credentials, http: httpx.AsyncClient) -> TokenManagerProto:
    """Factory: return the right token manager for these credentials."""
    if credentials.deployment == "onprem":
        return OnPremTokenManager(credentials, http)
    return CloudTokenManager(credentials, http)
