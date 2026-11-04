"""OAuth2 password grant + automatic token refresh.

Two token managers, one per deployment kind:

- :class:`CloudTokenManager` - ESET Connect cloud. Standard OAuth2 password
  grant against ``/oauth/token``, snake_case response, supports refresh
  tokens. Refreshes proactively 5 minutes before expiry.

- :class:`OnPremTokenManager` - ESET PROTECT on-prem console. Bespoke
  ``POST /GetTokens`` endpoint with a JSON body and a **camelCase** response
  (``accessToken`` / ``expiresIn``). The default legacy profile repeats the
  password handshake; explicit ``v13`` enables the documented camelCase
  password/refresh grants. Short token lifetimes use an adaptive margin.

A token manager is tied to one set of credentials (one ESET account in one
region OR one on-prem console). In multi-tenant mode each pooled
:class:`EsetHttpClient` owns its own manager - tokens never leak between
tenants.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from .credentials import Credentials
from .errors import EsetApiError
from .observability import inc_token_refresh, log_event
from .regions import resolve_auth_url
from .security import remember_secrets
from .transport import response_json, send_request

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
    access_token: str = field(repr=False)
    refresh_token: str | None = field(repr=False)
    expires_at: float  # epoch seconds
    refresh_at: float | None = None


class TokenManagerProto(Protocol):
    """Minimal interface required by :class:`EsetHttpClient`."""

    async def get_access_token(self) -> str: ...
    async def force_refresh(self, rejected_token: str | None = None) -> str: ...


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
        if margin is None and self._token.refresh_at is not None:
            return time.time() >= self._token.refresh_at
        m = self._refresh_margin_s if margin is None else margin
        return time.time() >= self._token.expires_at - m

    async def get_access_token(self) -> str:
        async with self._lock:
            if self._expired_or_expiring():
                reason = "initial" if self._token is None else "proactive"
                await self._refresh_locked()
                self._record_refresh(reason)
            assert self._token is not None
            self._remember()
            return self._token.access_token

    async def force_refresh(self, rejected_token: str | None = None) -> str:
        async with self._lock:
            # Coalesce: under a 401 burst (e.g. cloud-side token revoked),
            # N concurrent requests all call force_refresh(). The first
            # one re-auths; subsequent ones acquire the lock, see that
            # the cached token is fresh (just minted), and return it
            # without re-auth. Otherwise we'd do N identical OAuth
            # handshakes back-to-back.
            if not self._expired_or_expiring() and (
                rejected_token is None or self._token.access_token != rejected_token
            ):
                assert self._token is not None
                self._remember()
                return self._token.access_token
            await self._refresh_locked()
            self._record_refresh("forced_401")
            assert self._token is not None
            self._remember()
            return self._token.access_token

    def _remember(self) -> None:
        remember_secrets(self._creds.password, self._creds.cf_access_client_secret)
        if self._token:
            remember_secrets(self._token.access_token, self._token.refresh_token)

    def _set_token(self, payload, *, access_key: str, refresh_key: str | None, expiry_key: str,
                   previous_refresh: str | None = None) -> None:
        if not isinstance(payload, dict) or not isinstance(payload.get(access_key), str) or not payload[access_key]:
            raise EsetApiError(502, f"ESET auth response is missing a valid {access_key}.")
        access = payload[access_key]
        if not access.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in access):
            raise EsetApiError(502, "ESET auth response has an invalid access token.")
        expiry = payload.get(expiry_key, 3600)
        try:
            seconds = int(expiry)
            if isinstance(expiry, bool) or seconds <= 0 or seconds > 365 * 86400:
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            raise EsetApiError(502, "ESET auth response has an invalid token lifetime.") from None
        refresh = payload.get(refresh_key, previous_refresh) if refresh_key else None
        if refresh is not None and not isinstance(refresh, str):
            raise EsetApiError(502, "ESET auth response has an invalid refresh token.")
        now = time.time()
        self._token = Token(payload[access_key], refresh, now + seconds,
                            now + seconds - min(self._refresh_margin_s, seconds / 10))
        self._remember()

    async def _send_auth(self, *, form=None, body=None) -> httpx.Response:
        headers = {"Content-Type": "application/x-www-form-urlencoded" if form is not None else "application/json"}
        if body is not None:
            headers["Accept"] = "application/json"
        self._remember()
        return await send_request(
            self._http, "POST", resolve_auth_url(self._creds), deployment=self._creds.deployment,
            headers=headers, timeout=_AUTH_REQUEST_TIMEOUT_S,
            **({"data": form} if form is not None else {"json": body}),
        )

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


def _invalid_refresh(response: httpx.Response) -> bool:
    if response.status_code not in {400, 401}:
        return False
    try:
        payload = response.json()
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("error") == "invalid_grant"


class CloudTokenManager(_TokenManagerBase):
    """OAuth2 password / refresh grant against the ESET Connect cloud."""

    _refresh_margin_s = _REFRESH_MARGIN_CLOUD_S

    async def _refresh_locked(self) -> None:
        # Access-token expiry does not imply refresh-token expiry. A rejected
        # refresh may fall back once, only on explicit invalid_grant.
        if self._token and self._token.refresh_token:
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

        resp = await self._send_auth(form=data)
        previous_refresh = data.get("refresh_token") if data["grant_type"] == "refresh_token" else None
        if data["grant_type"] == "refresh_token" and _invalid_refresh(resp):
            previous_refresh = None
            resp = await self._send_auth(form={"grant_type": "password", "username": self._creds.user,
                                              "password": self._creds.password, "refresh_token": ""})
        self._set_token(response_json(resp), access_key="access_token",
                        refresh_key="refresh_token", expiry_key="expires_in", previous_refresh=previous_refresh)


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
    Legacy mode preserves that request. Explicit v13 mode uses grantType
    PASSWORD/REFRESH_TOKEN and retains refreshToken from the response.
    """

    _refresh_margin_s = _REFRESH_MARGIN_ONPREM_S

    async def _refresh_locked(self) -> None:
        modern = self._creds.onprem_auth_style == "v13"
        password_body = {"username": self._creds.user, "password": self._creds.password,
                         **({"grantType": "PASSWORD"} if modern else {"grant_type": "password"})}
        refreshing = modern and self._token and self._token.refresh_token
        body = {"grantType": "REFRESH_TOKEN", "refreshToken": self._token.refresh_token} if refreshing else password_body
        resp = await self._send_auth(body=body)
        previous_refresh = self._token.refresh_token if refreshing else None
        # No dialect guessing, and no fallback on ambiguous 5xx/network errors.
        if refreshing and _invalid_refresh(resp):
            previous_refresh = None
            resp = await self._send_auth(body=password_body)
        self._set_token(response_json(resp), access_key="accessToken",
                        refresh_key="refreshToken" if modern else None, expiry_key="expiresIn",
                        previous_refresh=previous_refresh)


def make_token_manager(credentials: Credentials, http: httpx.AsyncClient) -> TokenManagerProto:
    """Factory: return the right token manager for these credentials."""
    if credentials.deployment == "onprem":
        return OnPremTokenManager(credentials, http)
    return CloudTokenManager(credentials, http)
