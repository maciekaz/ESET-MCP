"""Credential resolution — env-based (single tenant) or per-request (multi-tenant).

The MCP server can run in two auth modes:

- ``env``:  credentials are read once from ``.env`` and used for every request.
            Suitable for a single-tenant deployment (one MCP server, one ESET
            account). Works on both stdio and HTTP transports.

- ``basic``: credentials are read per-request from HTTP ``Authorization: Basic``
             headers and (optionally) ``X-ESET-Region``. One MCP server can
             then serve many tenants. Only meaningful on the HTTP transport;
             stdio refuses this mode at startup.

The resolver returns a :class:`Credentials` triple; the rest of the codebase
(:mod:`auth`, :mod:`http_client`, :mod:`client_pool`) never sees a fixed set
of credentials any more — they always come through a resolver.
"""
from __future__ import annotations

import base64
import binascii
from contextvars import ContextVar
from dataclasses import dataclass

from .config import VALID_REGIONS, Region, Settings


@dataclass(frozen=True)
class Credentials:
    user: str
    password: str
    region: Region

    def cache_key(self) -> tuple[str, str, Region]:
        """Identity used by the client pool.

        Includes a *hash* of the password so that changing the password (e.g.
        after a rotation) forces a new client + fresh OAuth login, rather
        than reusing a cached client whose token was minted with the old
        password. We hash rather than embed the raw value so the key is safe
        to log / inspect for debugging.
        """
        import hashlib
        pw_hash = hashlib.sha256(self.password.encode("utf-8")).hexdigest()[:16]
        return (self.user, pw_hash, self.region)


class CredentialResolverError(Exception):
    """Raised when per-request credentials cannot be resolved (basic mode)."""


# ContextVar populated by the ASGI middleware on every HTTP request that
# carries an `Authorization: Basic ...` header. None outside an HTTP request
# (stdio mode, background tasks, etc.).
request_credentials: ContextVar[Credentials | None] = ContextVar(
    "eset_mcp_request_credentials", default=None
)


class EnvCredentialResolver:
    """Always returns the credentials baked in at startup."""

    def __init__(self, settings: Settings):
        self._creds = Credentials(
            user=settings.user, password=settings.password, region=settings.region
        )

    def resolve(self) -> Credentials:
        return self._creds


class BasicAuthCredentialResolver:
    """Returns credentials pulled from the per-request ContextVar.

    `default_region` is the fallback used when the client did not send an
    explicit ``X-ESET-Region`` header — typically the value from ``.env``.
    """

    def __init__(self, default_region: Region):
        self._default_region = default_region

    def resolve(self) -> Credentials:
        creds = request_credentials.get()
        if creds is None:
            raise CredentialResolverError(
                "No request-scoped credentials. ESET_AUTH_MODE=basic requires the client to send "
                "an 'Authorization: Basic ...' header on every request."
            )
        return creds


# ─── Helpers used by the ASGI middleware ─────────────────────────────────────

def parse_basic_auth_header(value: str) -> tuple[str, str]:
    """Parse ``Basic <base64(user:password)>`` and return (user, password).

    Raises CredentialResolverError on any malformed input — the middleware
    translates that into a 401 response.
    """
    if not value or not value.lower().startswith("basic "):
        raise CredentialResolverError("Authorization header must be 'Basic <base64>'.")
    token = value.split(" ", 1)[1].strip()
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError) as e:
        raise CredentialResolverError(f"Invalid Basic auth payload: {e}") from e
    if ":" not in decoded:
        raise CredentialResolverError("Basic auth payload must contain ':'.")
    user, password = decoded.split(":", 1)
    if not user or not password:
        raise CredentialResolverError("Basic auth payload missing username or password.")
    return user, password


def normalize_region(raw: str | None, default: Region) -> Region:
    """Normalize a region string (from header) or fall back to the default."""
    if not raw:
        return default
    val = raw.strip().lower()
    if val not in VALID_REGIONS:
        raise CredentialResolverError(
            f"X-ESET-Region must be one of {VALID_REGIONS}; got {raw!r}."
        )
    return val  # type: ignore[return-value]
