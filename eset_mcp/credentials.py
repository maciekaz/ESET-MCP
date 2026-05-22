"""Credential resolution — env-based (single tenant) or per-request (multi-tenant).

The MCP server can run in two auth modes and two deployment kinds:

- ``env``:  credentials are read once from ``.env`` and used for every request.
            Suitable for a single-tenant deployment (one MCP server, one ESET
            account). Works on both stdio and HTTP transports.

- ``basic``: credentials are read per-request from HTTP ``Authorization: Basic``
             headers and (optionally) ``X-ESET-Region`` and/or
             ``X-ESET-Server-URL``. One MCP server can then serve many
             tenants — and a mix of cloud + on-prem in the same process.
             Only meaningful on the HTTP transport; stdio refuses this mode
             at startup.

Deployment kind:

- ``cloud``: hits the ESET Connect API at ``{region}.*.eset.systems`` with
             OAuth2 password grant against ``/oauth/token``. Region picked
             from ``X-ESET-Region`` or the env default.
- ``onprem``: hits a customer-hosted ESET PROTECT console at a single
             ``server_url`` with the on-prem auth endpoint ``/GetTokens``
             (camelCase response). Selected by the presence of
             ``X-ESET-Server-URL`` (basic mode) or ``ESET_DEPLOYMENT=onprem``
             (env mode).

The resolver returns a :class:`Credentials` object; the rest of the codebase
(:mod:`auth`, :mod:`http_client`, :mod:`client_pool`) never sees a fixed set
of credentials any more — they always come through a resolver.
"""
from __future__ import annotations

import base64
import binascii
from contextvars import ContextVar
from dataclasses import dataclass

from .config import VALID_REGIONS, Deployment, Region, Settings, _normalize_server_url


@dataclass(frozen=True)
class Credentials:
    user: str
    password: str
    region: Region
    deployment: Deployment = "cloud"
    # On-prem only: full origin URL (e.g. "https://protect.example.com:9443").
    # Empty string for cloud credentials.
    server_url: str = ""
    # On-prem only: whether httpx should verify the TLS cert. Always True for
    # cloud (the public ESET endpoints have valid certs).
    verify_ssl: bool = True
    # On-prem only: optional Cloudflare Access Service Token used when the
    # console sits behind Cloudflare Access. Both values are sent on every
    # request (auth + API) as CF-Access-Client-Id / CF-Access-Client-Secret.
    # Empty strings mean "no CF Access in front of the origin".
    cf_access_client_id: str = ""
    cf_access_client_secret: str = ""

    def cache_key(self) -> tuple[str, str, str, str, str]:
        """Identity used by the client pool.

        Includes a *hash* of the password so that changing the password (e.g.
        after a rotation) forces a new client + fresh OAuth login, rather
        than reusing a cached client whose token was minted with the old
        password. We hash rather than embed the raw value so the key is safe
        to log / inspect for debugging.

        For cloud credentials the fourth tuple element is the region
        (``"eu"``/``"us"``/…). For on-prem it is the server URL. This way
        cloud and on-prem clients never collide in the pool, and the same
        on-prem console hit via two different URLs (e.g. IP vs hostname)
        gets two pool entries.

        The fifth slot carries a hash of the Cloudflare Access secret (or
        empty string when none is configured). Two requests against the
        same on-prem URL with different CF tokens get separate pool entries
        because the CF headers are baked into the httpx client's defaults
        at construction time — swapping them per-request on a shared
        instance would race.
        """
        import hashlib
        pw_hash = hashlib.sha256(self.password.encode("utf-8")).hexdigest()[:16]
        # The fourth slot is "region OR server_url" — unique per deployment.
        endpoint = self.server_url if self.deployment == "onprem" else self.region
        cf_hash = ""
        if self.cf_access_client_secret:
            cf_hash = hashlib.sha256(
                self.cf_access_client_secret.encode("utf-8")
            ).hexdigest()[:16]
        return (self.user, pw_hash, self.deployment, endpoint, cf_hash)


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
            user=settings.user,
            password=settings.password,
            region=settings.region,
            deployment=settings.deployment,
            server_url=settings.onprem_server_url,
            verify_ssl=settings.onprem_verify_ssl,
            cf_access_client_id=settings.onprem_cf_access_client_id,
            cf_access_client_secret=settings.onprem_cf_access_client_secret,
        )

    def resolve(self) -> Credentials:
        return self._creds


class BasicAuthCredentialResolver:
    """Returns credentials pulled from the per-request ContextVar.

    Defaults — used for fields the client did not override via headers — come
    from the server's ``.env`` (region, deployment, server URL, verify-SSL).
    """

    def __init__(self, settings: Settings):
        self._settings = settings

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


def normalize_server_url_header(raw: str | None) -> str:
    """Normalise an ``X-ESET-Server-URL`` header. Returns ``""`` if not set.

    Reuses :func:`config._normalize_server_url` for the validation rules
    (https-only, no path/query/fragment, trailing slash stripped). On invalid
    input raises :class:`CredentialResolverError` so the middleware can
    translate it into a 400 response.
    """
    if not raw:
        return ""
    try:
        return _normalize_server_url(raw.strip())
    except RuntimeError as e:
        raise CredentialResolverError(f"X-ESET-Server-URL invalid: {e}") from e
