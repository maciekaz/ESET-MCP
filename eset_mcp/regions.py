"""Region → per-service domain mapping (cloud) + on-prem URL resolution.

Cloud sources: ESET Connect docs (Network Prerequisites) + OpenAPI spec names
from eu.esetconnect.eset.systems.

On-prem: ESET PROTECT consoles expose a single host (default port 9443) that
serves both authentication (``POST /GetTokens``) and the REST API. There is
no per-service split, so :func:`resolve_base_url` returns the same origin
regardless of the ``service`` argument.
"""
from __future__ import annotations

from .config import Region
from .credentials import Credentials

# Key   = OpenAPI spec basename (file under eset_mcp/openapi/),
# Value = subdomain (without region prefix and without .eset.systems suffix).
SERVICE_DOMAINS: dict[str, str] = {
    "business-account": "business-account.iam",
    "application-management": "application-management",
    "asset-management": "asset-management",
    "automation": "automation",
    "device-management": "device-management",
    "iam": "iam",
    "incident-management": "incident-management",
    "installer-management": "installer-management",
    "mobile-device-management": "mobile-device-management",
    "network-access-protection": "network-access-protection",
    "patch-management": "patch-management",
    "policy-management": "policy-management",
    "quarantine-management": "quarantine-management",
    "user-management": "user-management",
    "vulnerability-management": "vulnerability-management",
    "web-access-protection": "web-access-protection",
}


def base_url(region: Region, service: str) -> str:
    """Return the cloud base URL for the given service in the given region.

    Example: base_url("eu", "device-management") → "https://eu.device-management.eset.systems"
    """
    if service not in SERVICE_DOMAINS:
        raise KeyError(f"Unknown ESET service: {service!r}. Allowed: {sorted(SERVICE_DOMAINS)}")
    return f"https://{region}.{SERVICE_DOMAINS[service]}.eset.systems"


def auth_url(region: Region) -> str:
    """Cloud OAuth /oauth/token endpoint for the given region."""
    return f"{base_url(region, 'business-account')}/oauth/token"


def resolve_base_url(creds: Credentials, service: str) -> str:
    """Pick the right API origin for these credentials.

    - Cloud: per-service regional domain (e.g. ``eu.device-management.eset.systems``).
    - On-prem: the single ``server_url`` of the PROTECT console - same URL
      for every service, since on-prem hosts everything from one origin.
    """
    if creds.deployment == "onprem":
        if not creds.server_url:
            raise RuntimeError(
                "On-prem credentials without a server URL. In env mode set "
                "ESET_ONPREM_SERVER_URL; in basic-auth mode send the "
                "X-ESET-Server-URL header."
            )
        return creds.server_url
    return base_url(creds.region, service)


def resolve_auth_url(creds: Credentials) -> str:
    """Pick the right authentication endpoint for these credentials.

    - Cloud: ``{region}.business-account.iam.eset.systems/oauth/token``
      (OAuth2 password grant, snake_case response).
    - On-prem: ``{server_url}/GetTokens`` (bespoke JSON endpoint with a
      camelCase response - see :class:`eset_mcp.auth.OnPremTokenManager`).
    """
    if creds.deployment == "onprem":
        if not creds.server_url:
            raise RuntimeError(
                "On-prem credentials without a server URL. In env mode set "
                "ESET_ONPREM_SERVER_URL; in basic-auth mode send the "
                "X-ESET-Server-URL header."
            )
        return f"{creds.server_url}/GetTokens"
    return auth_url(creds.region)
