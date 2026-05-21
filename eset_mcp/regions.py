"""Region → per-service domain mapping.

Sources: ESET Connect docs (Network Prerequisites) + OpenAPI spec names from
eu.esetconnect.eset.systems.
"""
from __future__ import annotations

from .config import Region

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
    """Return the full base URL for the given service in the given region.

    Example: base_url("eu", "device-management") → "https://eu.device-management.eset.systems"
    """
    if service not in SERVICE_DOMAINS:
        raise KeyError(f"Unknown ESET service: {service!r}. Allowed: {sorted(SERVICE_DOMAINS)}")
    return f"https://{region}.{SERVICE_DOMAINS[service]}.eset.systems"


def auth_url(region: Region) -> str:
    """OAuth /oauth/token endpoint for the given region."""
    return f"{base_url(region, 'business-account')}/oauth/token"
