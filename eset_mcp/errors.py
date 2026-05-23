"""Map HTTP / ESET errors to agent-friendly messages.

Goal: the agent receives not just a status code but a readable hint about
what went wrong and what to do about it - especially for 403 (permissions),
401 (token / password), 429 (rate limit), and 5xx (backend).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EsetApiError(Exception):
    status: int
    message: str
    body: str | None = None
    request_id: str | None = None
    endpoint: str | None = None

    def __str__(self) -> str:
        parts = [f"[{self.status}] {self.message}"]
        if self.endpoint:
            parts.append(f"endpoint={self.endpoint}")
        if self.request_id:
            parts.append(f"request-id={self.request_id}")
        if self.body and len(self.body) < 500:
            parts.append(f"body={self.body}")
        return " | ".join(parts)


@dataclass
class ModeForbiddenError(Exception):
    """Raised when an RW tool is invoked while the server is in RO mode."""
    tool_name: str

    def __str__(self) -> str:
        return (
            f"Tool '{self.tool_name}' requires RW mode, but the MCP server is in RO mode "
            f"(ESET_MODE=RO). Set ESET_MODE=RW in .env and restart the server if you "
            f"intend to perform a mutating action."
        )


def map_http_error(status: int, body: str, endpoint: str, request_id: str | None) -> EsetApiError:
    """Return an EsetApiError with an agent-readable description.

    Wording follows the "Status codes" section of the ESET Connect docs.
    """
    msg = {
        400: (
            "Bad Request - validation error or missing/invalid authorization. "
            "Verify the call's parameters against the endpoint documentation."
        ),
        401: (
            "Unauthorized - the access token has expired or is invalid. "
            "The MCP server refreshes the token automatically; if you keep seeing "
            "this, check ESET_USER/ESET_PASSWORD in .env."
        ),
        403: (
            "Forbidden - the API account lacks permission for this operation. "
            "In ESET PROTECT Hub → Permission Sets, verify the user has the right "
            "Permission Set for this resource and group. If this is an RW operation, "
            "the account may be read-only."
        ),
        404: "Not Found - resource does not exist (check the UUID) or the 202 cache expired.",
        409: "Conflict - e.g. resource already exists or stale ETag.",
        429: (
            "Rate limit (10 req/s per credential/IP). The MCP server retries with backoff; "
            "if you still see this after retries, reduce request frequency or wait."
        ),
        500: "Internal Server Error from ESET - retry in a moment.",
        502: "Bad Gateway from ESET - retry in a moment.",
        503: "Service Unavailable (ESET maintenance) - retry later.",
        504: "Gateway Timeout - response did not arrive within 120s; the 202 cache expired.",
    }.get(status, f"HTTP {status} - unexpected error from the ESET API.")

    return EsetApiError(
        status=status,
        message=msg,
        body=body[:500] if body else None,
        request_id=request_id,
        endpoint=endpoint,
    )
