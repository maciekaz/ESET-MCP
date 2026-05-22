"""Prometheus metrics for ESET-MCP.

Metric inventory (all prefixed ``esetmcp_``):

- ``tool_calls_total{tool, deployment, status}`` - counter
- ``tool_duration_seconds{tool, deployment}`` - histogram
- ``token_refresh_total{deployment, reason}`` - counter
- ``http_retries_total{deployment, status}`` - counter
- ``response_bytes{tool, deployment}`` - histogram (post-shaping)
- ``responses_capped_total{tool}`` - counter
- ``client_pool_size`` - gauge

Label cardinality rules:

- ``tool``: bounded - one value per registered tool (~100).
- ``deployment``: ``"cloud"`` | ``"onprem"``.
- ``status``: HTTP status code as a string (``"200"``, ``"404"``, …) or
  ``"exception"`` for unhandled exceptions in the dispatch layer.
- ``reason``: ``"proactive"`` | ``"forced_401"`` | ``"initial"``.

The ``prometheus_client`` dependency is **optional** - install via
``pip install eset-mcp[metrics]``. When the package is missing all the
``inc_*`` / ``observe_*`` / ``set_*`` helpers become no-ops, and
:func:`metrics_asgi_app` returns a tiny ASGI handler that replies 503
explaining how to enable metrics.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

# ─── Optional dependency: prometheus_client ───────────────────────────────────

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    _METRICS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when extra not installed
    _METRICS_AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain"
    REGISTRY = None  # type: ignore[assignment]

    def generate_latest(_registry: Any = None) -> bytes:  # type: ignore[misc]
        return b""

    Counter = Gauge = Histogram = None  # type: ignore[assignment,misc]


# ─── Metric definitions (only built when prometheus_client is present) ────────

if _METRICS_AVAILABLE:
    _TOOL_CALLS = Counter(
        "esetmcp_tool_calls_total",
        "Total MCP tool calls dispatched",
        labelnames=("tool", "deployment", "status"),
    )
    _TOOL_DURATION = Histogram(
        "esetmcp_tool_duration_seconds",
        "End-to-end duration of tool call dispatch",
        labelnames=("tool", "deployment"),
        # Buckets chosen for typical ESET API latencies (50ms - 60s).
        buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
    )
    _TOKEN_REFRESH = Counter(
        "esetmcp_token_refresh_total",
        "Auth-token refresh operations",
        labelnames=("deployment", "reason"),
    )
    _HTTP_RETRIES = Counter(
        "esetmcp_http_retries_total",
        "HTTP retries triggered by upstream responses",
        labelnames=("deployment", "status"),
    )
    _RESPONSE_BYTES = Histogram(
        "esetmcp_response_bytes",
        "Bytes returned to the MCP client (after fields projection + cap)",
        labelnames=("tool", "deployment"),
        buckets=(1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000),
    )
    _RESPONSES_CAPPED = Counter(
        "esetmcp_responses_capped_total",
        "Responses that hit the per-call byte cap and were trimmed",
        labelnames=("tool",),
    )
    _CLIENT_POOL_SIZE = Gauge(
        "esetmcp_client_pool_size",
        "Number of active EsetHttpClient instances in the LRU pool",
    )


# ─── Public no-op-safe helpers ────────────────────────────────────────────────


def inc_tool_call(tool: str, deployment: str, status: str | int) -> None:
    if _METRICS_AVAILABLE:
        _TOOL_CALLS.labels(tool=tool, deployment=deployment, status=str(status)).inc()


def observe_tool_duration(tool: str, deployment: str, seconds: float) -> None:
    if _METRICS_AVAILABLE:
        _TOOL_DURATION.labels(tool=tool, deployment=deployment).observe(seconds)


def inc_token_refresh(deployment: str, reason: str) -> None:
    if _METRICS_AVAILABLE:
        _TOKEN_REFRESH.labels(deployment=deployment, reason=reason).inc()


def inc_http_retry(deployment: str, status: str | int) -> None:
    if _METRICS_AVAILABLE:
        _HTTP_RETRIES.labels(deployment=deployment, status=str(status)).inc()


def observe_response_bytes(tool: str, deployment: str, n_bytes: int) -> None:
    if _METRICS_AVAILABLE:
        _RESPONSE_BYTES.labels(tool=tool, deployment=deployment).observe(n_bytes)


def inc_capped(tool: str) -> None:
    if _METRICS_AVAILABLE:
        _RESPONSES_CAPPED.labels(tool=tool).inc()


def set_pool_size(n: int) -> None:
    if _METRICS_AVAILABLE:
        _CLIENT_POOL_SIZE.set(n)


# ─── /metrics endpoint as an ASGI app ─────────────────────────────────────────


Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


async def _metrics_app_enabled(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] != "http":
        return  # ignore lifespan / websocket
    # Exposition generation should never fail with the standard collectors,
    # but if a custom collector ever throws we surface a 500 with a short
    # body instead of crashing the worker.
    try:
        payload = generate_latest(REGISTRY) if _METRICS_AVAILABLE else b""
        status = 200
        ct = CONTENT_TYPE_LATEST.encode("ascii")
    except Exception as exc:  # noqa: BLE001 - never let a scraper take us down
        payload = f"metrics generation failed: {type(exc).__name__}\n".encode()
        status = 500
        ct = b"text/plain; charset=utf-8"
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", ct),
            (b"content-length", str(len(payload)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ],
    })
    await send({"type": "http.response.body", "body": payload})


async def _metrics_app_unavailable(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] != "http":
        return
    msg = (
        b"prometheus_client is not installed. "
        b"Install with: pip install eset-mcp[metrics]\n"
    )
    await send({
        "type": "http.response.start",
        "status": 503,
        "headers": [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(msg)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": msg})


def metrics_asgi_app() -> Callable[[Scope, Receive, Send], Awaitable[None]]:
    """Return an ASGI handler for ``/metrics``.

    Returns a real Prometheus exposition handler when ``prometheus_client``
    is importable, otherwise a 503-with-hint handler so operators get a
    clear error rather than a silent 404 / 500.
    """
    return _metrics_app_enabled if _METRICS_AVAILABLE else _metrics_app_unavailable


def metrics_available() -> bool:
    """True iff prometheus_client is importable (i.e. the extra was installed)."""
    return _METRICS_AVAILABLE
