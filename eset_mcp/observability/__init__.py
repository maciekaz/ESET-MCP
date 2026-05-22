"""Observability layer: structured logging + Prometheus metrics.

Two independent outputs from the same instrumentation events:

- :mod:`eset_mcp.observability.logging` - JSON Lines or human text to stderr.
- :mod:`eset_mcp.observability.metrics` - Prometheus counters / histograms /
  gauges exposed via an optional ``/metrics`` endpoint.

Design rules (enforced in code, not just docs):

1. **Never** log or label-metric anything that could carry a secret:
   passwords, ``Authorization`` headers, Cloudflare Access secrets, raw
   request/response bodies, query strings, or path parameters substituted
   with concrete values (those can reveal device UUIDs etc.). The logger
   has a hard-coded deny-list applied in :func:`log_event`.
2. Path-template values (``/v1/devices/{deviceUuid}:rename``) are fine to
   log - they come from the OpenAPI spec, not the request.
3. Metric labels stay low-cardinality: tool name, deployment kind, HTTP
   status. Never per-user, per-request-id, per-server-url.
4. Username is OK in logs (helps operators debug per-tenant issues), but
   never in metric labels (would explode cardinality in multi-tenant
   deployments).
"""

from .logging import configure_logging, log_event
from .metrics import (
    inc_capped,
    inc_http_retry,
    inc_token_refresh,
    inc_tool_call,
    metrics_asgi_app,
    observe_response_bytes,
    observe_tool_duration,
    set_pool_size,
)

__all__ = [
    "configure_logging",
    "inc_capped",
    "inc_http_retry",
    "inc_token_refresh",
    "inc_tool_call",
    "log_event",
    "metrics_asgi_app",
    "observe_response_bytes",
    "observe_tool_duration",
    "set_pool_size",
]
