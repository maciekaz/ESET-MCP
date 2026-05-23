"""Unit tests for the observability layer.

Coverage:

- :func:`log_event` strips known-sensitive fields BEFORE they reach any
  formatter. Defensive deny-list - never trust callers.
- JSON formatter produces one self-contained object per record, ISO ts.
- Text formatter falls back gracefully and appends scrubbed extras.
- Prometheus helpers are no-ops when prometheus_client is missing (we
  can't easily test that here since the dep IS installed for tests, but
  we DO assert the public API behaves correctly when present).
- ``/metrics`` ASGI app returns the expected content-type and body.
"""
from __future__ import annotations

import io
import json
import logging

import pytest

from eset_mcp.observability.logging import (
    _is_sensitive,
    _JsonFormatter,
    _scrub,
    _TextFormatter,
    configure_logging,
    log_event,
)
from eset_mcp.observability.metrics import (
    inc_capped,
    inc_http_retry,
    inc_token_refresh,
    inc_tool_call,
    metrics_asgi_app,
    metrics_available,
    observe_response_bytes,
    observe_tool_duration,
    set_pool_size,
)


# --- Sensitive-key deny-list ---
@pytest.mark.parametrize("key", [
    "password",
    "Password",
    "PASSWORD",
    "user_password",
    "secret",
    "client_secret",
    "cf_access_client_secret",
    "X-CF-Access-Client-Secret",
    "authorization",
    "Authorization",
    "Cookie",
    "api_key",
    "api-key",
    "bearer_token",
    "credentials",
])
def test_sensitive_keys_detected(key: str) -> None:
    assert _is_sensitive(key) is True


@pytest.mark.parametrize("key", [
    "user",          # username is OK to log
    "tool",
    "deployment",
    "status",
    "duration_ms",
    "method",
    "service",
    "path",
    "region",
    "host",          # hostname only, not full URL
    "request_id",
])
def test_non_sensitive_keys_pass(key: str) -> None:
    assert _is_sensitive(key) is False


def test_scrub_removes_sensitive_keys() -> None:
    fields = {
        "tool": "device_list",
        "password": "should-vanish",
        "duration_ms": 100,
        "Authorization": "Basic xxx",
        "user": "api@firma.tld",
        "cf_access_client_secret": "also-gone",
    }
    out = _scrub(fields)
    assert out == {
        "tool": "device_list",
        "duration_ms": 100,
        "user": "api@firma.tld",
    }


# --- log_event end-to-end ---
def _capture_json_logs() -> tuple[logging.Logger, io.StringIO]:
    """Build a logger writing JSON Lines into a StringIO buffer."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_JsonFormatter())
    logger = logging.getLogger("eset_mcp.test.json")
    # Reset to avoid duplicate handlers when test re-runs.
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, buf


def test_log_event_emits_json_with_event_and_fields() -> None:
    logger, buf = _capture_json_logs()
    log_event(logger, "tool_call", tool="device_list", deployment="cloud", status="200")
    line = buf.getvalue().strip()
    record = json.loads(line)
    assert record["event"] == "tool_call"
    assert record["tool"] == "device_list"
    assert record["deployment"] == "cloud"
    assert record["status"] == "200"
    assert record["level"] == "INFO"
    assert record["ts"].endswith("Z")  # UTC, no offset


def test_log_event_drops_sensitive_fields_silently() -> None:
    logger, buf = _capture_json_logs()
    log_event(
        logger, "tool_call",
        tool="device_list",
        password="hunter2",
        Authorization="Basic xxx",
        cf_access_client_secret="leaked!",
    )
    line = buf.getvalue().strip()
    record = json.loads(line)
    assert "password" not in record
    assert "Authorization" not in record
    assert "cf_access_client_secret" not in record
    assert "hunter2" not in line  # no leakage anywhere in the line
    assert "leaked!" not in line
    assert record["tool"] == "device_list"


def test_log_event_warning_level_respected() -> None:
    logger, buf = _capture_json_logs()
    log_event(logger, "http_request_retry", level=logging.WARNING, status=429)
    record = json.loads(buf.getvalue().strip())
    assert record["level"] == "WARNING"


def test_text_formatter_appends_extras_and_drops_sensitive() -> None:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_TextFormatter())
    logger = logging.getLogger("eset_mcp.test.text")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    log_event(logger, "tool_call", tool="x", password="should-vanish", status="200")
    line = buf.getvalue()
    assert "tool='x'" in line or "tool=x" in line.replace("'", "")
    assert "should-vanish" not in line
    assert "password" not in line


def test_configure_logging_is_idempotent() -> None:
    """Calling configure_logging twice replaces the handler, not stacks them."""
    configure_logging(fmt="text")
    configure_logging(fmt="json")
    root = logging.getLogger()
    owned = [h for h in root.handlers if getattr(h, "_eset_mcp_owned", False)]
    assert len(owned) == 1


# --- Metrics ---
def test_metrics_available_in_test_env() -> None:
    """prometheus_client is installed as a dev dependency, so metrics work."""
    assert metrics_available() is True


def test_metric_helpers_do_not_raise() -> None:
    """Smoke test that every public helper accepts the documented shape."""
    inc_tool_call(tool="t", deployment="cloud", status="200")
    observe_tool_duration(tool="t", deployment="cloud", seconds=0.123)
    inc_token_refresh(deployment="cloud", reason="proactive")
    inc_http_retry(deployment="cloud", status="429")
    observe_response_bytes(tool="t", deployment="cloud", n_bytes=4096)
    inc_capped(tool="t")
    set_pool_size(3)


async def test_metrics_endpoint_returns_prometheus_format() -> None:
    """/metrics returns the right content-type and contains our metrics."""
    inc_tool_call(tool="probe_endpoint", deployment="cloud", status="200")
    inc_tool_call(tool="probe_endpoint", deployment="cloud", status="200")

    app = metrics_asgi_app()
    captured: dict[str, list] = {"start": [], "body": []}

    async def _recv() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(msg: dict) -> None:
        if msg["type"] == "http.response.start":
            captured["start"].append(msg)
        elif msg["type"] == "http.response.body":
            captured["body"].append(msg["body"])

    await app({"type": "http", "method": "GET", "path": "/metrics"}, _recv, _send)
    assert captured["start"][0]["status"] == 200
    ct = dict(captured["start"][0]["headers"]).get(b"content-type", b"").decode()
    assert "text/plain" in ct  # Prometheus exposition format
    body = b"".join(captured["body"]).decode()
    assert "esetmcp_tool_calls_total" in body
    assert 'tool="probe_endpoint"' in body
    assert "deployment=\"cloud\"" in body


def test_metrics_endpoint_ignores_lifespan_scope() -> None:
    """Non-HTTP scopes (lifespan, websocket) must not crash the handler."""
    import asyncio
    app = metrics_asgi_app()

    async def _recv() -> dict:
        return {"type": "lifespan.startup"}

    async def _send(_msg: dict) -> None:
        raise AssertionError("send must not be called for lifespan scope")

    asyncio.get_event_loop().run_until_complete(
        app({"type": "lifespan"}, _recv, _send)
    ) if not asyncio.get_event_loop().is_running() else asyncio.create_task(
        app({"type": "lifespan"}, _recv, _send)
    )
