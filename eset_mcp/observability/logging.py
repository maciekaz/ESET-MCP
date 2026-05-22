"""Structured logging with a hard deny-list for sensitive fields.

Two output formats, switchable via ``ESET_MCP_LOG_FORMAT``:

- ``text`` (default): human-readable single line per record, ideal for dev.
- ``json``: JSON Lines, one self-contained object per line, ideal for prod
  log shippers (Loki, Vector, Fluent Bit, Datadog Agent, ELK, CloudWatch).

The :func:`log_event` helper attaches structured fields to a log record via
the ``extra`` mechanism. Every call passes its fields through a deny-list
that drops anything matching known-sensitive substrings (``password``,
``secret``, ``token``, ``authorization``, ``cf-access-client-secret``, …).
The check is defensive: even if a future caller accidentally passes
``password=...``, it never reaches the formatter.

Logs go to **stderr** - MCP stdio uses stdout for JSON-RPC, so any log
written to stdout corrupts the protocol stream.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import sys
from typing import Any, Final

# Substrings that, if present in a field name, cause that field to be
# dropped before it reaches the formatter. Case-insensitive match. Add
# liberally - false-positives just mean "this field doesn't show up in
# logs", which is a safe default.
_SENSITIVE_KEY_SUBSTRINGS: Final[tuple[str, ...]] = (
    "password",
    "secret",
    "token",
    "authorization",
    "cookie",
    "api_key",
    "api-key",
    "bearer",
    "credentials",
    "cf-access-client-id",         # not strictly secret but uniquely identifies tenant
    "cf-access-client-secret",
)


def _is_sensitive(key: str) -> bool:
    k = key.lower()
    return any(sub in k for sub in _SENSITIVE_KEY_SUBSTRINGS)


def _scrub(fields: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *fields* with sensitive keys removed entirely.

    No redaction-with-stars (``****``) - operators have asked for those
    fields and we make a deliberate choice NOT to log them at all, so they
    never appear in any log artefact under any circumstance.
    """
    return {k: v for k, v in fields.items() if not _is_sensitive(k)}


class _JsonFormatter(logging.Formatter):
    """One JSON object per log record. Suitable for line-oriented log shippers."""

    # Keys we always pull out of LogRecord and put at the top level.
    _STANDARD_KEYS: Final[set[str]] = {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message", "taskName", "_eset_event",
    }

    def format(self, record: logging.LogRecord) -> str:
        ts = _dt.datetime.fromtimestamp(record.created, tz=_dt.UTC).isoformat(timespec="milliseconds")
        if ts.endswith("+00:00"):
            ts = ts[:-6] + "Z"
        out: dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Caller-supplied event name (via log_event(event="..."))
        event = getattr(record, "_eset_event", None)
        if event:
            out["event"] = event
        # Any extra structured fields the caller attached via `extra=...`.
        for k, v in record.__dict__.items():
            if k in self._STANDARD_KEYS:
                continue
            if k.startswith("_"):
                continue
            if _is_sensitive(k):
                continue
            try:
                # Round-trip through json to ensure the value is serialisable.
                json.dumps(v)
                out[k] = v
            except (TypeError, ValueError):
                out[k] = repr(v)
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False)


class _TextFormatter(logging.Formatter):
    """Human-readable format. Falls back to the standard formatter, then
    appends scrubbed structured fields in ``k=v`` form if any are present.
    """

    def __init__(self):
        super().__init__(
            fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras: dict[str, Any] = {}
        event = getattr(record, "_eset_event", None)
        if event:
            extras["event"] = event
        standard = _JsonFormatter._STANDARD_KEYS
        for k, v in record.__dict__.items():
            if k in standard or k.startswith("_"):
                continue
            if _is_sensitive(k):
                continue
            extras[k] = v
        if extras:
            kv = " ".join(f"{k}={v!r}" if isinstance(v, str) else f"{k}={v}" for k, v in extras.items())
            return f"{base}  {kv}"
        return base


def configure_logging(*, level: str = "INFO", fmt: str = "text") -> None:
    """Install the right formatter on the root logger and route to stderr.

    Idempotent: calling twice replaces the handler rather than stacking
    them (useful in tests that re-run setup).
    """
    root = logging.getLogger()
    # Remove any pre-existing handlers we might own to avoid duplicate output.
    for h in list(root.handlers):
        if getattr(h, "_eset_mcp_owned", False):
            root.removeHandler(h)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler._eset_mcp_owned = True  # type: ignore[attr-defined]
    if fmt.lower() == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(_TextFormatter())
    root.addHandler(handler)
    try:
        root.setLevel(level.upper())
    except ValueError:
        root.setLevel(logging.INFO)


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    msg: str | None = None,
    **fields: Any,
) -> None:
    """Emit a structured log record.

    Sensitive-keyed fields are dropped before reaching the formatter (see
    :data:`_SENSITIVE_KEY_SUBSTRINGS`). The ``event`` argument names the
    activity (e.g. ``"tool_call"``, ``"token_refresh"``,
    ``"http_request_complete"``) and shows up as ``event`` in both
    formatters.

    Example::

        log_event(LOG, "tool_call",
                  tool="device_devices__list_devices",
                  deployment="onprem", status=200, duration_ms=312)
    """
    safe = _scrub(fields)
    safe["_eset_event"] = event
    logger.log(level, msg or event, extra=safe)
