"""Secret handling at the model/log boundary; never an authentication mechanism."""
from __future__ import annotations

import base64
import json
import re
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import quote, quote_plus

REDACTED = "[REDACTED]"


def sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    # Pagination tokens are data, not authorization credentials.
    if normalized in {"pagetoken", "nextpagetoken", "responsetoken"}:
        return False
    return any(part in normalized for part in (
        "password", "secret", "accesstoken", "refreshtoken", "authorization",
        "cookie", "apikey", "bearer", "credentials", "cfaccessclient",
    )) or normalized in {"token", "tokens"}


class SecretRedactor:
    """Request-local known values plus structural redaction of upstream data.

    Kept out of result metadata and exceptions. The object is shared by child
    tasks of one call so composite tools and concurrent refreshes are covered.
    """

    def __init__(self):
        self._values: set[str] = set()

    def add(self, *values: str | None) -> None:
        for value in values:
            if not isinstance(value, str) or not value:
                continue
            self._values.update((value, quote(value, safe=""), quote_plus(value),
                                 json.dumps(value, ensure_ascii=True)[1:-1],
                                 base64.b64encode(value.encode()).decode(),
                                 base64.urlsafe_b64encode(value.encode()).decode()))

    def text(self, text: str) -> str:
        # Replace in one pass: a short secret must not corrupt the marker itself.
        if self._values:
            pattern = "|".join(re.escape(v) if len(v) >= 4 else r"(?<!\w)" + re.escape(v) + r"(?!\w)"
                               for v in sorted(self._values, key=len, reverse=True))
            text = re.sub(pattern, lambda _: REDACTED, text)
        text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 " + REDACTED, text)
        # Defense for diagnostics containing credentials outside a JSON object.
        text = re.sub(
            r'''(?i)(["']?(?:access[_-]?token|refresh[_-]?token|password|client[_-]?secret)["']?\s*[:=]\s*)["']?[^\s,"'}&]+["']?''',
            lambda m: m.group(1) + REDACTED, text,
        )
        return text

    def clean(self, value):
        if isinstance(value, dict):
            return {self.text(str(k)): REDACTED if sensitive_key(str(k)) else self.clean(v)
                    for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            # Tool text and JSON nested in diagnostic strings are also boundaries.
            if value.lstrip().startswith(("{", "[")):
                try:
                    parsed = json.loads(value)
                except (ValueError, RecursionError):
                    pass
                else:
                    return json.dumps(self.clean(parsed), ensure_ascii=False, indent=2)
            return self.text(value)
        return value


_current: ContextVar[SecretRedactor | None] = ContextVar("eset_secret_scope", default=None)


@contextmanager
def secret_scope():
    redactor = SecretRedactor()
    token = _current.set(redactor)
    try:
        yield redactor
    finally:
        _current.reset(token)


def remember_secrets(*values: str | None) -> None:
    redactor = _current.get()
    if redactor is not None:
        redactor.add(*values)


def clean_output(value):
    return (_current.get() or SecretRedactor()).clean(value)


def clean_text(text: str) -> str:
    return (_current.get() or SecretRedactor()).text(text)


def path_segment(value: object) -> str:
    """Preserve ordinary IDs, encode reserved bytes, reject traversal outright."""
    from urllib.parse import unquote
    raw = str(value)
    decoded = raw
    for _ in range(3):
        decoded = unquote(decoded)
    if not raw or decoded in {".", ".."} or any(c in decoded for c in "/\\?#\r\n\x00"):
        raise ValueError("Invalid path parameter")
    return quote(raw, safe="-._~")
