"""Response shaping — keep tool output usable inside an LLM context window.

Two independent transformations applied after the ESET API responds and
before the result is serialised to the MCP client:

1. **Fields projection** (`apply_fields_projection`) — when the agent passes a
   ``fields`` argument, every list-item is filtered down to the requested
   keys. This is **not** a native ESET API parameter; it is enforced server
   side on the JSON we already pulled. Cheap on bytes, agent decides per call.

2. **Smart size cap** (`cap_response_size`) — if the serialised response
   exceeds the byte budget, drop *items* from the longest list value while
   keeping every top-level field (especially ``nextPageToken`` /
   ``totalSize``) intact, then attach a ``_capped`` metadata block telling
   the agent how to fetch the rest. For non-paginated responses we fall back
   to a structured truncation stub.

Both helpers are pure functions: they accept and return Python objects (the
parsed JSON), never strings. The MCP layer serialises afterwards.
"""
from __future__ import annotations

import json
from typing import Any

# How many extra bytes we reserve for the `_capped` metadata block so we
# never overshoot the budget when we attach it.
_CAPPED_METADATA_OVERHEAD = 512

# Top-level keys we always keep, even when truncating the items list — they
# carry pagination + totals so the agent can continue.
_PAGINATION_KEYS = frozenset({"nextPageToken", "pageToken", "totalSize", "totalCount"})


def apply_fields_projection(result: Any, fields: list[str] | None) -> Any:
    """Project every list-item in ``result`` to the requested ``fields``.

    Top-level keys (e.g. ``nextPageToken``) are preserved. If ``fields`` is
    falsy, the input is returned unchanged. Single-object responses are
    untouched — projection only meaningfully reduces tokens on lists.

    >>> apply_fields_projection({"devices": [{"uuid": "1", "displayName": "a", "tags": []}]}, ["uuid"])
    {'devices': [{'uuid': '1'}]}
    """
    if not fields or not isinstance(result, dict):
        return result
    allow = set(fields)
    out: dict[str, Any] = {}
    for key, value in result.items():
        if isinstance(value, list) and value and isinstance(value[0], dict):
            out[key] = [
                {k: v for k, v in item.items() if k in allow}
                for item in value
                if isinstance(item, dict)
            ]
        else:
            out[key] = value
    return out


def cap_response_size(result: Any, max_bytes: int) -> tuple[Any, bool]:
    """Truncate ``result`` if its serialised size exceeds ``max_bytes``.

    Returns ``(possibly_modified_result, was_truncated)``.

    Behaviour:
      * Already small → returned as-is, ``was_truncated=False``.
      * Dict with one (or a "main") list value → keep top-level keys intact,
        trim items until the whole payload fits, attach ``_capped`` metadata
        explaining how to continue (``nextPageToken`` is preserved when present).
      * Anything else → returned wrapped in a hard-truncation stub.
    """
    if max_bytes <= 0:
        return result, False
    serialized_len = _byte_len(result)
    if serialized_len <= max_bytes:
        return result, False

    if isinstance(result, dict):
        list_key = _pick_main_list_key(result)
        if list_key is not None:
            return _truncate_paginated(result, list_key, max_bytes, serialized_len), True

    return _hard_truncate(result, max_bytes, serialized_len), True


# ─── helpers ──────────────────────────────────────────────────────────────────

def _byte_len(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


def _pick_main_list_key(d: dict[str, Any]) -> str | None:
    """Return the key whose value is the longest list (by serialised bytes).

    We pick by size, not by length: a dict with a 1000-element list of UUIDs
    and a 5-element list of fat dicts should trim the fat ones.
    Returns None if no list is found.
    """
    candidates: list[tuple[str, int]] = []
    for k, v in d.items():
        if isinstance(v, list) and v:
            candidates.append((k, _byte_len(v)))
    if not candidates:
        return None
    candidates.sort(key=lambda kv: kv[1], reverse=True)
    return candidates[0][0]


def _truncate_paginated(
    payload: dict[str, Any], list_key: str, max_bytes: int, original_bytes: int
) -> dict[str, Any]:
    """Keep top-level fields, trim the items list until everything fits."""
    items: list[Any] = list(payload[list_key])
    original_count = len(items)

    # Reserve space for everything except the items list, plus the metadata block.
    skeleton = {k: v for k, v in payload.items() if k != list_key}
    skeleton[list_key] = []
    overhead = _byte_len(skeleton) + _CAPPED_METADATA_OVERHEAD
    budget = max(max_bytes - overhead, 0)

    kept: list[Any] = []
    used = 0
    for item in items:
        # +1 covers the inter-item comma in the JSON list.
        cost = _byte_len(item) + 1
        if used + cost > budget:
            break
        kept.append(item)
        used += cost

    capped = {**payload, list_key: kept}
    next_token = payload.get("nextPageToken")
    if next_token:
        hint = (
            f"Response exceeded the {max_bytes}-byte cap. Continue with the "
            f"`nextPageToken` field above, or re-call with a smaller `pageSize` "
            f"or `fields=[...]` projection."
        )
    else:
        hint = (
            f"Response exceeded the {max_bytes}-byte cap and the underlying "
            f"endpoint did not return a nextPageToken on this page. Re-call "
            f"with a smaller `pageSize`, narrower filter, or a `fields=[...]` "
            f"projection."
        )

    capped["_capped"] = {
        "truncated": True,
        "itemsKey": list_key,
        "returnedItems": len(kept),
        "originalItems": original_count,
        "originalBytes": original_bytes,
        "byteBudget": max_bytes,
        "hint": hint,
    }
    return capped


def _hard_truncate(result: Any, max_bytes: int, original_bytes: int) -> dict[str, Any]:
    """Fallback when the payload shape doesn't look like a paginated list."""
    preview_budget = max(max_bytes - _CAPPED_METADATA_OVERHEAD, 0)
    serialized = json.dumps(result, ensure_ascii=False)
    preview = serialized[:preview_budget]
    return {
        "_capped": {
            "truncated": True,
            "itemsKey": None,
            "returnedItems": None,
            "originalItems": None,
            "originalBytes": original_bytes,
            "byteBudget": max_bytes,
            "hint": (
                "Response exceeded the byte cap and is not a paginated list "
                "shape; only a textual preview is included below. Use a more "
                "specific tool or query to narrow the result."
            ),
        },
        "_preview": preview,
    }
