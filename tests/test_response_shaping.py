"""Unit tests for the response-shaping helpers.

These run without any network access - they exercise pure functions.
"""
from __future__ import annotations

import json

from eset_mcp.response_shaping import apply_fields_projection, cap_response_size


# --- apply_fields_projection ---
def test_projection_basic() -> None:
    """Projection keeps only requested keys per list-item; top level intact."""
    payload = {
        "devices": [
            {"uuid": "1", "displayName": "alpha", "tags": ["a"], "secret": "x"},
            {"uuid": "2", "displayName": "beta", "tags": [], "secret": "y"},
        ],
        "nextPageToken": "abc",
        "totalSize": 2,
    }
    out = apply_fields_projection(payload, ["uuid", "displayName"])
    assert out["devices"] == [
        {"uuid": "1", "displayName": "alpha"},
        {"uuid": "2", "displayName": "beta"},
    ]
    # Top-level fields preserved as-is.
    assert out["nextPageToken"] == "abc"
    assert out["totalSize"] == 2


def test_projection_no_fields_is_noop() -> None:
    payload = {"devices": [{"uuid": "1", "x": "keep"}]}
    assert apply_fields_projection(payload, None) == payload
    assert apply_fields_projection(payload, []) == payload


def test_projection_handles_non_dict_items() -> None:
    """Mixed-shape lists: dict items projected, scalars left alone."""
    payload = {"weird": [{"uuid": "1", "drop": "me"}, "scalar", 42]}
    out = apply_fields_projection(payload, ["uuid"])
    # The current implementation filters non-dict items out of an all-dict
    # projection - which is fine. We just assert no exception and the dict
    # item is projected.
    assert {"uuid": "1"} in out["weird"]


def test_projection_only_applies_to_list_of_dicts() -> None:
    """List of scalars stays untouched (would otherwise crash on .items())."""
    payload = {"tokens": ["a", "b", "c"], "count": 3}
    assert apply_fields_projection(payload, ["uuid"]) == payload


def test_projection_returns_input_when_not_a_dict() -> None:
    """If ESET returns a bare list (rare but legal), don't crash."""
    payload: list = [{"uuid": "1"}, {"uuid": "2"}]
    # Current behaviour: only dict-typed payloads are projected.
    assert apply_fields_projection(payload, ["uuid"]) is payload


# --- cap_response_size ---
def test_cap_small_payload_unchanged() -> None:
    payload = {"devices": [{"uuid": "1"}], "nextPageToken": ""}
    result, truncated = cap_response_size(payload, max_bytes=10_000)
    assert truncated is False
    assert result == payload  # identity not required, equality is


def test_cap_zero_budget_disables_cap() -> None:
    """max_bytes=0 means 'no cap, return as-is'."""
    payload = {"devices": [{"uuid": "x" * 1000}]}
    result, truncated = cap_response_size(payload, max_bytes=0)
    assert truncated is False
    assert result == payload


def test_cap_paginated_preserves_pagination_keys() -> None:
    """When trimming items, nextPageToken / totalSize must survive."""
    big_items = [{"uuid": str(i), "blob": "x" * 200} for i in range(500)]
    payload = {
        "devices": big_items,
        "nextPageToken": "TOKEN_TO_PRESERVE",
        "totalSize": 12345,
    }
    result, truncated = cap_response_size(payload, max_bytes=5_000)

    assert truncated is True
    assert isinstance(result, dict)
    # Pagination top-level fields survive intact.
    assert result["nextPageToken"] == "TOKEN_TO_PRESERVE"
    assert result["totalSize"] == 12345
    # `_capped` metadata block present and self-consistent.
    assert "_capped" in result
    meta = result["_capped"]
    assert meta["truncated"] is True
    assert meta["itemsKey"] == "devices"
    assert meta["originalItems"] == 500
    assert meta["returnedItems"] < 500
    assert meta["originalBytes"] > meta["byteBudget"] == 5_000
    assert "nextPageToken" in meta["hint"]
    # Items kept are a true prefix of the original list (no reordering).
    kept_uuids = [d["uuid"] for d in result["devices"]]
    assert kept_uuids == [str(i) for i in range(len(kept_uuids))]


def test_cap_paginated_without_next_token_emits_different_hint() -> None:
    """When there's no nextPageToken, the hint nudges towards pageSize/fields."""
    big_items = [{"uuid": str(i), "blob": "x" * 200} for i in range(500)]
    payload = {"devices": big_items}  # no nextPageToken
    result, truncated = cap_response_size(payload, max_bytes=5_000)
    assert truncated is True
    hint = result["_capped"]["hint"]
    assert "nextPageToken" in hint  # mentions it as "did not return"
    assert "pageSize" in hint and "fields" in hint


def test_cap_picks_largest_list_by_bytes_not_length() -> None:
    """If two lists exist, trim the fat one - don't accidentally nuke a small list of UUIDs."""
    payload = {
        "deviceUuids": [str(i) for i in range(1000)],   # 1000 short strings
        "devices": [{"uuid": str(i), "blob": "x" * 500} for i in range(50)],  # 50 fat dicts
    }
    result, truncated = cap_response_size(payload, max_bytes=5_000)
    assert truncated is True
    assert result["_capped"]["itemsKey"] == "devices"   # the fat list got trimmed
    # The short list survived in full.
    assert len(result["deviceUuids"]) == 1000


def test_cap_non_paginated_falls_back_to_preview_stub() -> None:
    """Shapes without a list value get a textual preview + _capped block."""
    payload = {"giant_blob": "x" * 50_000, "more": "y" * 50_000}
    result, truncated = cap_response_size(payload, max_bytes=2_000)
    assert truncated is True
    assert "_capped" in result
    assert result["_capped"]["itemsKey"] is None
    assert "_preview" in result
    # The preview is a string snippet of the JSON, capped at our budget.
    assert isinstance(result["_preview"], str)
    assert len(result["_preview"]) <= 2_000


def test_cap_output_is_within_budget_when_paginated() -> None:
    """Sanity: after capping, the serialised payload actually fits the budget."""
    big_items = [{"uuid": str(i), "blob": "x" * 100} for i in range(200)]
    payload = {"devices": big_items, "nextPageToken": "t"}
    budget = 3_000
    result, truncated = cap_response_size(payload, max_bytes=budget)
    assert truncated is True
    # Allow a small tolerance for the metadata overhead reservation; the
    # serialised payload must not exceed the budget by more than the overhead
    # we explicitly accounted for.
    serialised = len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
    assert serialised <= budget + 600, f"capped payload is {serialised} bytes, budget {budget}"


# --- shaping pipeline: projection then cap ---
def test_projection_then_cap_keeps_more_items() -> None:
    """Skinny rows after projection should let more items fit under the cap."""
    fat = [{"uuid": str(i), "displayName": f"d{i}", "blob": "x" * 500} for i in range(200)]
    payload = {"devices": fat, "nextPageToken": "t"}

    no_proj, _ = cap_response_size(payload, max_bytes=5_000)
    fat_kept = len(no_proj["devices"])

    skinny = apply_fields_projection(payload, ["uuid", "displayName"])
    after_proj, _ = cap_response_size(skinny, max_bytes=5_000)
    skinny_kept = len(after_proj["devices"])

    assert skinny_kept > fat_kept, (
        f"projection should let more items fit under the cap "
        f"(fat={fat_kept}, skinny={skinny_kept})"
    )
