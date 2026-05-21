"""Pagination test: paginate() must traverse all pages via nextPageToken
and yield the same total as a single request with pageSize=1000.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.ro


async def test_paginate_device_groups_matches_full_page(http) -> None:
    full = await http.request("GET", "device-management", "/v1/device_groups", query={"pageSize": 1000})
    full_count = len(full["deviceGroups"])

    paged = []
    async for item in http.paginate(
        "device-management", "/v1/device_groups", page_size=5, items_key="deviceGroups"
    ):
        paged.append(item)
    assert len(paged) == full_count, (
        f"Pagination yielded {len(paged)} items; single-page (pageSize=1000) returned {full_count}."
    )


async def test_paginate_terminates_on_last_page(http) -> None:
    """The helper must terminate — not spin forever."""
    # Small pageSize forces at least one nextPageToken iteration.
    count = 0
    async for _ in http.paginate("device-management", "/v1/device_groups", page_size=2, items_key="deviceGroups"):
        count += 1
        if count > 10_000:  # safety net
            pytest.fail("paginate() did not terminate in a reasonable time")
    assert count > 0
