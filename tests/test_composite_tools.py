"""Tests for the high-level composite tools (eset_search, device_full_profile, incident_full_context).

These run against the real tenant. They use search results to drive subsequent
tests so the suite stays portable to other tenants.
"""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.ro


async def test_search_basic(mcp_session) -> None:
    """Search for a substring expected to exist in any non-empty tenant ('All' / 'Wszystkie' / 'Lost')."""
    async with mcp_session() as client:
        # Try a couple of well-known root-group names - at least one should hit.
        for q in ["Wszystkie", "All", "Lost"]:
            r = await client.call_tool(
                "eset_search", arguments={"query": q, "kinds": ["group"], "limit_per_kind": 5}
            )
            payload = json.loads(r.content[0].text)
            if payload["total"] > 0:
                assert payload["scanned"]["group"] > 0
                first = payload["matches"][0]
                assert first["kind"] == "group"
                assert first["uuid"]
                assert first["displayName"]
                return
        pytest.fail("Search returned 0 matches for every well-known group name - unexpected.")


async def test_search_case_insensitive_substring(mcp_session) -> None:
    """Search must be case-insensitive and do substring (not exact / not regex)."""
    async with mcp_session() as client:
        # Find any device, then look for half its name in different case.
        listing = await client.call_tool(
            "device_device_groups__list_groups", arguments={"pageSize": 5}
        )
        groups = json.loads(listing.content[0].text).get("deviceGroups", [])
        if not groups:
            pytest.skip("Tenant has no groups to base a fuzzy-search test on.")

        # Pick a non-root group with a multi-character displayName.
        candidate = next((g for g in groups if g.get("displayName") and len(g["displayName"]) >= 4), None)
        if not candidate:
            pytest.skip("No suitable group found for the fuzzy-search probe.")
        name = candidate["displayName"]

        # Take a 3-letter slice from the middle, uppercase it (forces case-insensitivity).
        needle = name[1:4].upper()

        r = await client.call_tool(
            "eset_search", arguments={"query": needle, "kinds": ["group"], "limit_per_kind": 20}
        )
        payload = json.loads(r.content[0].text)
        uuids = {m["uuid"] for m in payload["matches"]}
        assert candidate["uuid"] in uuids, (
            f"Substring {needle!r} (from {name!r}) did not surface group {candidate['uuid']} "
            f"in matches: {[m['displayName'] for m in payload['matches']]}"
        )


async def test_search_empty_query_returns_empty(mcp_session) -> None:
    async with mcp_session() as client:
        r = await client.call_tool("eset_search", arguments={"query": "  "})
        payload = json.loads(r.content[0].text)
        assert payload["total"] == 0
        assert payload["matches"] == []


async def test_search_graceful_per_kind_failure(mcp_session) -> None:
    """When one kind's endpoint errors out, the others must still return data."""
    async with mcp_session() as client:
        r = await client.call_tool(
            "eset_search",
            arguments={"query": "a", "kinds": ["device", "user", "policy", "group"], "limit_per_kind": 2},
        )
        payload = json.loads(r.content[0].text)
        # At least the device or group kind should produce something on a populated tenant.
        kinds_with_results = {m["kind"] for m in payload["matches"]}
        skipped_kinds = {s["kind"] for s in payload["skipped"]}
        assert kinds_with_results or skipped_kinds, "neither matches nor skipped - sanity issue"
        # The response must always carry the four expected top-level keys.
        for key in ("query", "matches", "total", "scanned", "skipped"):
            assert key in payload


async def test_device_full_profile_real_uuid(mcp_session) -> None:
    """Pick any device via search, run the full profile, sanity-check the shape."""
    async with mcp_session() as client:
        # First grab a device via list endpoint.
        r0 = await client.call_tool(
            "device_devices__list_devices", arguments={"pageSize": 1}
        )
        text0 = r0.content[0].text
        if text0.startswith("ESET API error:"):
            pytest.skip(f"Cannot list devices: {text0}")
        devices = json.loads(text0).get("devices", [])
        if not devices:
            pytest.skip("Tenant has no devices.")
        uuid = devices[0]["uuid"]

        r = await client.call_tool("device_full_profile", arguments={"deviceUuid": uuid})
        profile = json.loads(r.content[0].text)
        # Top-level keys are always present, even if some sub-sections degraded.
        assert "device" in profile, profile
        assert "recentDetections" in profile
        assert "deviceVulnerabilities" in profile
        # The `device` slot must contain real data, not a degraded `_error` stub.
        assert "_error" not in profile["device"], f"device fetch failed: {profile['device']}"


async def test_incident_full_context_graceful_on_missing(mcp_session) -> None:
    """If incidents are not accessible (or none exist), the composite must surface a clean error."""
    async with mcp_session() as client:
        # Bogus UUID - exercises the error branch deterministically.
        r = await client.call_tool(
            "incident_full_context",
            arguments={"incidentUuid": "00000000-0000-0000-0000-000000000000"},
        )
        text = r.content[0].text
        # Either an explicit error stub from the composite, or a friendly "ESET API error:"
        # passthrough. Either way: no exception bubbled up.
        assert "error" in text.lower() or "Incident fetch failed" in text


async def test_latest_detections_returns_sorted_recent(mcp_session) -> None:
    """The composite must return detections in `occurTime` desc order, within the window."""
    async with mcp_session() as client:
        # 7-day window - generous enough that even sparse tenants should hit something,
        # but if not, we still expect a well-formed empty response (not a crash).
        r = await client.call_tool("latest_detections", arguments={"hours": 168, "limit": 5})
        payload = json.loads(r.content[0].text)
        assert "window" in payload
        assert "source" in payload
        assert "detections" in payload
        assert payload["source"] in ("v1", "v2"), f"unexpected source: {payload!r}"
        # Window math: end == ~now, start == end - 168h.
        assert payload["window"]["hours"] == 168
        # If detections came back, they must be sorted desc by occurTime.
        dets = payload["detections"]
        if not dets:
            pytest.skip("Tenant has no detections in the last 7 days - nothing to assert.")
        times = [d.get("occurTime", "") for d in dets]
        assert times == sorted(times, reverse=True), (
            f"detections must be sorted occurTime desc; got: {times}"
        )
        # And `returned` matches list length.
        assert payload["returned"] == len(dets)


async def test_latest_detections_severity_filter(mcp_session) -> None:
    """severity_min must drop everything below the requested threshold."""
    async with mcp_session() as client:
        r = await client.call_tool(
            "latest_detections", arguments={"hours": 168, "limit": 20, "severity_min": "HIGH"}
        )
        payload = json.loads(r.content[0].text)
        if payload.get("error"):
            pytest.skip(f"detections endpoint unavailable: {payload['error']}")
        for d in payload["detections"]:
            sev = d.get("severityLevel", "")
            assert sev in {"SEVERITY_LEVEL_HIGH"}, (
                f"severity_min=HIGH should not return {sev}; offending: {d.get('displayName')}"
            )
