"""Preserve graceful composite behavior under missing modules and API failures."""
from __future__ import annotations

import json

import httpx

from audits.composite_fixture import FixedDateTime
from audits.test_security_boundaries import (
    AUTH_URL,
    GROUP_TOOL,
    GROUPS_URL,
    SECRET,
    memory_client,
    mock_auth,
)


async def test_profile_keeps_successful_sections_when_module_is_forbidden(offline):
    mock_auth(offline)
    offline.get("https://eu.device-management.eset.systems/v1/devices/device-a").respond(200, json={"uuid": "device-a"})
    offline.get("https://eu.incident-management.eset.systems/v2/detections").respond(403, text=SECRET)
    offline.get("https://eu.incident-management.eset.systems/v1/detections").respond(200, json={"detections": [{"uuid": "det-a"}]})
    for path in ("device-vulnerabilities", "device-os-vulnerabilities", "scans/recent"):
        offline.get(f"https://eu.vulnerability-management.eset.systems/v1/{path}").respond(200, json={"items": []})
    async with memory_client() as client:
        result = await client.call_tool("device_full_profile", {"deviceUuid": "device-a"})
    payload = json.loads(result.content[0].text)
    assert not result.is_error and SECRET not in result.model_dump_json()
    assert payload["device"]["uuid"] == "device-a"
    assert payload["recentDetections"]["detections"][0]["uuid"] == "det-a"
    assert "403" in payload["recentDetectionsV2"]["_error"]


async def test_search_group_fallback_and_nested_user_match(offline):
    mock_auth(offline)
    offline.get(GROUPS_URL).respond(404, text=SECRET)
    offline.get("https://eu.asset-management.eset.systems/v1/groups").respond(200, json={"groups": [{"uuid": "group-a", "displayName": "Fixture group"}]})
    offline.get("https://eu.user-management.eset.systems/v1/users").respond(200, json={"users": [{"uuid": "user-a", "displayName": "User A", "identities": [{"userName": "Fixture login"}]}]})
    offline.get("https://eu.policy-management.eset.systems/v2/policies").respond(403, text=SECRET)
    async with memory_client() as client:
        result = await client.call_tool("eset_search", {"query": "fixture", "kinds": ["group", "user", "policy"]})
    payload = json.loads(result.content[0].text)
    assert not result.is_error and SECRET not in result.model_dump_json()
    assert {m["uuid"] for m in payload["matches"]} == {"group-a", "user-a"}
    assert payload["skipped"][0]["kind"] == "policy"


async def test_latest_falls_back_to_v1_and_preserves_date_sort(monkeypatch, offline):
    monkeypatch.setattr("eset_mcp.composite_tools.datetime", FixedDateTime)
    mock_auth(offline)
    offline.get("https://eu.incident-management.eset.systems/v2/detections").respond(403, text=SECRET)
    route = offline.get("https://eu.incident-management.eset.systems/v1/detections").mock(side_effect=[
        httpx.Response(200, json={"detections": [{"uuid": "old", "occurTime": "2026-09-25T08:00:00Z"}], "nextPageToken": "next"}),
        httpx.Response(200, json={"detections": [{"uuid": "new", "occurTime": "2026-09-25T11:00:00Z"}]}),
    ])
    async with memory_client() as client:
        result = await client.call_tool("latest_detections", {"hours": 24, "limit": 1})
    payload = json.loads(result.content[0].text)
    assert not result.is_error
    assert payload["source"] == "v1" and payload["detections"][0]["uuid"] == "new"
    assert route.calls[1].request.url.params["pageToken"] == "next"
    assert route.calls[0].request.url.params["startTime"] == "2026-09-24T12:00:00Z"


async def test_cached_token_projection_and_cap_keep_model_boundary(offline):
    auth = mock_auth(offline)
    offline.get(GROUPS_URL).respond(200, json={"deviceGroups": [{"uuid": f"item-{i}", "metadata": {"opaque": SECRET}, "description": "x" * 1000} for i in range(20)],
                                             "nextPageToken": "cursor-ok"})
    async with memory_client(response_bytes_max=1000) as client:
        for _ in range(2):
            result = await client.call_tool(GROUP_TOOL, {"fields": ["uuid", "metadata", "description"]})
            assert not result.is_error and SECRET not in result.model_dump_json()
            payload = json.loads(result.content[0].text)
            assert payload["nextPageToken"] == "cursor-ok" and "_capped" in payload
    assert auth.call_count == 1


async def test_auth_failure_is_safe_error_and_never_calls_business_endpoint(offline):
    route = offline.post(AUTH_URL).respond(401, text="Bearer " + SECRET)
    async with memory_client() as client:
        result = await client.call_tool(GROUP_TOOL, {})
    assert result.is_error and SECRET not in result.model_dump_json()
    assert route.call_count == len(offline.calls) == 1
