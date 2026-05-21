"""High-level, hand-written MCP tools that compose multiple ESET API calls.

These do NOT come from the OpenAPI generator (`tools_loader.py`) — they sit on
top, calling several endpoints under the hood to spare the agent from gluing
3-5 raw tool calls together. They also degrade gracefully when individual
sub-calls return 403/404 (e.g. a tenant without vulnerability-management access).

Currently:
- `eset_search`         — cross-cutting substring search over devices/users/policies/groups
- `device_full_profile` — device + parent group + recent detections + vulnerabilities + OS vulns
- `incident_full_context` — incident + comments + related detections + affected devices
- `latest_detections`   — newest detections in a time window (v2→v1 fallback, paginated, sorted)

Each composite is registered in `server.py` alongside the auto-generated tools.
"""
from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from .errors import EsetApiError
from .http_client import EsetHttpClient

SearchKind = Literal["device", "user", "policy", "group"]
ALL_KINDS: tuple[SearchKind, ...] = ("device", "user", "policy", "group")

# Per-kind: where to fetch the list, what response field holds items, and which
# fields to scan with the substring query. Field paths use dot notation; a
# trailing `[]` walks into a list and inspects each element.
_KIND_CONFIG: dict[SearchKind, dict[str, Any]] = {
    "device": {
        "service": "device-management",
        "path": "/v1/devices",
        "items_key": "devices",
        "fields": [
            "displayName",
            "originalDisplayName",
            "description",
            "primaryLocalIpAddress",
            "publicIpAddress",
            "tags[]",
        ],
    },
    "user": {
        "service": "user-management",
        "path": "/v1/users",
        "items_key": "users",
        "fields": [
            "displayName",
            "primaryEmailAddress",
            "proxyEmailAddresses[]",
            "identities[].userName",
            "department",
            "jobTitle",
        ],
    },
    "policy": {
        "service": "policy-management",
        "path": "/v2/policies",
        "items_key": "policies",
        "fields": [
            "displayName",
            "description",
        ],
    },
    "group": {
        # Two endpoints can return groups: asset-management /v1/groups (static
        # groups in MSP tenants) and device-management /v1/device_groups
        # (always available). We try them in order and accept whichever works,
        # so the caller does not need to care which tree their target sits in.
        "service": "device-management",
        "path": "/v1/device_groups",
        "items_key": "deviceGroups",
        "fields": ["displayName"],
        "fallback": {
            "service": "asset-management",
            "path": "/v1/groups",
            "items_key": "groups",
            "fields": ["displayName", "description"],
        },
    },
}


@dataclass
class SearchMatch:
    kind: SearchKind
    uuid: str
    display_name: str
    matched_field: str
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "uuid": self.uuid,
            "displayName": self.display_name,
            "matchedField": self.matched_field,
            "snippet": self.snippet,
        }


async def eset_search(
    http: EsetHttpClient,
    query: str,
    kinds: Iterable[SearchKind] | None = None,
    limit_per_kind: int = 20,
) -> dict[str, Any]:
    """Case-insensitive substring search across multiple ESET resource kinds.

    Returns a single JSON payload with matches across the requested kinds.
    Per-kind sub-failures (403/404/etc.) are surfaced under "skipped" so the
    overall call still succeeds even on tenants that lack some modules.
    """
    if not query or not query.strip():
        return {"query": query, "matches": [], "scanned": {}, "skipped": [], "total": 0}

    needle = query.strip().lower()
    selected = tuple(dict.fromkeys(kinds or ALL_KINDS))  # de-dup, preserve order

    # Hit each kind in parallel — the per-kind helper handles its own errors.
    results = await asyncio.gather(
        *(_search_one_kind(http, k, needle, limit_per_kind) for k in selected),
        return_exceptions=False,  # we already catch inside _search_one_kind
    )

    all_matches: list[SearchMatch] = []
    scanned: dict[str, int] = {}
    skipped: list[dict[str, str]] = []
    for kind, (matches, count, err) in zip(selected, results, strict=True):
        scanned[kind] = count
        if err:
            skipped.append({"kind": kind, "reason": err})
        all_matches.extend(matches)

    return {
        "query": query,
        "matches": [m.to_dict() for m in all_matches],
        "total": len(all_matches),
        "scanned": scanned,
        "skipped": skipped,
    }


async def _search_one_kind(
    http: EsetHttpClient,
    kind: SearchKind,
    needle_lower: str,
    limit: int,
) -> tuple[list[SearchMatch], int, str | None]:
    """Paginate one kind, filter locally, return (matches, scanned_count, error_or_None).

    Falls back to an alternative endpoint (when the config provides one) if the
    primary errors out — used for `group`, which is exposed by two different
    services depending on whether the tenant uses asset-management.
    """
    cfg = _KIND_CONFIG[kind]
    matches, scanned, err = await _scan_endpoint(http, kind, cfg, needle_lower, limit)
    if err and cfg.get("fallback"):
        fb_matches, fb_scanned, fb_err = await _scan_endpoint(
            http, kind, cfg["fallback"], needle_lower, limit
        )
        if not fb_err:
            return fb_matches, fb_scanned, None
        # Both failed — surface the primary error (most informative).
    return matches, scanned, err


async def _scan_endpoint(
    http: EsetHttpClient,
    kind: SearchKind,
    cfg: dict[str, Any],
    needle_lower: str,
    limit: int,
) -> tuple[list[SearchMatch], int, str | None]:
    matches: list[SearchMatch] = []
    scanned = 0
    try:
        async for item in http.paginate(
            cfg["service"], cfg["path"], page_size=1000, items_key=cfg["items_key"]
        ):
            scanned += 1
            hit = _scan_item(item, cfg["fields"], needle_lower)
            if hit is None:
                continue
            field, snippet = hit
            matches.append(
                SearchMatch(
                    kind=kind,
                    uuid=str(item.get("uuid", "")),
                    display_name=str(item.get("displayName", "")),
                    matched_field=field,
                    snippet=snippet,
                )
            )
            if len(matches) >= limit:
                break
    except EsetApiError as e:
        return matches, scanned, f"[{e.status}] {e.message}"
    return matches, scanned, None


def _scan_item(
    item: dict[str, Any],
    field_paths: list[str],
    needle_lower: str,
) -> tuple[str, str] | None:
    """Walk `item` through each `field_paths` entry; return (field, snippet) on first match.

    Path notation:
      "displayName"           — plain key
      "tags[]"                — list of strings
      "identities[].userName" — list of dicts; check `userName` on each
    """
    for path in field_paths:
        match = _scan_path(item, path, needle_lower)
        if match is not None:
            return match
    return None


def _scan_path(node: Any, path: str, needle_lower: str) -> tuple[str, str] | None:
    if "[]" in path:
        head, _, tail = path.partition("[]")
        head = head.rstrip(".")
        tail = tail.lstrip(".")
        items = _walk(node, head) if head else node
        if not isinstance(items, list):
            return None
        for elem in items:
            if not tail:
                # list of scalars
                if isinstance(elem, str) and needle_lower in elem.lower():
                    return (f"{head}[]" if head else "[]", elem)
            else:
                inner = _walk(elem, tail)
                if isinstance(inner, str) and needle_lower in inner.lower():
                    return (path, inner)
        return None

    val = _walk(node, path)
    if isinstance(val, str) and needle_lower in val.lower():
        return (path, val)
    return None


def _walk(obj: Any, dotted: str) -> Any:
    cur = obj
    if not dotted:
        return cur
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


# ─── Composite #2: full device profile ────────────────────────────────────────

async def device_full_profile(http: EsetHttpClient, device_uuid: str) -> dict[str, Any]:
    """One-shot snapshot of a device — main record + detections + vulnerabilities.

    Each sub-section degrades gracefully: if the tenant lacks permission for
    vulnerabilities or incident-management, those keys carry an error stub
    instead of failing the whole call.
    """
    try:
        device = await http.request("GET", "device-management", f"/v1/devices/{device_uuid}")
    except EsetApiError as e:
        return {"error": f"Device fetch failed: {e}"}

    detections_v2, detections_v1, dev_vulns, os_vulns, recent_scans = await asyncio.gather(
        _safe_get(http, "incident-management", "/v2/detections",
                  query={"pageSize": 10}),  # v2 has no deviceUuid filter — best-effort
        _safe_get(http, "incident-management", "/v1/detections",
                  query={"pageSize": 10, "deviceUuid": device_uuid}),
        _safe_get(http, "vulnerability-management", "/v1/device-vulnerabilities",
                  query={"pageSize": 10, "deviceUuid": device_uuid}),
        _safe_get(http, "vulnerability-management", "/v1/device-os-vulnerabilities",
                  query={"pageSize": 10, "deviceUuid": device_uuid}),
        _safe_get(http, "vulnerability-management", "/v1/scans/recent",
                  query={"pageSize": 5, "deviceUuid": device_uuid}),
    )

    return {
        "device": device,
        "recentDetections": detections_v1,
        "recentDetectionsV2": detections_v2,
        "deviceVulnerabilities": dev_vulns,
        "osVulnerabilities": os_vulns,
        "recentScans": recent_scans,
    }


# ─── Composite #3: full incident context ──────────────────────────────────────

async def incident_full_context(http: EsetHttpClient, incident_uuid: str) -> dict[str, Any]:
    """Pull an incident with its comments, related detections, and affected devices.

    To stay within rate limits we cap the number of fan-out fetches (detections
    + devices) at 10 each — anything beyond that surfaces as a UUID list.
    """
    try:
        incident_resp = await http.request(
            "GET", "incident-management", f"/v2/incidents/{incident_uuid}"
        )
    except EsetApiError as e:
        return {"error": f"Incident fetch failed: {e}"}

    incident = incident_resp.get("incident", incident_resp)
    det_uuids = list(incident.get("detectionUuids") or [])[:10]
    dev_uuids = list(incident.get("deviceUuids") or [])[:10]

    comments, detections, devices = await asyncio.gather(
        _safe_get(http, "incident-management", f"/v2/incidents/{incident_uuid}/comments"),
        _gather_by_uuid(http, "incident-management", "/v2/detections/{uuid}", det_uuids),
        _gather_by_uuid(http, "device-management", "/v1/devices/{uuid}", dev_uuids),
    )

    return {
        "incident": incident,
        "comments": comments,
        "detections": detections,
        "devices": devices,
        "truncated": {
            "detections": len(incident.get("detectionUuids") or []) > 10,
            "devices": len(incident.get("deviceUuids") or []) > 10,
        },
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _safe_get(
    http: EsetHttpClient, service: str, path: str, *, query: dict[str, Any] | None = None
) -> Any:
    try:
        return await http.request("GET", service, path, query=query)
    except EsetApiError as e:
        return {"_error": f"[{e.status}] {e.message}", "_endpoint": e.endpoint}


async def _gather_by_uuid(
    http: EsetHttpClient, service: str, path_template: str, uuids: list[str]
) -> list[Any]:
    if not uuids:
        return []
    results = await asyncio.gather(
        *(_safe_get(http, service, path_template.replace("{uuid}", u)) for u in uuids)
    )
    return list(results)


# ─── Composite #4: latest detections ──────────────────────────────────────────

# Don't blow the budget if the caller picks a huge window (e.g. 30d) on a
# noisy tenant — cap pagination at this many pages of 1000 rows = 50k items.
_LATEST_DETECTIONS_PAGE_CAP = 50


async def latest_detections(
    http: EsetHttpClient,
    *,
    hours: int = 24,
    limit: int = 10,
    severity_min: str | None = None,
) -> dict[str, Any]:
    """Return the newest detections in the last `hours`, sorted by occurTime desc.

    Why a composite: `/v1/detections` and `/v2/detections` neither accept an
    `orderBy` parameter, nor return results in chronological order — pulling
    "the first page" gives you a slice that has nothing to do with recency.
    Without time-window filtering plus a local sort, agents will silently
    surface stale data (see the bug we hit while building this tool).

    Strategy:
        1. Pick the right endpoint — try `/v2/detections` first (richer
           schema). If the tenant returns 501/403/etc., fall back to
           `/v1/detections` so the caller still gets something.
        2. Filter server-side with `startTime`/`endTime` so we don't drown
           in old rows.
        3. Paginate (capped at _LATEST_DETECTIONS_PAGE_CAP pages) and sort
           locally by `occurTime` descending.
        4. Optional `severity_min` post-filter (one of LOW/MEDIUM/HIGH).

    The response carries metadata (`source`, `truncated`, `totalInWindow`)
    so the agent knows whether it saw everything or only the head.
    """
    end = datetime.now(UTC)
    start = end - timedelta(hours=max(hours, 1))
    start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = end.strftime("%Y-%m-%dT%H:%M:%SZ")

    dets, source, truncated, err = await _fetch_detections_window(http, start_iso, end_iso)
    if dets is None:
        return {
            "error": err,
            "window": {"hours": hours, "startTime": start_iso, "endTime": end_iso},
        }

    if severity_min:
        wanted = _severity_set_at_least(severity_min)
        if wanted is not None:
            dets = [d for d in dets if d.get("severityLevel") in wanted]

    dets.sort(key=lambda d: d.get("occurTime", "") or "", reverse=True)

    return {
        "window": {"hours": hours, "startTime": start_iso, "endTime": end_iso},
        "source": source,
        "totalInWindow": len(dets),
        "truncated": truncated,
        "returned": min(len(dets), limit),
        "detections": dets[:limit],
    }


async def _fetch_detections_window(
    http: EsetHttpClient, start_iso: str, end_iso: str
) -> tuple[list[dict[str, Any]] | None, str, bool, str | None]:
    """Try v2 first, fall back to v1; return (detections, source, truncated, error)."""
    for source, service, path in [
        ("v2", "incident-management", "/v2/detections"),
        ("v1", "incident-management", "/v1/detections"),
    ]:
        dets, truncated, err = await _paginate_detections(http, service, path, start_iso, end_iso)
        if err is None:
            return dets, source, truncated, None
        last_err = err
    return None, "", False, last_err


async def _paginate_detections(
    http: EsetHttpClient, service: str, path: str, start_iso: str, end_iso: str
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Walk pages with startTime/endTime, capped. Returns (items, truncated, error)."""
    items: list[dict[str, Any]] = []
    page_token = ""
    pages = 0
    try:
        while True:
            q: dict[str, Any] = {"pageSize": 1000, "startTime": start_iso, "endTime": end_iso}
            if page_token:
                q["pageToken"] = page_token
            page = await http.request("GET", service, path, query=q)
            if isinstance(page, dict):
                items.extend(page.get("detections", []) or [])
                page_token = page.get("nextPageToken") or ""
            else:
                page_token = ""
            pages += 1
            if not page_token:
                return items, False, None
            if pages >= _LATEST_DETECTIONS_PAGE_CAP:
                return items, True, None
    except EsetApiError as e:
        return items, False, f"[{e.status}] {e.message}"


_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH"]


def _severity_set_at_least(min_level: str) -> set[str] | None:
    """Return the set of severityLevel string values >= `min_level` (LOW/MEDIUM/HIGH)."""
    norm = min_level.strip().upper().removeprefix("SEVERITY_LEVEL_")
    if norm not in _SEVERITY_ORDER:
        return None
    idx = _SEVERITY_ORDER.index(norm)
    return {f"SEVERITY_LEVEL_{lvl}" for lvl in _SEVERITY_ORDER[idx:]}
