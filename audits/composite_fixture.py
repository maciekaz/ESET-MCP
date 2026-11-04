"""Deterministic API data for original/new composite behavior comparison."""
from datetime import UTC, datetime


class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 9, 25, 12, 0, tzinfo=UTC)


COMPOSITE_CASES = [
    ("eset_search", {"query": "FIXTURE", "kinds": ["device", "user", "policy", "group"], "limit_per_kind": 2}),
    ("device_full_profile", {"deviceUuid": "device-fixture"}),
    ("incident_full_context", {"incidentUuid": "incident-fixture"}),
    ("latest_detections", {"hours": 24, "limit": 2, "severity_min": "MEDIUM"}),
]


def composite_reply(request):
    path = request.url.path
    if path == "/v2/incidents/incident-fixture":
        return {"incident": {"uuid": "incident-fixture", "detectionUuids": [f"det-{i}" for i in range(12)],
                             "deviceUuids": [f"dev-{i}" for i in range(12)]}}
    if path.endswith("/comments"):
        return {"comments": [{"text": "Synthetic comment"}]}
    if path.startswith(("/v1/devices/", "/v2/detections/")):
        return {"uuid": path.rsplit("/", 1)[1], "displayName": "Fixture endpoint"}
    if path in {"/v2/detections", "/v1/detections"}:
        if "pageToken" in request.url.params:
            return {"detections": [{"uuid": "new", "occurTime": "2026-09-25T11:00:00Z", "severityLevel": "SEVERITY_LEVEL_HIGH"}]}
        return {"detections": [{"uuid": "older", "occurTime": "2026-09-25T08:00:00Z", "severityLevel": "SEVERITY_LEVEL_MEDIUM"},
                               {"uuid": "low", "occurTime": "2026-09-25T11:30:00Z", "severityLevel": "SEVERITY_LEVEL_LOW"}],
                "nextPageToken": "next-detection-page"}
    key = {"/v1/devices": "devices", "/v1/users": "users", "/v2/policies": "policies",
           "/v1/device_groups": "deviceGroups", "/v1/groups": "groups"}.get(path)
    if key:
        if "pageToken" in request.url.params:
            return {key: [{"uuid": key + "-second", "displayName": "second fixture"}]}
        return {key: [{"uuid": key + "-first", "displayName": "First Fixture"},
                      {"uuid": key + "-unmatched", "displayName": "Unrelated"}], "nextPageToken": "next-search-page"}
    return {"items": [{"uuid": "fixture-subsection"}]}
