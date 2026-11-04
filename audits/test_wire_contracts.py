"""Historical parity and independent published authentication contract checks.

The historical fixture records the old mapping, including on-prem fallback
paths. Passing that comparison does NOT mean every path exists on-prem.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from eset_mcp.credentials import Credentials
from eset_mcp.http_client import EsetHttpClient
from eset_mcp.server import _execute_tool
from eset_mcp.tools_loader import load_all_tools

BASELINE = json.loads(Path(__file__).with_name("legacy_business_contract.json").read_text())
OPERATIONS = BASELINE["operations"]
TOOLS = {t.name: t for t in load_all_tools()}


def test_business_tool_names_and_input_schemas_match_historical_contract():
    assert {t.name for t in TOOLS.values() if t.service != "business-account"} == {
        entry["name"] for entry in OPERATIONS
    }
    for entry in OPERATIONS:
        schema = TOOLS[entry["name"]].input_schema
        digest = hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest()
        assert digest == entry["schema_sha256"], entry["name"]


@pytest.mark.parametrize("deployment", ["cloud", "onprem"])
@pytest.mark.parametrize("entry", OPERATIONS, ids=lambda entry: entry["name"])
async def test_business_request_matches_legacy_wire_contract(entry, deployment, offline):
    """Exercise mapper + real HTTP client; only the remote transport is mocked.

    Deliberately simple sentinel values test routing/serialization, not every
    input schema constraint or the vendor's acceptance of a request body.
    """
    creds = Credentials("audit-user", "audit-password", "eu", deployment=deployment,
                        server_url="https://protect.invalid:9443" if deployment == "onprem" else "")
    token = "AUDIT_ONLY_ACCESS"
    if deployment == "cloud":
        base = f"https://eu.{entry['domain']}.eset.systems"
        auth_url = "https://eu.business-account.iam.eset.systems/oauth/token"
        payload = {"access_token": token, "expires_in": 3600}
        path = entry["path"]
    else:
        base = creds.server_url
        auth_url = f"{base}/GetTokens"
        payload = {"accessToken": token, "expiresIn": 3600}
        path = entry["onprem_path"]
    offline.post(auth_url).respond(200, json=payload)
    args = {key: f"audit-{key}" for key in entry["path_params"]}
    for key, value in args.items():
        path = path.replace("{" + key + "}", value)
    query = {key: f"audit-{key}" for key in entry["query_params"]}
    args.update(query)
    if entry["has_body"]:
        args["body"] = {"audit": ["value", 1, True]}
    route = offline.request(entry["method"], base + path).respond(200, json={"audit": "ok"})
    async with EsetHttpClient(creds) as client:
        result = await _execute_tool(client, TOOLS[entry["name"]], args)
    assert result == {"audit": "ok"}
    assert route.call_count == 1
    request = route.calls.last.request
    assert request.method == entry["method"]
    assert str(request.url.copy_with(query=None)) == base + path
    assert dict(request.url.params) == query
    assert request.headers["authorization"] == f"Bearer {token}"
    assert request.headers["accept"] == "application/json"
    if entry["has_body"]:
        assert request.headers["content-type"] == "application/json"
        assert json.loads(request.content) == args["body"]
    else:
        assert request.content == b""


@pytest.mark.parametrize("region", ["eu", "de", "us", "ca", "jpn"])
async def test_cloud_auth_matches_published_form_contract(region, offline):
    # Independently specified from ESET's authentication_oauth_token_post.html.
    route = offline.post(f"https://{region}.business-account.iam.eset.systems/oauth/token").respond(
        200, json={"access_token": "AUDIT_ONLY", "refresh_token": "AUDIT_REFRESH", "expires_in": 3600},
    )
    async with EsetHttpClient(Credentials("user+audit@example.invalid", "p&= :ą", region)) as client:
        assert await client._token_mgr.get_access_token() == "AUDIT_ONLY"
    request = route.calls.last.request
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert parse_qs(request.content.decode(), keep_blank_values=True) == {
        "grant_type": ["password"], "username": ["user+audit@example.invalid"],
        "password": ["p&= :ą"], "refresh_token": [""],
    }
    assert "authorization" not in request.headers
    assert "cf-access-client-secret" not in request.headers
