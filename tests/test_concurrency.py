"""Concurrency / isolation stress tests for the multi-tenant code paths.

These tests intentionally try to break the isolation guarantees the README
makes:

- ContextVar credentials must not bleed between concurrent requests.
- The client pool must hand the SAME client to repeated same-credential
  requests and DIFFERENT clients to different credentials, even under
  concurrent access.
- Token refresh must serialise correctly: 100 concurrent requests hitting
  an expired token should trigger exactly ONE upstream /oauth/token call.
- One tenant's auth failure must not affect another tenant's success.
- Pool eviction interacting with in-flight requests on the evicted client.

Most tests are pure (mocked httpx via respx) so they're fast and
deterministic. Marked with ``concurrency`` for grouping.
"""
from __future__ import annotations

import asyncio
import base64
from contextvars import copy_context

import httpx
import pytest
import respx

from eset_mcp.auth import CloudTokenManager
from eset_mcp.client_pool import ClientPool
from eset_mcp.config import Settings
from eset_mcp.credentials import (
    BasicAuthCredentialResolver,
    Credentials,
    request_credentials,
)


def _make_settings(**overrides) -> Settings:
    """Build a Settings without touching .env."""
    import os
    base = {
        "ESET_AUTH_MODE": "basic",
        "ESET_USER": "",
        "ESET_PASSWORD": "",
        "ESET_MODE": "RO",
        "ESET_REGION": "eu",
        "ESET_MCP_TRANSPORT": "http",
        "ESET_DEPLOYMENT": "cloud",
        "ESET_MCP_METRICS_ENABLED": "false",
        "ESET_MCP_LOG_FORMAT": "text",
    }
    base.update(overrides)
    prev = {k: os.environ.get(k) for k in base}
    for k, v in base.items():
        os.environ[k] = v
    try:
        return Settings.from_env(env_file=None)
    finally:
        for k, v in prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# --- ContextVar isolation ---
async def test_contextvar_isolation_under_100_concurrent_tasks() -> None:
    """100 tasks each set the ContextVar to their own creds and then read it
    back after a couple of awaits. No task may observe another's creds.
    """
    settings = _make_settings()
    resolver = BasicAuthCredentialResolver(settings)

    async def one_task(idx: int) -> str:
        creds = Credentials(user=f"user-{idx}", password=f"pw-{idx}", region="eu")
        # Each task gets its own ContextVar copy (asyncio.Task semantics).
        token = request_credentials.set(creds)
        try:
            # Force a couple of suspension points so the scheduler interleaves us
            # with all the other tasks.
            await asyncio.sleep(0)
            await asyncio.sleep(0.001)
            await asyncio.sleep(0)
            seen = resolver.resolve()
            return seen.user
        finally:
            request_credentials.reset(token)

    # Each task must run in its own asyncio.Task (otherwise ContextVar is shared).
    results = await asyncio.gather(*(asyncio.create_task(one_task(i)) for i in range(100)))
    assert results == [f"user-{i}" for i in range(100)], (
        "ContextVar bled between concurrent tasks - tenant isolation broken"
    )


async def test_contextvar_copied_not_shared_into_child_tasks() -> None:
    """A child task launched from inside one parent must see the parent's
    ContextVar value, NOT some other parent's. Verifies the asyncio.Task
    copy-on-spawn semantics that everything else relies on.
    """
    seen: dict[int, str] = {}

    async def child(idx: int) -> None:
        # No further set() in the child - it should inherit the parent's.
        await asyncio.sleep(0.001)
        creds = request_credentials.get()
        seen[idx] = creds.user if creds else "(none)"

    async def parent(idx: int) -> None:
        creds = Credentials(user=f"u{idx}", password="pw", region="eu")
        token = request_credentials.set(creds)
        try:
            await asyncio.create_task(child(idx))
        finally:
            request_credentials.reset(token)

    await asyncio.gather(*(parent(i) for i in range(50)))
    assert seen == {i: f"u{i}" for i in range(50)}


# --- Client pool concurrency ---
async def test_pool_returns_same_client_for_repeated_same_creds() -> None:
    settings = _make_settings()
    pool = ClientPool(settings, max_clients=8)
    creds = Credentials(user="u", password="pw", region="eu")
    try:
        clients = await asyncio.gather(*(pool.get(creds) for _ in range(20)))
        first = clients[0]
        assert all(c is first for c in clients), (
            "Same creds returned different clients under concurrent access - "
            "pool deduplication broken"
        )
    finally:
        await pool.close()


async def test_pool_returns_distinct_clients_for_distinct_creds() -> None:
    settings = _make_settings()
    pool = ClientPool(settings, max_clients=64)
    try:
        creds = [
            Credentials(user=f"u{i}", password="pw", region="eu") for i in range(32)
        ]
        clients = await asyncio.gather(*(pool.get(c) for c in creds))
        # 32 unique creds -> 32 unique clients.
        assert len({id(c) for c in clients}) == 32
    finally:
        await pool.close()


async def test_pool_lock_serialises_creation_under_burst() -> None:
    """100 simultaneous get()s for 100 different creds must end up with
    exactly 100 distinct clients (one creation per cred, no duplicates,
    no lost-update on the OrderedDict)."""
    settings = _make_settings()
    pool = ClientPool(settings, max_clients=256)
    try:
        creds = [Credentials(user=f"u{i}", password="p", region="eu") for i in range(100)]
        clients = await asyncio.gather(*(pool.get(c) for c in creds))
        assert len({id(c) for c in clients}) == 100
        assert len(pool) == 100
    finally:
        await pool.close()


async def test_pool_eviction_closes_evicted_clients_eventually() -> None:
    """Above max_clients, oldest gets evicted and its aclose runs in background."""
    settings = _make_settings()
    pool = ClientPool(settings, max_clients=2)
    try:
        a = await pool.get(Credentials(user="a", password="p", region="eu"))
        await pool.get(Credentials(user="b", password="p", region="eu"))
        # Pool full at 2. Get c -> evict a.
        await pool.get(Credentials(user="c", password="p", region="eu"))
        assert len(pool) == 2
        # Wait for the background aclose to finish.
        for _ in range(50):
            if a._http.is_closed:
                break
            await asyncio.sleep(0.02)
        assert a._http.is_closed, "evicted client's underlying httpx was not closed"
    finally:
        await pool.close()


async def test_pool_eviction_race_documented_in_client_pool_module() -> None:
    """The eviction-vs-in-flight-request race is a known production edge
    case documented in :mod:`eset_mcp.client_pool` at the _DEFAULT_MAX_CLIENTS
    constant. We can't reproduce it cleanly here because respx intercepts
    the transport BEFORE httpcore's connection pool gets involved, so
    aclose() on a respx-mocked client doesn't disturb pending mock calls.

    This test asserts the documentation is present so it doesn't silently
    drift if someone refactors the pool. The mitigation is the high
    default cap (256) which makes the race effectively never fire in
    realistic multi-tenant deployments.
    """
    import inspect

    from eset_mcp import client_pool
    src = inspect.getsource(client_pool)
    assert "in flight" in src or "in-flight" in src, (
        "The pool-eviction race must remain documented in client_pool.py"
    )
    assert client_pool._DEFAULT_MAX_CLIENTS >= 256, (
        "Default pool cap was lowered below 256, which makes the "
        "eviction-vs-in-flight race more likely. If you intend this, "
        "update the documentation in client_pool.py and this test."
    )


# --- Token refresh serialisation ---
@respx.mock
async def test_concurrent_token_refresh_calls_api_once() -> None:
    """50 tasks ask for the access token at once. The token manager's lock
    must dedupe the upstream OAuth call to exactly one network round-trip.
    """
    creds = Credentials(user="u@example.com", password="pw", region="eu")
    route = respx.post("https://eu.business-account.iam.eset.systems/oauth/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "T", "refresh_token": "R", "expires_in": 3600}
        )
    )
    async with httpx.AsyncClient() as http:
        mgr = CloudTokenManager(creds, http)
        tokens = await asyncio.gather(*(mgr.get_access_token() for _ in range(50)))
    assert all(t == "T" for t in tokens)
    assert route.call_count == 1, (
        f"expected exactly 1 OAuth call under 50 concurrent get_access_token() requests, "
        f"got {route.call_count} - token-refresh deduplication broken"
    )


@respx.mock
async def test_concurrent_force_refresh_coalesces_under_401_storm() -> None:
    """Under a token-revocation storm, 20 concurrent 401-retry paths
    converge on force_refresh(). The token manager's lock serialises them
    AND it now checks 'did someone else just refresh?' before re-auth -
    so 20 concurrent force_refresh()s end up doing exactly ONE upstream
    handshake, not 20."""
    creds = Credentials(user="u", password="pw", region="eu")
    route = respx.post("https://eu.business-account.iam.eset.systems/oauth/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "T", "refresh_token": "R", "expires_in": 3600}
        )
    )
    async with httpx.AsyncClient() as http:
        mgr = CloudTokenManager(creds, http)
        tokens = await asyncio.gather(*(mgr.force_refresh() for _ in range(20)))
    assert all(t == "T" for t in tokens)
    assert route.call_count == 1, (
        f"force_refresh storm should coalesce to 1 upstream call, "
        f"got {route.call_count}"
    )


# --- Tenant isolation under partial failures ---
@respx.mock
async def test_one_tenants_bad_password_does_not_affect_another() -> None:
    """Tenant A has bad creds (401 from OAuth). Tenant B has good creds.
    A's failure must not break B in any way: B still gets its token,
    B's client is untouched, B's pool entry is independent.
    """
    settings = _make_settings()
    pool = ClientPool(settings, max_clients=8)

    creds_bad = Credentials(user="bad", password="wrong", region="eu")
    creds_good = Credentials(user="good", password="right", region="eu")

    respx.post("https://eu.business-account.iam.eset.systems/oauth/token").mock(
        side_effect=lambda request: (
            httpx.Response(401, text="bad creds")
            if b"bad" in request.content
            else httpx.Response(
                200, json={"access_token": "GOOD", "refresh_token": "R", "expires_in": 3600}
            )
        )
    )

    async def try_get_token(c: Credentials) -> str | Exception:
        client = await pool.get(c)
        try:
            return await client._token_mgr.get_access_token()
        except Exception as e:  # we WANT to see exceptions here
            return e

    try:
        bad_result, good_result = await asyncio.gather(
            try_get_token(creds_bad), try_get_token(creds_good)
        )
        assert isinstance(bad_result, Exception), "bad creds must surface as an error"
        assert good_result == "GOOD", "good tenant must NOT be affected by bad tenant"

        # And the pool keeps both entries (separate cache keys).
        assert len(pool) == 2
    finally:
        await pool.close()


# --- Mixed cloud + on-prem in flight at the same time ---
@respx.mock
async def test_cloud_and_onprem_same_user_independent_clients() -> None:
    """Same user, but one request goes cloud (eu) and another onprem (URL).
    Pool must give two separate clients keyed by deployment+endpoint."""
    settings = _make_settings()
    pool = ClientPool(settings, max_clients=8)

    cloud = Credentials(user="u", password="p", region="eu")
    onprem = Credentials(
        user="u", password="p", region="eu",
        deployment="onprem", server_url="https://protect.local:9443",
    )

    respx.post("https://eu.business-account.iam.eset.systems/oauth/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "CLOUD_TOKEN", "refresh_token": "R", "expires_in": 3600}
        )
    )
    respx.post("https://protect.local:9443/GetTokens").mock(
        return_value=httpx.Response(200, json={"accessToken": "ONPREM_TOKEN", "expiresIn": 3600})
    )

    try:
        c1, c2 = await asyncio.gather(pool.get(cloud), pool.get(onprem))
        assert c1 is not c2, "cloud and on-prem clients for same user must be distinct"
        # Drive each token manager - tokens must come from the right backend.
        t_cloud, t_onprem = await asyncio.gather(
            c1._token_mgr.get_access_token(),
            c2._token_mgr.get_access_token(),
        )
        assert t_cloud == "CLOUD_TOKEN"
        assert t_onprem == "ONPREM_TOKEN"
    finally:
        await pool.close()


# --- End-to-end through the ASGI middleware ---
async def test_concurrent_basic_auth_requests_carry_their_own_creds() -> None:
    """50 concurrent HTTP requests, each carrying its own Basic auth + maybe
    its own X-ESET-Server-URL. The middleware must stash each request's
    creds in the ContextVar without bleed."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from eset_mcp.middleware import BasicAuthCredentialsMiddleware

    seen: list[tuple[str, str, str]] = []
    seen_lock = asyncio.Lock()

    async def _echo(_request):
        # Yield a few times to interleave with other concurrent handlers.
        await asyncio.sleep(0)
        await asyncio.sleep(0.001)
        await asyncio.sleep(0)
        creds = request_credentials.get()
        async with seen_lock:
            seen.append((creds.user, creds.deployment, creds.server_url))
        return JSONResponse({"ok": True})

    settings = _make_settings(ESET_AUTH_MODE="basic", ESET_MCP_TRANSPORT="http")
    app = Starlette(routes=[Route("/echo", _echo)])
    app.add_middleware(BasicAuthCredentialsMiddleware, settings=settings)

    def _basic(u: str, p: str = "pw") -> str:
        return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        async def one(i: int) -> None:
            headers = {"authorization": _basic(f"user-{i}")}
            # Half the requests target on-prem, half cloud.
            if i % 2 == 0:
                headers["x-eset-server-url"] = f"https://onprem-{i}.local:9443"
            r = await client.get("/echo", headers=headers)
            assert r.status_code == 200

        await asyncio.gather(*(one(i) for i in range(50)))

    # Every request must show up exactly once, with its own creds.
    by_user = {u: (dep, url) for (u, dep, url) in seen}
    assert len(by_user) == 50
    for i in range(50):
        dep, url = by_user[f"user-{i}"]
        if i % 2 == 0:
            assert dep == "onprem"
            assert url == f"https://onprem-{i}.local:9443"
        else:
            assert dep == "cloud"
            assert url == ""


# --- ContextVar leaking into module-level coroutines ---
async def test_resolver_never_sees_stale_contextvar_after_reset() -> None:
    """After the middleware resets the ContextVar, the resolver must raise -
    no stale value from a previous request leaks into the next one."""
    settings = _make_settings()
    resolver = BasicAuthCredentialResolver(settings)
    # Pretend a previous request ran:
    token = request_credentials.set(Credentials(user="prev", password="p", region="eu"))
    request_credentials.reset(token)
    # Fresh context mimics the next request's task:
    ctx = copy_context()
    from eset_mcp.credentials import CredentialResolverError
    with pytest.raises(CredentialResolverError):
        ctx.run(resolver.resolve)
