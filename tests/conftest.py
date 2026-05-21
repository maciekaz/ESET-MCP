"""Shared fixtures for ESET-MCP integration tests.

Tests hit the **real** ESET Connect API (using the credentials from .env).
If credentials are missing, integration tests are skipped automatically so
that nobody's CI/local environment breaks just because they have no setup.
"""
from __future__ import annotations

import contextlib
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from dotenv import load_dotenv

from eset_mcp.client_pool import ClientPool
from eset_mcp.config import Settings
from eset_mcp.credentials import Credentials, EnvCredentialResolver
from eset_mcp.http_client import EsetHttpClient
from eset_mcp.server import build_server

# Load .env from repo root before anything reads os.getenv.
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)

# Integration tests always run in env-auth mode against the configured tenant
# credentials. Multi-tenant (basic auth) behaviour has its own unit tests in
# test_middleware.py — they don't need a running ESET account. Even if the
# operator has `ESET_AUTH_MODE=basic` in .env (a valid production setup), the
# test suite forces env mode so the fixtures keep working.
os.environ["ESET_AUTH_MODE"] = "env"


def _have_credentials() -> bool:
    return bool(os.getenv("ESET_USER") and os.getenv("ESET_PASSWORD"))


# Without credentials, skip every integration test (we still keep the unit-level
# `test_catalog_vs_openapi.py`, which doesn't talk to the network).
collect_ignore_glob = []
if not _have_credentials():
    collect_ignore_glob = ["test_smoke_ro.py", "test_mode_gate.py", "test_pagination.py"]


@pytest.fixture(scope="session")
def settings() -> Settings:
    if not _have_credentials():
        pytest.skip("ESET_USER/ESET_PASSWORD missing — integration tests skipped.")
    return Settings.from_env()


def _creds_from_settings(settings: Settings) -> Credentials:
    return Credentials(user=settings.user, password=settings.password, region=settings.region)


@pytest_asyncio.fixture
async def http(settings: Settings) -> AsyncIterator[EsetHttpClient]:
    """Direct HTTP client — for testing the http_client layer (e.g. pagination)."""
    async with EsetHttpClient(_creds_from_settings(settings)) as c:
        yield c


@pytest.fixture
def mcp_session(settings: Settings):
    """Factory returning an async context manager that yields a connected MCP ClientSession.

    Used as:

        async def test_x(mcp_session):
            async with mcp_session() as client:
                tools = await client.list_tools()

    Why a factory instead of an async fixture: MCP's memory transport uses anyio
    task groups, and a yield-style async fixture in pytest-asyncio runs __aenter__
    and __aexit__ in different tasks → RuntimeError("cancel scope in different task").
    Keeping the entire `async with` inside one test task keeps the scope consistent.
    """

    @contextlib.asynccontextmanager
    async def _factory():
        from mcp.shared.memory import create_connected_server_and_client_session
        pool = ClientPool(settings)
        resolver = EnvCredentialResolver(settings)
        try:
            server = build_server(settings, pool, resolver)
            async with create_connected_server_and_client_session(server) as client:
                await client.initialize()
                yield client
        finally:
            await pool.close()

    return _factory
