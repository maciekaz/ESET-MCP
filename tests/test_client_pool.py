"""Unit tests for ClientPool (no network)."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from eset_mcp.client_pool import ClientPool
from eset_mcp.credentials import Credentials


@dataclass
class _FakeSettings:
    """Minimal stand-in for Settings — ClientPool only reads it to pass through."""
    user: str = "ignored"
    password: str = "ignored"
    region: str = "eu"


pytestmark = pytest.mark.asyncio


async def test_pool_returns_same_client_for_same_creds() -> None:
    pool = ClientPool(_FakeSettings())  # type: ignore[arg-type]
    try:
        a = await pool.get(Credentials("alice", "x", "eu"))
        b = await pool.get(Credentials("alice", "x", "eu"))
        assert a is b
        assert len(pool) == 1
    finally:
        await pool.close()


async def test_pool_separates_clients_per_user() -> None:
    pool = ClientPool(_FakeSettings())  # type: ignore[arg-type]
    try:
        a = await pool.get(Credentials("alice", "x", "eu"))
        b = await pool.get(Credentials("bob", "x", "eu"))
        assert a is not b
        assert len(pool) == 2
    finally:
        await pool.close()


async def test_pool_separates_clients_per_region() -> None:
    pool = ClientPool(_FakeSettings())  # type: ignore[arg-type]
    try:
        eu = await pool.get(Credentials("alice", "x", "eu"))
        us = await pool.get(Credentials("alice", "x", "us"))
        assert eu is not us
    finally:
        await pool.close()


async def test_pool_rotates_client_when_password_changes() -> None:
    pool = ClientPool(_FakeSettings())  # type: ignore[arg-type]
    try:
        old = await pool.get(Credentials("alice", "old-pw", "eu"))
        new = await pool.get(Credentials("alice", "new-pw", "eu"))
        assert old is not new, "password rotation must mint a fresh client"
    finally:
        await pool.close()


async def test_pool_lru_evicts_oldest() -> None:
    pool = ClientPool(_FakeSettings(), max_clients=2)  # type: ignore[arg-type]
    try:
        first = await pool.get(Credentials("u1", "x", "eu"))
        second = await pool.get(Credentials("u2", "x", "eu"))
        # Touch u1 to make it most-recently-used; now u2 is LRU.
        await pool.get(Credentials("u1", "x", "eu"))
        # Adding a 3rd entry evicts u2 (the LRU), not u1.
        third = await pool.get(Credentials("u3", "x", "eu"))
        assert len(pool) == 2

        # u1 must still be the same cached instance.
        assert await pool.get(Credentials("u1", "x", "eu")) is first
        # u3 must still be the same cached instance.
        assert await pool.get(Credentials("u3", "x", "eu")) is third
        # u2 was evicted — re-fetch mints a fresh client (different instance).
        revived = await pool.get(Credentials("u2", "x", "eu"))
        assert revived is not second
    finally:
        await pool.close()
