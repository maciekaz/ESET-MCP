"""Pool of EsetHttpClient instances keyed by (user, region).

Why a pool: in multi-tenant mode each request can come from a different ESET
account. We don't want to create a fresh httpx.AsyncClient + TokenManager on
every call (auth handshake + connection overhead), but we also can't share a
single client across tenants (each one needs its own OAuth token).

The pool also bounds memory: an LRU eviction with a small cap keeps the server
from accumulating clients forever in a busy multi-tenant deployment.

Single-tenant (env mode) just hits the pool with the same key over and over,
so it's effectively a no-op — same client every time.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict

from .config import Settings
from .credentials import Credentials
from .http_client import EsetHttpClient

# Hard cap on concurrently-cached clients. Realistic multi-tenant MCP
# deployments fronting an ESET MSP will see well under 100 active credentials
# at any time; the cap exists to bound memory if something goes wrong.
_DEFAULT_MAX_CLIENTS = 64


class ClientPool:
    """Async-safe LRU pool of EsetHttpClient instances.

    Usage:
        pool = ClientPool(settings)
        client = await pool.get(credentials)
        await client.request(...)

    The caller does NOT close the returned client — the pool owns its lifecycle.
    On shutdown, call `await pool.close()` to drain every cached client.
    """

    def __init__(self, settings: Settings, *, max_clients: int = _DEFAULT_MAX_CLIENTS):
        self._settings = settings
        self._max = max_clients
        # Key is (user, password_hash, deployment, region_or_server_url,
        # cf_secret_hash) — see Credentials.cache_key() for the rationale.
        self._clients: OrderedDict[
            tuple[str, str, str, str, str], EsetHttpClient
        ] = OrderedDict()
        self._lock = asyncio.Lock()
        # Hold strong refs to background eviction tasks so they don't get GC'd
        # before they finish closing the underlying httpx clients.
        self._eviction_tasks: set[asyncio.Task] = set()

    async def get(self, creds: Credentials) -> EsetHttpClient:
        """Return a cached client for these credentials, creating one if needed."""
        key = creds.cache_key()
        async with self._lock:
            existing = self._clients.get(key)
            if existing is not None:
                # Move to end of LRU.
                self._clients.move_to_end(key)
                return existing

            client = EsetHttpClient(creds)
            self._clients[key] = client
            await self._maybe_evict_locked()
            return client

    async def _maybe_evict_locked(self) -> None:
        while len(self._clients) > self._max:
            _, evicted = self._clients.popitem(last=False)
            # Close in background — don't block the get() that triggered eviction.
            task = asyncio.create_task(evicted.aclose())
            self._eviction_tasks.add(task)
            task.add_done_callback(self._eviction_tasks.discard)

    async def close(self) -> None:
        """Close every cached client. Call on shutdown."""
        async with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        # Best-effort close of all clients in parallel.
        await asyncio.gather(*(c.aclose() for c in clients), return_exceptions=True)

    def __len__(self) -> int:
        return len(self._clients)
