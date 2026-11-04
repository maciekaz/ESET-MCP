"""Pool of EsetHttpClient instances keyed by (user, region).

Why a pool: in multi-tenant mode each request can come from a different ESET
account. We don't want to create a fresh httpx.AsyncClient + TokenManager on
every call (auth handshake + connection overhead), but we also can't share a
single client across tenants (each one needs its own OAuth token).

The pool also bounds memory: an LRU eviction with a small cap keeps the server
from accumulating clients forever in a busy multi-tenant deployment.

Single-tenant (env mode) just hits the pool with the same key over and over,
so it's effectively a no-op - same client every time.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager

from .config import Settings
from .credentials import Credentials
from .http_client import EsetHttpClient
from .observability import set_pool_size

# Cached clients are bounded; active leases survive eviction and close on release.
_DEFAULT_MAX_CLIENTS = 256


class ClientPool:
    """Async-safe LRU pool of EsetHttpClient instances.

    Usage:
        pool = ClientPool(settings)
        async with pool.acquire(credentials) as client:
            await client.request(...)

    The caller does NOT close the returned client - the pool owns its lifecycle.
    On shutdown, call `await pool.close()` to drain every cached client.
    """

    def __init__(self, settings: Settings, *, max_clients: int = _DEFAULT_MAX_CLIENTS):
        if max_clients < 1:
            raise ValueError("max_clients must be positive")
        self._settings = settings
        self._max = max_clients
        # Key is (user, password_hash, deployment, region_or_server_url,
        # cf_secret_hash) - see Credentials.cache_key() for the rationale.
        self._clients: OrderedDict[
            tuple[str, str, str, str, str], EsetHttpClient
        ] = OrderedDict()
        self._lock = asyncio.Lock()
        self._leases: dict[EsetHttpClient, int] = {}
        self._retired: set[EsetHttpClient] = set()
        self._closed = False
        # Hold strong refs to background eviction tasks so they don't get GC'd
        # before they finish closing the underlying httpx clients.
        self._eviction_tasks: set[asyncio.Task] = set()

    async def get(self, creds: Credentials) -> EsetHttpClient:
        """Return a client without a lease; use acquire() around concurrent API work."""
        async with self._lock:
            return await self._get_locked(creds)

    async def _get_locked(self, creds):
        if self._closed:
            raise RuntimeError("Client pool is closed")
        key = creds.cache_key()
        existing = self._clients.get(key)
        if existing is not None:
            self._clients.move_to_end(key)
            return existing
        client = EsetHttpClient(creds)
        self._clients[key] = client
        await self._maybe_evict_locked()
        set_pool_size(len(self._clients))
        return client

    @asynccontextmanager
    async def acquire(self, creds: Credentials):
        """Lease a client for a complete tool call, including its composites."""
        async with self._lock:
            client = await self._get_locked(creds)
            self._leases[client] = self._leases.get(client, 0) + 1
        try:
            yield client
        finally:
            async with self._lock:
                remaining = self._leases[client] - 1
                if remaining:
                    self._leases[client] = remaining
                else:
                    del self._leases[client]
                    if client in self._retired:
                        self._retired.remove(client)
                        self._close_in_background(client)

    def _close_in_background(self, client):
        task = asyncio.create_task(client.aclose())
        self._eviction_tasks.add(task)
        task.add_done_callback(self._eviction_tasks.discard)

    async def _maybe_evict_locked(self) -> None:
        while len(self._clients) > self._max:
            _, evicted = self._clients.popitem(last=False)
            if self._leases.get(evicted):
                self._retired.add(evicted)
            else:
                self._close_in_background(evicted)

    async def close(self) -> None:
        """Close every cached client. Call on shutdown."""
        async with self._lock:
            self._closed = True
            clients = list(self._clients.values())
            self._clients.clear()
            for client in clients:
                if self._leases.get(client):
                    self._retired.add(client)
                else:
                    self._close_in_background(client)
        set_pool_size(0)
        # Best-effort close of all clients in parallel.
        await asyncio.gather(*tuple(self._eviction_tasks), return_exceptions=True)

    def __len__(self) -> int:
        return len(self._clients)
