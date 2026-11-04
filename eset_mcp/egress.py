"""On-prem DNS policy enforced at the actual TCP connection, before secrets.

The approved hostname is kept for Host/SNI and certificate verification; only
the validated IP is passed to the socket backend, preventing a second DNS lookup.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend


class GuardedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, networks: tuple[str, ...]):
        self._networks = tuple(ipaddress.ip_network(n) for n in networks)
        self._backend = AutoBackend()

    def allows(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if self._networks:
            return any(ip in network for network in self._networks)
        # Private networks are a normal on-prem deployment. Special-purpose
        # targets require explicit network configuration, including localhost.
        return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or
                    ip.is_unspecified or ip.is_reserved)

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            async with asyncio.timeout(timeout):
                addresses = await asyncio.get_running_loop().getaddrinfo(
                    host, port, type=socket.SOCK_STREAM,
                )
                ips = list(dict.fromkeys(row[4][0] for row in addresses))
                if not ips or not all(self.allows(ip) for ip in ips):
                    raise httpcore.ConnectError("On-prem address rejected by egress policy")
                for ip in ips:
                    try:
                        return await self._backend.connect_tcp(
                            ip, port, timeout=timeout, local_address=local_address,
                            socket_options=socket_options,
                        )
                    except httpcore.ConnectError:
                        continue
                raise httpcore.ConnectError("On-prem connection failed")
        except TimeoutError:
            raise httpcore.ConnectTimeout("On-prem connection timed out") from None
        except OSError:
            raise httpcore.ConnectError("On-prem name resolution failed") from None

    async def connect_unix_socket(self, *args, **kwargs):
        raise httpcore.ConnectError("Unix sockets are not an ESET origin")

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


class OnPremTransport(httpx.AsyncHTTPTransport):
    def __init__(self, *, verify: bool | ssl.SSLContext, networks: tuple[str, ...]):
        super().__init__(verify=verify, trust_env=False)
        # HTTPX exposes no network_backend hook. This small adapter is covered
        # by tests and pinned to HTTPX 0.28.1 / HTTPCore 1.0.9 in the lockfile.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=verify, trust_env=False),
            network_backend=GuardedBackend(networks),
        )
