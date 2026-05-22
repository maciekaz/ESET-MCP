"""Server entrypoint — stdio or Streamable HTTP transport."""
from __future__ import annotations

import asyncio
import logging
import sys

from .client_pool import ClientPool
from .config import Settings
from .credentials import BasicAuthCredentialResolver, EnvCredentialResolver
from .server import build_server


def main() -> None:
    settings = Settings.from_env()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,  # MCP stdio uses stdout for JSON-RPC — logs MUST go to stderr.
    )
    log = logging.getLogger("eset_mcp")
    log.info(
        "ESET-MCP starting — mode=%s region=%s transport=%s auth=%s deployment=%s",
        settings.mode, settings.region, settings.transport, settings.auth_mode, settings.deployment,
    )
    if settings.deployment == "onprem":
        log.info("ESET-MCP on-prem default URL: %s (verify_ssl=%s)",
                 settings.onprem_server_url or "(none — must be supplied per request)",
                 settings.onprem_verify_ssl)

    asyncio.run(_run(settings))


async def _run(settings: Settings) -> None:
    pool = ClientPool(settings)
    if settings.auth_mode == "env":
        resolver = EnvCredentialResolver(settings)
    else:
        resolver = BasicAuthCredentialResolver(settings)

    server = build_server(settings, pool, resolver)
    try:
        if settings.transport == "stdio":
            from mcp.server.stdio import stdio_server
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
        elif settings.transport == "http":
            await _serve_http(settings, server)
        else:
            raise RuntimeError(f"Unknown transport: {settings.transport!r}")
    finally:
        await pool.close()


async def _serve_http(settings: Settings, server) -> None:
    """Streamable HTTP transport per MCP spec 2025-11-25.

    NOTE: StreamableHTTPSessionManager owns an anyio task group that MUST be
    entered via `async with manager.run()` BEFORE any request hits
    `manager.handle_request`. Skipping that yields 500s with
    "Task group is not initialized. Make sure to use run().".
    """
    import contextlib

    import uvicorn
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Mount

    manager = StreamableHTTPSessionManager(app=server, stateless=False)

    @contextlib.asynccontextmanager
    async def _lifespan(_app):
        async with manager.run():
            yield

    app = Starlette(
        routes=[Mount("/mcp", app=manager.handle_request)],
        lifespan=_lifespan,
    )

    # Basic-auth middleware sits in front of everything in `basic` mode.
    if settings.auth_mode == "basic":
        from .middleware import BasicAuthCredentialsMiddleware
        app.add_middleware(BasicAuthCredentialsMiddleware, settings=settings)

    config = uvicorn.Config(
        app, host=settings.http_host, port=settings.http_port, log_level=settings.log_level.lower()
    )
    await uvicorn.Server(config).serve()


if __name__ == "__main__":
    main()
