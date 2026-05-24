# syntax=docker/dockerfile:1.7
FROM python:3.13-slim

# OCI image metadata. Most fields are overridden by docker/metadata-action
# in the publish-image workflow (source SHA, version, etc.); the values
# here are sensible defaults for local builds.
LABEL org.opencontainers.image.title="ESET-MCP" \
      org.opencontainers.image.description="MCP server for the ESET ecosystem (Connect cloud + PROTECT On-Prem)" \
      org.opencontainers.image.source="https://github.com/maciekaz/ESET-MCP" \
      org.opencontainers.image.url="https://github.com/maciekaz/ESET-MCP" \
      org.opencontainers.image.documentation="https://github.com/maciekaz/ESET-MCP#readme" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="maciekaz" \
      io.modelcontextprotocol.server.name="io.github.maciekaz/eset-mcp"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Deps layer: pyproject + LICENSE + README are everything pip needs to
# resolve the project; copying them first keeps this layer warm across
# code-only rebuilds. BuildKit cache mount survives between builds and
# turns a cold rebuild from ~30s to ~3s.
COPY pyproject.toml README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip setuptools wheel

# Source layer: code changes invalidate this and below, but the deps
# above stay cached.
COPY eset_mcp ./eset_mcp
RUN --mount=type=cache,target=/root/.cache/pip pip install .

# Defaults: stdio. For HTTP, expose the port (override in docker-compose).
ENV ESET_MCP_TRANSPORT=stdio \
    ESET_MCP_HTTP_HOST=0.0.0.0 \
    ESET_MCP_HTTP_PORT=8765

EXPOSE 8765

# Drop privileges. Non-root by uid 10001 so it never collides with a
# host user. /app is owned by esetmcp so future writes work without root.
RUN useradd --create-home --uid 10001 esetmcp && chown -R esetmcp:esetmcp /app
USER esetmcp

ENTRYPOINT ["eset-mcp"]
