# syntax=docker/dockerfile:1.6
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copy pyproject first (no source) — better layer caching for deps.
COPY pyproject.toml README.md ./
RUN pip install --upgrade pip setuptools wheel

# Copy the rest and install the package (deps come from pyproject).
COPY eset_mcp ./eset_mcp
RUN pip install .

# Defaults: stdio. For HTTP, expose the port (override in docker-compose).
ENV ESET_MCP_TRANSPORT=stdio \
    ESET_MCP_HTTP_HOST=0.0.0.0 \
    ESET_MCP_HTTP_PORT=8765

EXPOSE 8765

# Drop privileges.
RUN useradd --create-home --uid 10001 esetmcp && chown -R esetmcp:esetmcp /app
USER esetmcp

ENTRYPOINT ["eset-mcp"]
