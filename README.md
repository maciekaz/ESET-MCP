# ESET-MCP

[![Tests](https://github.com/maciekaz/ESET-MCP/actions/workflows/integration.yml/badge.svg)](https://github.com/maciekaz/ESET-MCP/actions/workflows/integration.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![MCP spec](https://img.shields.io/badge/MCP%20spec-2025--11--25-informational)](https://modelcontextprotocol.io/specification/2025-11-25)

A [Model Context Protocol](https://modelcontextprotocol.io) server for the
[ESET Connect API](https://help.eset.com/eset_connect/en-US/). Drive ESET
PROTECT / ESET Inspect / ESET Cloud Office from any MCP host — Claude Desktop,
Claude Code, OpenWebUI, or a custom agent — through tools, resources, and
prompts.

---

## Table of contents

- [Features](#features)
- [Security](#security)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Multi-tenant deployment (basic-auth mode)](#multi-tenant-deployment-basic-auth-mode)
- [Production deployment (HTTPS via Caddy)](#production-deployment-https-via-caddy)
- [Tools, resources & prompts](#tools-resources--prompts)
- [Architecture](#architecture)
- [Tests](#tests)
- [Refreshing the OpenAPI specs](#refreshing-the-openapi-specs)
- [License](#license)

---

## Features

### Complete API coverage

- **102 tools** auto-generated from 16 official ESET Connect OpenAPI 3.0.1
  specs, covering application-management, asset-management, automation,
  device-management, identity, incident-management, installer-management,
  mobile-device-management, network-access-protection, patch-management,
  policy-management, quarantine-management, user-management,
  vulnerability-management, and web-access-protection.
- **4 high-level composites** that fold 3–6 raw calls into one:
  `eset_search`, `device_full_profile`, `incident_full_context`,
  `latest_detections`.

### Read-only / read-write modes

- `ESET_MODE=RO` → catalog exposes **only** read-only tools (51 total).
  Write tools are hidden from `list_tools` entirely.
- `ESET_MODE=RW` → all 106 tools advertised; mutating tools carry
  `destructiveHint: true` in their MCP annotations.
- Independent of the ESET account's underlying permissions.
- A defence-in-depth in-memory gate rejects RW tool names in RO mode
  before any HTTP request is sent.

### Authentication

- `ESET_AUTH_MODE=env` — single tenant, credentials from `.env`.
- `ESET_AUTH_MODE=basic` — multi tenant, clients pass
  `Authorization: Basic <base64(user:password)>` (and optional
  `X-ESET-Region`) per request. One server fronts many ESET accounts.
- Per-tenant OAuth tokens, pooled and isolated by
  `(user, password_hash, region)`. Rotating a password mints a fresh
  token rather than reusing a stale one.

### Transports

- **stdio** — JSON-RPC over stdin/stdout for local hosts.
- **Streamable HTTP** — the current MCP transport (Nov 2025 spec).

### Multi-region

`eu` / `de` / `us` / `ca` / `jpn`. Fixed via `ESET_REGION` in `env` mode;
per-request via `X-ESET-Region` in `basic` mode.

### Resilience

- OAuth2 with proactive refresh ~5 min before token expiry and a forced
  refresh + retry on 401.
- 429 retries with exponential backoff (up to 3 attempts, honours
  `Retry-After`).
- Pagination (`nextPageToken`) walked transparently.
- 202 long-polling with the `response-id` header, up to 10 minutes.

### Response shaping (context-window protection)

A single uncapped `list_*` call can return hundreds of KB — enough to
overflow a model's context. Two transformations are applied to every
tool response:

- **`fields` projection** — every GET tool exposes an optional
  `fields: [string]` parameter that filters each list-item down to the
  requested keys (e.g. `["uuid", "displayName"]`). Applied server-side
  after fetch.
- **Byte cap** (`ESET_MCP_RESPONSE_BYTES_MAX`, default 100 KB) — if a
  payload still exceeds the budget, the longest list is trimmed while
  every top-level field (`nextPageToken`, `totalSize`, …) is preserved,
  and a `_capped` metadata block is attached with an actionable hint
  on how to continue. Agents retain full access to the data through
  pagination.

### Agent-friendly errors

HTTP errors are mapped to readable hints: 403 → check Permission Sets in
ESET PROTECT Hub; 401 → server refreshes the token automatically; 429 →
back off; 5xx → retry shortly.

---

## Security

### Credentials

- In `env` mode the password is read once at startup and kept in memory.
- In `basic` mode the password is on the wire only for the duration of
  the request, and in memory only while the per-tenant client is hot
  in the LRU pool. It is **never logged**.
- The pool key uses a SHA-256 hash of the password rather than the
  password itself.
- OAuth access/refresh tokens are held per-tenant; tokens never cross
  tenant boundaries within a single session.

### Authentication modes & transport

| Mode    | Transport allowed | Credentials source                       |
|---------|-------------------|------------------------------------------|
| `env`   | stdio or http     | `.env` (`ESET_USER` / `ESET_PASSWORD`)   |
| `basic` | http only         | `Authorization: Basic` header per request |

`basic` mode over plain HTTP would leak passwords. The server enforces
HTTP transport for `basic` mode at startup but does **not** enforce TLS —
that is the deployment's job. The `prod` docker-compose profile fronts
the server with Caddy + Let's Encrypt.

Missing / malformed `Authorization` in `basic` mode → HTTP 401 with a
`WWW-Authenticate: Basic` challenge. Unknown region in `X-ESET-Region`
→ HTTP 401.

### RO / RW isolation

Two independent layers:

1. **Catalog hiding** — `list_tools` filters out every non-GET tool in
   RO mode. The agent never sees write tools.
2. **Defence-in-depth gate** — `call_tool` validates the tool's declared
   mode against `ESET_MODE` before any HTTP request goes out. Hard-coded
   clients, prompt-injection attempts, and stale agent snapshots all hit
   the gate and receive a structured `ModeForbiddenError` text response
   (no exception, no network call).

In RW mode, mutating tools carry `destructiveHint: true` so MCP hosts
that respect annotations can require a per-call confirmation.

### Per-tenant isolation (basic-auth mode)

- Auth headers are parsed in dedicated ASGI middleware and stashed in a
  `ContextVar`; they never enter request bodies or logs.
- Each request resolves to a `Credentials` instance keyed by
  `(user, password_hash, region)`.
- An LRU bound on the client pool prevents unbounded memory growth from
  random-credential spraying.

### Network surface

- In dev (`docker compose up`) the MCP server publishes `:8765`.
- In the `prod` profile the MCP container has **no published port** —
  Caddy joins the same docker bridge network and proxies HTTPS in. The
  only host ports are 80 (HTTP-01 ACME) and 443 (HTTPS).
- No outbound traffic except to `*.eset.systems` (auth + APIs).

### Dependency & code audit

- **Snyk Code**: 0 issues in `eset_mcp/`.
- **Ruff**: clean (`select = E F W I B UP RUF`).
- Runtime dependencies: `mcp`, `httpx`, `pydantic`, `python-dotenv`.
  Plus `starlette` + `uvicorn` when running HTTP.

### Out of scope (by design)

- No webhook receivers.
- No persistent storage; logs go to stdout.
- No on-disk caching of OAuth tokens.
- No write-back of `basic`-mode credentials to disk.

### Responsible disclosure

Please open a private security advisory rather than a public issue:
<https://github.com/maciekaz/ESET-MCP/security/advisories/new>.

---

## Quick start

```bash
git clone https://github.com/maciekaz/ESET-MCP.git
cd ESET-MCP
cp .env.example .env          # fill in ESET_USER / ESET_PASSWORD / ESET_REGION
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
eset-mcp                       # stdio transport, ready for an MCP host
```

### Wire up to Claude Desktop / Claude Code

```jsonc
// claude_desktop_config.json
{
  "mcpServers": {
    "eset": {
      "command": "/absolute/path/to/.venv/bin/eset-mcp"
    }
  }
}
```

### Docker (HTTP transport)

```bash
docker compose up --build eset-mcp-http
# MCP endpoint: http://localhost:8765/mcp
```

One-off stdio inside a container:

```bash
docker compose --profile stdio run --rm eset-mcp-stdio
```

---

## Configuration

All settings live in `.env`. Required fields are marked in
[`.env.example`](.env.example).

| Variable                       | Default       | Purpose                                                       |
|--------------------------------|---------------|---------------------------------------------------------------|
| `ESET_AUTH_MODE`               | `env`         | `env` (single tenant) or `basic` (multi tenant)               |
| `ESET_USER`                    | —             | API user (required in `env` mode)                             |
| `ESET_PASSWORD`                | —             | API password (required in `env` mode)                         |
| `ESET_MODE`                    | `RO`          | `RO` (read-only catalog) or `RW`                              |
| `ESET_REGION`                  | `eu`          | `eu` / `de` / `us` / `ca` / `jpn`                             |
| `ESET_MCP_TRANSPORT`           | `stdio`       | `stdio` or `http`                                             |
| `ESET_MCP_HTTP_HOST`           | `127.0.0.1`   | HTTP bind address                                             |
| `ESET_MCP_HTTP_PORT`           | `8765`        | HTTP port                                                     |
| `ESET_MCP_RESPONSE_BYTES_MAX`  | `100000`      | Per-call response byte cap; `0` disables                      |
| `ESET_LOG_LEVEL`               | `INFO`        | `DEBUG` / `INFO` / `WARNING` / `ERROR`                        |
| `ESET_PUBLIC_DOMAIN`           | —             | Domain Caddy issues a TLS cert for (`prod` profile only)      |
| `ESET_ACME_EMAIL`              | —             | Email Let's Encrypt uses for renewals (`prod` profile only)   |

> Use a **dedicated API user** — not your console login. Create one in
> ESET PROTECT Hub / ESET Business Account → API users.

---

## Multi-tenant deployment (basic-auth mode)

```bash
# .env
ESET_AUTH_MODE=basic
ESET_MCP_TRANSPORT=http
ESET_REGION=eu   # default region; clients can override per request
```

Every HTTP request must carry:

| Header             | Required | Notes                                                |
|--------------------|----------|------------------------------------------------------|
| `Authorization`    | yes      | `Basic <base64(user:password)>`                      |
| `X-ESET-Region`    | no       | Override default region (`eu`/`de`/`us`/`ca`/`jpn`)  |

Example Python client:

```python
import base64
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

token = base64.b64encode(b"api-user@tenant.tld:secret").decode()
headers = {"Authorization": f"Basic {token}", "X-ESET-Region": "us"}

async with streamablehttp_client(
    "https://eset-mcp.example.com/mcp/", headers=headers
) as (r, w, _):
    async with ClientSession(r, w) as session:
        await session.initialize()
        tools = await session.list_tools()
```

> ⚠️ **Basic auth without TLS leaks credentials.** Always run `basic`
> mode behind HTTPS.

---

## Production deployment (HTTPS via Caddy)

The `prod` docker-compose profile launches Caddy in front of the MCP
server. Caddy fetches a Let's Encrypt cert on first start (HTTP-01
challenge — ports 80 / 443 must be reachable from the public internet)
and proxies HTTPS to the internal MCP container.

```bash
# .env
ESET_AUTH_MODE=basic
ESET_PUBLIC_DOMAIN=eset-mcp.example.com
ESET_ACME_EMAIL=ops@example.com

docker compose --profile prod up -d
# MCP endpoint: https://eset-mcp.example.com/mcp
```

You get:

- HTTPS on 443 with auto-renewing Let's Encrypt cert.
- HTTP-01 challenge on 80.
- MCP container bound only to the docker bridge network — no published port.
- gzip / zstd compression, JSON access logs on stdout.

---

## Tools, resources & prompts

### Composite high-level tools

| Tool                                                    | Returns                                                                          |
|---------------------------------------------------------|----------------------------------------------------------------------------------|
| `eset_search(query, kinds?, limit_per_kind?)`           | Case-insensitive substring matches across devices / users / policies / groups    |
| `device_full_profile(deviceUuid)`                       | Device record + recent detections + vulnerabilities + recent scans               |
| `incident_full_context(incidentUuid)`                   | Incident + comments + related detections + affected devices                      |
| `latest_detections(hours=24, limit=10, severity_min?)`  | Newest detections in a time window, sorted by `occurTime` desc; v2 → v1 fallback |

Each composite degrades gracefully when a sub-call returns 403/404
(e.g. on tenants missing a module). The shape carries `skipped` /
`truncated` flags where applicable.

### Resources

- `eset://config/mode` — `RO` or `RW`.
- `eset://config/region` — current region (per-request in basic-auth mode).
- `eset://config/tools-catalog` — JSON catalog of all 106 tools (name,
  mode, method, path, service, description).
- `eset://docs/rate-limits` — quick reminder about the 10 req/s ceiling.

### Prompts

- `audit_inactive_devices(days=30)` — offboarding candidates.
- `vulnerability_report` — per-device CVE report.
- `incident_triage` — open incidents + related detections.

---

## Architecture

```
eset_mcp/
├── __main__.py         # entrypoint — stdio or HTTP, wires resolver + pool
├── server.py           # MCP server (tools / resources / prompts)
├── credentials.py      # Credentials + EnvResolver / BasicAuthResolver + ContextVar
├── middleware.py       # ASGI Basic-auth middleware (basic mode only)
├── client_pool.py      # LRU pool of EsetHttpClient keyed by (user, region)
├── http_client.py      # async httpx + 202 polling + 429 retry + 401 refresh
├── auth.py             # OAuth2 password grant, proactive refresh
├── regions.py          # region → per-service domains
├── modes.py            # RO/RW gate
├── errors.py           # HTTP error → agent-friendly text
├── config.py           # .env loading
├── response_shaping.py # fields projection + byte cap
├── composite_tools.py  # hand-written high-level tools
├── tools_loader.py     # generator: tools from OpenAPI specs
└── openapi/            # 16 ESET Connect OpenAPI 3.0.1 specs (bundled)
```

---

## Tests

```bash
pytest                  # full suite (RO smoke + unit + integration)
pytest -m "not rw"      # RO only (default in CI)
pytest -m rw            # RW (requires an account with RW permissions)
```

Integration tests hit a real ESET tenant — credentials supplied via the
same `.env`. CI workflow:
[`.github/workflows/integration.yml`](.github/workflows/integration.yml)
runs on PR, on push to `main`, and once a day at 03:17 UTC. The cron
catches drift between the server and ESET's published OpenAPI specs.

---

## Refreshing the OpenAPI specs

```bash
cd eset_mcp/openapi
for name in business-account application-management asset-management automation \
            device-management iam incident-management installer-management \
            mobile-device-management network-access-protection patch-management \
            policy-management quarantine-management user-management \
            vulnerability-management web-access-protection; do
  curl -sO "https://eu.esetconnect.eset.systems/swagger/api/${name}.json"
done
```

`tests/test_catalog_vs_openapi.py` flags any new or changed operations
after a refresh.

---

## License

MIT
