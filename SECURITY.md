# Security policy

## Reporting a vulnerability

**Please do not file public GitHub issues for security problems.**

Open a private security advisory instead:

<https://github.com/maciekaz/ESET-MCP/security/advisories/new>

I aim to acknowledge reports within 72 hours and to ship a fix or a
documented mitigation within two weeks for high/critical severity issues.

## Scope

In scope:

- Anything in the `eset_mcp/` package (auth, credentials, middleware,
  client pool, HTTP client, observability, tools loader).
- The `Dockerfile`, `docker-compose.yml`, and `Caddyfile` shipped in
  this repo.
- The CI workflow under `.github/workflows/`.

Out of scope (report directly to the upstream maintainer):

- Vulnerabilities in the [Model Context Protocol SDK](https://github.com/modelcontextprotocol/python-sdk),
  `httpx`, `pydantic`, `python-dotenv`, `starlette`, `uvicorn`, or
  `prometheus-client`.
- Vulnerabilities in the ESET Connect API itself or in ESET PROTECT
  On-Prem (those belong to ESET's security team).
- Misconfigurations in your own deployment (e.g. running `basic` auth
  mode over plain HTTP, leaving `ESET_ONPREM_VERIFY_SSL=false` on
  the public internet, exposing `/metrics` without network ACLs).

## Verified security properties

These are continuously tested in CI:

- **Credential isolation between tenants**. ContextVar-scoped credentials
  per request; per-tenant OAuth token managers; pool keyed by
  `(user, password_hash, deployment, region_or_url, cf_secret_hash)`;
  one tenant's auth failure does not affect any other tenant. See
  `tests/test_concurrency.py`.
- **No secrets in logs**. Defensive deny-list in
  `eset_mcp/observability/logging.py` drops any field whose name matches
  `password` / `secret` / `token` / `authorization` / `cookie` /
  `api_key` / `bearer` / `credentials` / `cf-access-client-*` before any
  formatter sees it. Tested in `tests/test_observability.py`, including
  assertions that the raw secret bytes never appear in the output line.
- **No secrets on disk**. OAuth tokens live in process memory only;
  basic-auth credentials are never written back to the filesystem.
- **TLS required for basic auth**. The server enforces HTTP transport
  for `ESET_AUTH_MODE=basic` at startup; production deployments must
  front it with TLS (the `prod` docker-compose profile uses Caddy +
  Let's Encrypt).
- **RO/RW defence-in-depth**. Even in RO mode, write tools are both
  hidden from `list_tools` AND blocked at `call_tool` before any HTTP
  request goes out.
- **Dependency scanning**. Snyk SCA on every CI run; `prometheus-client`
  is an opt-in extra so default installs have a minimal dep surface.
- **SAST**. Snyk Code on every CI run; current count: 0 issues.
- **Secret scanning**. gitleaks with a project-specific allowlist
  for the OAuth RFC 6749 example values present in the bundled ESET
  OpenAPI spec. Current count: 0 leaks.

## Hardening checklist for operators

When you deploy ESET-MCP in production:

1. Use `ESET_AUTH_MODE=basic` only behind TLS (the `prod` compose
   profile + Caddy handles this for you).
2. Leave `ESET_ONPREM_VERIFY_SSL=true` unless you genuinely need to
   talk to an on-prem console with a self-signed cert on a trusted
   network.
3. Protect `/metrics` at the network layer (private subnet, VPN, or a
   Caddy ACL). The endpoint carries no secrets but does carry
   per-tenant activity counts.
4. Use a **dedicated** ESET API user (not your console login). Give it
   the minimum Permission Set required for the tools you expose.
5. Rotate basic-auth credentials and Cloudflare Access service tokens
   on the schedule your organisation requires. The MCP server picks
   up new credentials on the next request - no restart needed.
6. Set `ESET_LOG_LEVEL=WARNING` (or `ERROR`) on chatty deployments to
   suppress per-call INFO events while keeping retries / errors
   visible.
7. Pin a specific image digest (not just the `latest` tag) when
   deploying via Docker.
