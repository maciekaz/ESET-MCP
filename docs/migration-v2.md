# Upgrading to ESET-MCP 2.0

Version **2.0.0 is a breaking security release**. It implements MCP
**2026-07-28**, retains legacy **2025-11-25** clients and preserves the names,
input schemas and API mappings of all 101 business tools and four composites.
The default On-Prem login remains the previously used `legacy` format.
See the [configuration checklist](security-migration-status.md) for required
settings and client changes.

## Required changes from v1

| Existing use | Action in v2 |
|---|---|
| `auth_o_auth__token` | Remove calls to this tool. Authentication and token renewal are internal; tokens are never tool results. |
| HTTP behind a public proxy | Set `ESET_MCP_ALLOWED_HOSTS` to the public host. Set `ESET_MCP_ALLOWED_ORIGINS` only for required browser origins. Use Basic auth behind HTTPS. |
| Env-auth HTTP on a non-loopback address | Switch to Basic auth. The explicit `ESET_MCP_ALLOW_UNAUTHENTICATED_HTTP=true` override is only for an independently authenticated gateway. |
| Per-request On-Prem URL overrides | Authorize non-default origins per username with `ESET_ONPREM_ORIGINS`, e.g. `{"api-user":["https://protect.example.com:9443"]}`. |
| CF Access environment credentials | They apply only to the configured default console. Another allowed origin needs its own complete `X-ESET-CF-*` header pair. |
| Custom CA or environment proxy | Use `ESET_CA_BUNDLE` for the CA file. Automatic proxy variables and `SSL_CERT_FILE` are no longer used; redirects are rejected. |
| Special On-Prem networks | Loopback/link-local targets require explicit `ESET_ONPREM_NETWORKS` CIDRs. Ordinary private subnets remain allowed by default. |
| Credential or target rotation | Reconnect legacy MCP sessions after changing password, CF credentials, region or origin. |
| Docker Compose without a profile | Select `http`, `prod`, `stdio` or `dev`. HTTP profiles use Basic auth; local published ports bind to loopback. |
| Invalid tool arguments | Inputs are now checked against the advertised schema before any API call. |

Normal business response data is preserved; sensitive fields and known secret
values are redacted. API errors no longer expose raw upstream diagnostics.
Writes remain available in RW mode. A timeout does not establish whether a write
took effect: check its state before retrying.

The MCP ingress still uses the project's custom Basic profile. This release
does **not** implement the MCP OAuth 2.1 authorization profile; HTTP clients must
support custom headers. The registry's `server.json` schema date is independent
of the MCP wire-protocol version.

## Images and rollout

The signed multi-platform image is `ghcr.io/maciekaz/eset-mcp:2.0.0`
(`linux/amd64`, `linux/arm64`). Tags `:2.0` and `:2` track this major line.
The `:1` tag stays on v1. `:latest` moves to v2 and may cross major versions.
Prefer an exact version or a verified digest for production.

```sh
docker pull ghcr.io/maciekaz/eset-mcp:2.0.0
cosign verify \
  --certificate-identity 'https://github.com/maciekaz/ESET-MCP/.github/workflows/publish-image.yml@refs/tags/v2.0.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/maciekaz/eset-mcp:2.0.0
```

Update the configured image reference and recreate the relevant container after
applying the settings above. Pulling/building an image does not update a running
container. The bundled Compose file builds this checkout as `eset-mcp:2.0.0-local`;
its `--build` examples are for source deployments, not a pull from GHCR.
