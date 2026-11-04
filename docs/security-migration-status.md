# Required changes for ESET-MCP 2.0

Use this checklist when upgrading Cloud or On-Prem deployments from v1 to v2.
For image selection and rollout, see the [v1 → v2 migration guide](migration-v2.md).

## Configuration changes

| Setting or existing behavior | Required action |
|---|---|
| Calls to `auth_o_auth__token` | Remove these calls from client workflows. Authentication and token renewal are internal to the adapter. |
| `ESET_MCP_ALLOWED_HOSTS` | Add the public reverse-proxy host. Compose `prod` uses `ESET_PUBLIC_DOMAIN`. Use `host:*` only when multiple ports are required. |
| `ESET_MCP_ALLOWED_ORIGINS` | Add only the required browser origins. Native clients that omit `Origin` do not need an entry. |
| Env-auth HTTP on a non-loopback address | Switch to Basic auth behind HTTPS. Use `ESET_MCP_ALLOW_UNAUTHENTICATED_HTTP=true` only behind an independently authenticated gateway. |
| `ESET_ONPREM_ORIGINS` | Authorize additional origins per username, for example `{"api-user":["https://protect.example.com:9443"]}`. The configured default origin remains allowed. |
| Cloudflare Access environment credentials | Use them only for the configured default console. Another allowed origin protected by Access needs its own complete `X-ESET-CF-Access-Client-Id` and `X-ESET-CF-Access-Client-Secret` header pair. |
| `ESET_ONPREM_NETWORKS` | Set CIDRs to restrict target networks or explicitly allow required loopback/link-local targets. Ordinary private subnets remain allowed by default. |
| `ESET_CA_BUNDLE` | Set the path to a trusted PEM CA bundle when a private CA is required. Replace reliance on `SSL_CERT_FILE` or automatic environment proxies; redirects are rejected. |
| `ESET_ONPREM_AUTH_STYLE` | Keep `legacy` for the existing `grant_type` login format. Select `v13` explicitly for a console using `grantType: "PASSWORD"` / `"REFRESH_TOKEN"`. |
| Docker Compose | Select `http`, `prod`, `stdio` or `dev`. Configure `ESET_PUBLIC_DOMAIN` and `ESET_ACME_EMAIL` for `prod`; local published HTTP ports bind to loopback. |

## Client and workflow changes

- Use an HTTP client that supports the project's Basic authentication headers.
  The MCP OAuth 2.1 authorization profile is not implemented.
- Reconnect legacy MCP sessions after changing the password, Cloudflare Access
  credentials, region or console origin.
- Make tool arguments conform to the advertised input schema. Invalid arguments
  are rejected before an ESET API request is sent.
- Remove dependencies on raw upstream error bodies or secret-bearing response
  fields. Use the returned local correlation identifier for error reporting.
- Check the operation's state before manually retrying a write after a timeout
  or connection failure.

## Applying the update

1. Apply the relevant configuration and client changes above.
2. Update the deployment's image reference to `ghcr.io/maciekaz/eset-mcp:2.0.0`
   or its verified digest. For source deployments, rebuild the selected Compose
   profile from the updated checkout.
3. Recreate the affected container. Pulling or building an image does not update
   a running container. Restart the server after changing environment settings
   or the CA bundle.
4. Reconnect clients whose legacy session identity has changed.

Pin an exact image version or digest in production. `:2` and `:2.0` track the v2
line, `:1` remains on v1, and `:latest` may cross major versions.
