# Security policy

Report vulnerabilities using a [private GitHub security advisory](https://github.com/maciekaz/ESET-MCP/security/advisories/new), not a public issue.

The security scope includes the package, bundled deployment configuration and CI.
Vendor API behavior and third-party components also need independent updates and
monitoring; this project cannot guarantee their security.

## Security boundaries in 2.0.0

- Authentication is internal: `/oauth/token` and `/GetTokens` are absent from
  tools and catalogs, and blocked at the business request boundary.
- All tool outputs, including composites, pass through request-local secret
  filtering. Known passwords, access/refresh tokens, CF secrets, common encodings
  and sensitive nested keys are removed. Pagination cursors remain usable.
  Upstream error bodies, URLs and upstream correlation IDs are not returned.
- Per-call credentials come from the SDK's explicit HTTP request. Legacy MCP
  sessions are bound to connection identity; changed credentials require a new
  session. Modern requests are stateless. Pool entries isolate connection
  settings, and leases prevent eviction from closing an active operation.
- On-prem origins require operator authorization. Environment CF credentials
  are attached only to the configured default origin. DNS addresses are checked
  at connection time, with the approved IP pinned for TCP and the original host
  retained for TLS/SNI. Implicit proxies and redirects are disabled.
- Application logging sanitizes nested values, messages and exceptions; HTTP
  access logs are disabled. Caddy runtime logs filter request headers and URI.
  Apply equivalent secret filtering to custom tracing/exporters and externally
  installed log handlers.
- RO hides and blocks all 54 write operations before contacting ESET. RW remains
  available. Transport failures and 5xx responses do not automatically replay
  mutations. A timeout or cancellation does not prove a mutation was undone.

## Deployment requirements

Basic authentication is the existing custom ingress contract, not an OAuth 2.1
resource server implementation. It requires a host capable of supplying custom
headers and HTTPS at a trusted gateway. ESET bearer tokens are never accepted as
MCP bearer credentials. Stdio uses environment credentials.

Configure `ESET_MCP_ALLOWED_HOSTS` for the public host. An Origin header must
match `ESET_MCP_ALLOWED_ORIGINS`; absent Origin is accepted for native clients.
Env-auth HTTP bound beyond loopback is rejected unless the operator explicitly
sets `ESET_MCP_ALLOW_UNAUTHENTICATED_HTTP=true` behind an authenticated gateway.
The application cannot verify that this external gateway is configured correctly.

Configure `ESET_ONPREM_ORIGINS` by username for non-default consoles. Keep TLS
verification enabled and use `ESET_CA_BUNDLE` for a private CA. Default egress
allows normal private subnets but rejects loopback, link-local, multicast,
unspecified and reserved addresses. Use `ESET_ONPREM_NETWORKS` to restrict targets
further, or explicitly authorize a required special network. That is an operator
trust decision; avoid broad CIDRs on shared servers.

The prod Compose profile exposes only Caddy, excludes non-prod profiles and
keeps metrics private. Caddy receives only its public domain/email variables.
Use dedicated ESET accounts with the least required permissions. Password/CF
rotation requires a new legacy session; settings, environment credentials and CA
bundle changes require a restart. Tokens are kept in process memory, not a token
file; process dumps and privileged debugging still expose memory.

See the [required upgrade settings](docs/security-migration-status.md) when
migrating an existing deployment.

## Extending the server

Route new output types through the common secret-filtering boundary. Do not add
raw upstream diagnostic or authentication tools.
