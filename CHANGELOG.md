# Changelog

## 2.0.0 — 2026-11-04

Breaking security release. Read the [v1 → v2 migration guide](docs/migration-v2.md)
before updating HTTP or On-Prem installations.

### Security and compatibility

- Remove the authentication tool from the model-facing catalog; retain 101
  business tools and four composites with their existing input/API contracts.
- Filter credentials and tokens from results, nested diagnostics and logs.
- Bind legacy sessions to request identity, isolate connection settings and
  keep active clients alive during pool eviction.
- Authorize On-Prem origin overrides, pin validated DNS addresses and scope
  environment CF credentials to the default console.
- Correct rejected-token refresh, preserve refresh tokens and bound retries
  without replaying writes after ambiguous transport/5xx failures.

### MCP and deployment

- MCP 2026-07-28 through SDK 2.3.0; legacy 2025-11-25 remains supported.
- Explicit Host/Origin controls, secure HTTP defaults and private metrics.
- Pinned, hashed dependencies; signed AMD64/ARM64 images with SBOM/provenance.
- Public `:2.0.0`, `:2.0`, `:2` and `:latest` tags; `:1` remains on v1.
