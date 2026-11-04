Security and compatibility evidence
===================================

Release implementation: 2.0.0, MCP SDK 2.3.0, protocol 2026-07-28 and legacy
2025-11-25. [Implementation and risk report](../docs/security-migration-status.md).
Local 1.1.0 evidence refers to the unpublished candidate before the breaking
release was numbered 2.0.0. The original audit and `baseline-results.txt` are historical (2026-09-25).
The original baseline commit is `442dcadadcfde802cf0b7ccb1955438ed20fcf15`.

Run the current suite from the repository root:

```sh
python3 -m venv /tmp/eset-check
/tmp/eset-check/bin/python -m pip install --require-hashes -r requirements-dev.lock
/tmp/eset-check/bin/python -m pip install --no-deps --no-build-isolation -e .
PYTHON_DOTENV_DISABLED=1 ESET_RUN_LIVE_TESTS=0 /tmp/eset-check/bin/python -m pytest tests audits -q
/tmp/eset-check/bin/ruff check eset_mcp tests audits
```

Do not install the old SDK into the current source environment. The archived
baseline requires `requirements-baseline.txt`; it had **349 passing tests and
12 reproduced failures** in the combined original suites. Those failures are
now ordinary regression tests: no xfail remains in the current audit suite.
On-prem documented `grantType` testing explicitly selects the `v13` profile;
a separate golden test requires the original default `grant_type` request.

Two different historical comparisons are kept:

- `legacy_business_contract.json`: original 101 business tool names, input
  schema hashes and endpoint mapping. Its 202 probes use transport sentinels.
- `legacy_execution.json`: actual original MCP 1.27.1 executions through the
  archived 1.0.3 server, with schema-valid synthetic arguments, request bytes
  and MCP content for all 101 operations and four composites on both backends.
  It includes pagination, fan-out limits and detection sorting. The new server
  is checked through independent raw HTTP clients in both protocol eras.

`capture_legacy.py` regenerates the second fixture **only** against an isolated
checkout of the baseline commit with MCP 1.27.1. It asserts those versions and
uses synthetic responses; do not regenerate expectations against new code to
make a regression pass. Set `PYTHONPATH` to that checkout and pass an output
file. The input-schema snapshot must not change as part of this migration.

`conftest.py` in this folder rejects actual DNS and socket connections. RESPX
must intercept every upstream request. `tests/` permits loopback for real TLS
and blocks external connections unless live tests are explicitly opted into.
`tests/stdio_fixture_server.py` runs the actual CLI with a transport-only mock
and prohibits networking in its child process. `tests/legacy_sdk_probe.py`,
run with the old SDK and passed the new Python executable, checks a real old
client against the new stdio server.

Vendor checks are independently encoded for cloud form login (all five
regions), ESET 13 camelCase login/refresh and 202 response-id polling. Neither
historical fixture establishes endpoint availability on an arbitrary console,
license/permission coverage, write effects or idempotency in the vendor system.

`validation-python*.txt` record the latest local interpreter matrix. Branch
coverage is in `coverage-summary.txt`; subprocess coverage is not merged, so
CLI execution is tested but undercounted there. The pre-existing broken `.venv`
was left untouched; all validation environments were created under `/private/tmp`.

Container validation
--------------------

`validation-docker-*.txt` and `validation-docker-images.json` record actual
local builds and execution: ARM64 natively, AMD64 under Docker Desktop emulation.
Each production image passed 24 CLI/TLS scenarios and 300 additional reads at
concurrency 10. The Linux ARM64 image plus test dependencies also passed the
complete 525-test regression suite (8 skipped). The production ENTRYPOINT was
checked separately for stdio, HTTP authentication and graceful shutdown.

Reproduce the production-image TLS probe without external connectivity:

```sh
docker build -t eset-mcp:2.0.0-local .
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --add-host eu.business-account.iam.eset.systems:127.0.0.1 \
  --add-host eu.device-management.eset.systems:127.0.0.1 \
  --mount type=bind,src="$PWD/tests/docker_probe.py",dst=/tmp/docker_probe.py,readonly \
  --entrypoint python eset-mcp:2.0.0-local /tmp/docker_probe.py
```

The probe mounts only its own test script; the installed application's CLI,
authentication, mapping and transport code are unchanged. Synthetic certificates
and credentials live in the temporary container. These are bounded runtime tests,
not a production soak test or validation of a real ESET deployment.
