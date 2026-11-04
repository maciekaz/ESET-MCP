# Security and compatibility tests

Run the suite from the repository root:

```sh
python3 -m venv /tmp/eset-check
/tmp/eset-check/bin/python -m pip install --require-hashes -r requirements-dev.lock
/tmp/eset-check/bin/python -m pip install --no-deps --no-build-isolation -e .
PYTHON_DOTENV_DISABLED=1 ESET_RUN_LIVE_TESTS=0 /tmp/eset-check/bin/python -m pytest tests audits -q
/tmp/eset-check/bin/ruff check eset_mcp tests audits
```

## Maintaining compatibility fixtures

Keep the baseline environment separate from the current source environment.
The baseline commit is `442dcadadcfde802cf0b7ccb1955438ed20fcf15` (1.0.3),
with MCP SDK 1.27.1 and dependencies from `requirements-baseline.txt`.

- `legacy_business_contract.json` stores the original business tool names,
  input schema hashes and endpoint mappings.
- `legacy_execution.json` stores requests and MCP responses from the baseline
  server for business tools and composites on both backends.

Run `capture_legacy.py` only against an isolated checkout of the baseline commit.
Set `PYTHONPATH` to that checkout and pass an output file. Do not regenerate
historical expectations against the current implementation to make a regression
pass. Preserve the input-schema snapshot when changing the adapter or SDK.

Keep separate coverage for the default On-Prem `legacy` authentication format
and the explicitly selected `v13` format.

## Network isolation

`conftest.py` in this folder blocks DNS and socket connections; use RESPX to
intercept upstream requests. The `tests/` suite permits loopback TLS and blocks
external connections unless integration tests are explicitly enabled with
`ESET_RUN_LIVE_TESTS=1`. The stdio fixture server uses a transport mock and blocks
networking in its child process.

Run `tests/legacy_sdk_probe.py` in the baseline SDK environment, passing the
current Python executable, to check legacy client compatibility over stdio.

## Running the container probe

```sh
docker build -t eset-mcp:2.0.0-local .
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --add-host eu.business-account.iam.eset.systems:127.0.0.1 \
  --add-host eu.device-management.eset.systems:127.0.0.1 \
  --mount type=bind,src="$PWD/tests/docker_probe.py",dst=/tmp/docker_probe.py,readonly \
  --entrypoint python eset-mcp:2.0.0-local /tmp/docker_probe.py
```

Mount only the probe script, keeping the installed application code intact.
The probe creates temporary certificates and synthetic credentials inside the
container.
