"""Validate the real Caddyfile and its error-log filtering, on loopback only.

Usage: python tests/caddy_probe.py /path/to/verified/caddy
No real TLS/ACME requests: adapted routes/logging are used with auto-HTTPS off.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET = "SYNTHETIC_CADDY_SECRET_837292"  # gitleaks:allow -- synthetic log-redaction canary


def main():
    env = {**os.environ, "ESET_PUBLIC_DOMAIN": "eset-mcp.example.invalid", "ESET_ACME_EMAIL": "ops@example.invalid"}
    missing_domain = subprocess.run(
        [sys.argv[1], "adapt", "--config", str(ROOT / "Caddyfile"), "--adapter", "caddyfile"],
        env={**env, "ESET_PUBLIC_DOMAIN": ""}, capture_output=True, text=True,
    )
    assert missing_domain.returncode != 0, "Production must fail closed without a public domain"
    adapted = subprocess.run([sys.argv[1], "adapt", "--config", str(ROOT / "Caddyfile"), "--adapter", "caddyfile"],
                             env=env, check=True, capture_output=True, text=True)
    config = json.loads(adapted.stdout)
    server = next(iter(config["apps"]["http"]["servers"].values()))
    # Select an unused loopback port to exercise the proxy's connection error.
    with socket.socket() as unavailable, socket.socket() as port_probe, tempfile.TemporaryDirectory(prefix="eset-caddy-") as tmp:
        unavailable.bind(("127.0.0.1", 0))
        upstream_port = unavailable.getsockname()[1]
        unavailable.close()
        port_probe.bind(("127.0.0.1", 0))
        port = port_probe.getsockname()[1]
        port_probe.close()
        server["listen"] = [f"127.0.0.1:{port}"]
        server["automatic_https"] = {"disable": True}
        server.pop("tls_connection_policies", None)
        config["apps"].pop("tls", None)
        config["admin"] = {"disabled": True, "config": {"persist": False}}

        def patch(value):
            if isinstance(value, dict):
                if value.get("handler") == "reverse_proxy":
                    value["upstreams"] = [{"dial": f"127.0.0.1:{upstream_port}"}]
                for child in value.values():
                    patch(child)
            elif isinstance(value, list):
                for child in value:
                    patch(child)
        patch(config)
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps(config))
        process = subprocess.Popen([sys.argv[1], "run", "--config", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def get(path):
            request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={
                "Host": "eset-mcp.example.invalid", "Authorization": "Basic " + SECRET,
                "X-ESET-CF-Access-Client-Secret": SECRET,
            })
            try:
                return opener.open(request, timeout=10).status
            except urllib.error.HTTPError as error:
                return error.code
        try:
            for _ in range(50):
                try:
                    status = get("/mcp/?opaque=" + SECRET)
                    break
                except urllib.error.URLError:
                    time.sleep(.1)
            else:
                raise AssertionError("Caddy did not start")
            assert status == 502
            assert get("/metrics") == 404
        finally:
            process.terminate()
            stdout, stderr = process.communicate(timeout=10)
        logs = (stdout + stderr).decode()
        assert SECRET not in logs, "Caddy error log leaked a synthetic credential"
        records = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
        errors = [r for r in records if r.get("logger") == "http.log.error"]
        assert errors, "Probe must actually exercise the proxy error logger"
        assert all("headers" not in r.get("request", {}) and "uri" not in r.get("request", {}) for r in errors)
        print("PASS: real Caddyfile parses and rejects missing domain; proxy 502 logs omit secret headers/URI; public /metrics returns 404")


if __name__ == "__main__":
    main()
