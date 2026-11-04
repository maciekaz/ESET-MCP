"""Run inside the production image, with --network=none and cloud hosts on loopback.

Exercises the installed CLI, real HTTP/TLS, both MCP eras, Cloud/On-Prem and RO/RW.
Only this probe is mounted into the image; no application code is replaced.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import itertools
import json
import os
import signal
import ssl
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PASSWORD = "DOCKER_SYNTHETIC_PASSWORD_59283"
ACCESS = "DOCKER_SYNTHETIC_ACCESS_59283"
REFRESH = "DOCKER_SYNTHETIC_REFRESH_59283"
CF = "DOCKER_SYNTHETIC_CF_SECRET_59283"
HOSTS = ("localhost", "eu.business-account.iam.eset.systems", "eu.device-management.eset.systems")
SEEN = []
ERRORS = []
SNI = []


class Upstream(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def serve(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        host = self.headers["Host"]
        path = urlsplit(self.path).path
        try:
            if host == "localhost":
                assert self.headers["CF-Access-Client-Id"] == "docker-cf-id"
                assert self.headers["CF-Access-Client-Secret"] == CF
            else:
                assert self.headers.get("CF-Access-Client-Secret") is None
            if path == "/oauth/token":
                assert host == HOSTS[1] and self.command == "POST"
                assert parse_qs(body.decode()) == {"grant_type": ["password"], "username": ["docker-user"], "password": [PASSWORD]}
                result = {"access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 3600}
            elif path == "/GetTokens":
                payload = json.loads(body)
                assert payload in ({"username": "docker-user", "password": PASSWORD, "grant_type": "password"},
                                   {"username": "docker-user", "password": PASSWORD, "grantType": "PASSWORD"})
                result = {"accessToken": ACCESS, "refreshToken": REFRESH, "expiresIn": 3600}
            else:
                assert self.headers["Authorization"] == f"Bearer {ACCESS}"
                if self.command == "GET":
                    assert path == "/v1/device_groups"
                    assert parse_qs(urlsplit(self.path).query) == {"pageSize": ["3"]}
                else:
                    suffix = "renameDevice" if host == "localhost" else "rename"
                    assert self.command == "POST" and path == f"/v1/devices/device-1:{suffix}"
                    assert json.loads(body) == {"displayName": "renamed"}
                result = {"items": [{"uuid": "docker-fixture", "echo": ACCESS, "password": PASSWORD}]}
            SEEN.append((host, self.command, path))
            data = json.dumps(result).encode()
            status = 200
        except Exception as exc:
            ERRORS.append(type(exc).__name__)
            data, status = b'{"error":"synthetic upstream assertion failed"}', 500
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = serve
    do_POST = serve


def certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "docker-offline-probe")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in HOSTS]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / "ca.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


def http_request(body=None, headers=None):
    request = urllib.request.Request("http://127.0.0.1:8765/mcp/",
                                     data=json.dumps(body).encode() if body else None,
                                     headers=headers or {}, method="POST" if body else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        text = response.read().decode()
        if "text/event-stream" in response.headers.get("Content-Type", ""):
            result = next(json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: "))
        else:
            result = json.loads(text) if text else None
        return response.status, dict(response.headers), result


async def scenario(directory, transport, era, backend, mode):
    deployment = "cloud" if backend == "cloud" else "onprem"
    env = {k: v for k, v in os.environ.items() if not k.startswith("ESET_")}
    env.update(PYTHON_DOTENV_DISABLED="1", ESET_USER="docker-user", ESET_PASSWORD=PASSWORD,
               ESET_AUTH_MODE="env" if transport == "stdio" else "basic", ESET_MODE=mode,
               ESET_MCP_TRANSPORT=transport, ESET_MCP_HTTP_HOST="127.0.0.1", ESET_MCP_HTTP_PORT="8765",
               ESET_DEPLOYMENT=deployment, ESET_REGION="eu", ESET_LOG_LEVEL="DEBUG", ESET_MCP_LOG_FORMAT="json",
               ESET_ONPREM_SERVER_URL="https://localhost", ESET_ONPREM_NETWORKS="127.0.0.1/32,::1/128",
               ESET_ONPREM_AUTH_STYLE="v13" if backend == "onprem-v13" else "legacy",
               ESET_ONPREM_CF_ACCESS_CLIENT_ID="docker-cf-id", ESET_ONPREM_CF_ACCESS_CLIENT_SECRET=CF,
               ESET_CA_BUNDLE=str(directory / "ca.pem"), HTTPS_PROXY="http://unapproved.invalid:9999",
               SSL_CERT_FILE="/nonexistent/ignored.pem")
    output = []
    sequence = itertools.count(1)
    headers = {"Authorization": "Basic " + base64.b64encode(f"docker-user:{PASSWORD}".encode()).decode(),
               "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    with tempfile.TemporaryFile() as logs:
        child = await asyncio.create_subprocess_exec("eset-mcp", env=env, stdin=asyncio.subprocess.PIPE,
                                                    stdout=asyncio.subprocess.PIPE, stderr=logs, limit=4 * 1024 * 1024)

        async def send(method, params=None, notification=False):
            params = dict(params or {})
            routing = dict(headers)
            if era == "modern":
                params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                   "io.modelcontextprotocol/clientCapabilities": {},
                                   "io.modelcontextprotocol/clientInfo": {"name": "docker-probe", "version": "1"}}
                routing.update({"MCP-Protocol-Version": "2026-07-28", "MCP-Method": method})
                if "name" in params or "uri" in params:
                    routing["MCP-Name"] = params.get("name", params.get("uri"))
            body = {"jsonrpc": "2.0", "method": method, "params": params}
            if not notification:
                body["id"] = next(sequence)
            if transport == "http":
                status, response_headers, reply = await asyncio.to_thread(http_request, body, routing)
                assert status == (202 if notification else 200), (status, reply)
                if method == "initialize":
                    headers.update({"MCP-Session-Id": response_headers["mcp-session-id"], "MCP-Protocol-Version": "2025-11-25"})
            else:
                child.stdin.write(json.dumps(body).encode() + b"\n")
                await child.stdin.drain()
                if notification:
                    return None
                reply = json.loads(await asyncio.wait_for(child.stdout.readline(), 15))
                assert reply["id"] == body["id"]
            output.append(json.dumps(reply))
            if not notification:
                assert "error" not in reply, reply
                return reply["result"]
            return None

        try:
            if transport == "http":
                for _ in range(100):
                    try:
                        assert (await asyncio.to_thread(http_request))[0] == 401
                        break
                    except urllib.error.URLError:
                        await asyncio.sleep(.1)
                else:
                    raise AssertionError("HTTP server did not start")
            if era == "legacy":
                initialized = await send("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                                        "clientInfo": {"name": "docker-probe", "version": "1"}})
                assert initialized["protocolVersion"] == "2025-11-25"
                await send("notifications/initialized", notification=True)
            else:
                assert "2026-07-28" in json.dumps(await send("server/discover"))
            catalog = await send("tools/list")
            assert len(catalog["tools"]) == (51 if mode == "RO" else 105)
            assert "auth_o_auth__token" not in {t["name"] for t in catalog["tools"]}

            async def read():
                result = await send("tools/call", {"name": "device_device_groups__list_groups", "arguments": {"pageSize": 3}})
                assert not result.get("isError"), result
                assert json.loads(result["content"][0]["text"]) == {
                    "items": [{"uuid": "docker-fixture", "echo": "[REDACTED]", "password": "[REDACTED]"}]}

            await read()
            writes_before = sum(method == "POST" and ":rename" in path for _, method, path in SEEN)
            result = await send("tools/call", {"name": "device_devices__rename_device",
                                               "arguments": {"deviceUuid": "device-1", "body": {"displayName": "renamed"}}})
            assert bool(result.get("isError")) == (mode == "RO")
            assert sum(method == "POST" and ":rename" in path for _, method, path in SEEN) - writes_before == (mode == "RW")
            assert len((await send("resources/list"))["resources"]) == 5
            assert len((await send("prompts/list"))["prompts"]) == 3
            resource = await send("resources/read", {"uri": "eset://config/deployment"})
            assert deployment in resource["contents"][0]["text"]
            prompt = await send("prompts/get", {"name": "audit_inactive_devices", "arguments": {"days": "30"}})
            assert "30 days" in prompt["messages"][0]["content"]["text"]
            if transport == "http" and era == "modern" and mode == "RW":
                for _ in range(10):
                    await asyncio.gather(*(read() for _ in range(10)))
            assert not ERRORS, ERRORS
        finally:
            if transport == "stdio":
                child.stdin.close()
            else:
                child.terminate()
            try:
                await asyncio.wait_for(child.wait(), 10)
            except TimeoutError:
                child.kill()
                await child.wait()
                raise AssertionError("CLI did not shut down cleanly") from None
            logs.seek(0)
            output.append(logs.read().decode())
        # Uvicorn re-raises SIGTERM after completing its graceful shutdown.
        expected_codes = (0,) if transport == "stdio" else (0, -signal.SIGTERM)
        assert child.returncode in expected_codes, child.returncode
        if transport == "http":
            assert "Application shutdown complete." in output[-1]
        assert "Traceback (most recent call last)" not in output[-1]
        assert all(secret not in "".join(output) for secret in (PASSWORD, ACCESS, REFRESH, CF)), "Synthetic secret leaked"
    print(f"PASS: {transport} / {era} / {backend} / {mode}", flush=True)


async def main():
    assert os.getuid() == 10001, "Probe must run as the production non-root user"
    with tempfile.TemporaryDirectory(prefix="eset-docker-probe-") as tmp:
        directory = Path(tmp)
        cert, key = certificate(directory)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_servername_callback(lambda sock, name, ctx: SNI.append(name))
        upstream = ThreadingHTTPServer(("127.0.0.1", 443), Upstream)
        upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
        worker = threading.Thread(target=upstream.serve_forever, daemon=True)
        worker.start()
        try:
            for args in itertools.product(("stdio", "http"), ("legacy", "modern"), ("cloud", "onprem", "onprem-v13"), ("RO", "RW")):
                await scenario(directory, *args)
        finally:
            await asyncio.to_thread(upstream.shutdown)
            upstream.server_close()
            worker.join(timeout=5)
        assert not ERRORS and set(SNI) == set(HOSTS), (ERRORS, set(SNI))
        assert sum(path in {"/oauth/token", "/GetTokens"} for _, _, path in SEEN) == 24
        print("PASS: 24 CLI scenarios, 300 additional concurrent reads, real verified TLS/Host/SNI, CF headers, RO/RW, secret filtering and clean shutdown; external network disabled", flush=True)


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
