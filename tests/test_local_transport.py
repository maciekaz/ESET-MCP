"""Real loopback sockets/TLS; no ESET account or external network."""
from __future__ import annotations

import asyncio
import contextlib
import json
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from eset_mcp.credentials import Credentials
from eset_mcp.errors import EsetApiError
from eset_mcp.http_client import EsetHttpClient


@pytest.fixture
def certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "fixture.pem", tmp_path / "fixture.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


@pytest.mark.parametrize("style", ["legacy", "v13"])
@pytest.mark.parametrize("policy", ["trusted", "untrusted", "denied_network", "verify_disabled"])
async def test_real_tls_host_sni_ca_cf_and_network_policy(certificate, monkeypatch, style, policy):
    cert_path, key_path = certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    sni = []
    context.set_servername_callback(lambda sock, name, ctx: sni.append(name))
    seen = []
    tasks = set()

    async def serve(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            lines = raw.decode().split("\r\n")
            method, path, _ = lines[0].split()
            headers = {key.lower(): value for key, value in (line.split(": ", 1) for line in lines[1:] if line)}
            body = await reader.readexactly(int(headers.get("content-length", 0)))
            seen.append((method, path, headers, body))
            payload = {"accessToken": "TLS_ACCESS", "expiresIn": 3600} if path == "/GetTokens" else {"deviceGroups": [{"uuid": "tls-group"}]}
            data = json.dumps(payload).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(ConnectionResetError):
                await writer.wait_closed()
            tasks.discard(task)

    listener = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
    port = listener.sockets[0].getsockname()[1]
    # These process-global settings must not redirect either secrets or trust.
    monkeypatch.setenv("HTTPS_PROXY", "http://unapproved.invalid:9999")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/should-be-ignored")
    creds = Credentials("tls-user", "tls-password", "eu", deployment="onprem",
                        server_url=f"https://localhost:{port}", onprem_auth_style=style,
                        cf_access_client_id="cf-test-id", cf_access_client_secret="cf-test-secret",
                        allowed_networks=() if policy == "denied_network" else ("127.0.0.1/32", "::1/128"),
                        ca_bundle=str(cert_path) if policy == "trusted" else "",
                        verify_ssl=policy != "verify_disabled")
    try:
        async with listener, EsetHttpClient(creds) as client:
            if policy in {"untrusted", "denied_network"}:
                with pytest.raises(EsetApiError):
                    await client.request("GET", "device-management", "/v1/device_groups")
                assert not seen  # no password, CF token or bearer bytes received
            else:
                result = await client.request("GET", "device-management", "/v1/device_groups")
                assert result == {"deviceGroups": [{"uuid": "tls-group"}]}
                assert [x[:2] for x in seen] == [("POST", "/GetTokens"), ("GET", "/v1/device_groups")]
                body = json.loads(seen[0][3])
                assert body == {"username": "tls-user", "password": "tls-password",
                                **({"grantType": "PASSWORD"} if style == "v13" else {"grant_type": "password"})}
                assert all(h["host"] == f"localhost:{port}" and h["cf-access-client-secret"] == "cf-test-secret"
                           and h["cf-access-client-id"] == "cf-test-id" for _, _, h, _ in seen)
                assert seen[1][2]["authorization"] == "Bearer TLS_ACCESS"
                assert sni and all(name == "localhost" for name in sni)
    finally:
        listener.close()
        await listener.wait_closed()
        if tasks:
            await asyncio.gather(*tasks)
