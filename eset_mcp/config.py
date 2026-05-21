"""Configuration loaded from .env / environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

Mode = Literal["RO", "RW"]
Transport = Literal["stdio", "http"]
Region = Literal["eu", "de", "us", "ca", "jpn"]
AuthMode = Literal["env", "basic"]

VALID_REGIONS: tuple[Region, ...] = ("eu", "de", "us", "ca", "jpn")


@dataclass(frozen=True)
class Settings:
    user: str
    password: str
    mode: Mode
    region: Region
    transport: Transport
    http_host: str
    http_port: int
    log_level: str
    auth_mode: AuthMode
    # Per-call response byte cap applied AFTER fields projection and BEFORE
    # serialising to the MCP client. 0 disables the cap entirely (not
    # recommended in production — single calls can consume the whole LLM
    # context window). Default ≈25 k tokens on a 4-chars/token heuristic.
    response_bytes_max: int

    @property
    def has_env_credentials(self) -> bool:
        return bool(self.user and self.password)

    @classmethod
    def from_env(cls, env_file: Path | None = None) -> Settings:
        if env_file is None:
            # Prefer .env in the current working directory, then in the repo root,
            # so this works both for `python -m eset_mcp` and docker-compose.
            for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"):
                if candidate.exists():
                    env_file = candidate
                    break
        if env_file:
            load_dotenv(env_file, override=False)

        auth_mode = _parse_auth_mode(os.getenv("ESET_AUTH_MODE", "env"))
        transport = _parse_transport(os.getenv("ESET_MCP_TRANSPORT", "stdio"))

        # In `env` mode the .env credentials are mandatory (they're used for
        # every request). In `basic` mode they are optional: if present they
        # serve as a fallback when the client sends none, otherwise the request
        # is rejected with 401. `basic` mode also requires the HTTP transport.
        if auth_mode == "basic" and transport != "http":
            raise RuntimeError(
                "ESET_AUTH_MODE=basic requires ESET_MCP_TRANSPORT=http "
                "(stdio has no per-request HTTP headers to carry auth)."
            )

        user = os.getenv("ESET_USER", "")
        password = os.getenv("ESET_PASSWORD", "")
        if auth_mode == "env" and (not user or not password):
            raise RuntimeError(
                "ESET_AUTH_MODE=env requires ESET_USER and ESET_PASSWORD in .env."
            )

        return cls(
            user=user,
            password=password,
            mode=_parse_mode(os.getenv("ESET_MODE", "RO")),
            region=_parse_region(os.getenv("ESET_REGION", "eu")),
            transport=transport,
            http_host=os.getenv("ESET_MCP_HTTP_HOST", "127.0.0.1"),
            http_port=int(os.getenv("ESET_MCP_HTTP_PORT", "8765")),
            log_level=os.getenv("ESET_LOG_LEVEL", "INFO").upper(),
            auth_mode=auth_mode,
            response_bytes_max=_parse_int(
                os.getenv("ESET_MCP_RESPONSE_BYTES_MAX", "100000"),
                "ESET_MCP_RESPONSE_BYTES_MAX",
            ),
        )


def _parse_mode(raw: str) -> Mode:
    val = raw.split("#", 1)[0].strip().upper()
    if val not in ("RO", "RW"):
        raise RuntimeError(f"ESET_MODE must be 'RO' or 'RW', got {raw!r}")
    return val  # type: ignore[return-value]


def _parse_region(raw: str) -> Region:
    val = raw.split("#", 1)[0].strip().lower()
    if val not in VALID_REGIONS:
        raise RuntimeError(f"ESET_REGION must be one of {VALID_REGIONS}, got {raw!r}")
    return val  # type: ignore[return-value]


def _parse_transport(raw: str) -> Transport:
    val = raw.split("#", 1)[0].strip().lower()
    if val not in ("stdio", "http"):
        raise RuntimeError(f"ESET_MCP_TRANSPORT must be 'stdio' or 'http', got {raw!r}")
    return val  # type: ignore[return-value]


def _parse_auth_mode(raw: str) -> AuthMode:
    val = raw.split("#", 1)[0].strip().lower()
    if val not in ("env", "basic"):
        raise RuntimeError(f"ESET_AUTH_MODE must be 'env' or 'basic', got {raw!r}")
    return val  # type: ignore[return-value]


def _parse_int(raw: str, var: str) -> int:
    cleaned = raw.split("#", 1)[0].strip()
    try:
        n = int(cleaned)
    except ValueError as e:
        raise RuntimeError(f"{var} must be an integer, got {raw!r}") from e
    if n < 0:
        raise RuntimeError(f"{var} must be >= 0 (0 disables), got {n}")
    return n
