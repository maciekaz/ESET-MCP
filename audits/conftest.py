"""Offline audit: never load operator credentials or contact external APIs."""
import socket

import pytest
import respx


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny_network(*args, **kwargs):
        raise AssertionError("Security audit attempted a real network connection")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket.socket, "connect_ex", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router
