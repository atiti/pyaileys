from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, cast

import pytest

from pyaileys.auth.state import AuthenticationState
from pyaileys.auth.utils import init_auth_creds
from pyaileys.exceptions import TransportError
from pyaileys.socket import ConnectionUpdate, WASocket
from pyaileys.socket_config import SocketConfig


class MemoryKeyStore:
    async def get(self, _key_type: str, ids: list[str]) -> dict[str, object]:
        return {key_id: None for key_id in ids}

    async def set(self, _data: Mapping[str, Mapping[str, Any | None]]) -> None:
        return None

    async def clear(self) -> None:
        return None


class FailingTransport:
    def __init__(self) -> None:
        self.closed = False

    async def recv(self) -> bytes:
        raise TransportError("websocket recv failed: server closed connection")

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_receive_failure_releases_transport_and_reports_disconnect_reason() -> None:
    auth = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())
    socket = WASocket(config=SocketConfig(auto_reconnect=False), auth=auth)
    transport = FailingTransport()
    cast(Any, socket)._transport = transport
    cast(Any, socket)._noise = object()
    updates: list[ConnectionUpdate] = []
    socket.events.on("connection.update", updates.append)

    await socket._recv_loop()

    assert transport.closed is True
    assert socket._closed is True
    assert len(updates) == 1
    assert updates[0].connection == "close"
    assert str(updates[0].last_disconnect) == "websocket recv failed: server closed connection"


@pytest.mark.asyncio
async def test_unexpected_close_retries_until_connection_succeeds() -> None:
    auth = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())
    socket = WASocket(
        config=SocketConfig(
            auto_reconnect=True,
            reconnect_delay_s=0.001,
            reconnect_max_delay_s=0.002,
        ),
        auth=auth,
    )
    attempts = 0

    async def connect() -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TransportError("temporary route failure")
        socket._closed = False

    cast(Any, socket).connect = connect

    await socket.close(last_disconnect=TransportError("connection dropped"), reconnect=True)
    for _ in range(50):
        if not socket._closed:
            break
        await asyncio.sleep(0.002)

    assert attempts == 2
    assert socket._closed is False
