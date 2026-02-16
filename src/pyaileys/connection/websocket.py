from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Any

import websockets
from websockets.protocol import State

from ..constants import DEFAULT_ORIGIN
from ..exceptions import TransportError


@dataclass(slots=True)
class WebSocketConfig:
    url: str
    connect_timeout_s: float = 20.0
    extra_headers: dict[str, str] = field(default_factory=dict)


class WebSocketTransport:
    def __init__(self, cfg: WebSocketConfig) -> None:
        self.cfg = cfg
        self._ws: Any | None = None

    @property
    def is_open(self) -> bool:
        if not self._ws:
            return False
        # websockets>=15 uses `.state`; older versions had `.closed`.
        state = getattr(self._ws, "state", None)
        if state is not None:
            return bool(state == State.OPEN)
        closed = getattr(self._ws, "closed", None)
        if closed is not None:
            return not bool(closed)
        return True

    async def connect(self) -> None:
        if self._ws is not None:
            return
        try:
            connect_kwargs: dict[str, Any] = {
                "origin": DEFAULT_ORIGIN,
                "max_size": None,
                "open_timeout": self.cfg.connect_timeout_s,
                # WhatsApp Web expects application-layer pings (XMPP IQ ping).
                # The server may not respond to WS-level pings, so disable them.
                "ping_interval": None,
                "ping_timeout": None,
            }

            headers = self.cfg.extra_headers or None
            if headers is not None:
                # websockets>=15 renamed `extra_headers` -> `additional_headers`.
                params = inspect.signature(websockets.connect).parameters
                if "additional_headers" in params:
                    connect_kwargs["additional_headers"] = headers
                else:
                    connect_kwargs["extra_headers"] = headers

            self._ws = await asyncio.wait_for(
                websockets.connect(
                    self.cfg.url,
                    **connect_kwargs,
                ),
                timeout=self.cfg.connect_timeout_s,
            )
        except Exception as e:
            raise TransportError(f"failed to connect websocket: {e}") from e

    async def close(self) -> None:
        if self._ws is None:
            return
        try:
            await self._ws.close()
        finally:
            self._ws = None

    async def send(self, data: bytes) -> None:
        if not self._ws:
            raise TransportError("websocket not connected")
        try:
            await self._ws.send(data)
        except Exception as e:
            raise TransportError(f"websocket send failed: {e}") from e

    async def recv(self) -> bytes:
        if not self._ws:
            raise TransportError("websocket not connected")
        msg: Any
        try:
            msg = await self._ws.recv()
        except Exception as e:
            raise TransportError(f"websocket recv failed: {e}") from e
        if isinstance(msg, bytes):
            return msg
        if isinstance(msg, str):
            # WhatsApp Web speaks binary, but be defensive.
            return msg.encode("utf-8")
        raise TransportError(f"unexpected websocket message type: {type(msg).__name__}")
