from __future__ import annotations

import pytest

from pyaileys.auth.creds import Contact
from pyaileys.auth.state import AuthenticationState
from pyaileys.auth.utils import init_auth_creds
from pyaileys.client import WhatsAppClient


class MemoryKeyStore:
    async def get(self, _key_type: str, ids: list[str]) -> dict[str, object]:
        return {key_id: None for key_id in ids}

    async def set(self, _data: dict[str, dict[str, object | None]]) -> None:
        return None

    async def clear(self) -> None:
        return None


def make_authenticated_client() -> WhatsAppClient:
    creds = init_auth_creds()
    creds.me = Contact(id="test-user:1@s.whatsapp.net")
    return WhatsAppClient(auth=AuthenticationState(creds=creds, keys=MemoryKeyStore()))


@pytest.mark.asyncio
async def test_full_history_sync_is_disabled_before_any_phone_request() -> None:
    client = make_authenticated_client()

    async def unexpected_send(_message: object) -> str:
        raise AssertionError("must not send a full-history request")

    client._send_peer_message = unexpected_send  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="full history sync is disabled"):
        await client.request_full_history_sync()


@pytest.mark.asyncio
async def test_chat_history_requires_a_local_anchor_before_any_phone_request() -> None:
    client = make_authenticated_client()

    async def unexpected_send(_message: object) -> str:
        raise AssertionError("must not send an unanchored history request")

    client._send_peer_message = unexpected_send  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="requires a locally stored message"):
        await client.request_chat_history("test-group@g.us", count=100)
