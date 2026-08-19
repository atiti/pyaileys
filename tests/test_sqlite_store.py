from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pyaileys import store as store_module
from pyaileys.auth.creds import Contact
from pyaileys.auth.state import AuthenticationState
from pyaileys.auth.utils import init_auth_creds
from pyaileys.client import WhatsAppClient
from pyaileys.store import ChatInfo, ContactInfo, MessageInfo

SQLiteStore: Any = getattr(store_module, "SQLiteStore", None)


class MemoryKeyStore:
    async def get(self, _key_type: str, ids: list[str]) -> dict[str, object]:
        return {key_id: None for key_id in ids}

    async def set(self, _data: object) -> None:
        return None

    async def clear(self) -> None:
        return None


def test_sqlite_store_restores_chats_contacts_and_history_anchors(tmp_path: Path) -> None:
    assert SQLiteStore is not None
    path = tmp_path / "pyaileys.sqlite3"
    store = SQLiteStore(path)
    store.upsert_chat(ChatInfo(jid="test-group@g.us", name="Example group"))
    store.upsert_contact(ContactInfo(jid="test-user@s.whatsapp.net", name="Example user"))
    store.add_message(
        MessageInfo(
            id="oldest-message",
            chat_jid="test-group@g.us",
            sender_jid="test-user@s.whatsapp.net",
            timestamp_s=1_700_000_000,
            text="anchor",
            from_me=False,
        )
    )
    store.close()

    restored = SQLiteStore(path)

    assert restored.get_chat("test-group@g.us").name == "Example group"  # type: ignore[union-attr]
    assert restored.get_contact("test-user@s.whatsapp.net").name == "Example user"  # type: ignore[union-attr]
    anchor = restored.oldest_message("test-group@g.us")
    assert anchor is not None
    assert (anchor.id, anchor.timestamp_s, anchor.from_me, anchor.raw) == (
        "oldest-message",
        1_700_000_000,
        False,
        None,
    )
    restored.close()


@pytest.mark.asyncio
async def test_auth_folder_client_uses_persistent_store_by_default(tmp_path: Path) -> None:
    assert SQLiteStore is not None
    auth_dir = tmp_path / "auth"
    client, _ = await WhatsAppClient.from_auth_folder(str(auth_dir))

    assert isinstance(client.store, SQLiteStore)
    assert client.store.path == auth_dir / "pyaileys.sqlite3"
    client.store.close()


@pytest.mark.asyncio
async def test_persisted_anchor_allows_safe_history_request_after_restart(tmp_path: Path) -> None:
    assert SQLiteStore is not None
    path = tmp_path / "pyaileys.sqlite3"
    SQLiteStore(path).add_message(
        MessageInfo(
            id="oldest-message",
            chat_jid="test-group@g.us",
            sender_jid="test-user@s.whatsapp.net",
            timestamp_s=1_700_000_000,
            from_me=False,
        )
    )

    creds = init_auth_creds()
    creds.me = Contact(id="test-user:1@s.whatsapp.net")
    client = WhatsAppClient(
        auth=AuthenticationState(creds=creds, keys=MemoryKeyStore()),
        store=SQLiteStore(path),
    )
    sent: list[object] = []

    async def send(message: object) -> str:
        sent.append(message)
        return "request-id"

    client._send_peer_message = send  # type: ignore[method-assign]

    assert await client.request_chat_history("test-group@g.us", count=100)
    assert len(sent) == 1
    request = sent[0].protocolMessage.peerDataOperationRequestMessage.historySyncOnDemandRequest
    assert request.oldestMsgId == "oldest-message"
    assert request.oldestMsgTimestampMs == 1_700_000_000_000
    assert request.oldestMsgFromMe is False
    client.store.close()
