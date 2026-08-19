from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import pytest

from pyaileys.auth.creds import Contact
from pyaileys.auth.state import AuthenticationState
from pyaileys.auth.utils import init_auth_creds
from pyaileys.client import WhatsAppClient
from pyaileys.socket import GroupMetadata, WASocket
from pyaileys.socket_config import SocketConfig
from pyaileys.wabinary.types import BinaryNode


class MemoryKeyStore:
    async def get(self, _key_type: str, ids: list[str]) -> dict[str, object]:
        return {key_id: None for key_id in ids}

    async def set(self, _data: Mapping[str, Mapping[str, Any | None]]) -> None:
        return None

    async def clear(self) -> None:
        return None


@pytest.mark.asyncio
async def test_group_metadata_reads_subject_from_response() -> None:
    auth = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())
    socket = WASocket(config=SocketConfig(), auth=auth)

    async def query(_node: BinaryNode, *, timeout_s: float = 60.0) -> BinaryNode:
        return BinaryNode(
            tag="iq",
            attrs={"type": "result"},
            content=[
                BinaryNode(
                    tag="group",
                    attrs={"id": "test-group", "subject": "Example group"},
                    content=[],
                )
            ],
        )

    cast(Any, socket).query = query

    metadata = await socket.group_metadata("test-group@g.us")

    assert metadata.id == "test-group@g.us"
    assert metadata.subject == "Example group"


@pytest.mark.asyncio
async def test_resolve_group_name_caches_the_resolved_subject() -> None:
    creds = init_auth_creds()
    creds.me = Contact(id="test-user:1@s.whatsapp.net")
    client = WhatsAppClient(auth=AuthenticationState(creds=creds, keys=MemoryKeyStore()))

    async def group_metadata(jid: str) -> GroupMetadata:
        assert jid == "test-group@g.us"
        return GroupMetadata(id=jid, subject="Example group")

    cast(Any, client.socket).group_metadata = group_metadata

    assert await client.resolve_group_name("test-group@g.us") == "Example group"
    assert client.get_display_name("test-group@g.us") == "Example group"
