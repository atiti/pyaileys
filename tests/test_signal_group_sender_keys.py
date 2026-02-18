from __future__ import annotations

import pytest

from pyaileys.auth.state import AuthenticationState
from pyaileys.auth.utils import init_auth_creds
from pyaileys.messages import decode_wa_message_bytes, encode_wa_message_bytes
from pyaileys.signal.repository import SignalRepository


class MemoryKeyStore:
    def __init__(self) -> None:
        self._data: dict[str, dict[str, object]] = {}

    async def get(self, key_type: str, ids: list[str]) -> dict[str, object]:
        bucket = self._data.get(key_type, {})
        return {i: bucket.get(i) for i in ids}

    async def set(self, data: dict[str, dict[str, object | None]]) -> None:
        for cat, items in data.items():
            b = self._data.setdefault(cat, {})
            for k, v in items.items():
                if v is None:
                    b.pop(str(k), None)
                else:
                    b[str(k)] = v

    async def clear(self) -> None:
        self._data.clear()


@pytest.mark.asyncio
async def test_sender_keys_distribution_then_skmsg_roundtrip() -> None:
    alice_state = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())
    bob_state = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())

    alice = SignalRepository(alice_state)
    bob = SignalRepository(bob_state)

    group = "123-456@g.us"
    alice_jid = "alice:1@s.whatsapp.net"

    payload = b"hello group"
    padded = encode_wa_message_bytes(payload)

    ct, dist = await alice.encrypt_group_message(group_jid=group, me_jid=alice_jid, data=padded)
    await bob.process_sender_key_distribution_message(
        group, author_jid=alice_jid, distribution_bytes=dist
    )

    out = await bob.decrypt_group_message(group_jid=group, author_jid=alice_jid, ciphertext=ct)
    assert out == padded
    assert decode_wa_message_bytes(out) == payload


@pytest.mark.asyncio
async def test_sender_keys_multiple_messages_no_redistribution_needed() -> None:
    alice_state = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())
    bob_state = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())

    alice = SignalRepository(alice_state)
    bob = SignalRepository(bob_state)

    group = "123-456@g.us"
    alice_jid = "alice:1@s.whatsapp.net"

    ct1, dist1 = await alice.encrypt_group_message(
        group_jid=group, me_jid=alice_jid, data=encode_wa_message_bytes(b"m1")
    )
    await bob.process_sender_key_distribution_message(
        group, author_jid=alice_jid, distribution_bytes=dist1
    )
    assert (
        decode_wa_message_bytes(
            await bob.decrypt_group_message(group_jid=group, author_jid=alice_jid, ciphertext=ct1)
        )
        == b"m1"
    )

    # Next message can be decrypted without processing a new distribution message.
    ct2, _dist2 = await alice.encrypt_group_message(
        group_jid=group, me_jid=alice_jid, data=encode_wa_message_bytes(b"m2")
    )
    assert (
        decode_wa_message_bytes(
            await bob.decrypt_group_message(group_jid=group, author_jid=alice_jid, ciphertext=ct2)
        )
        == b"m2"
    )


@pytest.mark.asyncio
async def test_sender_keys_signature_mismatch_rejected() -> None:
    alice_state = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())
    bob_state = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())

    alice = SignalRepository(alice_state)
    bob = SignalRepository(bob_state)

    group = "123-456@g.us"
    alice_jid = "alice:1@s.whatsapp.net"

    ct, dist = await alice.encrypt_group_message(
        group_jid=group, me_jid=alice_jid, data=encode_wa_message_bytes(b"tamper")
    )
    await bob.process_sender_key_distribution_message(
        group, author_jid=alice_jid, distribution_bytes=dist
    )

    bad = ct[:-1] + bytes([ct[-1] ^ 0x01])
    with pytest.raises(ValueError):
        await bob.decrypt_group_message(group_jid=group, author_jid=alice_jid, ciphertext=bad)
