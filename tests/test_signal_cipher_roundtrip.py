from __future__ import annotations

import pytest

from pyaileys.auth.state import AuthenticationState
from pyaileys.auth.utils import init_auth_creds
from pyaileys.signal.repository import PreKeyBundle, PreKeyBundleKey, SignalRepository
from pyaileys.signal.util import signal_pubkey


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
async def test_signal_encrypt_decrypt_pkmsg_then_msg() -> None:
    # Two independent auth states representing two devices.
    alice_state = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())
    bob_state = AuthenticationState(creds=init_auth_creds(), keys=MemoryKeyStore())

    alice = SignalRepository(alice_state)
    bob = SignalRepository(bob_state)

    # Simulate WhatsApp "encrypt" IQ bundle for Bob (no one-time pre-key).
    bundle = PreKeyBundle(
        registration_id=bob_state.creds.registration_id,
        identity_key=signal_pubkey(bob_state.creds.signed_identity_key.public),
        signed_pre_key=PreKeyBundleKey(
            key_id=bob_state.creds.signed_pre_key.key_id,
            public_key=signal_pubkey(bob_state.creds.signed_pre_key.key_pair.public),
            signature=bob_state.creds.signed_pre_key.signature,
        ),
        pre_key=None,
    )

    await alice.inject_outgoing_session("bob@s.whatsapp.net", bundle)

    pt1 = b"hello world"
    typ1, ct1 = await alice.encrypt_message("bob@s.whatsapp.net", data=pt1)
    assert typ1 == "pkmsg"

    out1 = await bob.decrypt_message("alice@s.whatsapp.net", message_type=typ1, ciphertext=ct1)
    assert out1 == pt1

    # Until Alice decrypts *any* message from Bob, libsignal keeps wrapping messages as pkmsg.
    pt2 = b"second message"
    typ2, ct2 = await alice.encrypt_message("bob@s.whatsapp.net", data=pt2)
    assert typ2 == "pkmsg"

    out2 = await bob.decrypt_message("alice@s.whatsapp.net", message_type=typ2, ciphertext=ct2)
    assert out2 == pt2

    # Once Bob replies and Alice decrypts, Alice should switch to "msg".
    reply = b"reply"
    typ3, ct3 = await bob.encrypt_message("alice@s.whatsapp.net", data=reply)
    assert typ3 == "msg"
    out3 = await alice.decrypt_message("bob@s.whatsapp.net", message_type=typ3, ciphertext=ct3)
    assert out3 == reply

    pt4 = b"fourth message"
    typ4, ct4 = await alice.encrypt_message("bob@s.whatsapp.net", data=pt4)
    assert typ4 == "msg"

    out4 = await bob.decrypt_message("alice@s.whatsapp.net", message_type=typ4, ciphertext=ct4)
    assert out4 == pt4
