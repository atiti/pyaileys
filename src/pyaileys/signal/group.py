"""
Signal Sender Keys (group E2E) implementation for WhatsApp Web multi-device.

WhatsApp group messages use Signal's "Sender Keys" scheme:
- a per-sender, per-group symmetric sender key (chain key)
- a per-sender signing key to authenticate sender-key messages

On the wire this is exposed as:
- group message encryption type `skmsg` (SenderKeyMessage)
- per-device distribution message embedded in a normal E2E message:
  `proto.Message.senderKeyDistributionMessage.axolotlSenderKeyDistributionMessage`

This module is a small, dependency-minimal port of Baileys' sender keys logic.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Protocol

from ..crypto.aes import aes_decrypt_cbc_pkcs7, aes_encrypt_cbc_pkcs7
from ..crypto.curve import Curve25519Provider, DefaultCurve25519Provider
from ..crypto.hkdf import hkdf_sha256, hmac_sha256
from .address import SignalAddress, jid_to_signal_address

_CURRENT_VERSION = 3
_VERSION_BYTE = ((_CURRENT_VERSION << 4) | _CURRENT_VERSION) & 0xFF
_SIGNATURE_LENGTH = 64

_MAX_STATES = 5
_MAX_MESSAGE_KEYS = 2000
_MAX_FUTURE_MESSAGES = 2000


def _get_proto() -> Any:
    # Lazy import: WAProto is large.
    from ..proto import WAProto_pb2 as proto

    return proto


@dataclass(frozen=True, slots=True)
class SenderKeyName:
    """
    Identifier for a sender-key record: group id + sender address.

    Mirrors Baileys/libsignal format: `{groupId}::{senderId}::{senderDeviceId}`.
    """

    group_id: str
    sender: SignalAddress

    def serialize(self) -> str:
        return f"{self.group_id}::{self.sender.name}::{int(self.sender.device)}"

    def __str__(self) -> str:  # pragma: no cover
        return self.serialize()


class SenderKeyStore(Protocol):
    async def load_sender_key(self, sender_key_name: SenderKeyName) -> Any: ...

    async def store_sender_key(self, sender_key_name: SenderKeyName, record: Any) -> None: ...


def generate_sender_key() -> bytes:
    return secrets.token_bytes(32)


def generate_sender_key_id() -> int:
    # Baileys uses randomInt(2147483647)
    return secrets.randbelow(2_147_483_647)


def _with_signal_prefix(pub: bytes) -> bytes:
    # libsignal sometimes prefixes Curve25519 public keys with 0x05.
    if len(pub) == 32:
        return bytes([0x05]) + pub
    return pub


@dataclass(frozen=True, slots=True)
class SenderChainKey:
    iteration: int
    seed: bytes

    def sender_message_key(self) -> SenderMessageKey:
        msg_seed = hmac_sha256(self.seed, b"\x01")
        return SenderMessageKey(iteration=self.iteration, seed=msg_seed)

    def next(self) -> SenderChainKey:
        next_seed = hmac_sha256(self.seed, b"\x02")
        return SenderChainKey(iteration=int(self.iteration) + 1, seed=next_seed)


@dataclass(frozen=True, slots=True)
class SenderMessageKey:
    iteration: int
    seed: bytes

    @property
    def iv(self) -> bytes:
        return self._derive()[0]

    @property
    def cipher_key(self) -> bytes:
        return self._derive()[1]

    def _derive(self) -> tuple[bytes, bytes]:
        # libsignal deriveSecrets(seed, 32x00, "WhisperGroup") => 64 bytes
        expanded = hkdf_sha256(ikm=self.seed, length=64, salt=b"\x00" * 32, info=b"WhisperGroup")
        part1 = expanded[:32]
        part2 = expanded[32:]
        iv = part1[:16]
        cipher_key = part1[16:32] + part2[:16]
        return iv, cipher_key


def _state_get_chain_key(state: Any) -> SenderChainKey:
    ck = state.senderChainKey
    return SenderChainKey(iteration=int(ck.iteration or 0), seed=bytes(ck.seed or b""))


def _state_set_chain_key(state: Any, ck: SenderChainKey) -> None:
    state.senderChainKey.iteration = int(ck.iteration)
    state.senderChainKey.seed = bytes(ck.seed)


def _state_get_signing_public(state: Any) -> bytes:
    return _with_signal_prefix(bytes(state.senderSigningKey.public or b""))


def _state_get_signing_private(state: Any) -> bytes | None:
    priv = bytes(state.senderSigningKey.private or b"")
    return priv if priv else None


def _state_has_message_key(state: Any, iteration: int) -> bool:
    it = int(iteration)
    return any(int(k.iteration or 0) == it for k in list(state.senderMessageKeys))


def _state_add_message_key(state: Any, mk: SenderMessageKey) -> None:
    k = state.senderMessageKeys.add()
    k.iteration = int(mk.iteration)
    k.seed = bytes(mk.seed)
    if len(state.senderMessageKeys) > _MAX_MESSAGE_KEYS:
        del state.senderMessageKeys[0]


def _state_remove_message_key(state: Any, iteration: int) -> SenderMessageKey | None:
    it = int(iteration)
    for idx, k in enumerate(list(state.senderMessageKeys)):
        if int(k.iteration or 0) == it:
            seed = bytes(k.seed or b"")
            del state.senderMessageKeys[idx]
            return SenderMessageKey(iteration=it, seed=seed)
    return None


def _record_is_empty(record: Any) -> bool:
    return len(getattr(record, "senderKeyStates", [])) == 0


def _record_get_state(record: Any, key_id: int | None = None) -> Any | None:
    states = list(record.senderKeyStates)
    if not states:
        return None
    if key_id is None:
        return states[-1]
    for st in states:
        if int(st.senderKeyId or 0) == int(key_id):
            return st
    return None


def _record_add_sender_key_state(
    record: Any,
    *,
    sender_key_id: int,
    iteration: int,
    chain_key: bytes,
    signing_key_public: bytes,
) -> None:
    st = record.senderKeyStates.add()
    st.senderKeyId = int(sender_key_id)
    st.senderChainKey.iteration = int(iteration)
    st.senderChainKey.seed = bytes(chain_key)
    st.senderSigningKey.public = bytes(signing_key_public)
    # private absent for remote sender keys
    if len(record.senderKeyStates) > _MAX_STATES:
        del record.senderKeyStates[0]


def _record_set_sender_key_state(
    record: Any,
    *,
    sender_key_id: int,
    iteration: int,
    chain_key: bytes,
    signing_key_public: bytes,
    signing_key_private: bytes,
) -> None:
    del record.senderKeyStates[:]
    st = record.senderKeyStates.add()
    st.senderKeyId = int(sender_key_id)
    st.senderChainKey.iteration = int(iteration)
    st.senderChainKey.seed = bytes(chain_key)
    st.senderSigningKey.public = bytes(signing_key_public)
    st.senderSigningKey.private = bytes(signing_key_private)
    del st.senderMessageKeys[:]


class SenderKeyDistributionMessage:
    def __init__(self, *, serialized: bytes) -> None:
        if not serialized:
            raise ValueError("empty sender key distribution message")
        if len(serialized) < 2:
            raise ValueError("invalid sender key distribution message")

        proto = _get_proto()
        self._version = int(serialized[0])
        pb = proto.SenderKeyDistributionMessage()
        pb.ParseFromString(serialized[1:])
        self._pb = pb
        self._serialized = bytes(serialized)

    @classmethod
    def build(
        cls,
        *,
        sender_key_id: int,
        iteration: int,
        chain_key: bytes,
        signing_key: bytes,
    ) -> SenderKeyDistributionMessage:
        proto = _get_proto()
        pb = proto.SenderKeyDistributionMessage()
        pb.id = int(sender_key_id)
        pb.iteration = int(iteration)
        pb.chainKey = bytes(chain_key)
        pb.signingKey = bytes(signing_key)
        serialized = bytes([_VERSION_BYTE]) + pb.SerializeToString()
        return cls(serialized=serialized)

    @property
    def sender_key_id(self) -> int:
        return int(self._pb.id or 0)

    @property
    def iteration(self) -> int:
        return int(self._pb.iteration or 0)

    @property
    def chain_key(self) -> bytes:
        return bytes(self._pb.chainKey or b"")

    @property
    def signing_key(self) -> bytes:
        return bytes(self._pb.signingKey or b"")

    def serialize(self) -> bytes:
        return self._serialized


class SenderKeyMessage:
    def __init__(self, *, serialized: bytes) -> None:
        if not serialized:
            raise ValueError("empty sender key message")
        if len(serialized) <= 1 + _SIGNATURE_LENGTH:
            raise ValueError("invalid sender key message length")

        proto = _get_proto()
        self._version = int(serialized[0])
        self._message = bytes(serialized[1:-_SIGNATURE_LENGTH])
        self._signature = bytes(serialized[-_SIGNATURE_LENGTH:])
        pb = proto.SenderKeyMessage()
        pb.ParseFromString(self._message)
        self._pb = pb
        self._serialized = bytes(serialized)

    @classmethod
    def build(
        cls,
        *,
        sender_key_id: int,
        iteration: int,
        ciphertext: bytes,
        signing_key_private: bytes,
        curve: Curve25519Provider | None = None,
    ) -> SenderKeyMessage:
        if not signing_key_private:
            raise ValueError("signing_key_private is required")

        proto = _get_proto()
        pb = proto.SenderKeyMessage()
        pb.id = int(sender_key_id)
        pb.iteration = int(iteration)
        pb.ciphertext = bytes(ciphertext)
        msg = pb.SerializeToString()

        ver = _VERSION_BYTE
        to_sign = bytes([ver]) + msg
        c = curve or DefaultCurve25519Provider()
        sig = c.sign(signing_key_private, to_sign)
        if len(sig) != _SIGNATURE_LENGTH:  # pragma: no cover
            raise ValueError("invalid signature length")
        serialized = bytes([ver]) + msg + sig
        return cls(serialized=serialized)

    @property
    def sender_key_id(self) -> int:
        return int(self._pb.id or 0)

    @property
    def iteration(self) -> int:
        return int(self._pb.iteration or 0)

    @property
    def ciphertext(self) -> bytes:
        return bytes(self._pb.ciphertext or b"")

    def verify_signature(
        self, signing_key_public: bytes, *, curve: Curve25519Provider | None = None
    ) -> None:
        c = curve or DefaultCurve25519Provider()
        to_verify = bytes([self._version]) + self._message
        if not c.verify(signing_key_public, to_verify, self._signature):
            raise ValueError("invalid sender key signature")

    def serialize(self) -> bytes:
        return self._serialized


def _get_sender_message_key_for_iteration(state: Any, iteration: int) -> SenderMessageKey:
    ck = _state_get_chain_key(state)
    target = int(iteration)

    # Old counter: try cache.
    if ck.iteration > target:
        if _state_has_message_key(state, target):
            mk = _state_remove_message_key(state, target)
            if mk is None:
                raise ValueError("sender message key missing for cached iteration")
            return mk
        raise ValueError(f"received message with old counter: {ck.iteration}, {target}")

    if target - ck.iteration > _MAX_FUTURE_MESSAGES:
        raise ValueError("received message too far in the future (>2000)")

    while ck.iteration < target:
        _state_add_message_key(state, ck.sender_message_key())
        ck = ck.next()

    # Advance stored chain key one step past the used iteration.
    _state_set_chain_key(state, ck.next())
    return ck.sender_message_key()


class GroupSessionBuilder:
    def __init__(self, store: SenderKeyStore, *, curve: Curve25519Provider | None = None) -> None:
        self._store = store
        self._curve = curve or DefaultCurve25519Provider()

    async def process(self, name: SenderKeyName, msg: SenderKeyDistributionMessage) -> None:
        record = await self._store.load_sender_key(name)
        _record_add_sender_key_state(
            record,
            sender_key_id=msg.sender_key_id,
            iteration=msg.iteration,
            chain_key=msg.chain_key,
            signing_key_public=msg.signing_key,
        )
        await self._store.store_sender_key(name, record)

    async def create(self, name: SenderKeyName) -> SenderKeyDistributionMessage:
        record = await self._store.load_sender_key(name)
        if _record_is_empty(record):
            key_id = generate_sender_key_id()
            chain_key = generate_sender_key()
            signing = self._curve.generate_keypair()
            _record_set_sender_key_state(
                record,
                sender_key_id=key_id,
                iteration=0,
                chain_key=chain_key,
                signing_key_public=signing.public,
                signing_key_private=signing.private,
            )
            await self._store.store_sender_key(name, record)

        st = _record_get_state(record)
        if st is None:  # pragma: no cover
            raise RuntimeError("no sender key state")

        ck = _state_get_chain_key(st)
        return SenderKeyDistributionMessage.build(
            sender_key_id=int(st.senderKeyId or 0),
            iteration=int(ck.iteration),
            chain_key=ck.seed,
            signing_key=_state_get_signing_public(st),
        )


class GroupCipher:
    def __init__(
        self,
        store: SenderKeyStore,
        name: SenderKeyName,
        *,
        curve: Curve25519Provider | None = None,
    ) -> None:
        self._store = store
        self._name = name
        self._curve = curve or DefaultCurve25519Provider()

    async def encrypt(self, padded_plaintext: bytes) -> bytes:
        record = await self._store.load_sender_key(self._name)
        st = _record_get_state(record)
        if st is None:
            raise ValueError("no sender key state for encryption")

        ck = _state_get_chain_key(st)
        # Mirrors Baileys: use current iteration, except bump by 1 after the first message.
        target_iteration = 0 if ck.iteration == 0 else ck.iteration + 1
        mk = _get_sender_message_key_for_iteration(st, target_iteration)

        ct = aes_encrypt_cbc_pkcs7(bytes(padded_plaintext), key=mk.cipher_key, iv=mk.iv)

        signing_priv = _state_get_signing_private(st)
        if not signing_priv:
            raise ValueError("missing signing private key for sender key state")

        skm = SenderKeyMessage.build(
            sender_key_id=int(st.senderKeyId or 0),
            iteration=int(mk.iteration),
            ciphertext=ct,
            signing_key_private=signing_priv,
            curve=self._curve,
        )

        await self._store.store_sender_key(self._name, record)
        return skm.serialize()

    async def decrypt(self, sender_key_message_bytes: bytes) -> bytes:
        record = await self._store.load_sender_key(self._name)
        skm = SenderKeyMessage(serialized=bytes(sender_key_message_bytes))
        st = _record_get_state(record, key_id=skm.sender_key_id)
        if st is None:
            raise ValueError("no sender key state for sender key id")

        skm.verify_signature(_state_get_signing_public(st), curve=self._curve)
        mk = _get_sender_message_key_for_iteration(st, skm.iteration)

        pt = aes_decrypt_cbc_pkcs7(skm.ciphertext, key=mk.cipher_key, iv=mk.iv)
        await self._store.store_sender_key(self._name, record)
        return pt


def jid_to_sender_key_name(group_jid: str, sender_jid: str) -> SenderKeyName:
    return SenderKeyName(group_id=group_jid, sender=jid_to_signal_address(sender_jid))
