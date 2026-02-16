from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..auth.creds import KeyPair
from ..constants import NOISE_MODE, NOISE_WA_HEADER, WA_CERT_PUBLIC_KEY, WA_CERT_SERIAL
from ..exceptions import HandshakeError
from .aes import aes_decrypt_gcm, aes_encrypt_gcm
from .curve import Curve25519Provider, DefaultCurve25519Provider
from .hkdf import hkdf_sha256, sha256

_EMPTY = b""
_IV_LEN = 12


def _iv(counter: int) -> bytes:
    # 12-byte IV where the counter is stored in the last 4 bytes (big endian)
    return b"\x00" * 8 + counter.to_bytes(4, "big", signed=False)


@dataclass(slots=True)
class _TransportState:
    enc_key: bytes
    dec_key: bytes
    read_counter: int = 0
    write_counter: int = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        c = self.write_counter
        self.write_counter += 1
        return aes_encrypt_gcm(plaintext, key=self.enc_key, iv=_iv(c), aad=_EMPTY)

    def decrypt(self, ciphertext: bytes) -> bytes:
        c = self.read_counter
        self.read_counter += 1
        return aes_decrypt_gcm(ciphertext, key=self.dec_key, iv=_iv(c), aad=_EMPTY)


class NoiseHandler:
    """
    WhatsApp Web Noise_XX framing + crypto.

    Ported at a high level from Baileys' `makeNoiseHandler`.
    """

    def __init__(
        self,
        *,
        key_pair: KeyPair,
        noise_header: bytes = NOISE_WA_HEADER,
        routing_info: bytes | None = None,
        curve: Curve25519Provider | None = None,
    ) -> None:
        self._curve = curve or DefaultCurve25519Provider()

        self._private_key = key_pair.private
        self._public_key = key_pair.public

        data = bytes(NOISE_MODE)
        h = data if len(data) == 32 else sha256(data)
        self._hash = h
        self._salt = h
        self._enc_key = h
        self._dec_key = h
        self._counter = 0

        self._sent_intro = False
        self._in_bytes = bytearray()

        self._transport: _TransportState | None = None
        self._waiting_for_transport = False
        self._pending_on_frame: Callable[[bytes], Any] | None = None

        if routing_info is not None:
            ri = routing_info
            intro = bytearray()
            intro += b"ED"
            intro += bytes([0, 1])  # version?
            intro += bytes([(len(ri) >> 16) & 0xFF])
            intro += (len(ri) & 0xFFFF).to_bytes(2, "big")
            intro += ri
            intro += noise_header
            self._intro_header = bytes(intro)
        else:
            self._intro_header = bytes(noise_header)

        # Noise handshake transcript includes header + client ephemeral pub key.
        self.authenticate(noise_header)
        self.authenticate(self._public_key)

    @property
    def public_key(self) -> bytes:
        return self._public_key

    @property
    def transport_ready(self) -> bool:
        return self._transport is not None

    def authenticate(self, data: bytes) -> None:
        if self._transport is None:
            self._hash = sha256(self._hash + data)

    def encrypt(self, plaintext: bytes) -> bytes:
        if self._transport is not None:
            return self._transport.encrypt(plaintext)
        out = aes_encrypt_gcm(plaintext, key=self._enc_key, iv=_iv(self._counter), aad=self._hash)
        self._counter += 1
        self.authenticate(out)
        return out

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._transport is not None:
            return self._transport.decrypt(ciphertext)
        out = aes_decrypt_gcm(ciphertext, key=self._dec_key, iv=_iv(self._counter), aad=self._hash)
        self._counter += 1
        self.authenticate(ciphertext)
        return out

    def _local_hkdf(self, data: bytes) -> tuple[bytes, bytes]:
        key = hkdf_sha256(ikm=data, length=64, salt=self._salt, info=b"")
        return key[:32], key[32:]

    def mix_into_key(self, data: bytes) -> None:
        write, read = self._local_hkdf(data)
        self._salt = write
        self._enc_key = read
        self._dec_key = read
        self._counter = 0

    async def finish_init(self) -> None:
        self._waiting_for_transport = True
        write, read = self._local_hkdf(b"")
        self._transport = _TransportState(enc_key=write, dec_key=read)
        self._waiting_for_transport = False

        # Flush buffered frames that arrived while transitioning to transport.
        if self._pending_on_frame is not None:
            cb = self._pending_on_frame
            self._pending_on_frame = None
            await self._process_data(cb)

    def process_handshake(
        self, handshake_msg: Any, noise_key: KeyPair, *, verify_certificates: bool = True
    ) -> bytes:
        """
        Process serverHello and return the encrypted static key to include in clientFinish.

        `handshake_msg` is a `WAProto.HandshakeMessage`.
        """

        if not getattr(handshake_msg, "HasField", None) or not handshake_msg.HasField(
            "serverHello"
        ):
            raise HandshakeError("expected serverHello in HandshakeMessage")

        sh = handshake_msg.serverHello
        ephemeral = bytes(sh.ephemeral)

        self.authenticate(ephemeral)
        self.mix_into_key(self._curve.shared_key(self._private_key, ephemeral))

        dec_static = self.decrypt(bytes(sh.static))
        self.mix_into_key(self._curve.shared_key(self._private_key, dec_static))

        cert_decoded = self.decrypt(bytes(sh.payload))
        if verify_certificates:
            self._verify_cert_chain(cert_decoded)

        key_enc = self.encrypt(noise_key.public)
        self.mix_into_key(self._curve.shared_key(noise_key.private, ephemeral))
        return key_enc

    def encode_frame(self, payload: bytes) -> bytes:
        if self._transport is not None:
            payload = self._transport.encrypt(payload)

        intro = b""
        if not self._sent_intro:
            intro = self._intro_header
            self._sent_intro = True

        ln = len(payload)
        if ln > 0xFFFFFF:
            raise ValueError("frame too large")
        return intro + bytes([(ln >> 16) & 0xFF, (ln >> 8) & 0xFF, ln & 0xFF]) + payload

    async def decode_frame(self, new_data: bytes, on_frame: Callable[[bytes], Any]) -> None:
        """
        Feed raw WS bytes, invoke `on_frame` for each complete decoded frame payload.

        - before transport is ready: yields handshake protobuf bytes
        - after transport: yields decrypted binary node bytes
        """

        if self._waiting_for_transport:
            self._in_bytes.extend(new_data)
            self._pending_on_frame = on_frame
            return

        self._in_bytes.extend(new_data)
        await self._process_data(on_frame)

    async def _process_data(self, on_frame: Callable[[bytes], Any]) -> None:
        while True:
            if len(self._in_bytes) < 3:
                return
            size = (self._in_bytes[0] << 16) | (self._in_bytes[1] << 8) | self._in_bytes[2]
            if len(self._in_bytes) < 3 + size:
                return

            frame = bytes(self._in_bytes[3 : 3 + size])
            del self._in_bytes[: 3 + size]

            if self._transport is not None:
                frame = self._transport.decrypt(frame)

            res = on_frame(frame)
            if asyncio.iscoroutine(res):
                await res

    def _verify_cert_chain(self, cert_chain_bytes: bytes) -> None:
        # Import lazily: the generated WAProto module is large.
        try:
            from ..proto import WAProto_pb2 as proto
        except Exception as e:  # pragma: no cover
            raise HandshakeError(f"failed to import WAProto protobufs: {e}") from e

        chain = proto.CertChain()
        chain.ParseFromString(cert_chain_bytes)

        if not chain.leaf.details or not chain.leaf.signature:
            raise HandshakeError("invalid noise leaf certificate (missing details/signature)")
        if not chain.intermediate.details or not chain.intermediate.signature:
            raise HandshakeError(
                "invalid noise intermediate certificate (missing details/signature)"
            )

        details = proto.CertChain.NoiseCertificate.Details()
        details.ParseFromString(chain.intermediate.details)

        issuer_serial = int(getattr(details, "issuerSerial", 0))
        key = bytes(details.key)

        if issuer_serial != WA_CERT_SERIAL:
            raise HandshakeError("noise certificate issuerSerial mismatch")

        if not self._curve.verify(key, bytes(chain.leaf.details), bytes(chain.leaf.signature)):
            raise HandshakeError("noise certificate signature invalid")
        if not self._curve.verify(
            WA_CERT_PUBLIC_KEY,
            bytes(chain.intermediate.details),
            bytes(chain.intermediate.signature),
        ):
            raise HandshakeError("noise intermediate certificate signature invalid")
