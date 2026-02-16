from __future__ import annotations

import base64
from dataclasses import dataclass


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


@dataclass(frozen=True, slots=True)
class Crockford32:
    """Minimal Crockford Base32 helpers used for pairing-code style flows."""

    alphabet: str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    def encode(self, data: bytes) -> str:
        # Not a general-purpose Base32 implementation; included only for parity with Baileys.
        # WhatsApp pairing codes are derived from 5 random bytes -> 8 chars.
        value = int.from_bytes(data, "big")
        out = []
        for _ in range(8):
            out.append(self.alphabet[value & 31])
            value >>= 5
        return "".join(reversed(out))
