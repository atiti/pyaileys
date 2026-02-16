from __future__ import annotations

SIGNAL_CURVE_TYPE = 0x05
SIGNAL_VERSION = 3
SIGNAL_VERSION_BYTE = (SIGNAL_VERSION << 4) | SIGNAL_VERSION  # 0x33

# Signal v3 uses an 8-byte truncated HMAC for message authentication.
SIGNAL_MAC_LEN = 8


def signal_pubkey(raw32: bytes) -> bytes:
    """Prefix a Curve25519 public key with the Signal key type byte (0x05)."""

    if len(raw32) == 33 and raw32[0] == SIGNAL_CURVE_TYPE:
        return raw32
    if len(raw32) != 32:
        raise ValueError("expected 32-byte public key")
    return bytes([SIGNAL_CURVE_TYPE]) + raw32


def strip_signal_pubkey(pub: bytes) -> bytes:
    """Strip Signal key type prefix if present, yielding a 32-byte Curve25519 public key."""

    if len(pub) == 33 and pub[0] == SIGNAL_CURVE_TYPE:
        return pub[1:]
    if len(pub) == 32:
        return pub
    raise ValueError("invalid public key length")


def parse_signal_version_byte(b: int) -> tuple[int, int]:
    """
    Return (current_version, min_version) from the 1-byte Signal version header.
    """

    current = (b >> 4) & 0x0F
    minimum = b & 0x0F
    return current, minimum
