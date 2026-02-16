from __future__ import annotations

import hashlib
import hmac


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(*, ikm: bytes, length: int, salt: bytes, info: bytes = b"") -> bytes:
    """
    HKDF-SHA256 (RFC 5869).

    Matches Baileys' `hkdf(..., 64, { salt, info: '' })` usage.
    """

    if length <= 0:
        raise ValueError("length must be > 0")
    prk = hmac_sha256(salt, ikm)  # extract

    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]
