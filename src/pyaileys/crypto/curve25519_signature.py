"""
Curve25519 "Signal-style" signatures used by WhatsApp Web multi-device.

Baileys/libsignal-node implement these signatures via `curve25519-js`:
- Sign with a Curve25519 private scalar (X25519-style clamped 32 bytes)
- Verify with a Curve25519 public key (Montgomery u-coordinate)
- Internally converts keys/operations to an Ed25519-like signature scheme where
  the public-key sign bit is stored in the signature's MSB.

This module provides a compatible pure-Python implementation, intentionally
without external deps beyond stdlib.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

# Field prime for Ed25519.
_P = 2**255 - 19

# Group order (Ed25519).
_L = 2**252 + 27742317777372353535851937790883648493

# d parameter: -121665/121666 mod p
_D = -121665 * pow(121666, _P - 2, _P) % _P

# sqrt(-1) mod p
_I = pow(2, (_P - 1) // 4, _P)


def _clamp_scalar(sk32: bytes) -> bytes:
    if len(sk32) != 32:
        raise ValueError("expected 32-byte private key")
    b = bytearray(sk32)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def _le_bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)


def _int_to_le_bytes(x: int, length: int) -> bytes:
    return int(x).to_bytes(length, "little", signed=False)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _modp(x: int) -> int:
    return x % _P


def _inv(x: int) -> int:
    # Fermat inversion since p is prime.
    return pow(x, _P - 2, _P)


def _sqrt_mod_p(a: int) -> int:
    """
    Return x such that x^2 = a mod p, or raise ValueError if none exists.

    p ≡ 5 (mod 8), so use the standard Ed25519 sqrt algorithm.
    """

    a = a % _P
    x = pow(a, (_P + 3) // 8, _P)
    if (x * x - a) % _P != 0:
        x = (x * _I) % _P
    if (x * x - a) % _P != 0:
        raise ValueError("no square root")
    return x


@dataclass(frozen=True, slots=True)
class _ExtPoint:
    # Extended coordinates (X:Y:Z:T) with x=X/Z, y=Y/Z, T=XY/Z
    X: int
    Y: int
    Z: int
    T: int


def _point_add(p: _ExtPoint, q: _ExtPoint) -> _ExtPoint:
    # Unified addition formula for Ed25519 in extended coordinates.
    x1, y1, z1, t1 = p.X, p.Y, p.Z, p.T
    x2, y2, z2, t2 = q.X, q.Y, q.Z, q.T

    a = _modp((y1 - x1) * (y2 - x2))
    b = _modp((y1 + x1) * (y2 + x2))
    c = _modp(2 * _D * t1 * t2)
    d = _modp(2 * z1 * z2)
    e = _modp(b - a)
    f = _modp(d - c)
    g = _modp(d + c)
    h = _modp(b + a)

    x3 = _modp(e * f)
    y3 = _modp(g * h)
    z3 = _modp(f * g)
    t3 = _modp(e * h)
    return _ExtPoint(X=x3, Y=y3, Z=z3, T=t3)


def _point_double(p: _ExtPoint) -> _ExtPoint:
    x1, y1, z1 = p.X, p.Y, p.Z

    a = _modp(x1 * x1)
    b = _modp(y1 * y1)
    c = _modp(2 * z1 * z1)
    d = _modp(-a)
    e = _modp((x1 + y1) * (x1 + y1) - a - b)
    g = _modp(d + b)
    f = _modp(g - c)
    h = _modp(d - b)

    x3 = _modp(e * f)
    y3 = _modp(g * h)
    z3 = _modp(f * g)
    t3 = _modp(e * h)
    return _ExtPoint(X=x3, Y=y3, Z=z3, T=t3)


def _scalar_mult(p: _ExtPoint, s: int) -> _ExtPoint:
    # Simple double-and-add. Not constant-time (fine for non-secret scalars in verify).
    s = int(s)
    if s < 0:
        raise ValueError("scalar must be non-negative")

    # Neutral element in extended coords: (0,1,1,0)
    r = _ExtPoint(X=0, Y=1, Z=1, T=0)
    a = p
    while s:
        if s & 1:
            r = _point_add(r, a)
        a = _point_double(a)
        s >>= 1
    return r


def _encode_point(p: _ExtPoint) -> bytes:
    zinv = _inv(p.Z)
    x = _modp(p.X * zinv)
    y = _modp(p.Y * zinv)
    out = bytearray(_int_to_le_bytes(y, 32))
    out[31] |= (x & 1) << 7
    return bytes(out)


def _decode_point(enc: bytes) -> _ExtPoint:
    if len(enc) != 32:
        raise ValueError("expected 32-byte point encoding")
    sign = (enc[31] >> 7) & 1
    y = _le_bytes_to_int(bytes([enc[i] if i != 31 else enc[31] & 0x7F for i in range(32)]))
    if y >= _P:
        raise ValueError("invalid y coordinate")

    y2 = _modp(y * y)
    u = _modp(y2 - 1)
    v = _modp(_D * y2 + 1)
    x = _sqrt_mod_p(u * _inv(v))
    if (x & 1) != sign:
        x = _P - x

    # Extended coords from affine.
    return _ExtPoint(X=x, Y=y, Z=1, T=_modp(x * y))


# Ed25519 basepoint (in affine coords).
_B_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_B_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_B = _ExtPoint(X=_B_X, Y=_B_Y, Z=1, T=_modp(_B_X * _B_Y))


def _scalar_mult_base(s: int) -> _ExtPoint:
    return _scalar_mult(_B, s)


def _scrub_public_key(pk: bytes) -> bytes:
    # Some libsignal APIs prefix a version byte (0x05).
    if len(pk) == 33 and pk[0] == 0x05:
        return pk[1:]
    if len(pk) == 32:
        return pk
    raise ValueError("invalid public key length")


def _convert_curve25519_pub_to_ed25519_y(pk: bytes) -> bytes:
    """
    Convert Curve25519 Montgomery u-coordinate -> Ed25519 y coordinate encoding (no sign bit).

    edwardsY = (u - 1) / (u + 1)
    """

    pk = _scrub_public_key(pk)
    u = _le_bytes_to_int(pk) & ((1 << 255) - 1)
    y = _modp((u - 1) * _inv(u + 1))
    # y < p => top bit is 0, leaving space for the sign bit to be ORed in later.
    return _int_to_le_bytes(y, 32)


def curve25519_sign(private_key: bytes, message: bytes) -> bytes:
    """
    Sign message using Curve25519 private key (32 bytes).

    Returns 64-byte signature compatible with `curve25519-js`/libsignal.
    """

    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes-like")
    sk = _clamp_scalar(private_key)
    a = _le_bytes_to_int(sk)

    # Compute Ed25519 public key from scalar and extract sign bit.
    A = _scalar_mult_base(a)
    A_enc = _encode_point(A)
    sign_bit = A_enc[31] & 0x80

    # r = H(a || m) reduced mod L
    r = _le_bytes_to_int(_sha512(sk + bytes(message))) % _L
    R = _scalar_mult_base(r)
    R_enc = _encode_point(R)

    # h = H(R || A || m) reduced mod L
    hram = _le_bytes_to_int(_sha512(R_enc + A_enc + bytes(message))) % _L

    # S = (r + h*a) mod L
    S = (r + hram * a) % _L
    S_enc = _int_to_le_bytes(S, 32)

    sig = bytearray(R_enc + S_enc)
    sig[63] |= sign_bit
    return bytes(sig)


def curve25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify a Curve25519 signature compatible with `curve25519-js`/libsignal.
    """

    try:
        if not isinstance(message, (bytes, bytearray, memoryview)):
            return False
        if not isinstance(signature, (bytes, bytearray, memoryview)):
            return False

        sig = bytearray(bytes(signature))
        if len(sig) != 64:
            return False

        sign_bit = sig[63] & 0x80
        sig[63] &= 0x7F

        R_enc = bytes(sig[:32])
        S_enc = bytes(sig[32:])

        S = _le_bytes_to_int(S_enc)
        if S >= _L:
            return False

        # Convert Curve25519 public key -> Ed25519 public key bytes.
        edpk = bytearray(_convert_curve25519_pub_to_ed25519_y(public_key))
        edpk[31] |= sign_bit
        edpk_bytes = bytes(edpk)

        # Decode points.
        A = _decode_point(edpk_bytes)
        R = _decode_point(R_enc)

        h = _le_bytes_to_int(_sha512(R_enc + edpk_bytes + bytes(message))) % _L

        SB = _scalar_mult_base(S)
        hA = _scalar_mult(A, h)
        R_plus_hA = _point_add(R, hA)

        return hmac.compare_digest(_encode_point(SB), _encode_point(R_plus_hA))
    except Exception:
        return False
