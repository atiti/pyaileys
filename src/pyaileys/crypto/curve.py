from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from ..auth.creds import KeyPair
from .curve25519_signature import curve25519_sign, curve25519_verify


class Curve25519Provider(Protocol):
    def generate_keypair(self) -> KeyPair: ...

    def shared_key(self, private_key: bytes, public_key: bytes) -> bytes: ...

    def sign(self, private_key: bytes, message: bytes) -> bytes: ...

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


class DefaultCurve25519Provider:
    """
    X25519 provider via `cryptography`.

    Signal-style Curve25519 signatures are implemented to match libsignal/curve25519-js.
    """

    def generate_keypair(self) -> KeyPair:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        return KeyPair(
            private=priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            public=pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    def shared_key(self, private_key: bytes, public_key: bytes) -> bytes:
        priv = X25519PrivateKey.from_private_bytes(private_key)
        pub = X25519PublicKey.from_public_bytes(public_key)
        return priv.exchange(pub)

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return curve25519_sign(private_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return curve25519_verify(public_key, message, signature)
