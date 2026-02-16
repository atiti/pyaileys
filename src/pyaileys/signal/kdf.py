from __future__ import annotations

from ..crypto.hkdf import hkdf_sha256, hmac_sha256

_ZERO_32 = b"\x00" * 32

# Signal protocol labels.
INFO_TEXT = b"WhisperText"
INFO_RATCHET = b"WhisperRatchet"
INFO_MESSAGE_KEYS = b"WhisperMessageKeys"

# Chain key derivation constants (Signal v3).
_MESSAGE_KEY_SEED = b"\x01"
_CHAIN_KEY_SEED = b"\x02"


def kdf_text(master_secret: bytes) -> tuple[bytes, bytes]:
    """
    Derive (root_key, chain_key) from the X3DH master secret.
    """

    derived = hkdf_sha256(ikm=master_secret, length=64, salt=_ZERO_32, info=INFO_TEXT)
    return derived[:32], derived[32:]


def kdf_root(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """
    Derive (new_root_key, chain_key) for a DH ratchet step.
    """

    derived = hkdf_sha256(ikm=dh_out, length=64, salt=root_key, info=INFO_RATCHET)
    return derived[:32], derived[32:]


def kdf_chain(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    Derive (next_chain_key, message_key_seed) from a chain key.
    """

    message_key_seed = hmac_sha256(chain_key, _MESSAGE_KEY_SEED)
    next_chain_key = hmac_sha256(chain_key, _CHAIN_KEY_SEED)
    return next_chain_key, message_key_seed


def kdf_message_keys(message_key_seed: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Derive (cipher_key, mac_key, iv) for a Signal message from its seed.

    Output sizes match libsignal: 32/32/16 bytes.
    """

    mk = hkdf_sha256(ikm=message_key_seed, length=80, salt=_ZERO_32, info=INFO_MESSAGE_KEYS)
    return mk[:32], mk[32:64], mk[64:80]
