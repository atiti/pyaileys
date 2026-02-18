"""
App-state key expansion.

Algorithm is compatible with `wacore-appstate` (MIT):
Copyright (c) 2025 Joao Lucas de Oliveira Lopes
https://github.com/jlucaso1/whatsapp-rust
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.hkdf import hkdf_sha256


@dataclass(frozen=True, slots=True)
class ExpandedAppStateKeys:
    """
    Expanded app-state keys derived from a 32-byte master key.

    Mirrors `ExpandedAppStateKeys` in whatsmeow / wacore-appstate.
    """

    index: bytes
    value_encryption: bytes
    value_mac: bytes
    snapshot_mac: bytes
    patch_mac: bytes


def expand_app_state_keys(key_data: bytes) -> ExpandedAppStateKeys:
    """
    Expand the 32-byte master app state sync key into 5 sub-keys (160 bytes total).

    Algorithm:
    - HKDF-SHA256(key_data, salt=nil/empty, info="WhatsApp Mutation Keys", length=160)
    - slice into five 32-byte keys.
    """

    if not isinstance(key_data, (bytes, bytearray, memoryview)):
        raise TypeError("key_data must be bytes-like")
    key = bytes(key_data)
    if not key:
        raise ValueError("key_data is empty")
    okm = hkdf_sha256(ikm=key, length=160, salt=b"", info=b"WhatsApp Mutation Keys")
    return ExpandedAppStateKeys(
        index=okm[0:32],
        value_encryption=okm[32:64],
        value_mac=okm[64:96],
        snapshot_mac=okm[96:128],
        patch_mac=okm[128:160],
    )
