"""
LT-hash update logic for app-state patches.

Algorithm is compatible with `wacore-appstate` (MIT):
Copyright (c) 2025 Joao Lucas de Oliveira Lopes
https://github.com/jlucaso1/whatsapp-rust
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.hkdf import hkdf_sha256

WAPATCH_INTEGRITY_INFO = b"WhatsApp Patch Integrity"


def _perform_pointwise_with_overflow(base: bytearray, inp: bytes, *, subtract: bool) -> None:
    if len(base) != len(inp):
        raise ValueError("length mismatch")
    if (len(base) % 2) != 0:
        raise ValueError("slice lengths must be even")

    # Operate on little-endian u16 words with wraparound (matches rust bridge).
    for i in range(0, len(base), 2):
        x = int.from_bytes(base[i : i + 2], "little", signed=False)
        y = int.from_bytes(inp[i : i + 2], "little", signed=False)
        r = (x - y) & 0xFFFF if subtract else (x + y) & 0xFFFF
        base[i : i + 2] = r.to_bytes(2, "little", signed=False)


@dataclass(frozen=True, slots=True)
class LTHash:
    """
    Linear-Transform hash updater used by WhatsApp app state (LT-Hash).

    Ported from `wacore-appstate` (MIT). See:
    https://github.com/jlucaso1/whatsapp-rust
    """

    hkdf_info: bytes
    hkdf_size: int

    def subtract_then_add_in_place(
        self, base: bytearray, subtract: list[bytes], add: list[bytes]
    ) -> None:
        for item in subtract:
            derived = hkdf_sha256(ikm=item, length=self.hkdf_size, salt=b"", info=self.hkdf_info)
            _perform_pointwise_with_overflow(base, derived, subtract=True)
        for item in add:
            derived = hkdf_sha256(ikm=item, length=self.hkdf_size, salt=b"", info=self.hkdf_info)
            _perform_pointwise_with_overflow(base, derived, subtract=False)


WAPATCH_INTEGRITY = LTHash(hkdf_info=WAPATCH_INTEGRITY_INFO, hkdf_size=128)
