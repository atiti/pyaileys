from __future__ import annotations

from pyaileys.messages import decode_wa_message_bytes, encode_wa_message_bytes


def test_wa_message_padding_roundtrip() -> None:
    payloads = [b"", b"hello", bytes(range(0, 200))]
    for p in payloads:
        padded = encode_wa_message_bytes(p)
        assert 1 <= padded[-1] <= 16
        assert decode_wa_message_bytes(padded) == p
