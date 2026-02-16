from __future__ import annotations

import pytest

from pyaileys.crypto.curve import DefaultCurve25519Provider
from pyaileys.crypto.noise import NoiseHandler


@pytest.mark.asyncio
async def test_noise_decode_frame_splits_multiple_frames() -> None:
    curve = DefaultCurve25519Provider()
    nh = NoiseHandler(key_pair=curve.generate_keypair())

    frames: list[bytes] = []

    async def on_frame(frame: bytes) -> None:
        frames.append(frame)

    data = b"\x00\x00\x03abc" + b"\x00\x00\x03def"
    await nh.decode_frame(data, on_frame)

    assert frames == [b"abc", b"def"]


def test_noise_encode_frame_includes_intro_header_only_once() -> None:
    curve = DefaultCurve25519Provider()
    nh = NoiseHandler(key_pair=curve.generate_keypair())

    f1 = nh.encode_frame(b"hello")
    f2 = nh.encode_frame(b"world")

    assert b"hello" in f1
    assert b"world" in f2
    # The second frame should be shorter because the intro header is sent only once.
    assert len(f2) < len(f1)
