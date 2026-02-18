"""
Lightweight media metadata probing (pure Python).

This module intentionally avoids heavy runtime dependencies (ffmpeg, PIL, etc.)
and provides best-effort helpers used when composing media messages:
- OGG/Opus duration (for voice notes)
- MP4 duration (for videos)
- WebP dimensions (for stickers)

If a probe fails, functions return `None` rather than raising.
"""

from __future__ import annotations

from typing import Final

_OPUS_SAMPLE_RATE_HZ: Final[int] = 48_000


def probe_ogg_opus_duration_s(data: bytes) -> float | None:
    """
    Return duration in seconds for an OGG/Opus file, if detectable.

    Uses the last Ogg page's granule position (samples at 48kHz).
    """

    try:
        b = bytes(data)
        if len(b) < 27 or b[:4] != b"OggS":
            return None

        off = 0
        last_gp: int | None = None
        while off + 27 <= len(b):
            if b[off : off + 4] != b"OggS":
                # Try resync: search for next capture pattern.
                nxt = b.find(b"OggS", off + 1)
                if nxt < 0:
                    break
                off = nxt
                continue

            # Ogg page header.
            seg_count = b[off + 26]
            header_len = 27 + int(seg_count)
            if off + header_len > len(b):
                break
            gp = int.from_bytes(b[off + 6 : off + 14], "little", signed=False)
            if gp != 0xFFFFFFFFFFFFFFFF:
                last_gp = gp

            # Skip payload using segment table.
            payload_len = sum(b[off + 27 : off + header_len])
            off += header_len + int(payload_len)

        if last_gp is None:
            return None
        return float(last_gp) / float(_OPUS_SAMPLE_RATE_HZ)
    except Exception:
        return None


def _iter_mp4_boxes(b: bytes, start: int, end: int) -> list[tuple[str, int, int]]:
    """
    Return a flat list of (type, box_start, box_end) for the immediate children.
    """

    out: list[tuple[str, int, int]] = []
    off = int(start)
    while off + 8 <= end:
        size = int.from_bytes(b[off : off + 4], "big", signed=False)
        typ = b[off + 4 : off + 8].decode("ascii", errors="ignore")
        hdr = 8
        if size == 1:
            if off + 16 > end:
                break
            size = int.from_bytes(b[off + 8 : off + 16], "big", signed=False)
            hdr = 16
        elif size == 0:
            size = end - off

        if size < hdr or off + size > end:
            break

        out.append((typ, off, off + size))
        off += size
    return out


def probe_mp4_duration_s(data: bytes) -> float | None:
    """
    Return duration in seconds for an MP4/ISO-BMFF file, if detectable.

    Looks for `moov/mvhd` and returns duration/timescale.
    """

    try:
        b = bytes(data)
        if len(b) < 16:
            return None

        # Find moov at top-level.
        boxes = _iter_mp4_boxes(b, 0, len(b))
        moov = next((x for x in boxes if x[0] == "moov"), None)
        if not moov:
            return None
        _typ, moov_start, moov_end = moov

        # Find mvhd inside moov.
        moov_children = _iter_mp4_boxes(b, moov_start + 8, moov_end)
        mvhd = next((x for x in moov_children if x[0] == "mvhd"), None)
        if not mvhd:
            return None
        _typ2, mvhd_start, mvhd_end = mvhd

        # Full box header: version(1) + flags(3)
        if mvhd_start + 12 > mvhd_end:
            return None
        version = b[mvhd_start + 8]

        if version == 0:
            if mvhd_start + 28 > mvhd_end:
                return None
            timescale = int.from_bytes(b[mvhd_start + 20 : mvhd_start + 24], "big", signed=False)
            duration = int.from_bytes(b[mvhd_start + 24 : mvhd_start + 28], "big", signed=False)
        elif version == 1:
            if mvhd_start + 40 > mvhd_end:
                return None
            timescale = int.from_bytes(b[mvhd_start + 28 : mvhd_start + 32], "big", signed=False)
            duration = int.from_bytes(b[mvhd_start + 32 : mvhd_start + 40], "big", signed=False)
        else:
            return None

        if timescale <= 0:
            return None
        return float(duration) / float(timescale)
    except Exception:
        return None


def probe_webp_size(data: bytes) -> tuple[int, int] | None:
    """
    Return (width, height) for a WebP file, if detectable.
    """

    try:
        b = bytes(data)
        if len(b) < 16 or b[:4] != b"RIFF" or b[8:12] != b"WEBP":
            return None

        off = 12
        while off + 8 <= len(b):
            chunk_type = b[off : off + 4]
            chunk_size = int.from_bytes(b[off + 4 : off + 8], "little", signed=False)
            chunk_start = off + 8
            chunk_end = chunk_start + chunk_size
            if chunk_end > len(b):
                break

            if (
                chunk_type == b"VP8 "
                and chunk_size >= 10
                and b[chunk_start + 3 : chunk_start + 6] == b"\x9d\x01\x2a"
            ):
                # Lossy bitstream header.
                w = int.from_bytes(b[chunk_start + 6 : chunk_start + 8], "little") & 0x3FFF
                h = int.from_bytes(b[chunk_start + 8 : chunk_start + 10], "little") & 0x3FFF
                return int(w), int(h)

            if chunk_type == b"VP8L" and chunk_size >= 5 and b[chunk_start] == 0x2F:
                # Lossless header: signature(1) + 4 bytes.
                bits = int.from_bytes(b[chunk_start + 1 : chunk_start + 5], "little", signed=False)
                w = (bits & 0x3FFF) + 1
                h = ((bits >> 14) & 0x3FFF) + 1
                return int(w), int(h)

            if chunk_type == b"VP8X" and chunk_size >= 10:
                w = int.from_bytes(b[chunk_start + 4 : chunk_start + 7], "little", signed=False) + 1
                h = (
                    int.from_bytes(b[chunk_start + 7 : chunk_start + 10], "little", signed=False)
                    + 1
                )
                return int(w), int(h)

            # Chunks are padded to even sizes.
            off = chunk_end + (chunk_size % 2)

        return None
    except Exception:
        return None
