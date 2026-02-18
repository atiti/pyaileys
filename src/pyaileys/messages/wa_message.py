from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any


def encode_wa_message_bytes(payload: bytes) -> bytes:
    """
    Apply WhatsApp Web's random PKCS7-like padding (1..16 bytes).

    Baileys calls this `writeRandomPadMax16`. It is applied *before* Signal encryption.
    """

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")
    pad_len = (secrets.token_bytes(1)[0] & 0x0F) + 1
    return bytes(payload) + bytes([pad_len]) * pad_len


def decode_wa_message_bytes(padded: bytes) -> bytes:
    """
    Remove WhatsApp Web's random padding applied by `encode_wa_message_bytes`.

    Baileys calls this `unpadRandomMax16`.
    """

    if not isinstance(padded, (bytes, bytearray, memoryview)):
        raise TypeError("padded must be bytes-like")
    b = bytes(padded)
    if not b:
        raise ValueError("cannot unpad empty bytes")
    pad_len = b[-1]
    if pad_len <= 0 or pad_len > len(b):
        raise ValueError("invalid pad length")
    # All pad bytes should equal pad_len, but be permissive for forward-compat.
    return b[:-pad_len]


def extract_message_text(msg: Any) -> str | None:
    """
    Best-effort text extraction from a `proto.Message` (WAProto).

    Returns the most user-visible string if present.

    For non-text messages (images, audio, location), this returns a short
    placeholder or caption so demo apps have something sensible to display.
    """

    if msg is None:
        return None

    # Plain conversation text
    conv = getattr(msg, "conversation", None)
    if isinstance(conv, str) and conv:
        return conv

    # extendedTextMessage.text
    etm = getattr(msg, "extendedTextMessage", None)
    text = getattr(etm, "text", None) if etm is not None else None
    if isinstance(text, str) and text:
        return text

    has_field = getattr(msg, "HasField", None)
    has_field_fn = has_field if callable(has_field) else None

    # Documents (caption if any, otherwise a filename/title placeholder).
    if has_field_fn is not None and has_field_fn("documentMessage"):
        dm = msg.documentMessage
        cap = getattr(dm, "caption", None)
        if isinstance(cap, str) and cap:
            return cap
        fn = getattr(dm, "fileName", None)
        title = getattr(dm, "title", None)
        label = title or fn
        if isinstance(label, str) and label:
            return f"[document] {label}"
        return "[document]"

    # Contacts (vcard).
    if has_field_fn is not None and has_field_fn("contactMessage"):
        cm = msg.contactMessage
        dn = getattr(cm, "displayName", None)
        if isinstance(dn, str) and dn:
            return f"[contact] {dn}"
        return "[contact]"

    # Contacts array.
    if has_field_fn is not None and has_field_fn("contactsArrayMessage"):
        cam = msg.contactsArrayMessage
        dn = getattr(cam, "displayName", None)
        if isinstance(dn, str) and dn:
            return f"[contacts] {dn}"
        contacts = getattr(cam, "contacts", None)
        try:
            n = len(contacts) if contacts is not None else 0
        except Exception:
            n = 0
        return f"[contacts] {n}" if n else "[contacts]"

    # Image caption (if any), otherwise show a placeholder.
    if has_field_fn is not None and has_field_fn("imageMessage"):
        im = msg.imageMessage
        cap = getattr(im, "caption", None)
        if isinstance(cap, str) and cap:
            return cap
        return "[image]"

    # Video caption (if any), otherwise show a placeholder.
    if has_field_fn is not None and has_field_fn("videoMessage"):
        vm = msg.videoMessage
        cap = getattr(vm, "caption", None)
        if isinstance(cap, str) and cap:
            return cap
        gif = getattr(vm, "gifPlayback", None)
        return "[gif]" if gif is True else "[video]"

    # Audio/PTT has no caption; show a placeholder.
    if has_field_fn is not None and has_field_fn("audioMessage"):
        am = msg.audioMessage
        ptt = getattr(am, "ptt", None)
        if ptt is True:
            return "[voice message]"
        return "[audio]"

    # Static location.
    if has_field_fn is not None and has_field_fn("locationMessage"):
        lm = msg.locationMessage
        name = getattr(lm, "name", None)
        address = getattr(lm, "address", None)
        comment = getattr(lm, "comment", None)

        parts: list[str] = []
        if isinstance(name, str) and name:
            parts.append(name)
        if isinstance(address, str) and address:
            parts.append(address)
        if isinstance(comment, str) and comment:
            parts.append(comment)
        if parts:
            return " / ".join(parts)

        lat = getattr(lm, "degreesLatitude", None)
        lng = getattr(lm, "degreesLongitude", None)
        if isinstance(lat, (float, int)) and isinstance(lng, (float, int)):
            return f"[location] {float(lat):.6f},{float(lng):.6f}"
        return "[location]"

    # Live location.
    if has_field_fn is not None and has_field_fn("liveLocationMessage"):
        ll = msg.liveLocationMessage
        cap = getattr(ll, "caption", None)
        if isinstance(cap, str) and cap:
            return cap
        lat = getattr(ll, "degreesLatitude", None)
        lng = getattr(ll, "degreesLongitude", None)
        if isinstance(lat, (float, int)) and isinstance(lng, (float, int)):
            return f"[live location] {float(lat):.6f},{float(lng):.6f}"
        return "[live location]"

    # Stickers.
    if has_field_fn is not None and has_field_fn("stickerMessage"):
        return "[sticker]"

    return None


def generate_participant_hash_v2(participants: list[str]) -> str:
    """
    Generate WhatsApp's participant hash (phash) used in multi-device fanout messages.

    Port of Baileys' `generateParticipantHashV2`:
    - sort participants
    - sha256 over concatenated JIDs (no separators)
    - base64, take first 6 chars
    - prefix with "2:"
    """

    parts = sorted([p for p in participants if p])
    digest = hashlib.sha256("".join(parts).encode("utf-8")).digest()
    b64 = base64.b64encode(digest).decode("ascii")
    return "2:" + b64[:6]
