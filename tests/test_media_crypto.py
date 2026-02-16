from __future__ import annotations

import base64

import pytest

from pyaileys.media import build_upload_url, decrypt_media_bytes, encrypt_media_bytes
from pyaileys.messages.wa_message import extract_message_text
from pyaileys.proto import WAProto_pb2 as proto


def test_encrypt_decrypt_media_roundtrip_with_mac_validation() -> None:
    data = (b"hello world\n" * 1000) + b"!"
    enc = encrypt_media_bytes(data, media_type="image")

    assert enc.file_length == len(data)
    assert enc.enc_bytes.endswith(enc.mac)
    assert len(enc.mac) == 10

    out = decrypt_media_bytes(
        enc.enc_bytes, media_key=enc.media_key, media_type="image", validate_mac=True
    )
    assert out == data

    # Tamper with the MAC
    tampered = enc.enc_bytes[:-1] + bytes([enc.enc_bytes[-1] ^ 0x01])
    with pytest.raises(ValueError, match=r"MAC mismatch|ciphertext length|padding"):
        decrypt_media_bytes(
            tampered, media_key=enc.media_key, media_type="image", validate_mac=True
        )

    enc_doc = encrypt_media_bytes(b"%PDF-1.7\n...", media_type="document")
    out_doc = decrypt_media_bytes(
        enc_doc.enc_bytes, media_key=enc_doc.media_key, media_type="document", validate_mac=True
    )
    assert out_doc == b"%PDF-1.7\n..."


def test_build_upload_url_matches_baileys_token_encoding() -> None:
    digest = bytes(range(32))
    url = build_upload_url(
        hostname="example.com", auth="a b/+=", media_type="image", file_enc_sha256=digest
    )

    token = base64.b64encode(digest).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")
    assert url.startswith("https://example.com/mms/image/")
    assert f"/{token}?" in url
    assert "auth=" in url
    assert "token=" in url

    url_doc = build_upload_url(
        hostname="example.com", auth="auth", media_type="document", file_enc_sha256=digest
    )
    assert url_doc.startswith("https://example.com/mms/document/")


def test_extract_message_text_handles_media_captions_and_placeholders() -> None:
    m = proto.Message()
    m.conversation = "hi"
    assert extract_message_text(m) == "hi"

    m = proto.Message()
    m.imageMessage.caption = "cap"
    assert extract_message_text(m) == "cap"

    m = proto.Message()
    m.imageMessage.mimetype = "image/jpeg"
    assert extract_message_text(m) == "[image]"

    m = proto.Message()
    m.audioMessage.ptt = True
    assert extract_message_text(m) == "[voice message]"

    m = proto.Message()
    m.documentMessage.fileName = "file.pdf"
    assert extract_message_text(m) == "[document] file.pdf"

    m = proto.Message()
    m.documentMessage.caption = "here"
    assert extract_message_text(m) == "here"

    m = proto.Message()
    m.contactMessage.displayName = "Alice"
    m.contactMessage.vcard = "BEGIN:VCARD\nFN:Alice\nEND:VCARD\n"
    assert extract_message_text(m) == "[contact] Alice"

    m = proto.Message()
    m.contactsArrayMessage.displayName = "Friends"
    assert extract_message_text(m) == "[contacts] Friends"

    m = proto.Message()
    m.locationMessage.degreesLatitude = 1.2
    m.locationMessage.degreesLongitude = 3.4
    assert extract_message_text(m) == "[location] 1.200000,3.400000"
