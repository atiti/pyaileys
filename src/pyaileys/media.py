from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from typing import cast

from .constants import DEFAULT_ORIGIN
from .crypto.aes import aes_decrypt_cbc_pkcs7, aes_encrypt_cbc_pkcs7
from .crypto.hkdf import hkdf_sha256

_DEF_HOST = "mmg.whatsapp.net"

# Mirrors Baileys Defaults (MIT) closely.
_MEDIA_PATH_MAP: dict[str, str] = {
    "image": "/mms/image",
    "video": "/mms/video",
    "gif": "/mms/video",
    "document": "/mms/document",
    "audio": "/mms/audio",
    "ptt": "/mms/audio",
    "sticker": "/mms/image",
    "thumbnail-link": "/mms/image",
    # History/app-state use the same MMG host but different paths.
    "md-msg-hist": "/mms/md-app-state",
    "md-app-state": "",
}

_MEDIA_HKDF_KEY_MAPPING: dict[str, str] = {
    "audio": "Audio",
    "ptt": "Audio",
    "document": "Document",
    "gif": "Video",
    "image": "Image",
    "sticker": "Image",
    "video": "Video",
    "thumbnail-document": "Document Thumbnail",
    "thumbnail-image": "Image Thumbnail",
    "thumbnail-video": "Video Thumbnail",
    "thumbnail-link": "Link Thumbnail",
    "md-msg-hist": "History",
    "md-app-state": "App State",
}


def hkdf_info_key(media_type: str) -> bytes:
    """
    HKDF info label for WhatsApp media.

    `media_type` matches Baileys' `MediaType` values (e.g. `image`, `audio`, `ptt`).
    """

    label = _MEDIA_HKDF_KEY_MAPPING.get(media_type)
    if not label:
        raise ValueError(f"unsupported media_type: {media_type!r}")
    return f"WhatsApp {label} Keys".encode()


@dataclass(frozen=True, slots=True)
class MediaKeys:
    iv: bytes
    cipher_key: bytes
    mac_key: bytes


def get_media_keys(media_key: bytes, media_type: str) -> MediaKeys:
    """
    Derive (iv, cipher_key, mac_key) from a 32-byte `mediaKey`.

    Mirrors Baileys' `getMediaKeys` which expands to 112 bytes and slices:
    - iv: 16
    - cipherKey: 32
    - macKey: 32
    """

    if not media_key:
        raise ValueError("media_key is empty")
    expanded = hkdf_sha256(ikm=media_key, length=112, salt=b"", info=hkdf_info_key(media_type))
    return MediaKeys(iv=expanded[:16], cipher_key=expanded[16:48], mac_key=expanded[48:80])


@dataclass(frozen=True, slots=True)
class EncryptedMedia:
    """
    Result of WhatsApp media encryption.

    `enc_bytes` is the uploaded/downloaded payload: AES-CBC ciphertext + 10-byte MAC.
    """

    media_key: bytes
    enc_bytes: bytes
    file_sha256: bytes
    file_enc_sha256: bytes
    file_length: int
    mac: bytes


def _b64_for_upload(raw: bytes) -> str:
    """
    WhatsApp media upload token encoding (matches Baileys).

    - base64
    - replace '+' -> '-', '/' -> '_'
    - strip '=' padding
    """

    b64 = base64.b64encode(raw).decode("ascii")
    return b64.replace("+", "-").replace("/", "_").rstrip("=")


def build_upload_url(*, hostname: str, auth: str, media_type: str, file_enc_sha256: bytes) -> str:
    path = _MEDIA_PATH_MAP.get(media_type)
    if path is None:
        raise ValueError(f"unsupported media_type for upload: {media_type!r}")

    token = _b64_for_upload(file_enc_sha256)
    # Baileys applies encodeURIComponent after base64-url conversion. The token is already URL-safe,
    # but quoting keeps us aligned and future-proof.
    token_q = urllib.parse.quote(token, safe="")
    auth_q = urllib.parse.quote(auth, safe="")
    return f"https://{hostname}{path}/{token_q}?auth={auth_q}&token={token_q}"


def encrypt_media_bytes(data: bytes, *, media_type: str) -> EncryptedMedia:
    """
    Encrypt raw media bytes for WhatsApp upload.

    Algorithm (matches Baileys):
    - mediaKey: 32 random bytes
    - derive iv/cipherKey/macKey via HKDF(mediaKey, info=hkdfInfoKey(type), len=112)
    - ciphertext := AES-256-CBC(PKCS7(data))
    - mac := HMAC-SHA256(macKey, iv || ciphertext)[:10]
    - enc_bytes := ciphertext || mac
    - fileSha256 := SHA256(data)
    - fileEncSha256 := SHA256(enc_bytes)
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    plaintext = bytes(data)
    media_key = secrets.token_bytes(32)

    keys = get_media_keys(media_key, media_type)
    ciphertext = aes_encrypt_cbc_pkcs7(plaintext, key=keys.cipher_key, iv=keys.iv)
    mac_full = hmac.new(keys.mac_key, keys.iv + ciphertext, hashlib.sha256).digest()
    mac = mac_full[:10]
    enc_bytes = ciphertext + mac

    file_sha256 = hashlib.sha256(plaintext).digest()
    file_enc_sha256 = hashlib.sha256(enc_bytes).digest()
    return EncryptedMedia(
        media_key=media_key,
        enc_bytes=enc_bytes,
        file_sha256=file_sha256,
        file_enc_sha256=file_enc_sha256,
        file_length=len(plaintext),
        mac=mac,
    )


def decrypt_media_bytes(
    enc_bytes: bytes,
    *,
    media_key: bytes,
    media_type: str,
    validate_mac: bool = False,
) -> bytes:
    """
    Decrypt WhatsApp media bytes downloaded from MMG.

    The on-wire payload is AES-CBC ciphertext with a trailing 10-byte MAC. This
    function strips the MAC if present and optionally validates it.
    """

    if not isinstance(enc_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("enc_bytes must be bytes-like")
    raw = bytes(enc_bytes)
    keys = get_media_keys(media_key, media_type)

    mac: bytes | None = None
    ciphertext = raw

    # Most media ends with 10 MAC bytes which makes the total length not a multiple of 16.
    if len(raw) >= 10 and (len(raw) % 16) != 0 and ((len(raw) - 10) % 16) == 0:
        ciphertext = raw[:-10]
        mac = raw[-10:]

    if validate_mac and mac is not None:
        exp = hmac.new(keys.mac_key, keys.iv + ciphertext, hashlib.sha256).digest()[:10]
        if not hmac.compare_digest(exp, mac):
            raise ValueError("media MAC mismatch")

    if len(ciphertext) % 16 != 0:
        raise ValueError("invalid media ciphertext length")

    return aes_decrypt_cbc_pkcs7(ciphertext, key=keys.cipher_key, iv=keys.iv)


def url_from_direct_path(direct_path: str) -> str:
    if not direct_path.startswith("/"):
        direct_path = "/" + direct_path
    return f"https://{_DEF_HOST}{direct_path}"


def _download_bytes(url: str, *, origin: str = DEFAULT_ORIGIN) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "Origin": origin,
            "User-Agent": "pyaileys/0.1",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return cast(bytes, resp.read())


async def download_bytes(url: str, *, origin: str = DEFAULT_ORIGIN) -> bytes:
    return await asyncio.to_thread(_download_bytes, url, origin=origin)


async def download_and_decrypt_media(
    *,
    direct_path: str | None = None,
    url: str | None = None,
    media_key: bytes,
    media_type: str,
    origin: str = DEFAULT_ORIGIN,
    validate_mac: bool = False,
) -> bytes:
    """
    Download and AES-CBC decrypt a WhatsApp media payload.

    This strips the trailing 10-byte MAC if present. MAC validation can be enabled
    via `validate_mac=True`.
    """

    if url is None:
        if not direct_path:
            raise ValueError("either url or direct_path is required")
        url = url_from_direct_path(direct_path)
    enc = await download_bytes(url, origin=origin)
    return decrypt_media_bytes(
        enc, media_key=media_key, media_type=media_type, validate_mac=validate_mac
    )


def inflate_zlib(data: bytes) -> bytes:
    return zlib.decompress(data)


def parse_upload_response(body: bytes) -> dict[str, object]:
    """
    Parse JSON returned by WhatsApp media upload endpoint.
    """

    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"invalid upload response json: {e}") from e
    if not isinstance(parsed, dict):
        raise ValueError("invalid upload response type")
    return parsed
