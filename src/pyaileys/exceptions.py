from __future__ import annotations


class PyaileysError(Exception):
    """Base error for the pyaileys library."""


class TransportError(PyaileysError):
    """WebSocket transport-level failure."""


class HandshakeError(PyaileysError):
    """Noise/WA handshake failure."""


class DecodeError(PyaileysError):
    """Binary node decoding failure."""


class EncodeError(PyaileysError):
    """Binary node encoding failure."""


class AuthError(PyaileysError):
    """Authentication / credential store failure."""


class SendRejectedError(PyaileysError):
    """
    The server rejected a sent message.

    WhatsApp responds with an `<ack class="message" ... error="...">` stanza.
    """

    def __init__(self, *, code: str, ack_attrs: dict[str, str] | None = None) -> None:
        super().__init__(f"message send rejected (error={code})")
        self.code = code
        self.ack_attrs = ack_attrs or {}


class MediaUploadError(PyaileysError):
    """Media upload to WhatsApp MMG failed."""


class MediaDownloadError(PyaileysError):
    """Media download/decryption failed."""
