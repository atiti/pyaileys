"""
pyaileys: an asyncio-first WhatsApp Web (Multi-Device) protocol client.

This project is inspired by the Baileys TypeScript library and aims to provide
an idiomatic, typed Python API on top of the WhatsApp Web WebSocket protocol.
"""

from __future__ import annotations

from .client import WhatsAppClient
from .exceptions import PyaileysError

__all__ = [
    "PyaileysError",
    "WhatsAppClient",
]

__version__ = "0.1.4"
