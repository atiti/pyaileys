from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ChatInfo:
    jid: str
    name: str | None = None
    pn_jid: str | None = None
    lid_jid: str | None = None


@dataclass(slots=True)
class ContactInfo:
    """
    Best-effort contact/profile metadata.

    Notes:
    - `name` usually comes from history sync (often your saved contact name).
    - `notify` is the "push name" the contact has set for themselves and is
      commonly exposed as the stanza attribute `notify`.
    """

    jid: str
    name: str | None = None
    notify: str | None = None
    verified_name: str | None = None
    pn_jid: str | None = None
    lid_jid: str | None = None
    img_url: str | None = None
    status: str | None = None


@dataclass(slots=True)
class MessageInfo:
    id: str
    chat_jid: str
    sender_jid: str | None
    timestamp_s: int
    text: str | None = None
    raw: Any | None = None  # proto.Message or proto.WebMessageInfo


class InMemoryStore:
    """
    Minimal in-memory store for demo apps.

    This is intentionally small and lossy. It is *not* meant to be a full DB layer.
    """

    def __init__(self) -> None:
        self._chats: dict[str, ChatInfo] = {}
        self._messages: dict[str, list[MessageInfo]] = {}
        self._contacts: dict[str, ContactInfo] = {}

    def upsert_chat(self, chat: ChatInfo) -> None:
        existing = self._chats.get(chat.jid)
        if existing is None:
            self._chats[chat.jid] = chat
            return
        # Merge, preferring new non-null values.
        existing.name = chat.name or existing.name
        existing.pn_jid = chat.pn_jid or existing.pn_jid
        existing.lid_jid = chat.lid_jid or existing.lid_jid

    def add_message(self, msg: MessageInfo) -> None:
        self._messages.setdefault(msg.chat_jid, []).append(msg)

    def list_chats(self) -> list[ChatInfo]:
        return list(self._chats.values())

    def get_chat(self, jid: str) -> ChatInfo | None:
        return self._chats.get(jid)

    def upsert_contact(self, contact: ContactInfo) -> None:
        existing = self._contacts.get(contact.jid)
        if existing is None:
            self._contacts[contact.jid] = contact
            return
        # Merge, preferring new non-null values.
        existing.name = contact.name or existing.name
        existing.notify = contact.notify or existing.notify
        existing.verified_name = contact.verified_name or existing.verified_name
        existing.pn_jid = contact.pn_jid or existing.pn_jid
        existing.lid_jid = contact.lid_jid or existing.lid_jid
        existing.img_url = contact.img_url or existing.img_url
        if contact.status is not None:
            # Preserve empty-string semantics (blocked/hidden) for status.
            existing.status = contact.status

    def get_contact(self, jid: str) -> ContactInfo | None:
        return self._contacts.get(jid)

    def list_contacts(self) -> list[ContactInfo]:
        return list(self._contacts.values())

    def get_messages(self, chat_jid: str, *, limit: int = 50) -> list[MessageInfo]:
        msgs = self._messages.get(chat_jid) or []
        if limit <= 0:
            return []
        return msgs[-limit:]

    def last_message(self, chat_jid: str) -> MessageInfo | None:
        msgs = self._messages.get(chat_jid) or []
        return msgs[-1] if msgs else None

    def oldest_message(self, chat_jid: str) -> MessageInfo | None:
        msgs = self._messages.get(chat_jid) or []
        return msgs[0] if msgs else None

    def find_message(self, chat_jid: str, msg_id: str) -> MessageInfo | None:
        """
        Find a message by ID within a chat.

        This is a linear scan and intended for demos only.
        """

        if not msg_id:
            return None
        msgs = self._messages.get(chat_jid) or []
        for m in reversed(msgs):
            if m.id == msg_id:
                return m
        return None
