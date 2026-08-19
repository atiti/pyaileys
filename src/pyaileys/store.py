from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
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
    from_me: bool | None = None
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
        messages = self._messages.setdefault(msg.chat_jid, [])
        if msg.id:
            for index, existing in enumerate(messages):
                if existing.id == msg.id:
                    messages[index] = msg
                    return
        messages.append(msg)

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


class SQLiteStore(InMemoryStore):
    """
    Small durable cache for chats, contact metadata, and history anchors.

    Raw protobuf payloads and media bytes are deliberately not persisted. This
    keeps the local cache focused on listing chats and making safe, anchored
    history requests after a restart.
    """

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()
        self._load()

    def close(self) -> None:
        self._conn.close()

    def _create_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS chats (
                    jid TEXT PRIMARY KEY,
                    name TEXT,
                    pn_jid TEXT,
                    lid_jid TEXT
                );
                CREATE TABLE IF NOT EXISTS contacts (
                    jid TEXT PRIMARY KEY,
                    name TEXT,
                    notify TEXT,
                    verified_name TEXT,
                    pn_jid TEXT,
                    lid_jid TEXT,
                    img_url TEXT,
                    status TEXT
                );
                CREATE TABLE IF NOT EXISTS messages (
                    chat_jid TEXT NOT NULL,
                    id TEXT NOT NULL,
                    sender_jid TEXT,
                    timestamp_s INTEGER NOT NULL,
                    text TEXT,
                    from_me INTEGER,
                    PRIMARY KEY (chat_jid, id)
                );
                CREATE INDEX IF NOT EXISTS messages_by_chat_time
                    ON messages(chat_jid, timestamp_s, id);
                """
            )

    def _load(self) -> None:
        for jid, name, pn_jid, lid_jid in self._conn.execute(
            "SELECT jid, name, pn_jid, lid_jid FROM chats"
        ):
            super().upsert_chat(ChatInfo(jid=jid, name=name, pn_jid=pn_jid, lid_jid=lid_jid))

        for row in self._conn.execute(
            "SELECT jid, name, notify, verified_name, pn_jid, lid_jid, img_url, status FROM contacts"
        ):
            super().upsert_contact(ContactInfo(*row))

        for chat_jid, msg_id, sender_jid, timestamp_s, text, from_me in self._conn.execute(
            "SELECT chat_jid, id, sender_jid, timestamp_s, text, from_me "
            "FROM messages ORDER BY chat_jid, timestamp_s, id"
        ):
            super().add_message(
                MessageInfo(
                    id=msg_id,
                    chat_jid=chat_jid,
                    sender_jid=sender_jid,
                    timestamp_s=timestamp_s,
                    text=text,
                    from_me=None if from_me is None else bool(from_me),
                )
            )

    def upsert_chat(self, chat: ChatInfo) -> None:
        super().upsert_chat(chat)
        stored = self._chats[chat.jid]
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO chats (jid, name, pn_jid, lid_jid) VALUES (?, ?, ?, ?)
                ON CONFLICT(jid) DO UPDATE SET
                    name = COALESCE(excluded.name, chats.name),
                    pn_jid = COALESCE(excluded.pn_jid, chats.pn_jid),
                    lid_jid = COALESCE(excluded.lid_jid, chats.lid_jid)
                """,
                (stored.jid, stored.name, stored.pn_jid, stored.lid_jid),
            )

    def upsert_contact(self, contact: ContactInfo) -> None:
        super().upsert_contact(contact)
        stored = self._contacts[contact.jid]
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO contacts
                    (jid, name, notify, verified_name, pn_jid, lid_jid, img_url, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(jid) DO UPDATE SET
                    name = COALESCE(excluded.name, contacts.name),
                    notify = COALESCE(excluded.notify, contacts.notify),
                    verified_name = COALESCE(excluded.verified_name, contacts.verified_name),
                    pn_jid = COALESCE(excluded.pn_jid, contacts.pn_jid),
                    lid_jid = COALESCE(excluded.lid_jid, contacts.lid_jid),
                    img_url = COALESCE(excluded.img_url, contacts.img_url),
                    status = excluded.status
                """,
                (
                    stored.jid,
                    stored.name,
                    stored.notify,
                    stored.verified_name,
                    stored.pn_jid,
                    stored.lid_jid,
                    stored.img_url,
                    stored.status,
                ),
            )

    def add_message(self, msg: MessageInfo) -> None:
        super().add_message(msg)
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO messages (chat_jid, id, sender_jid, timestamp_s, text, from_me)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(chat_jid, id) DO UPDATE SET
                    sender_jid = COALESCE(excluded.sender_jid, messages.sender_jid),
                    timestamp_s = excluded.timestamp_s,
                    text = COALESCE(excluded.text, messages.text),
                    from_me = COALESCE(excluded.from_me, messages.from_me)
                """,
                (
                    msg.chat_jid,
                    msg.id,
                    msg.sender_jid,
                    msg.timestamp_s,
                    msg.text,
                    None if msg.from_me is None else int(msg.from_me),
                ),
            )
