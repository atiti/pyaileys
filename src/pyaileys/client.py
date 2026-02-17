from __future__ import annotations

import asyncio
import contextlib
import mimetypes
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from .auth.state import AuthenticationState
from .auth.store import MultiFileAuthState
from .constants import DEFAULT_ORIGIN
from .exceptions import MediaDownloadError, MediaUploadError, SendRejectedError
from .media import (
    EncryptedMedia,
    build_upload_url,
    download_and_decrypt_media,
    encrypt_media_bytes,
    inflate_zlib,
    parse_upload_response,
    url_from_direct_path,
)
from .messages import (
    decode_wa_message_bytes,
    encode_wa_message_bytes,
    extract_message_text,
    generate_participant_hash_v2,
)
from .signal import SignalRepository
from .socket import WASocket
from .socket_config import SocketConfig
from .store import ChatInfo, ContactInfo, InMemoryStore, MessageInfo
from .util.asyncio import ensure_task
from .util.events import Listener
from .wabinary import S_WHATSAPP_NET
from .wabinary.jid import jid_decode, jid_encode, jid_normalized_user
from .wabinary.types import BinaryNode

if TYPE_CHECKING:
    from .signal.repository import PreKeyBundle


@dataclass(slots=True)
class ClientConfig:
    socket: SocketConfig = field(default_factory=SocketConfig)


@dataclass(frozen=True, slots=True)
class MediaUpload:
    media_url: str
    direct_path: str


ChatState = Literal["composing", "paused", "recording"]


class WhatsAppClient:
    """
    High-level async client facade.

    The intention is to keep a stable user-facing API here while the lower-level
    socket/protocol implementation evolves.
    """

    def __init__(self, *, auth: AuthenticationState, config: ClientConfig | None = None) -> None:
        self.config = config or ClientConfig()
        self.socket = WASocket(config=self.config.socket, auth=auth)
        self.signal = SignalRepository(auth)
        self.store = InMemoryStore()
        # Best-effort alternate-JID mapping (PN <-> LID) for decrypt/send fallbacks.
        # Keys/values are normalized user JIDs (no device).
        self._jid_alt: dict[str, str] = {}
        self._seed_jid_alternates_from_creds()

        # Install E2E + history-sync processing on top of stanza stream.
        self.socket.events.on("stanza.message", self._on_message_stanza)

    @classmethod
    async def from_auth_folder(
        cls, folder: str, *, socket: SocketConfig | None = None
    ) -> tuple[WhatsAppClient, MultiFileAuthState]:
        """
        Convenience constructor using a Baileys-like multi-file auth folder.

        Returns `(client, auth_state)` so callers can `await auth_state.save_creds()` on updates.
        """

        auth_state = await MultiFileAuthState.load(folder)
        auth = AuthenticationState(creds=auth_state.creds, keys=auth_state.keys)
        config = ClientConfig(socket=socket or SocketConfig())
        return cls(auth=auth, config=config), auth_state

    async def connect(self) -> None:
        await self.socket.connect()

    async def disconnect(self) -> None:
        await self.socket.close()

    def on(self, event: str, listener: Listener) -> None:
        self.socket.events.on(event, listener)

    def _seed_jid_alternates_from_creds(self) -> None:
        me = self.socket.auth.creds.me
        if not me or not me.id or not me.lid:
            return

        pn = jid_normalized_user(me.id)
        lid = jid_normalized_user(me.lid)
        if pn and lid and pn != lid:
            self._remember_jid_mapping(pn, lid)

    def _remember_jid_mapping(self, a: str, b: str) -> None:
        a_norm = jid_normalized_user(a) or a
        b_norm = jid_normalized_user(b) or b
        if not a_norm or not b_norm or a_norm == b_norm:
            return
        self._jid_alt[a_norm] = b_norm
        self._jid_alt[b_norm] = a_norm

    def _alt_jid_preserve_device(self, jid: str) -> str | None:
        dec = jid_decode(jid)
        if not dec or not dec.user or not dec.server:
            return None
        base = jid_normalized_user(jid) or jid_encode(dec.user, dec.server)
        alt_base = self._jid_alt.get(base)
        if not alt_base:
            return None
        alt_dec = jid_decode(alt_base)
        if not alt_dec or not alt_dec.user or not alt_dec.server:
            return None
        return jid_encode(alt_dec.user, alt_dec.server, dec.device)

    def _is_user_like_jid(self, jid: str | None) -> bool:
        """
        True for 1:1 user JIDs (PN/LID), false for group/newsletter/etc.
        """

        norm = jid_normalized_user(jid)
        if not norm:
            return False
        dec = jid_decode(norm)
        if not dec or not dec.server:
            return False
        return dec.server in ("s.whatsapp.net", "lid", "hosted", "hosted.lid")

    def _upsert_contact_info(
        self,
        jid: str,
        *,
        name: str | None = None,
        notify: str | None = None,
        pn_jid: str | None = None,
        lid_jid: str | None = None,
        img_url: str | None = None,
        status: str | None = None,
    ) -> None:
        if not jid:
            return
        base = jid_normalized_user(jid) or jid
        self.store.upsert_contact(
            ContactInfo(
                jid=base,
                name=name or None,
                notify=notify or None,
                pn_jid=pn_jid or None,
                lid_jid=lid_jid or None,
                img_url=img_url or None,
                status=status if status is not None else None,
            )
        )
        alt = self._jid_alt.get(base)
        if alt:
            self.store.upsert_contact(
                ContactInfo(
                    jid=alt,
                    name=name or None,
                    notify=notify or None,
                    pn_jid=pn_jid or None,
                    lid_jid=lid_jid or None,
                    img_url=img_url or None,
                    status=status if status is not None else None,
                )
            )

    def get_contact(self, jid: str) -> ContactInfo | None:
        """
        Return best-effort contact metadata for a user JID, if known locally.

        This is populated from:
        - history sync conversation entries (displayName/name/username)
        - incoming message stanzas (`notify` push names)
        - explicit profile fetches (e.g. profile picture URL)
        """

        base = jid_normalized_user(jid) or jid
        c = self.store.get_contact(base)
        if c:
            return c
        alt = self._jid_alt.get(base)
        if alt:
            return self.store.get_contact(alt)
        return None

    def get_display_name(self, jid: str) -> str | None:
        """
        Best-effort display name resolution for a JID.

        For 1:1 JIDs, prefers history-sync names (often your saved contact name),
        then the contact's push name (stanza `notify`).
        For groups, returns the chat name if available.
        """

        base = jid_normalized_user(jid) or jid

        if not self._is_user_like_jid(base):
            chat = self.store.get_chat(base)
            return chat.name if chat and chat.name else None

        contact = self.get_contact(base)
        if contact:
            return contact.name or contact.notify or contact.verified_name

        chat = self.store.get_chat(base)
        return chat.name if chat and chat.name else None

    async def profile_picture_url(
        self,
        jid: str,
        *,
        picture_type: Literal["preview", "image"] = "preview",
        timeout_s: float = 20.0,
        update_store: bool = True,
    ) -> str | None:
        """
        Fetch the profile picture URL for a user/group (if set).

        Mirrors Baileys' `profilePictureUrl(jid, type)`.
        """

        target = jid_normalized_user(jid) or jid
        if not target:
            raise ValueError("jid is required")

        base_content: list[BinaryNode] = [
            BinaryNode(tag="picture", attrs={"type": picture_type, "query": "url"})
        ]

        async def _lookup_tc_token(j: str) -> bytes | None:
            try:
                res = await self.socket.auth.keys.get("tctoken", [j])
            except Exception:
                return None
            raw = res.get(j)
            if isinstance(raw, (bytes, bytearray, memoryview)):
                return bytes(raw)
            if isinstance(raw, dict):
                tok = raw.get("token")
                if isinstance(tok, (bytes, bytearray, memoryview)):
                    return bytes(tok)
            return None

        tc_token = await _lookup_tc_token(target)
        if tc_token is None:
            alt = self._jid_alt.get(target)
            if alt:
                tc_token = await _lookup_tc_token(alt)
        if tc_token is not None:
            base_content.append(BinaryNode(tag="tctoken", attrs={}, content=tc_token))

        res = await self.socket.query(
            BinaryNode(
                tag="iq",
                attrs={"target": target, "to": S_WHATSAPP_NET, "type": "get", "xmlns": "w:profile:picture"},
                content=base_content,
            ),
            timeout_s=timeout_s,
        )

        pic_node: BinaryNode | None = None
        if isinstance(res.content, list):
            for c in res.content:
                if isinstance(c, BinaryNode) and c.tag == "picture":
                    pic_node = c
                    break
        url = pic_node.attrs.get("url") if pic_node else None

        if update_store and url and self._is_user_like_jid(target):
            self._upsert_contact_info(target, img_url=url)

        return url

    async def fetch_status(
        self,
        *jids: str,
        timeout_s: float = 20.0,
        update_store: bool = True,
    ) -> dict[str, str | None]:
        """
        Fetch profile "about" (status) strings for one or more user JIDs.

        This uses a USync query with the `status` protocol (Baileys' `fetchStatus`).
        Returns a mapping `{jid: status}` where status can be:
        - `None` when unavailable
        - `""` when blocked/hidden (server returns code=401)
        - a non-empty string for the actual "about"
        """

        uniq = [jid_normalized_user(j) or j for j in jids if j]
        uniq = list(dict.fromkeys([j for j in uniq if j and self._is_user_like_jid(j)]))
        if not uniq:
            return {}

        sid = f"status-{int(time.time() * 1000)}"
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "usync"},
            content=[
                BinaryNode(
                    tag="usync",
                    attrs={"context": "interactive", "mode": "query", "sid": sid, "last": "true", "index": "0"},
                    content=[
                        BinaryNode(tag="query", attrs={}, content=[BinaryNode(tag="status", attrs={})]),
                        BinaryNode(
                            tag="list",
                            attrs={},
                            content=[BinaryNode(tag="user", attrs={"jid": j}, content=[]) for j in uniq],
                        ),
                    ],
                )
            ],
        )

        res = await self.socket.query(iq, timeout_s=timeout_s)
        if res.attrs.get("type") != "result" or not isinstance(res.content, list):
            return {}

        # Parse `usync/list/user/status`.
        out: dict[str, str | None] = {}
        usync: BinaryNode | None = None
        for c in res.content:
            if isinstance(c, BinaryNode) and c.tag == "usync":
                usync = c
                break
        if not usync or not isinstance(usync.content, list):
            return {}

        list_node: BinaryNode | None = None
        for c in usync.content:
            if isinstance(c, BinaryNode) and c.tag == "list":
                list_node = c
                break
        if not list_node or not isinstance(list_node.content, list):
            return {}

        for user_node in list_node.content:
            if not isinstance(user_node, BinaryNode) or user_node.tag != "user":
                continue
            jid_ = user_node.attrs.get("jid") or ""
            if not jid_:
                continue
            status_node: BinaryNode | None = None
            if isinstance(user_node.content, list):
                for c in user_node.content:
                    if isinstance(c, BinaryNode) and c.tag == "status":
                        status_node = c
                        break
            if not status_node:
                continue

            raw = status_node.content
            status_text = (
                bytes(raw).decode("utf-8", errors="replace")
                if isinstance(raw, (bytes, bytearray, memoryview))
                else (str(raw) if raw is not None else "")
            )

            if not status_text:
                # `code=401` => blocked/hidden
                code = status_node.attrs.get("code")
                if code and str(code) == "401":
                    status: str | None = ""
                else:
                    status = None
            else:
                status = status_text

            out[jid_] = status
            if update_store:
                self._upsert_contact_info(jid_, status=status)

        return out

    async def send_text(
        self,
        jid: str,
        text: str,
        *,
        fanout: bool = True,
        include_phash: bool = False,
        wait_ack: bool = False,
        timeout_s: float = 15.0,
    ) -> str:
        """
        Send a text message.

        This encrypts via Signal (MD) and fans out to:
        - the destination JID
        - your primary phone JID (so the phone stays in sync)
        """

        # Import lazily; the generated WAProto module is large.
        from .proto import WAProto_pb2 as proto

        base_msg = proto.Message()
        base_msg.conversation = text
        # WhatsApp Web expects most messages to include a message secret. Baileys
        # sets this for nearly all non-reaction messages.
        base_msg.messageContextInfo.messageSecret = secrets.token_bytes(32)
        return await self._send_message(
            jid,
            base_msg,
            stanza_type="text",
            enc_extra_attrs=None,
            fanout=fanout,
            include_phash=include_phash,
            wait_ack=wait_ack,
            timeout_s=timeout_s,
        )

    async def send_location(
        self,
        jid: str,
        *,
        latitude: float,
        longitude: float,
        name: str | None = None,
        address: str | None = None,
        comment: str | None = None,
        fanout: bool = True,
        include_phash: bool = False,
        wait_ack: bool = False,
        timeout_s: float = 15.0,
    ) -> str:
        """
        Send a static location.
        """

        from .proto import WAProto_pb2 as proto

        msg = proto.Message()
        msg.locationMessage.degreesLatitude = float(latitude)
        msg.locationMessage.degreesLongitude = float(longitude)
        if name:
            msg.locationMessage.name = name
        if address:
            msg.locationMessage.address = address
        if comment:
            msg.locationMessage.comment = comment
        msg.messageContextInfo.messageSecret = secrets.token_bytes(32)

        return await self._send_message(
            jid,
            msg,
            stanza_type="media",
            enc_extra_attrs={"mediatype": "location"},
            fanout=fanout,
            include_phash=include_phash,
            wait_ack=wait_ack,
            timeout_s=timeout_s,
        )

    async def send_image(
        self,
        jid: str,
        data: bytes,
        *,
        mimetype: str = "image/jpeg",
        caption: str | None = None,
        fanout: bool = True,
        include_phash: bool = False,
        wait_ack: bool = False,
        timeout_s: float = 15.0,
        upload_timeout_s: float = 30.0,
    ) -> str:
        """
        Upload and send an image message.
        """

        from .proto import WAProto_pb2 as proto

        enc = encrypt_media_bytes(data, media_type="image")
        up = await self._upload_encrypted_media(
            media_type="image", enc=enc, timeout_s=upload_timeout_s
        )

        msg = proto.Message()
        im = msg.imageMessage
        im.url = up.media_url
        im.directPath = up.direct_path
        im.mediaKey = enc.media_key
        im.fileSha256 = enc.file_sha256
        im.fileEncSha256 = enc.file_enc_sha256
        im.fileLength = int(enc.file_length)
        im.mimetype = mimetype
        im.mediaKeyTimestamp = int(time.time())
        if caption:
            im.caption = caption

        msg.messageContextInfo.messageSecret = secrets.token_bytes(32)

        return await self._send_message(
            jid,
            msg,
            stanza_type="media",
            enc_extra_attrs={"mediatype": "image"},
            fanout=fanout,
            include_phash=include_phash,
            wait_ack=wait_ack,
            timeout_s=timeout_s,
        )

    async def send_voice_note(
        self,
        jid: str,
        data: bytes,
        *,
        mimetype: str = "audio/ogg; codecs=opus",
        seconds: int | None = None,
        fanout: bool = True,
        include_phash: bool = False,
        wait_ack: bool = False,
        timeout_s: float = 15.0,
        upload_timeout_s: float = 30.0,
    ) -> str:
        """
        Upload and send a PTT (voice note).
        """

        from .proto import WAProto_pb2 as proto

        enc = encrypt_media_bytes(data, media_type="ptt")
        up = await self._upload_encrypted_media(
            media_type="ptt", enc=enc, timeout_s=upload_timeout_s
        )

        msg = proto.Message()
        am = msg.audioMessage
        am.url = up.media_url
        am.directPath = up.direct_path
        am.mediaKey = enc.media_key
        am.fileSha256 = enc.file_sha256
        am.fileEncSha256 = enc.file_enc_sha256
        am.fileLength = int(enc.file_length)
        am.mimetype = mimetype
        am.ptt = True
        am.mediaKeyTimestamp = int(time.time())
        if seconds is not None:
            am.seconds = int(seconds)

        msg.messageContextInfo.messageSecret = secrets.token_bytes(32)

        return await self._send_message(
            jid,
            msg,
            stanza_type="media",
            enc_extra_attrs={"mediatype": "ptt"},
            fanout=fanout,
            include_phash=include_phash,
            wait_ack=wait_ack,
            timeout_s=timeout_s,
        )

    async def send_image_file(
        self,
        jid: str,
        path: str | Path,
        *,
        caption: str | None = None,
        mimetype: str | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Convenience wrapper around `send_image` that reads a local file.
        """

        p = Path(path).expanduser()
        data = await asyncio.to_thread(p.read_bytes)
        mt = mimetype or (mimetypes.guess_type(str(p))[0] or "image/jpeg")
        return await self.send_image(jid, data, mimetype=mt, caption=caption, **kwargs)

    async def send_voice_note_file(
        self,
        jid: str,
        path: str | Path,
        *,
        mimetype: str | None = None,
        seconds: int | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Convenience wrapper around `send_voice_note` that reads a local file.
        """

        p = Path(path).expanduser()
        data = await asyncio.to_thread(p.read_bytes)
        mt = mimetype
        if mt is None:
            guessed = mimetypes.guess_type(str(p))[0]
            mt = "audio/ogg; codecs=opus" if guessed is None or guessed == "audio/ogg" else guessed
        return await self.send_voice_note(jid, data, mimetype=mt, seconds=seconds, **kwargs)

    async def send_document(
        self,
        jid: str,
        data: bytes,
        *,
        mimetype: str = "application/octet-stream",
        filename: str | None = None,
        title: str | None = None,
        caption: str | None = None,
        page_count: int | None = None,
        fanout: bool = True,
        include_phash: bool = False,
        wait_ack: bool = False,
        timeout_s: float = 15.0,
        upload_timeout_s: float = 30.0,
    ) -> str:
        """
        Upload and send a document message.
        """

        from .proto import WAProto_pb2 as proto

        enc = encrypt_media_bytes(data, media_type="document")
        up = await self._upload_encrypted_media(
            media_type="document", enc=enc, timeout_s=upload_timeout_s
        )

        msg = proto.Message()
        dm = msg.documentMessage
        dm.url = up.media_url
        dm.directPath = up.direct_path
        dm.mediaKey = enc.media_key
        dm.fileSha256 = enc.file_sha256
        dm.fileEncSha256 = enc.file_enc_sha256
        dm.fileLength = int(enc.file_length)
        dm.mimetype = mimetype
        dm.mediaKeyTimestamp = int(time.time())
        dm.fileName = filename or "file"
        if title:
            dm.title = title
        if caption:
            dm.caption = caption
        if page_count is not None:
            dm.pageCount = int(page_count)

        msg.messageContextInfo.messageSecret = secrets.token_bytes(32)

        return await self._send_message(
            jid,
            msg,
            stanza_type="media",
            enc_extra_attrs={"mediatype": "document"},
            fanout=fanout,
            include_phash=include_phash,
            wait_ack=wait_ack,
            timeout_s=timeout_s,
        )

    async def send_document_file(
        self,
        jid: str,
        path: str | Path,
        *,
        caption: str | None = None,
        mimetype: str | None = None,
        filename: str | None = None,
        title: str | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Convenience wrapper around `send_document` that reads a local file.
        """

        p = Path(path).expanduser()
        data = await asyncio.to_thread(p.read_bytes)
        mt = mimetype or (mimetypes.guess_type(str(p))[0] or "application/octet-stream")
        fn = filename or p.name
        return await self.send_document(
            jid,
            data,
            mimetype=mt,
            filename=fn,
            title=title,
            caption=caption,
            **kwargs,
        )

    async def send_contact(
        self,
        jid: str,
        *,
        display_name: str,
        vcard: str,
        fanout: bool = True,
        include_phash: bool = False,
        wait_ack: bool = False,
        timeout_s: float = 15.0,
    ) -> str:
        """
        Send a single vCard contact.

        `vcard` should be a VCF/vCard string (e.g. "BEGIN:VCARD...END:VCARD").
        """

        from .proto import WAProto_pb2 as proto

        if not display_name:
            raise ValueError("display_name is required")
        if not vcard:
            raise ValueError("vcard is required")

        msg = proto.Message()
        msg.contactMessage.displayName = display_name
        msg.contactMessage.vcard = vcard
        msg.messageContextInfo.messageSecret = secrets.token_bytes(32)

        return await self._send_message(
            jid,
            msg,
            stanza_type="media",
            enc_extra_attrs={"mediatype": "vcard"},
            fanout=fanout,
            include_phash=include_phash,
            wait_ack=wait_ack,
            timeout_s=timeout_s,
        )

    async def send_contacts(
        self,
        jid: str,
        contacts: list[tuple[str, str]],
        *,
        display_name: str | None = None,
        fanout: bool = True,
        include_phash: bool = False,
        wait_ack: bool = False,
        timeout_s: float = 15.0,
    ) -> str:
        """
        Send multiple vCard contacts in a single message.

        `contacts` is a list of `(display_name, vcard_string)` tuples.
        """

        from .proto import WAProto_pb2 as proto

        if not contacts:
            raise ValueError("contacts is empty")

        msg = proto.Message()
        cam = msg.contactsArrayMessage
        if display_name:
            cam.displayName = display_name
        for dn, vcf in contacts:
            c = cam.contacts.add()
            c.displayName = dn
            c.vcard = vcf
        msg.messageContextInfo.messageSecret = secrets.token_bytes(32)

        return await self._send_message(
            jid,
            msg,
            stanza_type="media",
            enc_extra_attrs={"mediatype": "contact_array"},
            fanout=fanout,
            include_phash=include_phash,
            wait_ack=wait_ack,
            timeout_s=timeout_s,
        )

    async def download_message_media(self, msg: Any, *, validate: bool = True) -> bytes:
        """
        Download & decrypt media bytes for an (already decrypted) proto message.

        Supports: imageMessage, audioMessage, documentMessage.
        """

        # Import lazily; big.
        from .proto import WAProto_pb2 as proto

        inner = msg
        if isinstance(msg, proto.WebMessageInfo) and msg.HasField("message"):
            inner = msg.message

        media_type: str | None = None
        url: str | None = None
        direct_path: str | None = None
        media_key: bytes | None = None
        exp_file_sha256: bytes | None = None

        if hasattr(inner, "HasField") and inner.HasField("imageMessage"):
            m = inner.imageMessage
            media_type = "image"
            url = str(m.url) if m.url else None
            direct_path = str(m.directPath) if m.directPath else None
            media_key = bytes(m.mediaKey) if m.mediaKey else None
            exp_file_sha256 = bytes(m.fileSha256) if m.fileSha256 else None
        elif hasattr(inner, "HasField") and inner.HasField("audioMessage"):
            m = inner.audioMessage
            media_type = "ptt" if bool(m.ptt) else "audio"
            url = str(m.url) if m.url else None
            direct_path = str(m.directPath) if m.directPath else None
            media_key = bytes(m.mediaKey) if m.mediaKey else None
            exp_file_sha256 = bytes(m.fileSha256) if m.fileSha256 else None
        elif hasattr(inner, "HasField") and inner.HasField("documentMessage"):
            m = inner.documentMessage
            media_type = "document"
            url = str(m.url) if m.url else None
            direct_path = str(m.directPath) if m.directPath else None
            media_key = bytes(m.mediaKey) if m.mediaKey else None
            exp_file_sha256 = bytes(m.fileSha256) if m.fileSha256 else None

        if not media_type or not media_key or (not direct_path and not url):
            raise MediaDownloadError("message has no downloadable media")

        try:
            data = await download_and_decrypt_media(
                direct_path=direct_path,
                url=url,
                media_key=media_key,
                media_type=media_type,
                validate_mac=validate,
            )
        except Exception as e:
            raise MediaDownloadError(str(e)) from e

        if validate and exp_file_sha256:
            import hashlib

            got = hashlib.sha256(data).digest()
            if got != exp_file_sha256:
                raise MediaDownloadError("media plaintext sha256 mismatch")

        return data

    async def _send_message(
        self,
        jid: str,
        msg: Any,
        *,
        stanza_type: str,
        enc_extra_attrs: dict[str, str] | None,
        fanout: bool,
        include_phash: bool,
        wait_ack: bool,
        timeout_s: float,
    ) -> str:
        # Keep alternates fresh if creds were updated after init.
        self._seed_jid_alternates_from_creds()

        dest_primary = jid_normalized_user(jid) or jid
        dest_alt = self._alt_jid_preserve_device(dest_primary)
        dest_candidates = [dest_primary]
        if dest_alt and dest_alt not in dest_candidates:
            dest_candidates.append(dest_alt)

        last_reject: SendRejectedError | None = None
        for dest_jid in dest_candidates:
            try:
                msg_id = await self._send_message_once(
                    dest_jid,
                    msg,
                    stanza_type=stanza_type,
                    enc_extra_attrs=enc_extra_attrs,
                    fanout=fanout,
                    include_phash=include_phash,
                    wait_ack=wait_ack,
                    timeout_s=timeout_s,
                )
                return msg_id
            except SendRejectedError as e:
                last_reject = e
                # Some servers reject LID-only addressing without a usable mapping; retry with alternate if known.
                if e.code == "479" and dest_alt and dest_jid != dest_alt:
                    continue
                raise

        assert last_reject is not None
        raise last_reject

    async def _send_message_once(
        self,
        dest_jid: str,
        msg: Any,
        *,
        stanza_type: str,
        enc_extra_attrs: dict[str, str] | None,
        fanout: bool,
        include_phash: bool,
        wait_ack: bool,
        timeout_s: float,
    ) -> str:
        """
        Internal send helper. `dest_jid` must be a normalized user JID.
        """

        from .proto import WAProto_pb2 as proto

        me = self.socket.auth.creds.me
        if not me:
            raise RuntimeError("not authenticated")

        dest_dec = jid_decode(dest_jid)
        if not dest_dec or not dest_dec.user or not dest_dec.server:
            raise ValueError(f"invalid destination jid: {dest_jid!r}")

        dest_server = "s.whatsapp.net" if dest_dec.server == "c.us" else dest_dec.server
        if dest_server == "g.us":
            raise NotImplementedError(
                "group send is not implemented yet (missing sender keys/skmsg)"
            )

        me_pn = jid_decode(me.id)
        if not me_pn or not me_pn.user:
            raise RuntimeError("invalid `me.id` in auth creds")

        me_lid = jid_decode(me.lid) if me.lid else None

        # Addressing consistency: match our sender identity to the conversation context.
        sender_identity = (
            jid_encode(me_lid.user, "lid")
            if dest_server == "lid" and me_lid and me_lid.user
            else jid_encode(me_pn.user, "s.whatsapp.net")
        )

        # Enumerate all recipient devices (our devices + target devices) via USync.
        device_jids = await self.socket.get_usync_devices(
            [sender_identity, dest_jid], context="message"
        )
        if not device_jids:
            # Best-effort fallback: send to device 0 of the destination and our phone JID.
            device_jids = [dest_jid]
            if dest_jid != sender_identity:
                device_jids.append(sender_identity)

        # Split recipients into "own devices" (DSM) vs "other devices" (raw message).
        me_pn_user = me_pn.user
        me_lid_user = me_lid.user if me_lid and me_lid.user else None
        me_recipients: list[str] = []
        other_recipients: list[str] = []
        for r in device_jids:
            r_dec = jid_decode(r)
            if not r_dec or not r_dec.user:
                continue

            # Exclude exact sender device, even if the server reports it under a hosted domain.
            if (
                r_dec.device is not None
                and int(r_dec.device) == int(me_pn.device or 0)
                and (
                    r_dec.user == me_pn_user
                    or (me_lid_user is not None and r_dec.user == me_lid_user)
                )
            ):
                continue

            is_me = r_dec.user == me_pn_user or (
                me_lid_user is not None and r_dec.user == me_lid_user
            )
            if is_me:
                me_recipients.append(r)
            else:
                other_recipients.append(r)

        if not fanout:
            # Debug/compat mode: only send to device 0 recipients.
            def _is_device0(j: str) -> bool:
                d = jid_decode(j)
                return bool(d and d.device is None)

            me_recipients = [r for r in me_recipients if _is_device0(r)]
            other_recipients = [r for r in other_recipients if _is_device0(r)]

        all_recipients = list(dict.fromkeys(me_recipients + other_recipients))
        if not all_recipients:
            raise RuntimeError("no recipients resolved for message send")

        await self._assert_sessions(all_recipients)

        # Encode WhatsApp proto.Message and apply WA random padding.
        msg_bytes = encode_wa_message_bytes(msg.SerializeToString())

        dsm = proto.Message()
        dsm.deviceSentMessage.destinationJid = dest_jid
        dsm.deviceSentMessage.message.CopyFrom(msg)
        # DSM wrapper should carry the same context info (incl. message secret).
        dsm.messageContextInfo.CopyFrom(msg.messageContextInfo)
        dsm_bytes = encode_wa_message_bytes(dsm.SerializeToString())

        to_nodes: list[BinaryNode] = []
        include_device_identity = False

        phash = (
            generate_participant_hash_v2(all_recipients)
            if (include_phash and all_recipients)
            else None
        )

        # Own devices get DSM, other devices get the raw message.
        for r in all_recipients:
            payload = dsm_bytes if r in me_recipients else msg_bytes
            enc_type, enc_bytes = await self.signal.encrypt_message(r, data=payload)
            if enc_type == "pkmsg":
                include_device_identity = True
            enc_attrs: dict[str, str] = {"v": "2", "type": enc_type}
            if enc_extra_attrs:
                enc_attrs.update(enc_extra_attrs)
            if phash:
                enc_attrs["phash"] = phash
            to_nodes.append(
                BinaryNode(
                    tag="to",
                    attrs={"jid": r},
                    content=[
                        BinaryNode(tag="enc", attrs=enc_attrs, content=enc_bytes),
                    ],
                )
            )

        stanza_content: list[BinaryNode] = [
            BinaryNode(tag="participants", attrs={}, content=to_nodes),
        ]

        if include_device_identity and isinstance(
            self.socket.auth.creds.account, (bytes, bytearray, memoryview)
        ):
            stanza_content.append(
                BinaryNode(
                    tag="device-identity", attrs={}, content=bytes(self.socket.auth.creds.account)
                )
            )

        async def _lookup_tc_token(j: str) -> bytes | None:
            try:
                res = await self.socket.auth.keys.get("tctoken", [j])
            except Exception:
                return None
            raw = res.get(j)
            if isinstance(raw, (bytes, bytearray, memoryview)):
                return bytes(raw)
            if isinstance(raw, dict):
                tok = raw.get("token")
                if isinstance(tok, (bytes, bytearray, memoryview)):
                    return bytes(tok)
            return None

        # Attach trusted-contact token if available (anti-abuse).
        tc_token = await _lookup_tc_token(dest_jid)
        if tc_token is None:
            alt = self._alt_jid_preserve_device(dest_jid)
            if alt:
                tc_token = await _lookup_tc_token(alt)
        if tc_token is not None:
            stanza_content.append(BinaryNode(tag="tctoken", attrs={}, content=tc_token))

        msg_id = self.signal.new_message_id()
        fut = None
        tag_event = f"tag:{msg_id}"
        if wait_ack:
            fut = self.socket.events.wait_for_future(tag_event)

        await self.socket.send_node(
            BinaryNode(
                tag="message",
                attrs={"id": msg_id, "to": dest_jid, "type": stanza_type},
                content=stanza_content,
            )
        )

        if fut is not None:
            try:
                ack = await asyncio.wait_for(fut, timeout=timeout_s)
            finally:
                self.socket.events._remove_waiter_future(tag_event, fut)
            if (
                isinstance(ack, BinaryNode)
                and ack.tag == "ack"
                and ack.attrs.get("class") == "message"
            ):
                err = ack.attrs.get("error")
                if err:
                    raise SendRejectedError(code=str(err), ack_attrs=dict(ack.attrs))

        # Best-effort local echo for demos.
        now_s = int(time.time())
        text = extract_message_text(msg)
        self.store.upsert_chat(ChatInfo(jid=dest_jid))
        self.store.add_message(
            MessageInfo(
                id=msg_id,
                chat_jid=dest_jid,
                sender_jid=jid_normalized_user(me.id) or me.id,
                timestamp_s=now_s,
                text=text,
                raw=msg,
            )
        )
        return msg_id

    def _upload_media_post_bytes(
        self, url: str, data: bytes, *, timeout_s: float, origin: str = DEFAULT_ORIGIN
    ) -> bytes:
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Origin": origin,
                "User-Agent": "pyaileys/0.1",
                "Content-Type": "application/octet-stream",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                return cast(bytes, resp.read())
        except urllib.error.HTTPError as e:
            body = b""
            with contextlib.suppress(Exception):
                body = e.read()
            raise MediaUploadError(f"upload http error {e.code}: {body[:200]!r}") from e
        except Exception as e:
            raise MediaUploadError(f"upload failed: {e}") from e

    async def _upload_encrypted_media(
        self,
        *,
        media_type: str,
        enc: EncryptedMedia,
        timeout_s: float = 30.0,
    ) -> MediaUpload:
        """
        Upload encrypted media to MMG using `media_conn` auth + host list.
        """

        last_err: Exception | None = None
        info = await self.socket.refresh_media_conn(force=False)

        # Some accounts return an empty host list; fall back to mmg.whatsapp.net.
        hosts = info.hosts or []
        if not hosts:
            from .socket import MediaHost

            hosts = [MediaHost(hostname="mmg.whatsapp.net")]

        for _attempt in range(2):
            for host in hosts:
                if (
                    host.max_content_length_bytes is not None
                    and len(enc.enc_bytes) > host.max_content_length_bytes
                ):
                    continue
                url = build_upload_url(
                    hostname=host.hostname,
                    auth=info.auth,
                    media_type=media_type,
                    file_enc_sha256=enc.file_enc_sha256,
                )
                try:
                    body = await asyncio.to_thread(
                        self._upload_media_post_bytes,
                        url,
                        enc.enc_bytes,
                        timeout_s=timeout_s,
                    )
                    parsed = parse_upload_response(body)
                    url_val = parsed.get("url")
                    dp_val = parsed.get("direct_path")
                    media_url = str(url_val) if isinstance(url_val, str) and url_val else None
                    direct_path = str(dp_val) if isinstance(dp_val, str) and dp_val else None
                    if direct_path and not media_url:
                        media_url = url_from_direct_path(direct_path)
                    if media_url and direct_path:
                        return MediaUpload(media_url=media_url, direct_path=direct_path)
                    raise MediaUploadError(f"upload response missing url/direct_path: {parsed!r}")
                except Exception as e:
                    last_err = e
                    continue

            # Retry with refreshed media_conn once.
            info = await self.socket.refresh_media_conn(force=True)
            hosts = info.hosts or hosts

        raise MediaUploadError(str(last_err) if last_err else "media upload failed")

    async def request_full_history_sync(self) -> str:
        """
        Ask the phone for a full history sync (peer data operation request).

        The phone should respond with one or more HistorySyncNotifications that
        the client will download & ingest into `self.store`.
        """

        # Import lazily; the generated WAProto module is large.
        from .proto import WAProto_pb2 as proto

        me = self.socket.auth.creds.me
        if not me:
            raise RuntimeError("not authenticated")

        request_id = self.signal.new_message_id()

        pdo = proto.Message.PeerDataOperationRequestMessage()
        pdo.peerDataOperationRequestType = (
            proto.Message.PeerDataOperationRequestType.FULL_HISTORY_SYNC_ON_DEMAND
        )
        pdo.fullHistorySyncOnDemandRequest.requestMetadata.requestId = request_id
        # Advertise companion capabilities (mirrors Baileys defaults).
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.storageQuotaMb = 10240
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.inlineInitialPayloadInE2EeMsg = True
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportCallLogHistory = False
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportBotUserAgentChatHistory = True
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportCagReactionsAndPolls = True
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportBizHostedMsg = True
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportRecentSyncChunkMessageCountTuning = True
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportHostedGroupMsg = True
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportFbidBotChatHistory = True
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportMessageAssociation = True
        pdo.fullHistorySyncOnDemandRequest.historySyncConfig.supportGroupHistory = False

        msg = proto.Message()
        msg.protocolMessage.type = (
            proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE
        )
        msg.protocolMessage.peerDataOperationRequestMessage.CopyFrom(pdo)

        await self._send_peer_message(msg)
        return request_id

    async def request_chat_history(self, chat_jid: str, *, count: int = 50) -> str:
        """
        Ask the phone for on-demand history for a single conversation.
        """

        # Import lazily; the generated WAProto module is large.
        from .proto import WAProto_pb2 as proto

        me = self.socket.auth.creds.me
        if not me:
            raise RuntimeError("not authenticated")

        request_id = self.signal.new_message_id()

        pdo = proto.Message.PeerDataOperationRequestMessage()
        pdo.peerDataOperationRequestType = (
            proto.Message.PeerDataOperationRequestType.HISTORY_SYNC_ON_DEMAND
        )
        chat_norm = jid_normalized_user(chat_jid) or chat_jid
        pdo.historySyncOnDemandRequest.chatJid = chat_norm
        pdo.historySyncOnDemandRequest.onDemandMsgCount = int(count)
        if me.lid:
            pdo.historySyncOnDemandRequest.accountLid = me.lid

        # On-demand history requests require an "anchor" message key.
        # Use the oldest message we currently have in the local store as the anchor.
        oldest = self.store.oldest_message(chat_norm)
        if oldest and oldest.id:
            pdo.historySyncOnDemandRequest.oldestMsgId = oldest.id
            pdo.historySyncOnDemandRequest.oldestMsgTimestampMs = int(oldest.timestamp_s) * 1000

            from_me: bool | None = None
            try:
                k = getattr(oldest.raw, "key", None)
                fm = getattr(k, "fromMe", None) if k is not None else None
                if isinstance(fm, bool):
                    from_me = fm
            except Exception:
                from_me = None

            if from_me is None:
                me_pn = jid_decode(me.id)
                me_lid = jid_decode(me.lid) if me.lid else None
                sender = jid_decode(oldest.sender_jid) if oldest.sender_jid else None
                sender_user = sender.user if sender else None
                if (sender_user and me_pn and sender_user == me_pn.user) or (
                    sender_user and me_lid and me_lid.user and sender_user == me_lid.user
                ):
                    from_me = True
                else:
                    from_me = False

            pdo.historySyncOnDemandRequest.oldestMsgFromMe = bool(from_me)

        msg = proto.Message()
        msg.protocolMessage.type = (
            proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE
        )
        msg.protocolMessage.peerDataOperationRequestMessage.CopyFrom(pdo)

        await self._send_peer_message(msg)
        return request_id

    async def set_presence(self, available: bool = True) -> None:
        await self.socket.send_node(
            BinaryNode(tag="presence", attrs={"type": "available" if available else "unavailable"})
        )

    async def send_chatstate(self, jid: str, state: ChatState) -> None:
        """
        Send a typing/recording indicator (chat state) to a 1:1 chat.

        Mirrors Baileys' `sendPresenceUpdate('composing'|'paused'|'recording', jid)`.
        """

        me = self.socket.auth.creds.me
        if not me:
            raise RuntimeError("not authenticated")

        to_jid = jid_normalized_user(jid) or jid
        dec = jid_decode(to_jid)
        if not dec or not dec.server:
            raise ValueError(f"invalid jid: {jid!r}")

        server = "s.whatsapp.net" if dec.server == "c.us" else dec.server
        is_lid = server == "lid"

        from_jid = me.lid if is_lid and me.lid else me.id
        if not from_jid:
            raise RuntimeError("missing sender jid in creds")

        child_tag = "composing" if state == "recording" else state
        child_attrs = {"media": "audio"} if state == "recording" else {}

        await self.socket.send_node(
            BinaryNode(
                tag="chatstate",
                attrs={"from": from_jid, "to": to_jid},
                content=[BinaryNode(tag=child_tag, attrs=child_attrs, content=None)],
            )
        )

    async def set_typing(self, jid: str, typing: bool = True) -> None:
        """
        Convenience wrapper for typing indications.
        """

        await self.send_chatstate(jid, "composing" if typing else "paused")

    async def set_recording(self, jid: str, recording: bool = True) -> None:
        """
        Convenience wrapper for voice-note recording indications.
        """

        await self.send_chatstate(jid, "recording" if recording else "paused")

    async def _send_peer_message(self, msg: Any) -> None:
        """
        Send an encrypted peer message to the phone (category=peer).
        """

        me = self.socket.auth.creds.me
        if not me:
            raise RuntimeError("not authenticated")

        phone_jid = jid_normalized_user(me.id)

        await self._assert_sessions([phone_jid])

        msg_bytes = encode_wa_message_bytes(msg.SerializeToString())
        enc_type, enc_bytes = await self.signal.encrypt_message(phone_jid, data=msg_bytes)

        stanza_content: list[BinaryNode] = [
            BinaryNode(tag="meta", attrs={"appdata": "default"}),
            BinaryNode(tag="enc", attrs={"v": "2", "type": enc_type}, content=enc_bytes),
        ]
        if enc_type == "pkmsg" and isinstance(
            self.socket.auth.creds.account, (bytes, bytearray, memoryview)
        ):
            stanza_content.append(
                BinaryNode(
                    tag="device-identity", attrs={}, content=bytes(self.socket.auth.creds.account)
                )
            )

        msg_id = self.signal.new_message_id()
        await self.socket.send_node(
            BinaryNode(
                tag="message",
                attrs={
                    "id": msg_id,
                    "to": phone_jid,
                    "type": "text",
                    "category": "peer",
                    "push_priority": "high_force",
                },
                content=stanza_content,
            )
        )

    async def _assert_sessions(self, jids: list[str]) -> None:
        """
        Ensure Signal sessions exist for the given wire JIDs by querying `encrypt` bundles.
        """

        to_fetch: list[str] = []
        for jid in jids:
            with contextlib.suppress(Exception):
                if await self.signal.validate_session(jid):
                    continue
            to_fetch.append(jid)

        if not to_fetch:
            return

        res = await self.socket.query(
            BinaryNode(
                tag="iq",
                attrs={"to": S_WHATSAPP_NET, "xmlns": "encrypt", "type": "get"},
                content=[
                    BinaryNode(
                        tag="key",
                        attrs={},
                        content=[
                            BinaryNode(tag="user", attrs={"jid": j}, content=None) for j in to_fetch
                        ],
                    )
                ],
            )
        )

        bundles = self._parse_encrypt_iq(res)
        for jid, bundle in bundles.items():
            with contextlib.suppress(Exception):
                await self.signal.inject_outgoing_session(jid, bundle)

    def _parse_encrypt_iq(self, stanza: BinaryNode) -> dict[str, PreKeyBundle]:
        from .signal.repository import PreKeyBundle, PreKeyBundleKey

        def child(n: BinaryNode | None, tag: str) -> BinaryNode | None:
            if not n or not isinstance(n.content, list):
                return None
            for c in n.content:
                if isinstance(c, BinaryNode) and c.tag == tag:
                    return c
            return None

        def children(n: BinaryNode | None, tag: str) -> list[BinaryNode]:
            if not n or not isinstance(n.content, list):
                return []
            out: list[BinaryNode] = []
            for c in n.content:
                if isinstance(c, BinaryNode) and c.tag == tag:
                    out.append(c)
            return out

        def read_int_be(b: bytes) -> int:
            return int.from_bytes(b, "big", signed=False)

        def read_child_bytes(n: BinaryNode, tag: str) -> bytes | None:
            c = child(n, tag)
            if not c:
                return None
            if isinstance(c.content, (bytes, bytearray, memoryview)):
                return bytes(c.content)
            return None

        def parse_key_node(n: BinaryNode, *, with_sig: bool) -> PreKeyBundleKey | None:
            key_id_raw = read_child_bytes(n, "id")
            val_raw = read_child_bytes(n, "value")
            if not key_id_raw or not val_raw:
                return None
            key_id = read_int_be(key_id_raw)
            pub = bytes([5]) + val_raw  # Signal key type prefix
            sig = read_child_bytes(n, "signature") if with_sig else None
            return PreKeyBundleKey(key_id=key_id, public_key=pub, signature=sig)

        out: dict[str, PreKeyBundle] = {}
        list_node = child(stanza, "list")
        for user_node in children(list_node, "user"):
            jid = user_node.attrs.get("jid")
            if not jid:
                continue
            registration_raw = read_child_bytes(user_node, "registration")
            identity_raw = read_child_bytes(user_node, "identity")
            skey_node = child(user_node, "skey")
            key_node = child(user_node, "key")
            if not registration_raw or not identity_raw or not skey_node:
                continue

            reg = read_int_be(registration_raw)
            identity_key = bytes([5]) + identity_raw
            signed_pre = parse_key_node(skey_node, with_sig=True)
            pre = parse_key_node(key_node, with_sig=False) if key_node else None
            if not signed_pre:
                continue

            out[jid] = PreKeyBundle(
                registration_id=reg,
                identity_key=identity_key,
                signed_pre_key=signed_pre,
                pre_key=pre,
            )
        return out

    async def _on_message_stanza(self, stanza: BinaryNode) -> None:
        """
        Best-effort E2E decrypt + history sync ingestion.
        """

        if not isinstance(stanza.content, list):
            return

        # Keep alternates fresh; LID mapping can change after initial sync.
        self._seed_jid_alternates_from_creds()

        from_jid = stanza.attrs.get("from")
        if not from_jid:
            return

        author_jid = stanza.attrs.get("participant") or from_jid

        for child in stanza.content:
            if not isinstance(child, BinaryNode) or child.tag != "enc":
                continue
            enc_type = child.attrs.get("type")
            if enc_type not in ("pkmsg", "msg"):
                continue
            if not isinstance(child.content, (bytes, bytearray, memoryview)):
                continue

            async def _decrypt_one(payload: bytes, *, typ: str) -> None:
                candidates = [author_jid]
                alt = self._alt_jid_preserve_device(author_jid)
                if alt and alt not in candidates:
                    candidates.append(alt)

                try:
                    pt: bytes | None = None
                    last_err: Exception | None = None
                    for cand in candidates:
                        try:
                            pt = await self.signal.decrypt_message(
                                cand, message_type=typ, ciphertext=payload
                            )
                            break
                        except Exception as e:
                            last_err = e
                            continue

                    if pt is None:
                        assert last_err is not None
                        raise last_err
                except Exception as e:
                    head = payload[:16].hex() if payload else ""
                    await self.socket.events.emit(
                        "message.decrypt_error",
                        {
                            "jid": author_jid,
                            "stanza_id": stanza.attrs.get("id"),
                            "type": typ,
                            "ciphertext_len": len(payload),
                            "ciphertext_head_hex": head,
                            "tried_jids": candidates,
                            "error": str(e),
                        },
                    )
                    return

                try:
                    wa = decode_wa_message_bytes(pt)
                except Exception as e:
                    await self.socket.events.emit(
                        "message.decode_error", {"jid": author_jid, "error": str(e)}
                    )
                    return

                # Import lazily; big.
                from .proto import WAProto_pb2 as proto

                msg = proto.Message()
                try:
                    msg.ParseFromString(wa)
                except Exception as e:
                    await self.socket.events.emit(
                        "message.proto_error", {"jid": author_jid, "error": str(e)}
                    )
                    return

                chat_jid = from_jid
                sender_jid: str | None = author_jid
                inner = msg

                # DeviceSentMessage is used for peer sync (phone <-> companions).
                if msg.HasField("deviceSentMessage") and msg.deviceSentMessage.destinationJid:
                    chat_jid = msg.deviceSentMessage.destinationJid
                    sender_jid = (
                        jid_normalized_user(self.socket.auth.creds.me.id)
                        if self.socket.auth.creds.me
                        else None
                    )
                    if msg.deviceSentMessage.HasField("message"):
                        inner = msg.deviceSentMessage.message

                # Group messages have participant as sender.
                if stanza.attrs.get("participant"):
                    chat_jid = from_jid
                    sender_jid = stanza.attrs.get("participant")

                notify = stanza.attrs.get("notify")
                if notify and sender_jid and self._is_user_like_jid(sender_jid):
                    self._upsert_contact_info(sender_jid, notify=notify)
                if notify and chat_jid and self._is_user_like_jid(chat_jid):
                    # Only populate chat names from `notify` if we don't have a better one yet.
                    existing = self.store.get_chat(chat_jid)
                    if existing is None or not existing.name:
                        self.store.upsert_chat(ChatInfo(jid=chat_jid, name=notify))
                    self._upsert_contact_info(chat_jid, notify=notify)

                text = extract_message_text(inner)
                ts = int(stanza.attrs.get("t") or 0)
                mid = stanza.attrs.get("id") or ""

                if chat_jid:
                    self.store.upsert_chat(ChatInfo(jid=chat_jid))
                    self.store.add_message(
                        MessageInfo(
                            id=mid,
                            chat_jid=chat_jid,
                            sender_jid=sender_jid,
                            timestamp_s=ts,
                            text=text,
                            raw=inner,
                        )
                    )

                await self.socket.events.emit(
                    "message.decrypted",
                    {
                        "id": mid,
                        "chat_jid": chat_jid,
                        "sender_jid": sender_jid,
                        "timestamp_s": ts,
                        "text": text,
                        "message": inner,
                    },
                )

                # History sync notification lives inside protocolMessage.
                if inner.HasField("protocolMessage") and inner.protocolMessage.HasField(
                    "historySyncNotification"
                ):
                    notif = inner.protocolMessage.historySyncNotification
                    ensure_task(self._handle_history_sync(notif), name="pyaileys.history_sync")

            ensure_task(
                _decrypt_one(bytes(child.content), typ=enc_type), name="pyaileys.decrypt.enc"
            )

    async def _handle_history_sync(self, notif: Any) -> None:
        """
        Download + process a HistorySyncNotification into `self.store`.
        """

        # Import lazily; big.
        from .proto import WAProto_pb2 as proto

        try:
            if notif.initialHistBootstrapInlinePayload:
                raw = inflate_zlib(bytes(notif.initialHistBootstrapInlinePayload))
            else:
                raw = await download_and_decrypt_media(
                    direct_path=str(notif.directPath),
                    media_key=bytes(notif.mediaKey),
                    media_type="md-msg-hist",
                )
                raw = inflate_zlib(raw)
            hs = proto.HistorySync()
            hs.ParseFromString(raw)
        except Exception as e:
            await self.socket.events.emit("history.sync_error", {"error": str(e)})
            return

        # Upsert chats and messages.
        for conv in list(hs.conversations):
            jid = str(conv.id)
            name = conv.displayName or conv.name or conv.username or None
            if conv.pnJid and conv.lidJid:
                self._remember_jid_mapping(str(conv.pnJid), str(conv.lidJid))
            self.store.upsert_chat(
                ChatInfo(jid=jid, name=name, pn_jid=conv.pnJid or None, lid_jid=conv.lidJid or None)
            )
            pn_jid = str(conv.pnJid) if conv.pnJid else None
            lid_jid = str(conv.lidJid) if conv.lidJid else None
            if name and (self._is_user_like_jid(jid) or pn_jid or lid_jid):
                for j in (jid, pn_jid, lid_jid):
                    if j and self._is_user_like_jid(j):
                        self._upsert_contact_info(j, name=name, pn_jid=pn_jid, lid_jid=lid_jid)

            for hm in list(conv.messages):
                if not hm.HasField("message"):
                    continue
                wm = hm.message
                if not wm.HasField("key"):
                    continue
                chat_jid = wm.key.remoteJid or jid
                sender = wm.key.participant or None
                text = extract_message_text(wm.message) if wm.HasField("message") else None
                ts = int(wm.messageTimestamp or 0)
                mid = wm.key.id or ""
                self.store.add_message(
                    MessageInfo(
                        id=mid,
                        chat_jid=chat_jid,
                        sender_jid=sender,
                        timestamp_s=ts,
                        text=text,
                        raw=wm,
                    )
                )

        await self.socket.events.emit(
            "history.sync",
            {
                "syncType": int(hs.syncType),
                "progress": int(hs.progress or 0),
                "conversations": len(hs.conversations),
            },
        )
