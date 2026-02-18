from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import hmac
import time
from dataclasses import dataclass
from dataclasses import field

from .auth.creds import Contact, KeyPair
from .auth.state import AuthenticationState
from .connection.websocket import WebSocketConfig, WebSocketTransport
from .constants import (
    DEFAULT_WS_URL,
    KEY_BUNDLE_TYPE,
    WA_ADV_ACCOUNT_SIG_PREFIX,
    WA_ADV_DEVICE_SIG_PREFIX,
    WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX,
)
from .crypto.curve import DefaultCurve25519Provider
from .crypto.hkdf import hmac_sha256
from .crypto.noise import NoiseHandler
from .exceptions import HandshakeError, TransportError
from .handshake import build_login_payload, build_registration_payload
from .socket_config import SocketConfig
from .usync import USyncUserResult, build_usync_iq, extract_device_jids, parse_usync_result
from .util.asyncio import cancel_suppress, ensure_task
from .util.events import AsyncEventEmitter
from .wabinary import S_WHATSAPP_NET, decode_binary_node, encode_binary_node
from .wabinary.jid import jid_decode, jid_normalized_user
from .wabinary.types import BinaryNode

DEF_TAG_PREFIX = "tag:"
DEF_CB_PREFIX = "cb:"


@dataclass(slots=True)
class ConnectionUpdate:
    connection: str | None = None  # "connecting" | "open" | "close"
    qr: str | None = None
    is_new_login: bool | None = None
    last_disconnect: Exception | None = None


@dataclass(slots=True)
class MediaHost:
    hostname: str
    max_content_length_bytes: int | None = None


@dataclass(slots=True)
class MediaConnInfo:
    """
    Media connection parameters for MMG uploads.

    Returned by the `media_conn` IQ query and cached for `ttl_s`.
    """

    hosts: list[MediaHost]
    auth: str
    ttl_s: int
    fetched_at_s: float


@dataclass(frozen=True, slots=True)
class GroupParticipant:
    id: str
    phone_number: str | None = None
    lid: str | None = None
    admin: str | None = None


@dataclass(frozen=True, slots=True)
class GroupMetadata:
    id: str
    addressing_mode: str = "lid"  # "lid" | "pn"
    ephemeral_duration: int | None = None
    participants: list[GroupParticipant] = field(default_factory=list)


class WASocket:
    """
    Low-level WhatsApp Web socket: Noise handshake + framed binary nodes.

    This mirrors Baileys' layering:
    - WebSocket transport
    - Noise handshake and transport encryption
    - WhatsApp "binary node" codec for stanzas
    """

    def __init__(self, *, config: SocketConfig, auth: AuthenticationState) -> None:
        self.config = config
        self.auth = auth

        self.events = AsyncEventEmitter()
        self._transport = WebSocketTransport(
            WebSocketConfig(
                url=config.ws_url or DEFAULT_WS_URL,
                connect_timeout_s=config.connect_timeout_s,
                extra_headers=config.headers,
            )
        )

        self._curve = DefaultCurve25519Provider()
        self._noise: NoiseHandler | None = None

        self._recv_task: asyncio.Task[object] | None = None
        self._keepalive_task: asyncio.Task[object] | None = None
        self._qr_task: asyncio.Task[object] | None = None

        self._frame_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._closed = False
        self._default_handlers_installed = False
        self._connect_lock = asyncio.Lock()
        self._restart_task: asyncio.Task[object] | None = None

        self._epoch = 1
        self._uq_tag = f"{int(dt.datetime.now().timestamp())}-"

        self._last_date_recv: dt.datetime | None = None
        self._server_time_offset_ms: int = 0

        self._noise_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()

        self._media_conn: MediaConnInfo | None = None
        self._media_conn_lock = asyncio.Lock()

    @property
    def is_open(self) -> bool:
        return self._transport.is_open

    def _next_tag(self) -> str:
        self._epoch += 1
        return f"{self._uq_tag}{self._epoch}"

    async def connect(self) -> None:
        async with self._connect_lock:
            # Allow reconnects (e.g. after server requests a restart).
            self._closed = False

            # Tear down any previous per-connection tasks/state (defensive).
            await cancel_suppress(self._qr_task)
            await cancel_suppress(self._keepalive_task)
            await cancel_suppress(self._recv_task)
            self._qr_task = None
            self._keepalive_task = None
            self._recv_task = None

            # New connection => new frame queue & handler state.
            self._frame_queue = asyncio.Queue()
            self._last_date_recv = None

            await self._transport.connect()
            if not self._default_handlers_installed:
                self._install_default_handlers()
                self._default_handlers_installed = True

            # Per-connection ephemeral keypair for Noise handshake.
            ephemeral = self._curve.generate_keypair()
            routing_info = self.auth.creds.routing_info
            self._noise = NoiseHandler(
                key_pair=ephemeral, routing_info=routing_info, curve=self._curve
            )

            self._recv_task = ensure_task(self._recv_loop(), name="pyaileys.recv_loop")

            await self.events.emit("connection.update", ConnectionUpdate(connection="connecting"))

            await self._validate_connection()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        await cancel_suppress(self._qr_task)
        await cancel_suppress(self._keepalive_task)
        await cancel_suppress(self._recv_task)
        self._qr_task = None
        self._keepalive_task = None
        self._recv_task = None
        await self._transport.close()

        await self.events.emit("connection.update", ConnectionUpdate(connection="close"))

    async def restart(self, *, delay_s: float = 0.2) -> None:
        # Best-effort: close current connection and reconnect.
        await self.close()
        await asyncio.sleep(delay_s)
        await self.connect()

    async def send_raw(self, payload: bytes) -> None:
        if not self._noise:
            raise TransportError("noise handler not initialized")
        async with self._send_lock:
            frame = self._noise.encode_frame(payload)
            await self._transport.send(frame)

    async def send_node(self, node: BinaryNode) -> None:
        # Best-effort visibility hook for debugging/telemetry.
        ensure_task(
            self.events.emit("node.outgoing", node), name=f"pyaileys.node.outgoing.{node.tag}"
        )
        await self.send_raw(encode_binary_node(node))

    async def query(self, node: BinaryNode, *, timeout_s: float = 60.0) -> BinaryNode:
        if "id" not in node.attrs:
            node.attrs["id"] = self._next_tag()
        msg_id = node.attrs["id"]

        # Register waiter before sending to avoid missing fast responses.
        event = f"{DEF_TAG_PREFIX}{msg_id}"
        fut = self.events.wait_for_future(event)
        await self.send_node(node)
        try:
            res = await asyncio.wait_for(fut, timeout=timeout_s)
        finally:
            self.events._remove_waiter_future(event, fut)
        if not isinstance(res, BinaryNode):
            raise TransportError(f"unexpected query response type: {type(res).__name__}")
        return res

    async def execute_usync_query(
        self,
        user_jids: list[str],
        *,
        context: str = "message",
        mode: str = "query",
        timeout_s: float | None = None,
    ) -> list[USyncUserResult]:
        """
        Execute a minimal USync query (devices + LID protocols).

        This is primarily used to enumerate device JIDs required for multi-device
        message fanout. It mirrors Baileys' `executeUSyncQuery` shape closely.
        """

        if not user_jids:
            return []

        sid = self._next_tag()
        iq = build_usync_iq(user_jids, sid=sid, context=context, mode=mode)
        res = await self.query(iq, timeout_s=timeout_s or self.config.connect_timeout_s)
        return parse_usync_result(res)

    async def get_usync_devices(
        self,
        jids: list[str],
        *,
        context: str = "message",
        use_cache: bool = False,
        ignore_zero_devices: bool = False,
    ) -> list[str]:
        """
        Enumerate device JIDs for the given user JIDs using USync.

        Returns wire JIDs like:
        - `12345@s.whatsapp.net` (device 0)
        - `12345:17@s.whatsapp.net` (device 17)

        The list excludes the exact sender device (this connected companion),
        because that device already has the message locally.

        Note: `use_cache` is reserved for future use (device list caching).
        """

        me = self.auth.creds.me
        if not me:
            raise TransportError("not authenticated")

        # Respect explicitly-addressed device JIDs.
        explicit: list[str] = []
        to_fetch: list[str] = []
        for jid in jids:
            if not jid:
                continue
            decoded = jid_decode(jid)
            if decoded and decoded.device is not None:
                explicit.append(jid)
            else:
                to_fetch.append(jid_normalized_user(jid) or jid)

        to_fetch = list(dict.fromkeys([j for j in to_fetch if j]))

        # TODO: implement device caching using auth keys (`device-list-*`).
        if use_cache:
            pass

        results = await self.execute_usync_query(to_fetch, context=context) if to_fetch else []
        extracted = extract_device_jids(
            results,
            my_jid=me.id,
            my_lid=me.lid,
            exclude_zero_devices=bool(ignore_zero_devices),
        )

        return list(dict.fromkeys([*explicit, *extracted]))

    async def group_metadata(self, jid: str) -> GroupMetadata:
        """
        Fetch group metadata needed for sender-key distribution (participants + addressing mode).

        Mirrors Baileys' `groupMetadata()` (subset).
        """

        def _child(n: BinaryNode | None, tag: str) -> BinaryNode | None:
            if not n or not isinstance(n.content, list):
                return None
            for c in n.content:
                if isinstance(c, BinaryNode) and c.tag == tag:
                    return c
            return None

        def _children(n: BinaryNode | None, tag: str) -> list[BinaryNode]:
            if not n or not isinstance(n.content, list):
                return []
            return [c for c in n.content if isinstance(c, BinaryNode) and c.tag == tag]

        res = await self.query(
            BinaryNode(
                tag="iq",
                attrs={"to": jid, "type": "get", "xmlns": "w:g2"},
                content=[BinaryNode(tag="query", attrs={"request": "interactive"}, content=None)],
            )
        )

        group = res if res.tag == "group" else _child(res, "group")
        if not group:
            raise TransportError("group metadata response missing <group/>")

        gid = group.attrs.get("id") or jid
        if "@" not in gid:
            from .wabinary.jid import jid_encode

            gid = jid_encode(gid, "g.us")

        addressing_mode = group.attrs.get("addressing_mode") or "lid"
        if addressing_mode not in ("lid", "pn"):
            addressing_mode = "lid"

        eph = None
        eph_node = _child(group, "ephemeral")
        if eph_node:
            raw = eph_node.attrs.get("expiration")
            if raw is not None:
                try:
                    eph = int(raw)
                except Exception:
                    eph = None

        parts: list[GroupParticipant] = []
        for p in _children(group, "participant"):
            pj = p.attrs.get("jid")
            if not pj:
                continue
            parts.append(
                GroupParticipant(
                    id=pj,
                    phone_number=p.attrs.get("phone_number"),
                    lid=p.attrs.get("lid"),
                    admin=p.attrs.get("type"),
                )
            )

        return GroupMetadata(
            id=gid,
            addressing_mode=addressing_mode,
            ephemeral_duration=eph,
            participants=parts,
        )

    async def refresh_media_conn(self, *, force: bool = False) -> MediaConnInfo:
        """
        Fetch (and cache) MMG media upload connection info.

        Mirrors Baileys' `refreshMediaConn()` which queries:
        `<iq to="s.whatsapp.net" type="set" xmlns="w:m"><media_conn/></iq>`
        """

        async with self._media_conn_lock:
            if self._media_conn and not force:
                age = time.time() - self._media_conn.fetched_at_s
                if age < float(self._media_conn.ttl_s):
                    return self._media_conn

            def _child(n: BinaryNode | None, tag: str) -> BinaryNode | None:
                if not n or not isinstance(n.content, list):
                    return None
                for c in n.content:
                    if isinstance(c, BinaryNode) and c.tag == tag:
                        return c
                return None

            def _children(n: BinaryNode | None, tag: str) -> list[BinaryNode]:
                if not n or not isinstance(n.content, list):
                    return []
                return [c for c in n.content if isinstance(c, BinaryNode) and c.tag == tag]

            res = await self.query(
                BinaryNode(
                    tag="iq",
                    attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:m"},
                    content=[BinaryNode(tag="media_conn", attrs={}, content=None)],
                )
            )
            mc = _child(res, "media_conn")
            if not mc:
                raise TransportError("media_conn response missing <media_conn>")

            auth = mc.attrs.get("auth") or ""
            ttl_s = int(mc.attrs.get("ttl") or 0)
            if not auth or ttl_s <= 0:
                raise TransportError("invalid media_conn response (missing auth/ttl)")

            hosts: list[MediaHost] = []
            for h in _children(mc, "host"):
                hn = h.attrs.get("hostname")
                if not hn:
                    continue
                mcl = h.attrs.get("maxContentLengthBytes")
                hosts.append(
                    MediaHost(
                        hostname=hn,
                        max_content_length_bytes=int(mcl) if mcl and mcl.isdigit() else None,
                    )
                )

            info = MediaConnInfo(hosts=hosts, auth=auth, ttl_s=ttl_s, fetched_at_s=time.time())
            self._media_conn = info
            return info

    async def _await_next_frame(self, *, timeout_s: float | None = None) -> bytes:
        if timeout_s is None:
            return await self._frame_queue.get()
        return await asyncio.wait_for(self._frame_queue.get(), timeout=timeout_s)

    async def _validate_connection(self) -> None:
        """
        Noise handshake based on Baileys' `validateConnection`.

        After this completes, the Noise handler is in transport mode and frames are encrypted.
        """

        if not self._noise:
            raise HandshakeError("noise handler not initialized")

        # Import lazily; the module is huge.
        from .proto import WAProto_pb2 as proto

        hello = proto.HandshakeMessage()
        hello.clientHello.ephemeral = self._noise.public_key
        init = hello.SerializeToString()

        # Send clientHello and wait for serverHello frame.
        await self.send_raw(init)
        raw = await self._await_next_frame(timeout_s=self.config.connect_timeout_s)

        handshake = proto.HandshakeMessage()
        handshake.ParseFromString(raw)

        async with self._noise_lock:
            key_enc = self._noise.process_handshake(
                handshake,
                self.auth.creds.noise_key,
                verify_certificates=self.config.verify_certificates,
            )

        if self.auth.creds.me is None:
            payload = build_registration_payload(
                registration_id=self.auth.creds.registration_id,
                signed_identity_public=self.auth.creds.signed_identity_key.public,
                signed_pre_key_id=self.auth.creds.signed_pre_key.key_id,
                signed_pre_key_public=self.auth.creds.signed_pre_key.key_pair.public,
                signed_pre_key_signature=self.auth.creds.signed_pre_key.signature,
                version=self.config.version,
                browser=self.config.browser,
                country_code=self.config.country_code,
                sync_full_history=self.config.sync_full_history,
            )
        else:
            payload = build_login_payload(
                user_jid=self.auth.creds.me.id,
                version=self.config.version,
                browser=self.config.browser,
                country_code=self.config.country_code,
                sync_full_history=self.config.sync_full_history,
            )

        payload_enc: bytes
        async with self._noise_lock:
            payload_enc = self._noise.encrypt(payload.SerializeToString())

        finish = proto.HandshakeMessage()
        finish.clientFinish.static = key_enc
        finish.clientFinish.payload = payload_enc
        await self.send_raw(finish.SerializeToString())

        async with self._noise_lock:
            await self._noise.finish_init()

        # Process any frames that arrived before transport was ready (rare, but possible).
        await self._drain_pre_transport_frames()

        self._keepalive_task = ensure_task(self._keepalive_loop(), name="pyaileys.keepalive")

    async def _drain_pre_transport_frames(self) -> None:
        if not self._noise or not self._noise.transport_ready:
            return
        while True:
            try:
                frame = self._frame_queue.get_nowait()
            except asyncio.QueueEmpty:
                return

            try:
                async with self._noise_lock:
                    plaintext = self._noise.decrypt(frame)
                node = decode_binary_node(plaintext)
            except Exception:
                continue
            await self.events.emit("node", node)
            await self._dispatch_node(node)

    async def _recv_loop(self) -> None:
        assert self._noise is not None, "noise handler must be initialized before recv loop starts"

        while not self._closed:
            try:
                data = await self._transport.recv()
            except TransportError as e:
                await self.events.emit(
                    "connection.update", ConnectionUpdate(connection="close", last_disconnect=e)
                )
                return

            async def _on_frame(frame: bytes) -> None:
                self._last_date_recv = dt.datetime.now(dt.UTC)

                # Before Noise transport is ready, frames are HandshakeMessage protobuf bytes.
                if self._noise and not self._noise.transport_ready:
                    await self._frame_queue.put(frame)
                    await self.events.emit("frame", frame)
                    return

                # After transport is ready, frames are encrypted binary-node payloads.
                await self.events.emit("frame.bytes", frame)
                try:
                    node = decode_binary_node(frame)
                except Exception:
                    # Keep raw visibility for debugging.
                    await self.events.emit("frame.decode_error", frame)
                    return

                await self.events.emit("node", node)
                await self._dispatch_node(node)

            async with self._noise_lock:
                await self._noise.decode_frame(data, _on_frame)

    async def _dispatch_node(self, node: BinaryNode) -> None:
        # Generic stanza hook
        await self.events.emit(f"stanza.{node.tag}", node)
        if node.tag == "message":
            await self.events.emit("message", node)
        elif node.tag == "presence":
            await self.events.emit("presence", node)

        # TAG response routing
        msg_id = node.attrs.get("id")
        if msg_id:
            await self.events.emit(f"{DEF_TAG_PREFIX}{msg_id}", node)

        # Callback routing (Baileys-style)
        l0 = node.tag
        l1 = node.attrs or {}
        l2 = ""
        if isinstance(node.content, list) and node.content:
            first = node.content[0]
            if isinstance(first, BinaryNode):
                l2 = first.tag

        any_triggered = False
        for key, value in l1.items():
            any_triggered = (
                await self.events.emit(f"{DEF_CB_PREFIX}{l0},{key}:{value},{l2}", node)
                or any_triggered
            )
            any_triggered = (
                await self.events.emit(f"{DEF_CB_PREFIX}{l0},{key}:{value}", node) or any_triggered
            )
            any_triggered = (
                await self.events.emit(f"{DEF_CB_PREFIX}{l0},{key}", node) or any_triggered
            )

        any_triggered = await self.events.emit(f"{DEF_CB_PREFIX}{l0},,{l2}", node) or any_triggered
        any_triggered = await self.events.emit(f"{DEF_CB_PREFIX}{l0}", node) or any_triggered

        if not any_triggered:
            await self.events.emit("node.unhandled", node)

    async def _keepalive_loop(self) -> None:
        while not self._closed:
            await asyncio.sleep(self.config.keep_alive_interval_s)
            if self._closed:
                return

            if self._last_date_recv is not None:
                diff = (dt.datetime.now(dt.UTC) - self._last_date_recv).total_seconds()
                if diff > self.config.keep_alive_interval_s + 5:
                    await self.close()
                    return

            if self.is_open:
                with contextlib.suppress(Exception):
                    await self.query(
                        BinaryNode(
                            tag="iq",
                            attrs={
                                "id": self._next_tag(),
                                "to": S_WHATSAPP_NET,
                                "type": "get",
                                "xmlns": "w:p",
                            },
                            content=[BinaryNode(tag="ping", attrs={})],
                        ),
                        timeout_s=self.config.connect_timeout_s,
                    )

    def _install_default_handlers(self) -> None:
        # Pair-device -> emit QR string.
        self.events.on(f"{DEF_CB_PREFIX}iq,type:set,pair-device", self._on_pair_device)
        self.events.on(f"{DEF_CB_PREFIX}iq,,pair-success", self._on_pair_success)
        self.events.on(f"{DEF_CB_PREFIX}success", self._on_success)
        self.events.on(f"{DEF_CB_PREFIX}stream:error", self._on_stream_error)
        self.events.on(f"{DEF_CB_PREFIX}ib,,edge_routing", self._on_edge_routing)
        self.events.on(f"{DEF_CB_PREFIX}ib,,dirty", self._on_dirty)
        self.events.on("stanza.iq", self._on_iq_ping)
        # WA expects an `ack` stanza for message-like deliveries, and delivery receipts
        # for incoming messages (even if we can't decrypt them yet).
        self.events.on("stanza.message", self._on_message_stanza)
        self.events.on("stanza.notification", self._on_ackable_stanza)
        self.events.on("stanza.receipt", self._on_ackable_stanza)
        # Privacy tokens (trusted contact) used for messaging anti-abuse.
        self.events.on("stanza.notification", self._on_privacy_token_notification)

    async def _on_pair_device(self, stanza: BinaryNode) -> None:
        # ACK the IQ.
        if "id" in stanza.attrs:
            await self.send_node(
                BinaryNode(
                    tag="iq",
                    attrs={
                        "to": S_WHATSAPP_NET,
                        "type": "result",
                        "id": stanza.attrs["id"],
                    },
                )
            )

        pair_device = _child(stanza, "pair-device")
        if not pair_device:
            return
        refs = _children(pair_device, "ref")

        noise_b64 = base64.b64encode(self.auth.creds.noise_key.public).decode("ascii")
        ident_b64 = base64.b64encode(self.auth.creds.signed_identity_key.public).decode("ascii")
        adv_b64 = self.auth.creds.adv_secret_key

        # Cancel prior QR rotation, if any.
        if self._qr_task:
            self._qr_task.cancel()

        async def rotate() -> None:
            qr_ms = 60.0
            for ref_node in refs:
                if self._closed:
                    return
                ref_raw = ref_node.content
                if isinstance(ref_raw, bytes):
                    ref = ref_raw.decode("utf-8", errors="replace")
                elif isinstance(ref_raw, str):
                    ref = ref_raw
                else:
                    continue

                qr = ",".join([ref, noise_b64, ident_b64, adv_b64])
                await self.events.emit("connection.update", ConnectionUpdate(qr=qr))
                await asyncio.sleep(qr_ms)
                qr_ms = 20.0

        self._qr_task = ensure_task(rotate(), name="pyaileys.qr_rotate")

    def _update_server_time_offset(self, stanza: BinaryNode) -> None:
        t = stanza.attrs.get("t")
        if not t:
            return
        try:
            parsed = int(t)
        except Exception:
            return
        if parsed <= 0:
            return
        local_ms = int(dt.datetime.now(dt.UTC).timestamp() * 1000)
        self._server_time_offset_ms = parsed * 1000 - local_ms

    def _unified_session_id(self) -> str:
        # Mirrors Baileys' getUnifiedSessionId.
        offset_ms = 3 * 24 * 60 * 60 * 1000  # 3 days
        week_ms = 7 * 24 * 60 * 60 * 1000
        now_ms = int(dt.datetime.now(dt.UTC).timestamp() * 1000) + self._server_time_offset_ms
        return str((now_ms + offset_ms) % week_ms)

    async def _send_unified_session(self) -> None:
        if not self.is_open:
            return
        with contextlib.suppress(Exception):
            await self.send_node(
                BinaryNode(
                    tag="ib",
                    attrs={},
                    content=[
                        BinaryNode(tag="unified_session", attrs={"id": self._unified_session_id()})
                    ],
                )
            )

    async def _send_passive_iq(self, tag: str) -> None:
        # Baileys calls this for 'active' after success.
        if not self.is_open:
            return
        with contextlib.suppress(Exception):
            await self.query(
                BinaryNode(
                    tag="iq",
                    attrs={"to": S_WHATSAPP_NET, "xmlns": "passive", "type": "set"},
                    content=[BinaryNode(tag=tag, attrs={})],
                ),
                timeout_s=self.config.connect_timeout_s,
            )

    async def _get_prekey_count_on_server(self) -> int:
        res = await self.query(
            BinaryNode(
                tag="iq",
                attrs={"to": S_WHATSAPP_NET, "xmlns": "encrypt", "type": "get"},
                content=[BinaryNode(tag="count", attrs={})],
            ),
            timeout_s=self.config.connect_timeout_s,
        )
        count_child = _child(res, "count")
        if not count_child:
            return 0
        try:
            return int(count_child.attrs.get("value") or 0)
        except Exception:
            return 0

    async def _upload_prekeys(self, count: int) -> None:
        # Minimal port of Baileys getNextPreKeysNode/uploadPreKeys.
        from .handshake import encode_big_endian

        start_id = int(self.auth.creds.next_pre_key_id)
        end_id = start_id + max(int(count), 0)
        if end_id <= start_id:
            return

        prekeys: dict[int, KeyPair] = {}
        store_obj: dict[str, dict[str, bytes]] = {}
        for key_id in range(start_id, end_id):
            kp = self._curve.generate_keypair()
            prekeys[key_id] = kp
            store_obj[str(key_id)] = {"public": kp.public, "private": kp.private}

        # Persist generated pre-keys before upload.
        await self.auth.keys.set({"pre-key": store_obj})

        # Advance counters (even if upload fails, these keys exist locally).
        self.auth.creds.next_pre_key_id = end_id
        self.auth.creds.first_unuploaded_pre_key_id = max(
            self.auth.creds.first_unuploaded_pre_key_id, end_id
        )
        await self.events.emit("creds.update", self.auth.creds)

        def xmpp_pre_key(pair: KeyPair, key_id: int) -> BinaryNode:
            return BinaryNode(
                tag="key",
                attrs={},
                content=[
                    BinaryNode(tag="id", attrs={}, content=encode_big_endian(key_id, 3)),
                    BinaryNode(tag="value", attrs={}, content=pair.public),
                ],
            )

        sk = self.auth.creds.signed_pre_key
        xmpp_skey = BinaryNode(
            tag="skey",
            attrs={},
            content=[
                BinaryNode(tag="id", attrs={}, content=encode_big_endian(int(sk.key_id), 3)),
                BinaryNode(tag="value", attrs={}, content=sk.key_pair.public),
                BinaryNode(tag="signature", attrs={}, content=sk.signature),
            ],
        )

        node = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "xmlns": "encrypt", "type": "set"},
            content=[
                BinaryNode(
                    tag="registration",
                    attrs={},
                    content=encode_big_endian(int(self.auth.creds.registration_id)),
                ),
                BinaryNode(tag="type", attrs={}, content=KEY_BUNDLE_TYPE),
                BinaryNode(
                    tag="identity", attrs={}, content=self.auth.creds.signed_identity_key.public
                ),
                BinaryNode(
                    tag="list",
                    attrs={},
                    content=[xmpp_pre_key(prekeys[i], i) for i in sorted(prekeys)],
                ),
                xmpp_skey,
            ],
        )

        await self.query(node, timeout_s=60.0)

    async def _upload_prekeys_to_server_if_required(self) -> None:
        # Keep this best-effort: failures shouldn't break login.
        try:
            count_on_server = await self._get_prekey_count_on_server()
            # Rough mirror of Baileys: upload a larger initial batch if server has none.
            want = 30 if count_on_server == 0 else 10
            if count_on_server <= want:
                await self._upload_prekeys(want)
        except Exception:
            return

    async def _on_pair_success(self, stanza: BinaryNode) -> None:
        if self._qr_task:
            self._qr_task.cancel()
            self._qr_task = None
        self._update_server_time_offset(stanza)

        pair_success = _child(stanza, "pair-success")
        if not pair_success:
            return

        msg_id = stanza.attrs.get("id")
        if not msg_id:
            raise HandshakeError("pair-success stanza missing id")

        # Import lazily; the generated WAProto module is large.
        from .proto import WAProto_pb2 as proto

        device_identity_node = _child(pair_success, "device-identity")
        platform_node = _child(pair_success, "platform")
        device_node = _child(pair_success, "device")
        business_node = _child(pair_success, "biz")

        if not device_identity_node or not device_node:
            raise HandshakeError("pair-success missing device-identity or device")

        device_id_raw = device_identity_node.content
        if not isinstance(device_id_raw, (bytes, bytearray, memoryview)):
            raise HandshakeError("pair-success device-identity had non-bytes content")

        # Verify the ADV HMAC using adv_secret_key.
        adv = proto.ADVSignedDeviceIdentityHMAC()
        adv.ParseFromString(bytes(device_id_raw))
        if not adv.HasField("details") or not adv.HasField("hmac"):
            raise HandshakeError("pair-success device-identity missing details/hmac")

        details = bytes(adv.details)
        expected_hmac = bytes(adv.hmac)

        hmac_prefix = b""
        if adv.HasField("accountType") and adv.accountType == proto.ADVEncryptionType.HOSTED:
            hmac_prefix = WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX

        adv_key = base64.b64decode(self.auth.creds.adv_secret_key)
        computed_hmac = hmac_sha256(adv_key, hmac_prefix + details)
        if not hmac.compare_digest(expected_hmac, computed_hmac):
            raise HandshakeError("pair-success invalid device-identity hmac")

        # Verify account signature.
        account = proto.ADVSignedDeviceIdentity()
        account.ParseFromString(details)

        if (
            not account.HasField("details")
            or not account.HasField("accountSignatureKey")
            or not account.HasField("accountSignature")
        ):
            raise HandshakeError("pair-success account identity missing required fields")

        device_details = bytes(account.details)
        account_sig_key = bytes(account.accountSignatureKey)
        account_sig = bytes(account.accountSignature)

        device_identity = proto.ADVDeviceIdentity()
        device_identity.ParseFromString(device_details)

        account_sig_prefix = (
            WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
            if device_identity.HasField("deviceType")
            and device_identity.deviceType == proto.ADVEncryptionType.HOSTED
            else WA_ADV_ACCOUNT_SIG_PREFIX
        )
        account_msg = (
            account_sig_prefix + device_details + self.auth.creds.signed_identity_key.public
        )

        if not self._curve.verify(account_sig_key, account_msg, account_sig):
            raise HandshakeError("pair-success failed to verify account signature")

        # Sign device identity and reply with pair-device-sign.
        device_msg = (
            WA_ADV_DEVICE_SIG_PREFIX
            + device_details
            + self.auth.creds.signed_identity_key.public
            + account_sig_key
        )
        account.deviceSignature = self._curve.sign(
            self.auth.creds.signed_identity_key.private, device_msg
        )

        account_for_reply = proto.ADVSignedDeviceIdentity()
        account_for_reply.CopyFrom(account)
        # Baileys: do not include accountSignatureKey in the reply.
        account_for_reply.ClearField("accountSignatureKey")
        account_enc = account_for_reply.SerializeToString()

        key_index = int(device_identity.keyIndex) if device_identity.HasField("keyIndex") else 0
        reply = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "result", "id": msg_id},
            content=[
                BinaryNode(
                    tag="pair-device-sign",
                    attrs={},
                    content=[
                        BinaryNode(
                            tag="device-identity",
                            attrs={"key-index": str(key_index)},
                            content=account_enc,
                        )
                    ],
                )
            ],
        )
        await self.send_node(reply)
        ensure_task(self._send_unified_session(), name="pyaileys.unified_session_after_pair")

        # Update credentials.
        jid = device_node.attrs.get("jid")
        lid = device_node.attrs.get("lid")
        if not jid or not lid:
            raise HandshakeError("pair-success device missing jid/lid")

        biz_name = business_node.attrs.get("name") if business_node else None
        self.auth.creds.account = account.SerializeToString()
        self.auth.creds.me = Contact(id=jid, name=biz_name, lid=lid)
        self.auth.creds.platform = platform_node.attrs.get("name") if platform_node else None

        identity = {
            "identifier": {"name": lid, "deviceId": 0},
            "identifierKey": (
                account_sig_key
                if len(account_sig_key) == 33
                else (KEY_BUNDLE_TYPE + account_sig_key)
            ),
        }
        current = list(self.auth.creds.signal_identities or [])
        current.append(identity)
        self.auth.creds.signal_identities = current

        await self.events.emit("creds.update", self.auth.creds)
        await self.events.emit("connection.update", ConnectionUpdate(is_new_login=True, qr=None))

    async def _on_success(self, stanza: BinaryNode) -> None:
        # Login complete
        if self._qr_task:
            self._qr_task.cancel()
            self._qr_task = None
        self._update_server_time_offset(stanza)
        await self.events.emit("connection.update", ConnectionUpdate(connection="open", qr=None))
        ensure_task(self._after_success_init(), name="pyaileys.after_success_init")

        # The server sometimes includes a more authoritative LID on success.
        if self.auth.creds.me is not None and stanza.attrs.get("lid"):
            self.auth.creds.me.lid = stanza.attrs["lid"]
            await self.events.emit("creds.update", self.auth.creds)

    async def _after_success_init(self) -> None:
        """
        Best-effort post-login initialization.

        This mirrors Baileys' sequencing more closely:
        1) upload pre-keys if required
        2) send passive 'active'
        3) validate digest
        (unified session can be sent at any point)
        """

        with contextlib.suppress(Exception):
            await self._send_unified_session()
        with contextlib.suppress(Exception):
            await self._upload_prekeys_to_server_if_required()
        with contextlib.suppress(Exception):
            await self._send_passive_iq("active")
        with contextlib.suppress(Exception):
            await self._digest_key_bundle()
        # Fetch server props (feature flags). Some servers appear to expect this early.
        with contextlib.suppress(Exception):
            await self._fetch_props()

    async def _fetch_props(self) -> dict[str, str]:
        """
        Fetch WhatsApp Web 'props' (feature flags) via `xmlns="w"` IQ.

        Mirrors Baileys' `fetchProps()` (protocol=2).
        """

        last_hash = self.auth.creds.last_prop_hash or ""
        res = await self.query(
            BinaryNode(
                tag="iq",
                attrs={"to": S_WHATSAPP_NET, "xmlns": "w", "type": "get"},
                content=[BinaryNode(tag="props", attrs={"protocol": "2", "hash": last_hash})],
            ),
            timeout_s=self.config.connect_timeout_s,
        )

        props_node = _child(res, "props")
        props: dict[str, str] = {}
        if props_node:
            new_hash = props_node.attrs.get("hash")
            if new_hash:
                self.auth.creds.last_prop_hash = new_hash
                await self.events.emit("creds.update", self.auth.creds)
            for p in _children(props_node, "prop"):
                name = p.attrs.get("name")
                value = p.attrs.get("value")
                if name and value is not None:
                    props[str(name)] = str(value)

        return props

    async def _on_stream_error(self, stanza: BinaryNode) -> None:
        code_raw = stanza.attrs.get("code")
        code = int(code_raw) if code_raw and code_raw.isdigit() else 0

        # WhatsApp requests a restart after successful pairing (Baileys maps this to DisconnectReason.restartRequired).
        if code == 515:
            if not self._restart_task or self._restart_task.done():
                self._restart_task = ensure_task(self.restart(), name="pyaileys.restart_required")
            return

        ensure_task(self.close(), name="pyaileys.close_on_stream_error")

    async def _on_iq_ping(self, stanza: BinaryNode) -> None:
        # The server periodically sends XMPP pings. If we don't ACK them,
        # it will drop the connection.
        if stanza.attrs.get("type") != "get":
            return
        if stanza.attrs.get("xmlns") != "urn:xmpp:ping":
            return

        attrs: dict[str, str] = {"to": stanza.attrs.get("from") or S_WHATSAPP_NET, "type": "result"}
        msg_id = stanza.attrs.get("id")
        if msg_id:
            attrs["id"] = msg_id
        with contextlib.suppress(Exception):
            await self.send_node(BinaryNode(tag="iq", attrs=attrs))

    async def _digest_key_bundle(self) -> None:
        # Best-effort port of Baileys' digestKeyBundle.
        try:
            res = await self.query(
                BinaryNode(
                    tag="iq",
                    attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "encrypt"},
                    content=[BinaryNode(tag="digest", attrs={})],
                ),
                timeout_s=self.config.connect_timeout_s,
            )
            if not _child(res, "digest"):
                # Attempt a (re)upload of pre-keys; don't fail the connection if this still doesn't help.
                await self._upload_prekeys(10)
        except Exception:
            return

    async def _on_ackable_stanza(self, stanza: BinaryNode) -> None:
        # ACK in the background so it doesn't block the receive pipeline.
        ensure_task(self._send_stanza_ack(stanza), name=f"pyaileys.ack.{stanza.tag}")

    async def _on_message_stanza(self, stanza: BinaryNode) -> None:
        # ACK stanza delivery and also send a delivery receipt.
        ensure_task(self._send_stanza_ack(stanza), name="pyaileys.ack.message")
        ensure_task(self._send_message_receipt(stanza), name="pyaileys.receipt.message")

    async def _send_stanza_ack(self, stanza: BinaryNode, *, error_code: int | None = None) -> None:
        msg_id = stanza.attrs.get("id")
        to = stanza.attrs.get("from")
        if not msg_id or not to:
            return

        ack_attrs: dict[str, str] = {"id": msg_id, "to": to, "class": stanza.tag}

        if error_code is not None and int(error_code) != 0:
            ack_attrs["error"] = str(int(error_code))

        participant = stanza.attrs.get("participant")
        if participant:
            ack_attrs["participant"] = participant

        recipient = stanza.attrs.get("recipient")
        if recipient:
            ack_attrs["recipient"] = recipient

        # Mirror Baileys: include `type` for non-message stanzas; for message stanzas
        # include it when `unavailable` or when error_code is not explicitly 0.
        stype = stanza.attrs.get("type")
        if stype:
            if stanza.tag != "message":
                ack_attrs["type"] = stype
            else:
                unavailable = _child(stanza, "unavailable") is not None
                include_type = unavailable or (error_code is None or int(error_code) != 0)
                if include_type:
                    ack_attrs["type"] = stype

        # Mirror Baileys: for unavailable messages, set from to our JID.
        if (
            stanza.tag == "message"
            and _child(stanza, "unavailable") is not None
            and self.auth.creds.me is not None
        ):
            ack_attrs["from"] = self.auth.creds.me.id

        with contextlib.suppress(Exception):
            await self.send_node(BinaryNode(tag="ack", attrs=ack_attrs))

    async def _send_message_receipt(self, stanza: BinaryNode) -> None:
        """
        Send a delivery receipt for an incoming `message` stanza.

        This is intentionally minimal and does not require successful E2E decryption.
        """

        msg_id = stanza.attrs.get("id")
        remote_jid = stanza.attrs.get("from")
        if not msg_id or not remote_jid:
            return

        attrs: dict[str, str] = {"id": msg_id, "to": remote_jid}

        participant = stanza.attrs.get("participant")
        if participant:
            attrs["participant"] = participant

        # Mirror Baileys: peer-category messages use peer_msg receipts.
        if stanza.attrs.get("category") == "peer":
            attrs["type"] = "peer_msg"

        with contextlib.suppress(Exception):
            await self.send_node(BinaryNode(tag="receipt", attrs=attrs))

    async def _on_edge_routing(self, stanza: BinaryNode) -> None:
        edge = _child(stanza, "edge_routing")
        routing = _child(edge, "routing_info")
        if not routing or not isinstance(routing.content, (bytes, bytearray, memoryview)):
            return
        self.auth.creds.routing_info = bytes(routing.content)
        await self.events.emit("creds.update", self.auth.creds)

    async def _on_dirty(self, stanza: BinaryNode) -> None:
        dirty = _child(stanza, "dirty")
        if not dirty:
            return
        dirty_type = dirty.attrs.get("type")
        if dirty_type not in ("account_sync", "groups"):
            return

        attrs: dict[str, str] = {"type": dirty_type}
        ts = dirty.attrs.get("timestamp")
        if ts:
            attrs["timestamp"] = ts

        # Clean dirty bits to acknowledge sync request (best-effort).
        with contextlib.suppress(Exception):
            await self.send_node(
                BinaryNode(
                    tag="iq",
                    attrs={
                        "to": S_WHATSAPP_NET,
                        "type": "set",
                        "xmlns": "urn:xmpp:whatsapp:dirty",
                        "id": self._next_tag(),
                    },
                    content=[BinaryNode(tag="clean", attrs=attrs)],
                )
            )

    async def _on_privacy_token_notification(self, stanza: BinaryNode) -> None:
        """
        Handle `notification type="privacy_token"` carrying trusted-contact tokens.

        Baileys stores these under the `tctoken` key store category and attaches them
        on outgoing 1:1 messages when available.
        """

        if stanza.tag != "notification":
            return
        if stanza.attrs.get("type") != "privacy_token":
            return

        from_jid = stanza.attrs.get("from")
        if not from_jid:
            return
        from_norm = jid_normalized_user(from_jid) or from_jid

        tokens_node = _child(stanza, "tokens")
        if not tokens_node:
            return

        for token_node in _children(tokens_node, "token"):
            typ = token_node.attrs.get("type")
            ts = token_node.attrs.get("t")
            content = token_node.content
            if typ != "trusted_contact":
                continue
            if not isinstance(content, (bytes, bytearray, memoryview)):
                continue
            await self.auth.keys.set(
                {"tctoken": {from_norm: {"token": bytes(content), "timestamp": ts}}}
            )
            await self.events.emit("tctoken.update", {"jid": from_norm, "timestamp": ts})


def _child(node: BinaryNode | None, tag: str) -> BinaryNode | None:
    if not node or not isinstance(node.content, list):
        return None
    for c in node.content:
        if isinstance(c, BinaryNode) and c.tag == tag:
            return c
    return None


def _children(node: BinaryNode | None, tag: str) -> list[BinaryNode]:
    if not node or not isinstance(node.content, list):
        return []
    out: list[BinaryNode] = []
    for c in node.content:
        if isinstance(c, BinaryNode) and c.tag == tag:
            out.append(c)
    return out
