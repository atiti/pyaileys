"""
Kitchen-sink demo app for pyaileys.

This is intentionally "app-like" (interactive) so it exercises:
- auth state load/save
- connect + QR pairing
- event subscriptions
- basic IQ queries (ping)
- presence updates
- raw node send/query

E2E (Signal) is implemented for basic 1:1 messages (text + some media types),
but group encryption and many rich message types are still in-progress.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import Any

from pyaileys import WhatsAppClient
from pyaileys.exceptions import SendRejectedError
from pyaileys.socket import ConnectionUpdate
from pyaileys.wabinary import S_WHATSAPP_NET
from pyaileys.wabinary.types import BinaryNode


def _fmt_bytes(b: bytes, *, max_hex: int = 32) -> str:
    if not b:
        return "b''"
    hx = b[:max_hex].hex()
    suffix = "" if len(b) <= max_hex else "..."
    return f"<bytes {len(b)} 0x{hx}{suffix}>"


def _format_node(node: BinaryNode, *, indent: int = 0, max_children: int = 30) -> str:
    sp = "  " * indent
    attrs = " ".join([f'{k}="{v}"' for k, v in node.attrs.items()])
    head = f"{sp}<{node.tag}{(' ' + attrs) if attrs else ''}>"

    c = node.content
    if c is None:
        return f"{head}</{node.tag}>"
    if isinstance(c, (bytes, bytearray, memoryview)):
        return f"{head}{_fmt_bytes(bytes(c))}</{node.tag}>"
    if isinstance(c, str):
        s = c if len(c) <= 200 else (c[:200] + "...")
        return f"{head}{s}</{node.tag}>"
    if isinstance(c, list):
        lines = [head]
        for _i, child in enumerate(c[:max_children]):
            if isinstance(child, BinaryNode):
                lines.append(_format_node(child, indent=indent + 1, max_children=max_children))
            elif isinstance(child, (bytes, bytearray, memoryview)):
                lines.append(f"{sp}  {_fmt_bytes(bytes(child))}")
            else:
                lines.append(f"{sp}  {child!r}")
        if len(c) > max_children:
            lines.append(f"{sp}  ... ({len(c) - max_children} more children)")
        lines.append(f"{sp}</{node.tag}>")
        return "\n".join(lines)

    return f"{head}{c!r}</{node.tag}>"


async def _ainput(prompt: str) -> str:
    return await asyncio.to_thread(input, prompt)


def _node_from_dict(d: dict[str, Any]) -> BinaryNode:
    tag = str(d["tag"])
    attrs = {str(k): str(v) for k, v in (d.get("attrs") or {}).items()}
    content = d.get("content")
    if isinstance(content, dict):
        content = _node_from_dict(content)
    if isinstance(content, list):
        out: list[BinaryNode] = []
        for item in content:
            if not isinstance(item, dict):
                raise TypeError("content list must contain objects")
            out.append(_node_from_dict(item))
        content = out
    if isinstance(content, str) and content.startswith("base64:"):
        import base64

        content = base64.b64decode(content[len("base64:") :])
    if isinstance(content, BinaryNode):
        content = [content]
    if content is not None and not isinstance(content, (list, str, bytes, bytearray, memoryview)):
        raise TypeError(f"unsupported content type: {type(content).__name__}")
    return BinaryNode(tag=tag, attrs=attrs, content=content)  # type: ignore[arg-type]


async def main() -> None:
    ap = argparse.ArgumentParser(prog="demo_app.py")
    ap.add_argument("--auth", default="./auth", help="auth folder (default: ./auth)")
    ap.add_argument("--no-qr-file", action="store_true", help="don't write QR to auth/qr.svg")
    ap.add_argument("--log-nodes", action="store_true", help="print every received node")
    ap.add_argument("--log-outgoing", action="store_true", help="print every sent node")
    ap.add_argument("--log-unhandled", action="store_true", help="print unhandled nodes")
    ap.add_argument(
        "--trace-errors", action="store_true", help="print stack traces on command errors"
    )
    args = ap.parse_args()

    auth_dir = Path(args.auth).expanduser().resolve()
    client, auth_state = await WhatsAppClient.from_auth_folder(str(auth_dir))

    async def on_update(update: ConnectionUpdate) -> None:
        if update.connection:
            print("connection:", update.connection)

        if update.qr:
            print("\nScan this QR in WhatsApp -> Settings -> Linked devices -> Link a device\n")

            wrote = False
            if not args.no_qr_file:
                with contextlib.suppress(Exception):
                    import qrcode  # optional extra
                    from qrcode.image.svg import SvgImage

                    svg_path = auth_dir / "qr.svg"
                    img = qrcode.make(update.qr, image_factory=SvgImage)
                    svg_path.write_bytes(img.to_string())
                    wrote = True
                    print(f"wrote {svg_path}")

            with contextlib.suppress(Exception):
                import qrcode  # optional extra

                qr = qrcode.QRCode(border=1)
                qr.add_data(update.qr)
                qr.make(fit=True)
                qr.print_ascii(invert=True)
                return

            if not wrote:
                print("QR string:", update.qr)

    async def on_creds_update(_creds) -> None:
        await auth_state.save_creds()

    async def on_node(node: BinaryNode) -> None:
        if args.log_nodes:
            print("\n[node]\n" + _format_node(node))

    async def on_outgoing(node: BinaryNode) -> None:
        if args.log_outgoing:
            print("\n[outgoing]\n" + _format_node(node))

    async def on_unhandled(node: BinaryNode) -> None:
        if args.log_unhandled:
            print("\n[unhandled]\n" + _format_node(node))

    async def on_message(node: BinaryNode) -> None:
        print("\n[message]\n" + _format_node(node))

    async def on_decrypted(ev: Any) -> None:
        text = ev.get("text")
        chat = ev.get("chat_jid")
        sender = ev.get("sender_jid")
        if text:
            print(f"\n[decrypted] {chat} {sender}: {text}")

    async def on_presence(node: BinaryNode) -> None:
        print("\n[presence]\n" + _format_node(node))

    client.on("connection.update", on_update)
    client.on("creds.update", on_creds_update)
    client.on("node", on_node)
    client.on("node.outgoing", on_outgoing)
    client.on("node.unhandled", on_unhandled)
    client.on("message", on_message)
    client.on("message.decrypted", on_decrypted)
    client.on("presence", on_presence)

    await client.connect()

    print(
        "\nCommands: help, me, ping, presence on|off, chatstate <jid> composing|paused|recording, send_node_json <file>, query_node_json <file>, send_text <jid> <text>, send_image <jid> <path> [caption], send_ptt <jid> <path> [seconds], send_doc <jid> <path> [caption], send_vcard <jid> <path> [display_name], send_contacts <jid> <vcf1> <vcf2>..., send_location <jid> <lat> <lng> [name], quit\n"
    )

    while True:
        try:
            line = (await _ainput("> ")).strip()
        except (EOFError, KeyboardInterrupt):
            line = "quit"

        if not line:
            continue

        parts = line.split(" ", 2)
        cmd = parts[0].lower()

        try:
            if cmd in ("quit", "exit"):
                break

            if cmd == "help":
                print("help")
                print("me")
                print("ping")
                print("presence on|off")
                print("chatstate <jid> composing|paused|recording")
                print("send_node_json <file>")
                print("query_node_json <file>")
                print("send_text <jid> <text>")
                print("send_image <jid> <path> [caption]")
                print("send_ptt <jid> <path> [seconds]")
                print("send_doc <jid> <path> [caption]")
                print("send_vcard <jid> <path> [display_name]")
                print("send_contacts <jid> <vcf1> <vcf2>...")
                print("send_location <jid> <lat> <lng> [name]")
                print("quit")
                continue

            if cmd == "me":
                print(
                    "me:",
                    asdict(client.socket.auth.creds.me) if client.socket.auth.creds.me else None,
                )
                print("platform:", client.socket.auth.creds.platform)
                continue

            if cmd == "ping":
                res = await client.socket.query(
                    BinaryNode(
                        tag="iq",
                        attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "w:p"},
                        content=[BinaryNode(tag="ping", attrs={})],
                    )
                )
                print(_format_node(res))
                continue

            if cmd == "presence":
                if len(parts) < 2:
                    print("usage: presence on|off")
                    continue
                on = parts[1].lower() in ("on", "1", "true", "available")
                await client.set_presence(on)
                print("ok")
                continue

            if cmd == "chatstate":
                p = line.split(" ", 2)
                if len(p) < 3:
                    print("usage: chatstate <jid> composing|paused|recording")
                    continue
                jid = p[1]
                state = p[2].strip().lower()
                if state not in ("composing", "paused", "recording"):
                    print("error: invalid state")
                    continue
                await client.send_chatstate(jid, state)  # type: ignore[arg-type]
                print("ok")
                continue

            if cmd in ("send_node_json", "query_node_json"):
                if len(parts) < 2:
                    print(f"usage: {cmd} <file>")
                    continue
                path = Path(parts[1]).expanduser()
                obj = json.loads(path.read_text("utf-8"))
                if not isinstance(obj, dict):
                    raise TypeError("expected a JSON object")
                node = _node_from_dict(obj)
                if cmd == "send_node_json":
                    await client.socket.send_node(node)
                    print("sent")
                else:
                    res = await client.socket.query(node)
                    print(_format_node(res))
                continue

            if cmd == "send_text":
                if len(parts) < 3:
                    print("usage: send_text <jid> <text>")
                    continue
                jid = parts[1]
                text = parts[2]
                try:
                    mid = await client.send_text(jid, text, wait_ack=True)
                    print("sent:", mid)
                except SendRejectedError as e:
                    print(f"rejected: error={e.code} ack={e.ack_attrs}")
                continue

            if cmd == "send_image":
                p = line.split(" ", 3)
                if len(p) < 3:
                    print("usage: send_image <jid> <path> [caption]")
                    continue
                jid = p[1]
                path = p[2]
                caption = p[3] if len(p) >= 4 else None
                try:
                    mid = await client.send_image_file(jid, path, caption=caption, wait_ack=True)
                    print("sent:", mid)
                except SendRejectedError as e:
                    print(f"rejected: error={e.code} ack={e.ack_attrs}")
                continue

            if cmd == "send_ptt":
                p = line.split(" ", 3)
                if len(p) < 3:
                    print("usage: send_ptt <jid> <path> [seconds]")
                    continue
                jid = p[1]
                path = p[2]
                seconds = None
                if len(p) >= 4 and p[3]:
                    with contextlib.suppress(Exception):
                        seconds = int(p[3])
                try:
                    mid = await client.send_voice_note_file(
                        jid, path, seconds=seconds, wait_ack=True
                    )
                    print("sent:", mid)
                except SendRejectedError as e:
                    print(f"rejected: error={e.code} ack={e.ack_attrs}")
                continue

            if cmd == "send_doc":
                p = line.split(" ", 3)
                if len(p) < 3:
                    print("usage: send_doc <jid> <path> [caption]")
                    continue
                jid = p[1]
                path = p[2]
                caption = p[3] if len(p) >= 4 else None
                try:
                    mid = await client.send_document_file(jid, path, caption=caption, wait_ack=True)
                    print("sent:", mid)
                except SendRejectedError as e:
                    print(f"rejected: error={e.code} ack={e.ack_attrs}")
                continue

            if cmd == "send_vcard":
                p = line.split(" ", 3)
                if len(p) < 3:
                    print("usage: send_vcard <jid> <path> [display_name]")
                    continue
                jid = p[1]
                path = p[2]
                display_name = p[3] if len(p) >= 4 else Path(path).stem
                try:
                    vcf = Path(path).expanduser().read_text("utf-8", errors="replace")
                    mid = await client.send_contact(
                        jid, display_name=display_name, vcard=vcf, wait_ack=True
                    )
                    print("sent:", mid)
                except SendRejectedError as e:
                    print(f"rejected: error={e.code} ack={e.ack_attrs}")
                continue

            if cmd == "send_contacts":
                p = line.split(" ")
                if len(p) < 3:
                    print("usage: send_contacts <jid> <vcf1> <vcf2>...")
                    continue
                jid = p[1]
                paths = p[2:]
                contacts: list[tuple[str, str]] = []
                try:
                    for pp in paths:
                        vcf = Path(pp).expanduser().read_text("utf-8", errors="replace")
                        contacts.append((Path(pp).stem, vcf))
                    mid = await client.send_contacts(jid, contacts, wait_ack=True)
                    print("sent:", mid)
                except SendRejectedError as e:
                    print(f"rejected: error={e.code} ack={e.ack_attrs}")
                continue

            if cmd == "send_location":
                p = line.split(" ", 4)
                if len(p) < 4:
                    print("usage: send_location <jid> <lat> <lng> [name]")
                    continue
                jid = p[1]
                try:
                    lat = float(p[2])
                    lng = float(p[3])
                except Exception:
                    print("error: invalid lat/lng")
                    continue
                name = p[4] if len(p) >= 5 else None
                try:
                    mid = await client.send_location(
                        jid, latitude=lat, longitude=lng, name=name, wait_ack=True
                    )
                    print("sent:", mid)
                except SendRejectedError as e:
                    print(f"rejected: error={e.code} ack={e.ack_attrs}")
                continue

            print(f"unknown command: {cmd} (try: help)")
        except Exception as e:
            print(f"error: {e}")
            if args.trace_errors:
                traceback.print_exc()
            continue

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
