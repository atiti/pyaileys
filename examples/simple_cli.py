"""
Simple interactive CLI for pyaileys.

Demonstrates:
- QR pairing + auth persistence
- Signal (E2E) message decrypt/encrypt
- history sync ingestion into an in-memory store
- listing chats and reading local history
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
from pathlib import Path

from pyaileys import WhatsAppClient
from pyaileys.exceptions import SendRejectedError
from pyaileys.socket import ConnectionUpdate


async def _ainput(prompt: str) -> str:
    return await asyncio.to_thread(input, prompt)


def _short(s: str | None, n: int = 80) -> str:
    if not s:
        return ""
    return s if len(s) <= n else (s[: n - 3] + "...")


async def main() -> None:
    ap = argparse.ArgumentParser(prog="simple_cli.py")
    ap.add_argument("--auth", default="./auth", help="auth folder (default: ./auth)")
    ap.add_argument("--no-qr-file", action="store_true", help="don't write QR to auth/qr.svg")
    args = ap.parse_args()

    auth_dir = Path(args.auth).expanduser().resolve()
    client, auth_state = await WhatsAppClient.from_auth_folder(str(auth_dir))

    async def on_update(update: ConnectionUpdate) -> None:
        if update.connection:
            print("connection:", update.connection)
        if update.qr:
            print("\nScan this QR in WhatsApp -> Settings -> Linked devices -> Link a device\n")

            if not args.no_qr_file:
                with contextlib.suppress(Exception):
                    import qrcode  # optional extra
                    from qrcode.image.svg import SvgImage

                    svg_path = auth_dir / "qr.svg"
                    img = qrcode.make(update.qr, image_factory=SvgImage)
                    svg_path.write_bytes(img.to_string())
                    print(f"wrote {svg_path}")

            with contextlib.suppress(Exception):
                import qrcode  # optional extra

                qr = qrcode.QRCode(border=1)
                qr.add_data(update.qr)
                qr.make(fit=True)
                qr.print_ascii(invert=True)
                return

            print("QR string:", update.qr)

    async def on_creds_update(_creds) -> None:
        await auth_state.save_creds()

    async def on_msg(ev) -> None:
        # `ev` is a dict emitted by WhatsAppClient._on_message_stanza
        chat = ev.get("chat_jid")
        sender = ev.get("sender_jid")
        text = ev.get("text")
        if text:
            print(f"\n[rx] {chat} {sender}: {text}")

    async def on_history(ev) -> None:
        print(
            f"\n[history] conversations={ev.get('conversations')} progress={ev.get('progress')} type={ev.get('syncType')}"
        )

    async def on_err(ev) -> None:
        print("\n[decrypt_error]", ev)

    client.on("connection.update", on_update)
    client.on("creds.update", on_creds_update)
    client.on("message.decrypted", on_msg)
    client.on("message.decrypt_error", on_err)
    client.on("history.sync", on_history)

    await client.connect()

    print(
        "\nCommands: help, sync, sync_chat <jid> [n], chats, history <jid> [n], send <jid> <text>, send_image <jid> <path> [caption], send_ptt <jid> <path> [seconds], send_doc <jid> <path> [caption], send_vcard <jid> <path> [display_name], send_contacts <jid> <vcf1> <vcf2>..., send_location <jid> <lat> <lng> [name], download <chat_jid> <msg_id> <out>, me, quit\n"
    )

    while True:
        try:
            line = (await _ainput("> ")).strip()
        except (EOFError, KeyboardInterrupt):
            line = "quit"

        if not line:
            continue

        cmd, *rest = line.split(" ", 1)
        cmd = cmd.lower()
        argstr = rest[0] if rest else ""

        if cmd in ("quit", "exit"):
            break

        if cmd == "help":
            print("help")
            print("sync  (request full history sync from phone)")
            print("sync_chat <jid> [n]  (request on-demand history for a chat)")
            print("chats")
            print("history <jid> [n]")
            print("send <jid> <text>")
            print("send_image <jid> <path> [caption]")
            print("send_ptt <jid> <path> [seconds]")
            print("send_doc <jid> <path> [caption]")
            print("send_vcard <jid> <path> [display_name]")
            print("send_contacts <jid> <vcf1> <vcf2>...")
            print("send_location <jid> <lat> <lng> [name]")
            print("download <chat_jid> <msg_id> <out>")
            print("me")
            print("quit")
            continue

        if cmd == "me":
            print("me:", client.socket.auth.creds.me)
            continue

        if cmd == "chats":
            chats = client.store.list_chats()
            if not chats:
                print("(no chats yet; wait for history sync)")
                continue
            for c in chats:
                last = client.store.last_message(c.jid)
                last_s = f" last={_short(last.text, 60)!r}" if last else ""
                name_s = f" {c.name!r}" if c.name else ""
                extra = ""
                if c.pn_jid or c.lid_jid:
                    extra = f" pn={c.pn_jid or '-'} lid={c.lid_jid or '-'}"
                print(f"- {c.jid}{name_s}{last_s}{extra}")
            continue

        if cmd == "sync":
            try:
                req = await client.request_full_history_sync()
                print("requested:", req)
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "sync_chat":
            parts = argstr.split(" ", 1) if argstr else []
            if len(parts) < 1:
                print("usage: sync_chat <jid> [n]")
                continue
            chat_jid = parts[0]
            n = 50
            if len(parts) >= 2 and parts[1]:
                with contextlib.suppress(Exception):
                    n = int(parts[1])
            try:
                req = await client.request_chat_history(chat_jid, count=n)
                print("requested:", req)
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "history":
            parts = argstr.split(" ", 1) if argstr else []
            if len(parts) < 1:
                print("usage: history <jid> [n]")
                continue
            chat_jid = parts[0]
            n = 20
            if len(parts) >= 2 and parts[1]:
                with contextlib.suppress(Exception):
                    n = int(parts[1])
            msgs = client.store.get_messages(chat_jid, limit=n)
            for m in msgs:
                print(f"- {m.timestamp_s} {m.sender_jid or ''} {m.id}: {_short(m.text, 200)!r}")
            continue

        if cmd == "send":
            parts = argstr.split(" ", 1) if argstr else []
            if len(parts) < 2:
                print("usage: send <jid> <text>")
                continue
            jid = parts[0]
            text = parts[1]
            try:
                mid = await client.send_text(jid, text, wait_ack=True)
                print("sent:", mid)
            except SendRejectedError as e:
                print(f"rejected: error={e.code} ack={e.ack_attrs}")
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "send_image":
            parts = argstr.split(" ", 2) if argstr else []
            if len(parts) < 2:
                print("usage: send_image <jid> <path> [caption]")
                continue
            jid = parts[0]
            path = parts[1]
            caption = parts[2] if len(parts) >= 3 else None
            try:
                mid = await client.send_image_file(jid, path, caption=caption, wait_ack=True)
                print("sent:", mid)
            except SendRejectedError as e:
                print(f"rejected: error={e.code} ack={e.ack_attrs}")
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "send_ptt":
            parts = argstr.split(" ", 2) if argstr else []
            if len(parts) < 2:
                print("usage: send_ptt <jid> <path> [seconds]")
                continue
            jid = parts[0]
            path = parts[1]
            seconds = None
            if len(parts) >= 3 and parts[2]:
                with contextlib.suppress(Exception):
                    seconds = int(parts[2])
            try:
                mid = await client.send_voice_note_file(jid, path, seconds=seconds, wait_ack=True)
                print("sent:", mid)
            except SendRejectedError as e:
                print(f"rejected: error={e.code} ack={e.ack_attrs}")
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "send_doc":
            parts = argstr.split(" ", 2) if argstr else []
            if len(parts) < 2:
                print("usage: send_doc <jid> <path> [caption]")
                continue
            jid = parts[0]
            path = parts[1]
            caption = parts[2] if len(parts) >= 3 else None
            try:
                mid = await client.send_document_file(jid, path, caption=caption, wait_ack=True)
                print("sent:", mid)
            except SendRejectedError as e:
                print(f"rejected: error={e.code} ack={e.ack_attrs}")
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "send_vcard":
            parts = argstr.split(" ", 2) if argstr else []
            if len(parts) < 2:
                print("usage: send_vcard <jid> <path> [display_name]")
                continue
            jid = parts[0]
            path = parts[1]
            display_name = parts[2] if len(parts) >= 3 else Path(path).stem
            try:
                vcf = Path(path).expanduser().read_text("utf-8", errors="replace")
                mid = await client.send_contact(
                    jid, display_name=display_name, vcard=vcf, wait_ack=True
                )
                print("sent:", mid)
            except SendRejectedError as e:
                print(f"rejected: error={e.code} ack={e.ack_attrs}")
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "send_contacts":
            parts = argstr.split(" ") if argstr else []
            if len(parts) < 2:
                print("usage: send_contacts <jid> <vcf1> <vcf2>...")
                continue
            jid = parts[0]
            paths = parts[1:]
            contacts: list[tuple[str, str]] = []
            try:
                for p in paths:
                    vcf = Path(p).expanduser().read_text("utf-8", errors="replace")
                    contacts.append((Path(p).stem, vcf))
                mid = await client.send_contacts(jid, contacts, wait_ack=True)
                print("sent:", mid)
            except SendRejectedError as e:
                print(f"rejected: error={e.code} ack={e.ack_attrs}")
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "send_location":
            parts = argstr.split(" ", 3) if argstr else []
            if len(parts) < 3:
                print("usage: send_location <jid> <lat> <lng> [name]")
                continue
            jid = parts[0]
            try:
                lat = float(parts[1])
                lng = float(parts[2])
            except Exception:
                print("error: invalid lat/lng")
                continue
            name = parts[3] if len(parts) >= 4 else None
            try:
                mid = await client.send_location(
                    jid, latitude=lat, longitude=lng, name=name, wait_ack=True
                )
                print("sent:", mid)
            except SendRejectedError as e:
                print(f"rejected: error={e.code} ack={e.ack_attrs}")
            except Exception as e:
                print("error:", e)
            continue

        if cmd == "download":
            parts = argstr.split(" ", 2) if argstr else []
            if len(parts) < 3:
                print("usage: download <chat_jid> <msg_id> <out>")
                continue
            chat_jid, msg_id, out = parts[0], parts[1], parts[2]
            m = client.store.find_message(chat_jid, msg_id)
            if not m or not m.raw:
                print("error: message not found (or no raw payload stored)")
                continue
            try:
                data = await client.download_message_media(m.raw, validate=True)
                Path(out).expanduser().write_bytes(data)
                print(f"wrote {out} ({len(data)} bytes)")
            except Exception as e:
                print("error:", e)
            continue

        print(f"unknown command: {cmd} (try: help)")

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
