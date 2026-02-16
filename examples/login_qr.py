from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path

from pyaileys import WhatsAppClient


async def main() -> None:
    auth_dir = Path("./auth").resolve()
    client, auth_state = await WhatsAppClient.from_auth_folder(str(auth_dir))

    last_qr: str | None = None

    async def on_update(update) -> None:
        nonlocal last_qr
        if update.qr and update.qr != last_qr:
            last_qr = update.qr
            print("\nScan this QR in WhatsApp -> Settings -> Linked devices -> Link a device\n")
            with contextlib.suppress(Exception):
                import qrcode  # optional extra
                from qrcode.image.svg import SvgImage

                # Write a scannable QR to disk.
                svg_path = auth_dir / "qr.svg"
                img = qrcode.make(update.qr, image_factory=SvgImage)
                svg_path.write_bytes(img.to_string())
                print(f"wrote {svg_path}")

                qr = qrcode.QRCode(border=1)
                qr.add_data(update.qr)
                qr.make(fit=True)
                qr.print_ascii(invert=True)
                return

            print("QR string:", update.qr)
        if update.connection:
            print("connection:", update.connection)

    client.on("connection.update", on_update)

    async def on_creds_update(_creds) -> None:
        await auth_state.save_creds()

    client.on("creds.update", on_creds_update)

    await client.connect()
    await auth_state.save_creds()

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
