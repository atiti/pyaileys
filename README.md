# pyaileys

[![CI](https://github.com/atiti/pyaileys/actions/workflows/ci.yml/badge.svg)](https://github.com/atiti/pyaileys/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pyaileys.svg)](https://pypi.org/project/pyaileys/)
[![Python Versions](https://img.shields.io/pypi/pyversions/pyaileys.svg)](https://pypi.org/project/pyaileys/)
[![License](https://img.shields.io/pypi/l/pyaileys.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://github.com/astral-sh/ruff)

Async WhatsApp Web (Multi-Device) protocol client in pure Python, inspired by Baileys.

## What This Is

- WebSocket protocol client (no browser automation)
- QR pairing + multi-device session persistence (Baileys-like auth folder)
- `asyncio` API for receiving stanzas/events and sending messages
- Minimal runtime deps: `websockets`, `protobuf`, `cryptography`

## Status

This is an early-stage protocol client.

What works today:

- MD session login + QR pairing
- Basic 1:1 Signal E2E (`pkmsg`/`msg`) decrypt/encrypt
- Basic text send (with multi-device fanout)
- Typing/recording indications (`chatstate`)
- Media send (image, PTT voice note, documents, static location, contacts)
- Media download/decrypt (image, audio/PTT, documents)
- History Sync ingestion into an in-memory store

## Limitations (Important)

- Group E2E (`skmsg`) / Sender Keys: not implemented
- Media support is partial: no video/stickers yet, and no automatic thumbnails/duration/waveform
- App-state sync + rich chat/contact model: minimal (demo store)
- API stability: no guarantees yet (pre-1.0)

## Legal / Safety

This project is not affiliated with WhatsApp/Meta. Using unofficial clients may violate WhatsApp Terms of Service.
You are responsible for compliance and for preventing abuse (spam/automation).

## Installation

```bash
pip install pyaileys
```

Optional (pretty QR output in terminal + SVG QR file):

```bash
pip install "pyaileys[qrcode]"
```

## Quickstart (Pair + Connect)

```python
import asyncio

from pyaileys import WhatsAppClient


async def main() -> None:
    client, auth_state = await WhatsAppClient.from_auth_folder("./auth")

    async def on_update(update) -> None:
        # update is `pyaileys.socket.ConnectionUpdate`
        if update.qr:
            print("QR string:", update.qr)
        if update.connection:
            print("connection:", update.connection)

    async def on_creds_update(_creds) -> None:
        await auth_state.save_creds()

    client.on("connection.update", on_update)
    client.on("creds.update", on_creds_update)

    await client.connect()
    await auth_state.save_creds()

    # keep the process alive
    await asyncio.Event().wait()


asyncio.run(main())
```

## Examples

Kitchen sink (interactive):

```bash
python examples/demo_app.py --auth ./auth --log-nodes
```

Simple CLI (decrypt + store + send text/media):

```bash
python examples/simple_cli.py --auth ./auth
```

QR-only helper (writes `qr.svg` into the auth dir if `qrcode` extra is installed):

```bash
python examples/login_qr.py
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

ruff check .
ruff format .
mypy src/pyaileys
pytest -q
```

## Releasing to PyPI (Trusted Publishing)

This repo includes a GitHub Actions workflow (`.github/workflows/release.yml`) that publishes to PyPI when you push a
tag like `v0.1.0`.

- Bump versions in `pyproject.toml` and `src/pyaileys/__init__.py`
- Tag and push: `git tag vX.Y.Z && git push --tags`

## Regenerating Generated Files

`wabinary` token tables are generated from a Baileys checkout:

```bash
git clone https://github.com/WhiskeySockets/Baileys.git /path/to/Baileys
python3 tools/gen_wabinary_constants.py --baileys /path/to/Baileys
```

`proto/WAProto.proto` is vendored from Baileys and patched to satisfy `protoc`:

```bash
python3 tools/patch_waproto_for_protoc.py
protoc -Iproto --python_out=src/pyaileys/proto proto/WAProto.proto
```

## Credits

- Inspired by the Baileys TypeScript library (MIT): https://github.com/WhiskeySockets/Baileys

## Contributing

See `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md`.
