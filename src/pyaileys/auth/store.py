from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..exceptions import AuthError
from ..util import json as bufferjson
from .creds import AuthenticationCreds
from .serde import creds_from_dict
from .utils import init_auth_creds

_FILE_LOCKS: dict[Path, asyncio.Lock] = {}


def _fix_filename(name: str) -> str:
    return name.replace("/", "__").replace(":", "-")


def _lock_for(path: Path) -> asyncio.Lock:
    lock = _FILE_LOCKS.get(path)
    if lock is None:
        lock = asyncio.Lock()
        _FILE_LOCKS[path] = lock
    return lock


async def _read_text(path: Path) -> str:
    return await asyncio.to_thread(path.read_text, "utf-8")


async def _write_text(path: Path, data: str) -> None:
    await asyncio.to_thread(path.write_text, data, "utf-8")


async def _unlink(path: Path) -> None:
    await asyncio.to_thread(path.unlink, missing_ok=True)  # py311+


class MultiFileKeyStore:
    def __init__(self, folder: Path) -> None:
        self._folder = folder

    async def get(self, key_type: str, ids: list[str]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key_id in ids:
            fn = self._folder / _fix_filename(f"{key_type}-{key_id}.json")
            try:
                lock = _lock_for(fn)
                async with lock:
                    raw = await _read_text(fn)
                out[key_id] = bufferjson.loads(raw)
            except FileNotFoundError:
                out[key_id] = None
        return out

    async def set(self, data: Mapping[str, Mapping[str, Any | None]]) -> None:
        tasks: list[asyncio.Task[None]] = []
        for category, items in data.items():
            for key_id, value in items.items():
                fn = self._folder / _fix_filename(f"{category}-{key_id}.json")
                if value is None:
                    tasks.append(asyncio.create_task(self._remove(fn)))
                else:
                    tasks.append(asyncio.create_task(self._write(fn, value)))
        if tasks:
            await asyncio.gather(*tasks)

    async def clear(self) -> None:
        for p in self._folder.glob("*.json"):
            if p.name == "creds.json":
                continue
            await self._remove(p)

    async def _write(self, path: Path, obj: Any) -> None:
        lock = _lock_for(path)
        async with lock:
            await _write_text(path, bufferjson.dumps(obj))

    async def _remove(self, path: Path) -> None:
        lock = _lock_for(path)
        async with lock:
            await _unlink(path)


class MultiFileAuthState:
    """
    Baileys-style multi-file auth state.

    - `creds.json` stores the credential bundle.
    - key material is stored as `{type}-{id}.json` files.
    """

    def __init__(self, folder: Path, creds: AuthenticationCreds) -> None:
        self.folder = folder
        self.creds = creds
        self.keys = MultiFileKeyStore(folder)

    @classmethod
    async def load(cls, folder: str | Path) -> MultiFileAuthState:
        p = Path(folder).expanduser()
        await asyncio.to_thread(p.mkdir, parents=True, exist_ok=True)

        creds_path = p / "creds.json"
        if creds_path.exists():
            try:
                lock = _lock_for(creds_path)
                async with lock:
                    raw = await _read_text(creds_path)
                d = bufferjson.loads(raw)
                if not isinstance(d, dict):
                    raise TypeError("creds.json did not contain an object")
                creds = creds_from_dict(d)
            except Exception as e:  # pragma: no cover
                raise AuthError(f"failed to load creds from {creds_path}: {e}") from e
        else:
            creds = init_auth_creds()

        return cls(p, creds)

    async def save_creds(self) -> None:
        creds_path = self.folder / "creds.json"
        lock = _lock_for(creds_path)
        async with lock:
            await _write_text(creds_path, bufferjson.dumps(asdict(self.creds), indent=2))
