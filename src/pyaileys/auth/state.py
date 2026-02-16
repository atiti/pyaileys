from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .creds import AuthenticationCreds


class SignalKeyStore(Protocol):
    async def get(self, key_type: str, ids: list[str]) -> dict[str, Any]: ...

    async def set(self, data: Mapping[str, Mapping[str, Any | None]]) -> None: ...

    async def clear(self) -> None: ...


@dataclass(slots=True)
class AuthenticationState:
    creds: AuthenticationCreds
    keys: SignalKeyStore
