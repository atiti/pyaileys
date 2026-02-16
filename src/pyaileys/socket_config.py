from __future__ import annotations

from dataclasses import dataclass, field

from .constants import DEFAULT_WS_URL


@dataclass(slots=True)
class SocketConfig:
    ws_url: str = DEFAULT_WS_URL
    version: tuple[int, int, int] = (2, 3000, 1033105955)
    browser: tuple[str, str] = ("Mac OS", "Desktop")
    country_code: str = "US"

    connect_timeout_s: float = 20.0
    keep_alive_interval_s: float = 30.0

    sync_full_history: bool = True
    verify_certificates: bool = True

    headers: dict[str, str] = field(default_factory=dict)
