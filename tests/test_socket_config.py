from __future__ import annotations

from pyaileys.socket_config import SocketConfig


def test_default_config_advertises_current_baileys_web_version() -> None:
    assert SocketConfig().version == (2, 3000, 1043857760)


def test_default_config_uses_current_baileys_mac_chrome_fingerprint() -> None:
    assert SocketConfig().browser == ("Mac OS", "Chrome")
