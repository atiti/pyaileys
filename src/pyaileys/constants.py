from __future__ import annotations

DEFAULT_ORIGIN = "https://web.whatsapp.com"
DEFAULT_WS_URL = "wss://web.whatsapp.com/ws/chat"

NOISE_MODE = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0"
DICT_VERSION = 3
NOISE_WA_HEADER = bytes([87, 65, 6, DICT_VERSION])  # "WA" + version tuple

# Libsignal/Baileys: version byte required for some key bundle encodings.
KEY_BUNDLE_TYPE = b"\x05"

# ADV / pairing signature prefixes (mirrors Baileys Defaults).
WA_ADV_ACCOUNT_SIG_PREFIX = bytes([6, 0])
WA_ADV_DEVICE_SIG_PREFIX = bytes([6, 1])
WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX = bytes([6, 5])
WA_ADV_HOSTED_DEVICE_SIG_PREFIX = bytes([6, 6])

# Values mirrored from Baileys Defaults (MIT) for Noise certificate validation.
WA_CERT_SERIAL = 0
WA_CERT_ISSUER = "WhatsAppLongTerm1"
WA_CERT_PUBLIC_KEY = bytes.fromhex(
    "142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b"
)
