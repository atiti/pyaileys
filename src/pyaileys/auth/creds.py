from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class KeyPair:
    public: bytes
    private: bytes


@dataclass(slots=True)
class SignedKeyPair:
    key_pair: KeyPair
    signature: bytes
    key_id: int
    timestamp_s: int | None = None


@dataclass(slots=True)
class Contact:
    id: str  # JID
    name: str | None = None
    lid: str | None = None


@dataclass(slots=True)
class AccountSettings:
    unarchive_chats: bool = False
    default_disappearing_mode: dict[str, Any] | None = None


@dataclass(slots=True)
class AuthenticationCreds:
    """
    Rough Python mirror of Baileys' `AuthenticationCreds`.

    This structure is intentionally "wide" so we can persist everything needed for
    multi-device sessions as the implementation matures.
    """

    # Signal / identity material
    noise_key: KeyPair
    pairing_ephemeral_key_pair: KeyPair
    signed_identity_key: KeyPair
    signed_pre_key: SignedKeyPair
    registration_id: int

    # Pairing / ADV
    adv_secret_key: str

    # Session identity
    me: Contact | None = None
    account: Any | None = None
    signal_identities: list[dict[str, Any]] | None = None
    my_app_state_key_id: str | None = None

    # Key counters
    first_unuploaded_pre_key_id: int = 1
    next_pre_key_id: int = 1

    # Sync state
    last_account_sync_timestamp: int | None = None
    platform: str | None = None
    processed_history_messages: list[Any] = field(default_factory=list)
    account_sync_counter: int = 0
    account_settings: AccountSettings = field(default_factory=AccountSettings)
    registered: bool = False
    pairing_code: str | None = None
    last_prop_hash: str | None = None
    routing_info: bytes | None = None
    additional_data: Any | None = None
