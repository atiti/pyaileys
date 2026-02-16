from __future__ import annotations

from typing import Any

from .creds import AccountSettings, AuthenticationCreds, Contact, KeyPair, SignedKeyPair


def _expect_bytes(v: Any, *, field: str) -> bytes:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    raise TypeError(f"Expected bytes for {field}, got {type(v).__name__}")


def keypair_from_dict(d: dict[str, Any]) -> KeyPair:
    return KeyPair(
        public=_expect_bytes(d["public"], field="KeyPair.public"),
        private=_expect_bytes(d["private"], field="KeyPair.private"),
    )


def signed_keypair_from_dict(d: dict[str, Any]) -> SignedKeyPair:
    return SignedKeyPair(
        key_pair=keypair_from_dict(d["key_pair"]),
        signature=_expect_bytes(d.get("signature", b""), field="SignedKeyPair.signature"),
        key_id=int(d["key_id"]),
        timestamp_s=int(d["timestamp_s"]) if d.get("timestamp_s") is not None else None,
    )


def contact_from_dict(d: dict[str, Any]) -> Contact:
    return Contact(id=str(d["id"]), name=d.get("name"), lid=d.get("lid"))


def account_settings_from_dict(d: dict[str, Any]) -> AccountSettings:
    return AccountSettings(
        unarchive_chats=bool(d.get("unarchive_chats", False)),
        default_disappearing_mode=d.get("default_disappearing_mode"),
    )


def creds_from_dict(d: dict[str, Any]) -> AuthenticationCreds:
    return AuthenticationCreds(
        noise_key=keypair_from_dict(d["noise_key"]),
        pairing_ephemeral_key_pair=keypair_from_dict(d["pairing_ephemeral_key_pair"]),
        signed_identity_key=keypair_from_dict(d["signed_identity_key"]),
        signed_pre_key=signed_keypair_from_dict(d["signed_pre_key"]),
        registration_id=int(d["registration_id"]),
        adv_secret_key=str(d["adv_secret_key"]),
        me=contact_from_dict(d["me"]) if d.get("me") else None,
        account=d.get("account"),
        signal_identities=d.get("signal_identities"),
        my_app_state_key_id=d.get("my_app_state_key_id"),
        first_unuploaded_pre_key_id=int(d.get("first_unuploaded_pre_key_id", 1)),
        next_pre_key_id=int(d.get("next_pre_key_id", 1)),
        last_account_sync_timestamp=d.get("last_account_sync_timestamp"),
        platform=d.get("platform"),
        processed_history_messages=list(d.get("processed_history_messages") or []),
        account_sync_counter=int(d.get("account_sync_counter", 0)),
        account_settings=account_settings_from_dict(d.get("account_settings") or {}),
        registered=bool(d.get("registered", False)),
        pairing_code=d.get("pairing_code"),
        last_prop_hash=d.get("last_prop_hash"),
        routing_info=d.get("routing_info"),
        additional_data=d.get("additional_data"),
    )
