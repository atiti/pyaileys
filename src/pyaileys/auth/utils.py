from __future__ import annotations

import base64
import secrets

from ..constants import KEY_BUNDLE_TYPE
from ..crypto.curve import Curve25519Provider, DefaultCurve25519Provider
from .creds import AuthenticationCreds, SignedKeyPair


def generate_registration_id() -> int:
    # Match Baileys: Uint16 & 16383 (14 bits)
    return (int.from_bytes(secrets.token_bytes(2), "big") & 16383) or 1


def init_auth_creds(*, curve: Curve25519Provider | None = None) -> AuthenticationCreds:
    """
    Initialize a new credential bundle.
    """

    curve = curve or DefaultCurve25519Provider()

    signed_identity = curve.generate_keypair()
    pre_key = curve.generate_keypair()

    # Baileys/libsignal: signature is over the version-prefixed pre-key public key.
    signature = curve.sign(signed_identity.private, KEY_BUNDLE_TYPE + pre_key.public)

    return AuthenticationCreds(
        noise_key=curve.generate_keypair(),
        pairing_ephemeral_key_pair=curve.generate_keypair(),
        signed_identity_key=signed_identity,
        signed_pre_key=SignedKeyPair(key_pair=pre_key, signature=signature, key_id=1),
        registration_id=generate_registration_id(),
        adv_secret_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        processed_history_messages=[],
        next_pre_key_id=1,
        first_unuploaded_pre_key_id=1,
        account_sync_counter=0,
        registered=False,
        pairing_code=None,
        last_prop_hash=None,
        routing_info=None,
        additional_data=None,
    )
