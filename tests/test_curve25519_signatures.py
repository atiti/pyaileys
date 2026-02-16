from __future__ import annotations

from pyaileys.auth.utils import init_auth_creds
from pyaileys.crypto.curve import DefaultCurve25519Provider


def test_curve25519_signature_known_vector() -> None:
    """
    Test vector generated with Node + curve25519-js.
    """

    curve = DefaultCurve25519Provider()

    priv = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f")
    pub = bytes.fromhex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f")
    msg = b"pyaileys-test"

    expected_sig = bytes.fromhex(
        "57968243e94390d78e51c15540cec7379e19800128afa8ffdc36f898ffa770c2"
        "230aa18f6dfeaa3ab702b7bce6019a2139560904437ecabba540122d6414c80d"
    )

    sig = curve.sign(priv, msg)
    assert sig == expected_sig
    assert curve.verify(pub, msg, sig) is True
    assert curve.verify(b"\x05" + pub, msg, sig) is True


def test_init_auth_creds_generates_signed_pre_key_signature() -> None:
    creds = init_auth_creds()
    assert len(creds.signed_pre_key.signature) == 64
