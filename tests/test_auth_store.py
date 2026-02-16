from __future__ import annotations

import pytest

from pyaileys.auth.store import MultiFileAuthState


@pytest.mark.asyncio
async def test_multifile_auth_state_roundtrip(tmp_path) -> None:
    a1 = await MultiFileAuthState.load(tmp_path)
    await a1.save_creds()

    a2 = await MultiFileAuthState.load(tmp_path)

    assert a1.creds.adv_secret_key == a2.creds.adv_secret_key
    assert a1.creds.noise_key.public == a2.creds.noise_key.public
    assert a1.creds.noise_key.private == a2.creds.noise_key.private


@pytest.mark.asyncio
async def test_multifile_keystore_set_get(tmp_path) -> None:
    auth = await MultiFileAuthState.load(tmp_path)
    await auth.keys.set({"session": {"abc": {"some": "value"}}})

    got = await auth.keys.get("session", ["abc", "missing"])
    assert got["abc"] == {"some": "value"}
    assert got["missing"] is None
