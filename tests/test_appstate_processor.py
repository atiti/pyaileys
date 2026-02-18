from __future__ import annotations

import hashlib
import hmac
import json

from pyaileys.appstate.keys import expand_app_state_keys
from pyaileys.appstate.lthash import WAPATCH_INTEGRITY
from pyaileys.appstate.processor import (
    HashState,
    b64_index,
    generate_content_mac,
    generate_patch_mac,
    process_patch,
    process_snapshot,
)
from pyaileys.crypto.aes import aes_encrypt_cbc_pkcs7
from pyaileys.proto import WAProto_pb2 as proto


def _make_record(
    *,
    op: int,
    keys,
    key_id: bytes,
    index: list[str],
    timestamp: int,
) -> proto.SyncdRecord:
    idx_json = json.dumps(index, separators=(",", ":")).encode("utf-8")
    idx_mac = hmac.new(keys.index, idx_json, hashlib.sha256).digest()

    action = proto.SyncActionData()
    action.index = idx_json
    action.value.timestamp = int(timestamp)
    plaintext = action.SerializeToString()

    iv = b"\x00" * 16
    ciphertext = aes_encrypt_cbc_pkcs7(plaintext, key=keys.value_encryption, iv=iv)
    value_with_iv = iv + ciphertext
    value_mac = generate_content_mac(op, value_with_iv, key_id, keys.value_mac)
    value_blob = value_with_iv + value_mac

    rec = proto.SyncdRecord()
    rec.index.blob = idx_mac
    rec.value.blob = value_blob
    rec.keyId.id = key_id
    return rec


def test_expand_app_state_keys_deterministic() -> None:
    key = b"\x07" * 32
    a = expand_app_state_keys(key)
    b = expand_app_state_keys(key)
    assert a == b
    assert len(a.index) == 32
    assert len(a.value_encryption) == 32
    assert len(a.value_mac) == 32
    assert len(a.snapshot_mac) == 32
    assert len(a.patch_mac) == 32


def test_lthash_add_then_subtract_round_trip() -> None:
    base = bytearray(b"\x00" * 128)
    item = b"\x01" * 32
    WAPATCH_INTEGRITY.subtract_then_add_in_place(base, subtract=[], add=[item])
    assert bytes(base) != (b"\x00" * 128)
    WAPATCH_INTEGRITY.subtract_then_add_in_place(base, subtract=[item], add=[])
    assert bytes(base) == (b"\x00" * 128)


def test_process_snapshot_decodes_index_and_updates_hash() -> None:
    master = b"\x07" * 32
    keys = expand_app_state_keys(master)
    key_id = b"test_key_id"
    index = ["mute", "123@s.whatsapp.net"]

    rec = _make_record(op=0, keys=keys, key_id=key_id, index=index, timestamp=1234567890)

    snap = proto.SyncdSnapshot()
    snap.version.version = 1
    snap.keyId.id = key_id
    snap.records.append(rec)

    state = HashState()
    res = process_snapshot(
        snap,
        state,
        lambda _kid: keys,
        validate_macs=True,
        collection_name="regular",
    )

    assert res.state.version == 1
    assert res.state.hash != (b"\x00" * 128)
    assert len(res.mutations) == 1
    assert res.mutations[0].index == index


def test_process_patch_overwrite_with_mac_validation() -> None:
    master = b"\x07" * 32
    keys = expand_app_state_keys(master)
    key_id = b"test_key_id"
    idx = ["markChatAsRead", "123@s.whatsapp.net"]

    rec1 = _make_record(op=0, keys=keys, key_id=key_id, index=idx, timestamp=1000)
    snap = proto.SyncdSnapshot()
    snap.version.version = 1
    snap.keyId.id = key_id
    snap.records.append(rec1)

    state = HashState()
    snap_res = process_snapshot(
        snap,
        state,
        lambda _kid: keys,
        validate_macs=False,
        collection_name="regular",
    )
    state = snap_res.state
    for mm in snap_res.mutation_macs:
        state.indexValueMap[b64_index(mm.index_mac)] = mm.value_mac

    # Overwrite same index with a new value
    rec2 = _make_record(op=0, keys=keys, key_id=key_id, index=idx, timestamp=2000)
    patch = proto.SyncdPatch()
    patch.version.version = 2
    patch.keyId.id = key_id
    mut = patch.mutations.add()
    mut.operation = proto.SyncdMutation.SyncdOperation.SET
    mut.record.CopyFrom(rec2)

    # Pre-compute expected snapshotMac/patchMac for validation.
    tmp = HashState.from_store(state.to_store())
    tmp.version = 2

    def _prev(index_mac: bytes) -> bytes | None:
        return state.indexValueMap.get(b64_index(index_mac))

    tmp.update_hash(list(patch.mutations), lambda mac, _i: _prev(mac))
    patch.snapshotMac = tmp.generate_snapshot_mac("regular", keys.snapshot_mac)
    patch.patchMac = generate_patch_mac(patch, "regular", keys.patch_mac, 2)

    res = process_patch(
        patch,
        state,
        lambda _kid: keys,
        _prev,
        validate_macs=True,
        collection_name="regular",
    )
    assert res.state.version == 2
    assert len(res.added_macs) == 1

