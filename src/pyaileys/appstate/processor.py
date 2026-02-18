"""
Syncd snapshot/patch decode + MAC verification + mutation processing.

Algorithm and flow are compatible with `wacore-appstate` (MIT):
Copyright (c) 2025 Joao Lucas de Oliveira Lopes
https://github.com/jlucaso1/whatsapp-rust
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..crypto.aes import aes_decrypt_cbc_pkcs7
from .keys import ExpandedAppStateKeys
from .lthash import WAPATCH_INTEGRITY


class AppStateError(Exception):
    pass


class KeyNotFound(AppStateError):
    pass


class SnapshotMACMismatch(AppStateError):
    pass


class PatchSnapshotMACMismatch(AppStateError):
    pass


class PatchMACMismatch(AppStateError):
    pass


class MismatchingContentMAC(AppStateError):
    pass


class MismatchingIndexMAC(AppStateError):
    pass


class DecryptionFailed(AppStateError):
    pass


class DecodeFailed(AppStateError):
    pass


@dataclass(slots=True)
class HashState:
    """
    Stored LT-hash state for an app-state collection.

    We intentionally mirror Baileys field names to keep keystore JSON compatible:
    - version: int
    - hash: bytes(128)
    - indexValueMap: dict[str(base64(indexMac)) -> bytes(valueMac)]
    """

    version: int = 0
    hash: bytes = b"\x00" * 128
    indexValueMap: dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def from_store(cls, obj: Any | None) -> HashState:
        if not isinstance(obj, dict):
            return cls()
        ver = int(obj.get("version") or 0)
        h = obj.get("hash")
        if not isinstance(h, (bytes, bytearray, memoryview)) or len(h) != 128:
            h = b"\x00" * 128
        ivm_raw = obj.get("indexValueMap")
        ivm: dict[str, bytes] = {}
        if isinstance(ivm_raw, dict):
            for k, v in ivm_raw.items():
                if not isinstance(k, str):
                    continue
                if isinstance(v, (bytes, bytearray, memoryview)):
                    ivm[k] = bytes(v)
        return cls(version=ver, hash=bytes(h), indexValueMap=ivm)

    def to_store(self) -> dict[str, Any]:
        return {"version": int(self.version), "hash": bytes(self.hash), "indexValueMap": dict(self.indexValueMap)}

    def update_hash_from_records(self, records: list[Any]) -> None:
        added: list[bytes] = []
        for rec in records:
            try:
                blob = rec.value.blob if rec.value and rec.value.blob else None
            except Exception:
                blob = None
            if isinstance(blob, (bytes, bytearray, memoryview)) and len(blob) >= 32:
                added.append(bytes(blob)[-32:])
        base = bytearray(self.hash)
        WAPATCH_INTEGRITY.subtract_then_add_in_place(base, subtract=[], add=added)
        self.hash = bytes(base)

    def update_hash(
        self,
        mutations: list[Any],
        get_prev_set_value_mac: Callable[[bytes, int], bytes | None],
    ) -> tuple[bool, None]:
        """
        Update LT-hash in place and return `has_missing_remove`.
        """

        added: list[bytes] = []
        removed: list[bytes] = []
        has_missing_remove = False

        for idx, mutation in enumerate(mutations):
            op = int(getattr(mutation, "operation", 0) or 0)
            rec = getattr(mutation, "record", None)
            if rec is not None:
                val = getattr(rec, "value", None)
                blob = getattr(val, "blob", None) if val is not None else None
                if op == 0 and isinstance(blob, (bytes, bytearray, memoryview)) and len(blob) >= 32:
                    added.append(bytes(blob)[-32:])

                ind = getattr(rec, "index", None)
                index_mac = getattr(ind, "blob", None) if ind is not None else None
                if isinstance(index_mac, (bytes, bytearray, memoryview)):
                    prev = get_prev_set_value_mac(bytes(index_mac), idx)
                    if isinstance(prev, (bytes, bytearray, memoryview)):
                        removed.append(bytes(prev))
                    elif op == 1:  # REMOVE
                        has_missing_remove = True

        base = bytearray(self.hash)
        WAPATCH_INTEGRITY.subtract_then_add_in_place(base, subtract=removed, add=added)
        self.hash = bytes(base)
        return has_missing_remove, None

    def generate_snapshot_mac(self, name: str, key: bytes) -> bytes:
        mac = hmac.new(key, digestmod=hashlib.sha256)
        mac.update(self.hash)
        mac.update(int(self.version).to_bytes(8, "big", signed=False))
        mac.update(name.encode("utf-8"))
        return mac.digest()


def generate_patch_mac(patch: Any, name: str, key: bytes, version: int) -> bytes:
    parts: list[bytes] = []
    snap = getattr(patch, "snapshotMac", None)
    if isinstance(snap, (bytes, bytearray, memoryview)) and bytes(snap):
        parts.append(bytes(snap))
    for m in list(getattr(patch, "mutations", []) or []):
        rec = getattr(m, "record", None)
        if rec is None:
            continue
        val = getattr(rec, "value", None)
        blob = getattr(val, "blob", None) if val is not None else None
        if isinstance(blob, (bytes, bytearray, memoryview)) and len(blob) >= 32:
            parts.append(bytes(blob)[-32:])
    parts.append(int(version).to_bytes(8, "big", signed=False))
    parts.append(name.encode("utf-8"))
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        mac.update(p)
    return mac.digest()


def generate_content_mac(operation: int, data: bytes, key_id: bytes, key: bytes) -> bytes:
    # operation is SyncdOperation (SET=0, REMOVE=1) => op_byte = operation + 1
    op_byte = bytes([(int(operation) & 0xFF) + 1])
    key_data_length = int(len(key_id) + 1).to_bytes(8, "big", signed=False)
    mac = hmac.new(key, digestmod=hashlib.sha512)
    mac.update(op_byte)
    mac.update(key_id)
    mac.update(data)
    mac.update(key_data_length)
    return mac.digest()[:32]


def validate_index_mac(index_json_bytes: bytes, expected_mac: bytes, key: bytes) -> None:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(index_json_bytes)
    computed = mac.digest()
    if not hmac.compare_digest(computed, expected_mac):
        raise MismatchingIndexMAC("mismatching index MAC")


@dataclass(frozen=True, slots=True)
class Mutation:
    action_value: Any | None
    index_mac: bytes
    value_mac: bytes
    index: list[str]
    operation: int


def _decode_record(
    *,
    operation: int,
    record: Any,
    keys: ExpandedAppStateKeys,
    key_id: bytes,
    validate_macs: bool,
) -> Mutation:
    from ..proto import WAProto_pb2 as proto

    value = getattr(record, "value", None)
    value_blob = getattr(value, "blob", None) if value is not None else None
    if not isinstance(value_blob, (bytes, bytearray, memoryview)):
        raise AppStateError("missing value blob in record")
    value_blob_b = bytes(value_blob)
    if len(value_blob_b) < 16 + 32:
        raise AppStateError("value blob too short")

    iv = value_blob_b[:16]
    rest = value_blob_b[16:]
    ciphertext = rest[:-32]
    value_mac = rest[-32:]

    if validate_macs:
        expected = generate_content_mac(operation, value_blob_b[:-32], key_id, keys.value_mac)
        if not hmac.compare_digest(expected, value_mac):
            raise MismatchingContentMAC("mismatching content MAC")

    try:
        plaintext = aes_decrypt_cbc_pkcs7(ciphertext, key=keys.value_encryption, iv=iv)
    except Exception as e:
        raise DecryptionFailed(str(e)) from e

    action = proto.SyncActionData()
    try:
        action.ParseFromString(plaintext)
    except Exception as e:
        raise DecodeFailed(str(e)) from e

    index_list: list[str] = []
    idx_bytes = bytes(action.index) if getattr(action, "index", None) else b""
    if idx_bytes:
        if validate_macs:
            ind = getattr(record, "index", None)
            exp_mac = getattr(ind, "blob", None) if ind is not None else None
            if not isinstance(exp_mac, (bytes, bytearray, memoryview)):
                raise AppStateError("missing index MAC in record")
            validate_index_mac(idx_bytes, bytes(exp_mac), keys.index)
        try:
            parsed = json.loads(idx_bytes.decode("utf-8"))
            if isinstance(parsed, list):
                index_list = [str(x) for x in parsed]
        except Exception:
            index_list = []

    ind = getattr(record, "index", None)
    index_mac = getattr(ind, "blob", None) if ind is not None else None
    index_mac_b = bytes(index_mac) if isinstance(index_mac, (bytes, bytearray, memoryview)) else b""

    action_value = action.value if action.HasField("value") else None
    return Mutation(
        action_value=action_value,
        index_mac=index_mac_b,
        value_mac=value_mac,
        index=index_list,
        operation=int(operation),
    )


@dataclass(frozen=True, slots=True)
class AppStateMutationMAC:
    index_mac: bytes
    value_mac: bytes


@dataclass(frozen=True, slots=True)
class ProcessedSnapshot:
    state: HashState
    mutations: list[Mutation]
    mutation_macs: list[AppStateMutationMAC]


@dataclass(frozen=True, slots=True)
class PatchProcessingResult:
    state: HashState
    mutations: list[Mutation]
    added_macs: list[AppStateMutationMAC]
    removed_index_macs: list[bytes]
    has_missing_remove: bool


def validate_snapshot_mac(snapshot: Any, state: HashState, keys: ExpandedAppStateKeys, name: str) -> None:
    mac_expected = getattr(snapshot, "mac", None)
    if (
        isinstance(mac_expected, (bytes, bytearray, memoryview))
        and bytes(mac_expected)
        and (not hasattr(snapshot, "HasField") or snapshot.HasField("mac"))
    ):
        computed = state.generate_snapshot_mac(name, keys.snapshot_mac)
        if not hmac.compare_digest(computed, bytes(mac_expected)):
            raise SnapshotMACMismatch("snapshot MAC mismatch")


def validate_patch_macs(
    patch: Any,
    state: HashState,
    keys: ExpandedAppStateKeys,
    name: str,
    *,
    had_no_prior_state: bool,
    has_missing_remove: bool,
) -> None:
    if had_no_prior_state:
        return

    snap_mac = getattr(patch, "snapshotMac", None)
    if (
        isinstance(snap_mac, (bytes, bytearray, memoryview))
        and bytes(snap_mac)
        and (not hasattr(patch, "HasField") or patch.HasField("snapshotMac"))
    ):
        computed_snap = state.generate_snapshot_mac(name, keys.snapshot_mac)
        if (not hmac.compare_digest(computed_snap, bytes(snap_mac))) and not has_missing_remove:
            raise PatchSnapshotMACMismatch("patch snapshot MAC mismatch")

    patch_mac = getattr(patch, "patchMac", None)
    if (
        isinstance(patch_mac, (bytes, bytearray, memoryview))
        and bytes(patch_mac)
        and (not hasattr(patch, "HasField") or patch.HasField("patchMac"))
    ):
        ver = 0
        try:
            ver = int(getattr(getattr(patch, "version", None), "version", 0) or 0)
        except Exception:
            ver = 0
        computed_patch = generate_patch_mac(patch, name, keys.patch_mac, ver)
        if (not hmac.compare_digest(computed_patch, bytes(patch_mac))) and not has_missing_remove:
            raise PatchMACMismatch("patch MAC mismatch")


def process_snapshot(
    snapshot: Any,
    initial_state: HashState,
    get_keys: Callable[[bytes], ExpandedAppStateKeys],
    *,
    validate_macs: bool,
    collection_name: str,
) -> ProcessedSnapshot:
    # version
    try:
        initial_state.version = int(getattr(getattr(snapshot, "version", None), "version", 0) or 0)
    except Exception:
        initial_state.version = 0

    # reset hash for snapshot processing
    initial_state.hash = b"\x00" * 128
    initial_state.indexValueMap = {}
    initial_state.update_hash_from_records(list(getattr(snapshot, "records", []) or []))

    if validate_macs:
        kid = getattr(getattr(snapshot, "keyId", None), "id", None)
        if isinstance(kid, (bytes, bytearray, memoryview)):
            keys = get_keys(bytes(kid))
            validate_snapshot_mac(snapshot, initial_state, keys, collection_name)

    mutations: list[Mutation] = []
    mutation_macs: list[AppStateMutationMAC] = []

    records = list(getattr(snapshot, "records", []) or [])
    for rec in records:
        kid = getattr(getattr(rec, "keyId", None), "id", None)
        if not isinstance(kid, (bytes, bytearray, memoryview)):
            raise AppStateError("missing key ID in record")
        kid_b = bytes(kid)
        keys = get_keys(kid_b)
        mut = _decode_record(
            operation=0,  # SET
            record=rec,
            keys=keys,
            key_id=kid_b,
            validate_macs=validate_macs,
        )
        mutations.append(mut)
        mutation_macs.append(AppStateMutationMAC(index_mac=mut.index_mac, value_mac=mut.value_mac))

    return ProcessedSnapshot(state=HashState.from_store(initial_state.to_store()), mutations=mutations, mutation_macs=mutation_macs)


def process_patch(
    patch: Any,
    state: HashState,
    get_keys: Callable[[bytes], ExpandedAppStateKeys],
    get_prev_value_mac: Callable[[bytes], bytes | None],
    *,
    validate_macs: bool,
    collection_name: str,
) -> PatchProcessingResult:
    original_version = int(state.version or 0)
    original_hash_is_empty = state.hash == (b"\x00" * 128)
    had_no_prior_state = original_version == 0 and original_hash_is_empty

    try:
        state.version = int(getattr(getattr(patch, "version", None), "version", 0) or 0)
    except Exception:
        state.version = 0

    muts = list(getattr(patch, "mutations", []) or [])

    def _get_prev(index_mac: bytes, idx: int) -> bytes | None:
        # First check previous mutations in this patch (overwrites).
        for prev in reversed(muts[:idx]):
            rec = getattr(prev, "record", None)
            if rec is None:
                continue
            ind = getattr(rec, "index", None)
            b = getattr(ind, "blob", None) if ind is not None else None
            if not isinstance(b, (bytes, bytearray, memoryview)) or bytes(b) != index_mac:
                continue
            val = getattr(rec, "value", None)
            vb = getattr(val, "blob", None) if val is not None else None
            if isinstance(vb, (bytes, bytearray, memoryview)) and len(vb) >= 32:
                return bytes(vb)[-32:]
        return get_prev_value_mac(index_mac)

    has_missing_remove, _ = state.update_hash(muts, _get_prev)

    if validate_macs:
        kid = getattr(getattr(patch, "keyId", None), "id", None)
        if isinstance(kid, (bytes, bytearray, memoryview)):
            keys = get_keys(bytes(kid))
            validate_patch_macs(
                patch,
                state,
                keys,
                collection_name,
                had_no_prior_state=had_no_prior_state,
                has_missing_remove=has_missing_remove,
            )

    mutations: list[Mutation] = []
    added_macs: list[AppStateMutationMAC] = []
    removed_index_macs: list[bytes] = []

    for m in muts:
        rec = getattr(m, "record", None)
        if rec is None:
            continue
        op = int(getattr(m, "operation", 0) or 0)
        kid = getattr(getattr(rec, "keyId", None), "id", None)
        if not isinstance(kid, (bytes, bytearray, memoryview)):
            raise AppStateError("missing key ID in record")
        kid_b = bytes(kid)
        keys = get_keys(kid_b)
        mut = _decode_record(
            operation=op,
            record=rec,
            keys=keys,
            key_id=kid_b,
            validate_macs=validate_macs,
        )
        mutations.append(mut)
        if op == 0:
            added_macs.append(AppStateMutationMAC(index_mac=mut.index_mac, value_mac=mut.value_mac))
        elif op == 1:
            removed_index_macs.append(mut.index_mac)

    return PatchProcessingResult(
        state=HashState.from_store(state.to_store()),
        mutations=mutations,
        added_macs=added_macs,
        removed_index_macs=removed_index_macs,
        has_missing_remove=has_missing_remove,
    )


def b64_index(mac: bytes) -> str:
    return base64.b64encode(mac).decode("ascii")
