"""
USync (user sync) helpers.

WhatsApp Web uses USync queries to:
- resolve the list of devices for a set of users (for multi-device fanout)
- optionally resolve LID mappings

This module provides a minimal subset needed for message sending.
"""

from __future__ import annotations

from dataclasses import dataclass

from .wabinary import S_WHATSAPP_NET
from .wabinary.jid import jid_decode, jid_encode
from .wabinary.types import BinaryNode


@dataclass(frozen=True, slots=True)
class USyncDevice:
    device_id: int
    key_index: int | None = None
    is_hosted: bool = False


@dataclass(frozen=True, slots=True)
class USyncDevicesResult:
    device_list: list[USyncDevice]


@dataclass(frozen=True, slots=True)
class USyncUserResult:
    id: str
    devices: USyncDevicesResult | None = None
    lid: str | None = None


def _child(node: BinaryNode | None, tag: str) -> BinaryNode | None:
    if not node or not isinstance(node.content, list):
        return None
    for c in node.content:
        if isinstance(c, BinaryNode) and c.tag == tag:
            return c
    return None


def _children(node: BinaryNode | None, tag: str) -> list[BinaryNode]:
    if not node or not isinstance(node.content, list):
        return []
    out: list[BinaryNode] = []
    for c in node.content:
        if isinstance(c, BinaryNode) and c.tag == tag:
            out.append(c)
    return out


def build_usync_iq(
    user_jids: list[str],
    *,
    sid: str,
    context: str = "message",
    mode: str = "query",
    include_device_protocol: bool = True,
    include_lid_protocol: bool = True,
) -> BinaryNode:
    """
    Build a USync IQ node for `executeUSyncQuery` (Baileys).

    Note: user nodes intentionally have an empty child list for now, because we
    do not support per-user protocol elements (e.g., providing a known LID).
    """

    protocols: list[BinaryNode] = []
    if include_device_protocol:
        protocols.append(BinaryNode(tag="devices", attrs={"version": "2"}))
    if include_lid_protocol:
        protocols.append(BinaryNode(tag="lid", attrs={}))

    query_node = BinaryNode(tag="query", attrs={}, content=protocols)

    # Mirror Baileys: pass a `user` node per JID. Content is an explicit empty list
    # (encodes as LIST_EMPTY) rather than absent.
    uniq = list(dict.fromkeys([j for j in user_jids if j]))
    list_node = BinaryNode(
        tag="list",
        attrs={},
        content=[BinaryNode(tag="user", attrs={"jid": jid}, content=[]) for jid in uniq],
    )

    return BinaryNode(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "usync"},
        content=[
            BinaryNode(
                tag="usync",
                attrs={"context": context, "mode": mode, "sid": sid, "last": "true", "index": "0"},
                content=[query_node, list_node],
            )
        ],
    )


def _parse_devices_node(node: BinaryNode) -> USyncDevicesResult:
    # Port of Baileys' USyncDeviceProtocol parser (subset: only deviceList).
    device_list: list[USyncDevice] = []

    device_list_node = _child(node, "device-list")
    if device_list_node and isinstance(device_list_node.content, list):
        for c in device_list_node.content:
            if not isinstance(c, BinaryNode) or c.tag != "device":
                continue
            raw_id = c.attrs.get("id")
            if not raw_id:
                continue
            try:
                device_id = int(raw_id)
            except Exception:
                continue

            raw_key_index = c.attrs.get("key-index")
            key_index: int | None = None
            if raw_key_index is not None:
                with_key = str(raw_key_index).strip()
                if with_key:
                    try:
                        key_index = int(with_key)
                    except Exception:
                        key_index = None

            is_hosted = c.attrs.get("is_hosted") == "true"
            device_list.append(
                USyncDevice(device_id=device_id, key_index=key_index, is_hosted=is_hosted)
            )

    return USyncDevicesResult(device_list=device_list)


def parse_usync_result(iq: BinaryNode) -> list[USyncUserResult]:
    """
    Parse a USync IQ result into a flat list of per-user results.
    """

    if iq.attrs.get("type") != "result":
        return []

    usync = _child(iq, "usync")
    list_node = _child(usync, "list")
    out: list[USyncUserResult] = []

    for user_node in _children(list_node, "user"):
        jid = user_node.attrs.get("jid") or ""
        if not jid:
            continue

        devices: USyncDevicesResult | None = None
        lid: str | None = None

        if isinstance(user_node.content, list):
            for c in user_node.content:
                if not isinstance(c, BinaryNode):
                    continue
                if c.tag == "devices":
                    devices = _parse_devices_node(c)
                elif c.tag == "lid":
                    lid = c.attrs.get("val")

        out.append(USyncUserResult(id=jid, devices=devices, lid=lid))

    return out


def extract_device_jids(
    results: list[USyncUserResult],
    *,
    my_jid: str,
    my_lid: str | None,
    exclude_zero_devices: bool,
) -> list[str]:
    """
    Extract device wire JIDs from a USync result list.

    Mirrors Baileys' `extractDeviceJids` logic:
    - Exclude the exact sender device (me.user + me.device)
    - Require `key-index` for non-zero devices
    - Optionally exclude device 0 entries
    - Map hosted devices to the hosted domain
    """

    my = jid_decode(my_jid)
    if not my or not my.user:
        return []
    my_user = my.user
    my_device = int(my.device or 0)

    my_lid_user: str | None = None
    if my_lid:
        decoded = jid_decode(my_lid)
        if decoded and decoded.user:
            my_lid_user = decoded.user

    out: list[str] = []

    for r in results:
        if not r.devices:
            continue
        decoded = jid_decode(r.id)
        if not decoded or not decoded.user or not decoded.server:
            continue

        user = decoded.user
        server = decoded.server

        for dev in r.devices.device_list:
            device = int(dev.device_id)

            if exclude_zero_devices and device == 0:
                continue

            # Either a different user, or if it's me, it must not be my current device.
            is_me_user = user == my_user or (my_lid_user is not None and user == my_lid_user)
            if is_me_user and device == my_device:
                continue

            # WhatsApp requires a key index for non-zero devices.
            if device != 0 and dev.key_index is None:
                continue

            # Hosted domain mapping (best-effort).
            out_server = server
            if dev.is_hosted:
                out_server = "hosted.lid" if server == "lid" else "hosted"

            out.append(jid_encode(user, out_server, device))

    # Preserve stable order while deduping.
    return list(dict.fromkeys(out))
