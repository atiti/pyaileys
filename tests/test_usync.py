from __future__ import annotations

from pyaileys.usync import (
    USyncDevice,
    USyncDevicesResult,
    USyncUserResult,
    build_usync_iq,
    extract_device_jids,
    parse_usync_result,
)
from pyaileys.wabinary.types import BinaryNode


def _child(node: BinaryNode, tag: str) -> BinaryNode | None:
    if not isinstance(node.content, list):
        return None
    for c in node.content:
        if isinstance(c, BinaryNode) and c.tag == tag:
            return c
    return None


def test_build_usync_iq_shape() -> None:
    iq = build_usync_iq(
        ["111@s.whatsapp.net", "999@lid"], sid="sid1", context="message", mode="query"
    )
    assert iq.tag == "iq"
    assert iq.attrs["xmlns"] == "usync"
    assert iq.attrs["type"] == "get"

    usync = _child(iq, "usync")
    assert usync is not None
    assert usync.attrs["context"] == "message"
    assert usync.attrs["mode"] == "query"
    assert usync.attrs["sid"] == "sid1"

    query = _child(usync, "query")
    assert query is not None
    assert isinstance(query.content, list)
    assert {c.tag for c in query.content if isinstance(c, BinaryNode)} == {"devices", "lid"}

    lst = _child(usync, "list")
    assert lst is not None
    assert isinstance(lst.content, list)
    user_jids = [
        n.attrs.get("jid") for n in lst.content if isinstance(n, BinaryNode) and n.tag == "user"
    ]
    assert user_jids == ["111@s.whatsapp.net", "999@lid"]


def test_parse_usync_result_devices_and_lid() -> None:
    iq = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="usync",
                attrs={},
                content=[
                    BinaryNode(
                        tag="list",
                        attrs={},
                        content=[
                            BinaryNode(
                                tag="user",
                                attrs={"jid": "111@s.whatsapp.net"},
                                content=[
                                    BinaryNode(
                                        tag="devices",
                                        attrs={},
                                        content=[
                                            BinaryNode(
                                                tag="device-list",
                                                attrs={},
                                                content=[
                                                    BinaryNode(
                                                        tag="device",
                                                        attrs={"id": "0"},
                                                        content=None,
                                                    ),
                                                    BinaryNode(
                                                        tag="device",
                                                        attrs={"id": "5", "key-index": "1"},
                                                        content=None,
                                                    ),
                                                ],
                                            )
                                        ],
                                    ),
                                    BinaryNode(tag="lid", attrs={"val": "999@lid"}, content=None),
                                ],
                            )
                        ],
                    )
                ],
            )
        ],
    )

    out = parse_usync_result(iq)
    assert len(out) == 1
    assert out[0].id == "111@s.whatsapp.net"
    assert out[0].lid == "999@lid"
    assert out[0].devices is not None
    assert [d.device_id for d in out[0].devices.device_list] == [0, 5]


def test_extract_device_jids_excludes_sender_device_and_requires_key_index_for_nonzero() -> None:
    results = [
        USyncUserResult(
            id="111@s.whatsapp.net",
            devices=USyncDevicesResult(
                device_list=[
                    USyncDevice(device_id=0),
                    USyncDevice(device_id=5, key_index=1),  # sender device -> excluded
                    USyncDevice(device_id=6, key_index=2),
                    USyncDevice(device_id=7),  # missing key-index -> excluded
                ]
            ),
        ),
        USyncUserResult(
            id="999@lid",
            devices=USyncDevicesResult(
                device_list=[
                    USyncDevice(device_id=0),
                    USyncDevice(device_id=5, key_index=1),  # sender device -> excluded
                    USyncDevice(device_id=7, key_index=3),
                ]
            ),
        ),
    ]

    jids = extract_device_jids(
        results, my_jid="111:5@s.whatsapp.net", my_lid="999:5@lid", exclude_zero_devices=False
    )
    assert "111@s.whatsapp.net" in jids
    assert "111:6@s.whatsapp.net" in jids
    assert "111:7@s.whatsapp.net" not in jids
    assert "111:5@s.whatsapp.net" not in jids
    assert "999@lid" in jids
    assert "999:7@lid" in jids
    assert "999:5@lid" not in jids

    jids_no0 = extract_device_jids(
        results, my_jid="111:5@s.whatsapp.net", my_lid="999:5@lid", exclude_zero_devices=True
    )
    assert "111@s.whatsapp.net" not in jids_no0
    assert "999@lid" not in jids_no0
