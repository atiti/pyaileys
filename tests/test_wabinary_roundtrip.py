from __future__ import annotations

from pyaileys.wabinary import decode_binary_node, encode_binary_node
from pyaileys.wabinary.types import BinaryNode


def test_encode_decode_roundtrip_simple_node() -> None:
    node = BinaryNode(
        tag="iq",
        attrs={"id": "123", "to": "@s.whatsapp.net", "type": "get", "xmlns": "w:p"},
        content=[BinaryNode(tag="ping", attrs={})],
    )

    enc = encode_binary_node(node)
    dec = decode_binary_node(enc)

    assert dec.tag == node.tag
    assert dec.attrs["id"] == "123"
    assert dec.attrs["type"] == "get"
    assert isinstance(dec.content, list)
    assert dec.content[0].tag == "ping"
