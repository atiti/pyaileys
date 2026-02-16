from __future__ import annotations

import zlib

from ..exceptions import DecodeError
from . import constants
from .jid import JidServer, WAJIDDomains, jid_encode
from .types import BinaryNode, BinaryNodeData


def decompressing_if_required(buffer: bytes) -> bytes:
    if not buffer:
        raise DecodeError("empty buffer")
    flags = buffer[0]
    if flags & 2:
        return zlib.decompress(buffer[1:])
    return buffer[1:]


def decode_decompressed_binary_node(
    buffer: bytes, *, index_ref: list[int] | None = None
) -> BinaryNode:
    idx = index_ref if index_ref is not None else [0]

    TAGS = constants.TAGS
    DOUBLE = constants.DOUBLE_BYTE_TOKENS
    SINGLE = constants.SINGLE_BYTE_TOKENS

    def check_eos(length: int) -> None:
        if idx[0] + length > len(buffer):
            raise DecodeError("end of stream")

    def next_u8() -> int:
        v = buffer[idx[0]]
        idx[0] += 1
        return v

    def read_byte() -> int:
        check_eos(1)
        return next_u8()

    def read_bytes(n: int) -> bytes:
        check_eos(n)
        v = buffer[idx[0] : idx[0] + n]
        idx[0] += n
        return v

    def read_int(n: int, *, little_endian: bool = False) -> int:
        check_eos(n)
        val = 0
        for i in range(n):
            shift = i if little_endian else (n - 1 - i)
            val |= next_u8() << (shift * 8)
        return val

    def read_int20() -> int:
        check_eos(3)
        return ((next_u8() & 15) << 16) + (next_u8() << 8) + next_u8()

    def unpack_hex(value: int) -> int:
        if 0 <= value < 16:
            return (ord("0") + value) if value < 10 else (ord("A") + value - 10)
        raise DecodeError(f"invalid hex: {value}")

    def unpack_nibble(value: int) -> int:
        if 0 <= value <= 9:
            return ord("0") + value
        if value == 10:
            return ord("-")
        if value == 11:
            return ord(".")
        if value == 15:
            return 0
        raise DecodeError(f"invalid nibble: {value}")

    def unpack_byte(tag: int, value: int) -> int:
        if tag == TAGS["NIBBLE_8"]:
            return unpack_nibble(value)
        if tag == TAGS["HEX_8"]:
            return unpack_hex(value)
        raise DecodeError(f"unknown tag: {tag}")

    def read_packed8(tag: int) -> str:
        start = read_byte()
        out = []
        for _ in range(start & 127):
            cur = read_byte()
            out.append(chr(unpack_byte(tag, (cur & 0xF0) >> 4)))
            out.append(chr(unpack_byte(tag, cur & 0x0F)))
        s = "".join(out)
        if (start >> 7) != 0:
            s = s[:-1]
        return s

    def is_list_tag(tag: int) -> bool:
        return tag in (TAGS["LIST_EMPTY"], TAGS["LIST_8"], TAGS["LIST_16"])

    def read_list_size(tag: int) -> int:
        if tag == TAGS["LIST_EMPTY"]:
            return 0
        if tag == TAGS["LIST_8"]:
            return read_byte()
        if tag == TAGS["LIST_16"]:
            return read_int(2)
        raise DecodeError(f"invalid tag for list size: {tag}")

    def get_token_double(index1: int, index2: int) -> str:
        try:
            d = DOUBLE[index1]
        except Exception as e:
            raise DecodeError(f"invalid double token dict ({index1})") from e
        try:
            v = d[index2]
        except Exception as e:
            raise DecodeError(f"invalid double token ({index2})") from e
        return v

    def read_string(tag: int) -> str:
        if 1 <= tag < len(SINGLE):
            return SINGLE[tag] or ""

        if tag in (
            TAGS["DICTIONARY_0"],
            TAGS["DICTIONARY_1"],
            TAGS["DICTIONARY_2"],
            TAGS["DICTIONARY_3"],
        ):
            return get_token_double(tag - TAGS["DICTIONARY_0"], read_byte())
        if tag == TAGS["LIST_EMPTY"]:
            return ""
        if tag == TAGS["BINARY_8"]:
            return read_bytes(read_byte()).decode("utf-8")
        if tag == TAGS["BINARY_20"]:
            return read_bytes(read_int20()).decode("utf-8")
        if tag == TAGS["BINARY_32"]:
            return read_bytes(read_int(4)).decode("utf-8")
        if tag == TAGS["JID_PAIR"]:
            i = read_string(read_byte())
            j = read_string(read_byte())
            if j:
                return f"{i or ''}@{j}"
            raise DecodeError(f"invalid jid pair: {i}, {j}")
        if tag == TAGS["FB_JID"]:
            user = read_string(read_byte())
            device = read_int(2)
            server = read_string(read_byte())
            return f"{user}:{device}@{server}"
        if tag == TAGS["INTEROP_JID"]:
            user = read_string(read_byte())
            device = read_int(2)
            integrator = read_int(2)
            # optional server
            before = idx[0]
            try:
                server = read_string(read_byte())
            except DecodeError:
                idx[0] = before
                server = "interop"
            return f"{integrator}-{user}:{device}@{server}"
        if tag == TAGS["AD_JID"]:
            raw_domain_type = read_byte()
            domain_type = int(raw_domain_type)
            device = read_byte()
            user = read_string(read_byte())
            server_jid: JidServer = "s.whatsapp.net"
            if domain_type == int(WAJIDDomains.LID):
                server_jid = "lid"
            elif domain_type == int(WAJIDDomains.HOSTED):
                server_jid = "hosted"
            elif domain_type == int(WAJIDDomains.HOSTED_LID):
                server_jid = "hosted.lid"
            return jid_encode(user, server_jid, device)
        if tag in (TAGS["HEX_8"], TAGS["NIBBLE_8"]):
            return read_packed8(tag)

        raise DecodeError(f"invalid string with tag: {tag}")

    def read_list(tag: int) -> list[BinaryNode]:
        items: list[BinaryNode] = []
        size = read_list_size(tag)
        for _ in range(size):
            items.append(decode_decompressed_binary_node(buffer, index_ref=idx))
        return items

    list_size = read_list_size(read_byte())
    header = read_string(read_byte())
    if not list_size or not header:
        raise DecodeError("invalid node")

    attrs: dict[str, str] = {}
    data: BinaryNodeData = None

    attributes_len = (list_size - 1) >> 1
    for _ in range(attributes_len):
        k = read_string(read_byte())
        v = read_string(read_byte())
        attrs[k] = v

    if list_size % 2 == 0:
        tag = read_byte()
        if is_list_tag(tag):
            data = read_list(tag)
        else:
            if tag == TAGS["BINARY_8"]:
                data = read_bytes(read_byte())
            elif tag == TAGS["BINARY_20"]:
                data = read_bytes(read_int20())
            elif tag == TAGS["BINARY_32"]:
                data = read_bytes(read_int(4))
            else:
                data = read_string(tag)

    return BinaryNode(tag=header, attrs=attrs, content=data)


def decode_binary_node(buffer: bytes) -> BinaryNode:
    return decode_decompressed_binary_node(decompressing_if_required(buffer))
