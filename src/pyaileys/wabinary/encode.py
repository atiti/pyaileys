from __future__ import annotations

from ..exceptions import EncodeError
from . import constants
from .jid import jid_decode
from .types import BinaryNode


def encode_binary_node(node: BinaryNode) -> bytes:
    buf: list[int] = [0]  # 0x00 => no compression
    _encode_node_inner(node, buf)
    return bytes(buf)


def _encode_node_inner(node: BinaryNode, buf: list[int]) -> None:
    TAGS = constants.TAGS
    TOKEN_MAP = constants.TOKEN_MAP

    def push_u8(v: int) -> None:
        buf.append(v & 0xFF)

    def push_int(v: int, n: int, *, little_endian: bool = False) -> None:
        for i in range(n):
            shift = i if little_endian else (n - 1 - i)
            buf.append((v >> (shift * 8)) & 0xFF)

    def push_bytes(b: bytes | bytearray | memoryview | list[int]) -> None:
        if isinstance(b, list):
            buf.extend((x & 0xFF) for x in b)
        else:
            buf.extend(bytes(b))

    def push_int16(v: int) -> None:
        push_bytes([(v >> 8) & 0xFF, v & 0xFF])

    def push_int20(v: int) -> None:
        push_bytes([(v >> 16) & 0x0F, (v >> 8) & 0xFF, v & 0xFF])

    def write_byte_length(length: int) -> None:
        if length >= 2**32:
            raise EncodeError(f"string too large to encode: {length}")
        if length >= 1 << 20:
            push_u8(TAGS["BINARY_32"])
            push_int(length, 4)
        elif length >= 256:
            push_u8(TAGS["BINARY_20"])
            push_int20(length)
        else:
            push_u8(TAGS["BINARY_8"])
            push_u8(length)

    def write_string_raw(s: str) -> None:
        b = s.encode("utf-8")
        write_byte_length(len(b))
        push_bytes(b)

    def write_jid(jid: str) -> None:
        decoded = jid_decode(jid)
        if not decoded:
            raise EncodeError(f"invalid jid: {jid}")
        if decoded.device is not None:
            push_u8(TAGS["AD_JID"])
            push_u8(decoded.domain_type or 0)
            push_u8(decoded.device or 0)
            write_string(decoded.user)
        else:
            push_u8(TAGS["JID_PAIR"])
            if decoded.user:
                write_string(decoded.user)
            else:
                push_u8(TAGS["LIST_EMPTY"])
            write_string(decoded.server)

    def pack_nibble(ch: str) -> int:
        if ch == "-":
            return 10
        if ch == ".":
            return 11
        if ch == "\0":
            return 15
        if "0" <= ch <= "9":
            return ord(ch) - ord("0")
        raise EncodeError(f'invalid byte for nibble "{ch}"')

    def pack_hex(ch: str) -> int:
        if "0" <= ch <= "9":
            return ord(ch) - ord("0")
        if "A" <= ch <= "F":
            return 10 + ord(ch) - ord("A")
        if "a" <= ch <= "f":
            return 10 + ord(ch) - ord("a")
        if ch == "\0":
            return 15
        raise EncodeError(f'invalid hex char "{ch}"')

    def write_packed_bytes(s: str, typ: str) -> None:
        if len(s) > TAGS["PACKED_MAX"]:
            raise EncodeError("too many bytes to pack")
        push_u8(TAGS["NIBBLE_8"] if typ == "nibble" else TAGS["HEX_8"])

        rounded = (len(s) + 1) // 2
        if len(s) % 2 != 0:
            rounded |= 128
        push_u8(rounded)

        fn = pack_nibble if typ == "nibble" else pack_hex

        def pack_pair(v1: str, v2: str) -> int:
            return ((fn(v1) << 4) | fn(v2)) & 0xFF

        half = len(s) // 2
        for i in range(half):
            push_u8(pack_pair(s[2 * i], s[2 * i + 1]))
        if len(s) % 2 != 0:
            push_u8(pack_pair(s[-1], "\0"))

    def is_nibble(s: str | None) -> bool:
        if not s or len(s) > TAGS["PACKED_MAX"]:
            return False
        return all(("0" <= ch <= "9" or ch in "-.") for ch in s)

    def is_hex(s: str | None) -> bool:
        if not s or len(s) > TAGS["PACKED_MAX"]:
            return False
        return all(("0" <= ch <= "9" or "A" <= ch <= "F") for ch in s)

    def write_string(s: str | None) -> None:
        if s is None:
            push_u8(TAGS["LIST_EMPTY"])
            return
        if s == "":
            write_string_raw(s)
            return

        tok = TOKEN_MAP.get(s)
        if tok:
            if "dict" in tok:
                push_u8(TAGS["DICTIONARY_0"] + tok["dict"])
            push_u8(tok["index"])
            return
        if is_nibble(s):
            write_packed_bytes(s, "nibble")
            return
        if is_hex(s):
            write_packed_bytes(s, "hex")
            return
        if jid_decode(s):
            write_jid(s)
            return
        write_string_raw(s)

    def write_list_start(list_size: int) -> None:
        if list_size == 0:
            push_u8(TAGS["LIST_EMPTY"])
        elif list_size < 256:
            push_bytes([TAGS["LIST_8"], list_size])
        else:
            push_u8(TAGS["LIST_16"])
            push_int16(list_size)

    tag = node.tag
    attrs = node.attrs or {}
    content = node.content

    if not tag:
        raise EncodeError("invalid node: tag cannot be empty")

    valid_attrs = [k for k, v in attrs.items() if v is not None]

    write_list_start(2 * len(valid_attrs) + 1 + (1 if content is not None else 0))
    write_string(tag)

    for k in valid_attrs:
        v = attrs[k]
        if isinstance(v, str):
            write_string(k)
            write_string(v)

    if isinstance(content, str):
        write_string(content)
    elif isinstance(content, (bytes, bytearray, memoryview)):
        b = bytes(content)
        write_byte_length(len(b))
        push_bytes(b)
    elif isinstance(content, list):
        valid = [c for c in content if isinstance(c, BinaryNode) and c.tag]
        write_list_start(len(valid))
        for child in valid:
            _encode_node_inner(child, buf)
    elif content is None:
        return
    else:
        raise EncodeError(f'invalid children for header "{tag}": {type(content).__name__}')
