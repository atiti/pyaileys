#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "proto" / "WAProto.proto"


ENUM_START_RE = re.compile(r"^(?P<indent>\s*)enum\s+(?P<name>[A-Za-z0-9_]+)\s*\{\s*$")
ENUM_VALUE_RE = re.compile(r"^(?P<indent>\s*)(?P<sym>[A-Za-z0-9_]+)\s*=\s*(?P<num>-?\d+)\s*;")

_CAMEL_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")


def _enum_unspecified_name(enum_name: str) -> str:
    # CamelCase -> UPPER_SNAKE
    s1 = _CAMEL_1.sub(r"\1_\2", enum_name)
    s2 = _CAMEL_2.sub(r"\1_\2", s1)
    return s2.upper() + "_UNSPECIFIED"


def patch_enum_block(enum_name: str, lines: list[str]) -> list[str]:
    # Find the first enum value line and check if it's zero.
    value_idxs: list[int] = []
    zero_idx: int | None = None
    first_indent: str | None = None

    for i, line in enumerate(lines):
        m = ENUM_VALUE_RE.match(line)
        if not m:
            continue
        value_idxs.append(i)
        if first_indent is None:
            first_indent = m.group("indent")
        if int(m.group("num")) == 0 and zero_idx is None:
            zero_idx = i

    if not value_idxs:
        return lines

    first_value_idx = value_idxs[0]
    if zero_idx == first_value_idx:
        return lines

    if zero_idx is not None:
        # Move the existing `= 0` value to the first position.
        zero_line = lines.pop(zero_idx)
        lines.insert(first_value_idx, zero_line)
        return lines

    # No zero value exists: insert one at the first value position.
    indent = first_indent or "    "
    lines.insert(first_value_idx, f"{indent}{_enum_unspecified_name(enum_name)} = 0;\n")
    return lines


def main() -> None:
    raw = PROTO.read_text("utf-8").splitlines(keepends=True)

    out: list[str] = []
    i = 0
    changed = 0

    while i < len(raw):
        line = raw[i]
        m = ENUM_START_RE.match(line)
        if not m:
            out.append(line)
            i += 1
            continue

        # Collect enum block (until the first standalone closing brace).
        block = [line]
        i += 1
        while i < len(raw):
            block.append(raw[i])
            if raw[i].lstrip().startswith("}"):
                i += 1
                break
            i += 1

        before = block[:]
        patched = patch_enum_block(m.group("name"), block)
        if patched != before:
            changed += 1
        out.extend(patched)

    if changed:
        PROTO.write_text("".join(out), "utf-8")
        print(f"patched {changed} enum blocks in {PROTO}")
    else:
        print("no changes required")


if __name__ == "__main__":
    main()
