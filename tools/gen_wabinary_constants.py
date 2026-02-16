#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from os import environ
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "pyaileys" / "wabinary" / "constants.py"


def _extract_between(text: str, start_pat: str, end_pat: str) -> str:
    start = text.find(start_pat)
    if start < 0:
        raise SystemExit(f"start pattern not found: {start_pat!r}")
    start += len(start_pat)
    end = text.find(end_pat, start)
    if end < 0:
        raise SystemExit(f"end pattern not found: {end_pat!r}")
    return text[start:end]


def _to_json_array(ts_array: str):
    # TS -> JSON (best-effort)
    s = ts_array
    s = s.replace("'", '"')
    s = re.sub(r",\s*([\]\}])", r"\1", s)  # trailing commas
    return json.loads(s)


def _resolve_baileys_dir(path: str | None) -> Path:
    # Explicit path takes precedence.
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path).expanduser().resolve())

    # Common local layouts for contributors.
    candidates.extend(
        [
            (ROOT / "Baileys"),
            (ROOT.parent / "Baileys"),
        ]
    )

    for base in candidates:
        if (base / "src" / "WABinary" / "constants.ts").exists():
            return base

    raise SystemExit(
        "Baileys checkout not found.\n\n"
        "Clone https://github.com/WhiskeySockets/Baileys and pass the path via:\n"
        "  python3 tools/gen_wabinary_constants.py --baileys /path/to/Baileys\n"
        "or set:\n"
        "  BAILEYS_DIR=/path/to/Baileys\n"
    )


def main() -> None:
    ap = argparse.ArgumentParser(prog="gen_wabinary_constants.py")
    ap.add_argument(
        "--baileys",
        default=environ.get("BAILEYS_DIR"),
        help="path to a Baileys checkout (https://github.com/WhiskeySockets/Baileys)",
    )
    args = ap.parse_args()

    baileys_dir = _resolve_baileys_dir(args.baileys)
    src = baileys_dir / "src" / "WABinary" / "constants.ts"

    text = src.read_text("utf-8")

    tags_block = _extract_between(
        text, "export const TAGS = {", "}\n\nexport const DOUBLE_BYTE_TOKENS"
    )
    tags: dict[str, int] = {}
    for line in tags_block.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        # e.g. LIST_EMPTY: 0,
        m = re.match(r"^([A-Z0-9_]+):\s*(\d+),?$", line)
        if not m:
            continue
        tags[m.group(1)] = int(m.group(2))

    dbl_start_pat = "export const DOUBLE_BYTE_TOKENS = "
    dbl_start = text.find(dbl_start_pat)
    if dbl_start < 0:
        raise SystemExit(f"start pattern not found: {dbl_start_pat!r}")
    dbl_start += len(dbl_start_pat)
    dbl_end = text.find("] as const", dbl_start)
    if dbl_end < 0:
        raise SystemExit("end pattern not found for DOUBLE_BYTE_TOKENS")
    dbl_block = text[dbl_start : dbl_end + 1]
    double_byte_tokens = _to_json_array(dbl_block.strip())

    sgl_start_pat = "export const SINGLE_BYTE_TOKENS = "
    sgl_start = text.find(sgl_start_pat)
    if sgl_start < 0:
        raise SystemExit(f"start pattern not found: {sgl_start_pat!r}")
    sgl_start += len(sgl_start_pat)
    sgl_end = text.find("]\n\nexport const TOKEN_MAP", sgl_start)
    if sgl_end < 0:
        raise SystemExit("end pattern not found for SINGLE_BYTE_TOKENS")
    sgl_block = text[sgl_start : sgl_end + 1]
    single_byte_tokens = _to_json_array(sgl_block.strip())

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "# This file is auto-generated from WhiskeySockets/Baileys (src/WABinary/constants.ts).\n"
        "# Do not edit by hand. Regenerate via: python3 tools/gen_wabinary_constants.py\n"
        "from __future__ import annotations\n\n"
        f"TAGS = {tags!r}\n\n"
        f"DOUBLE_BYTE_TOKENS = {double_byte_tokens!r}\n\n"
        f"SINGLE_BYTE_TOKENS = {single_byte_tokens!r}\n\n"
        "TOKEN_MAP: dict[str, dict[str, int]] = {}\n"
        "for i, tok in enumerate(SINGLE_BYTE_TOKENS):\n"
        '    TOKEN_MAP[tok] = {"index": i}\n'
        "for i, d in enumerate(DOUBLE_BYTE_TOKENS):\n"
        "    for j, tok in enumerate(d):\n"
        '        TOKEN_MAP[tok] = {"dict": i, "index": j}\n',
        "utf-8",
    )

    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
