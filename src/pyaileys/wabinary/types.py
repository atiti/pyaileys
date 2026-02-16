from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

BinaryNodeData: TypeAlias = list["BinaryNode"] | str | bytes | None


@dataclass(slots=True)
class BinaryNode:
    """
    The binary node structure WhatsApp Web uses internally for transport.

    This mirrors Baileys' `BinaryNode` shape:
    - `tag`: node name
    - `attrs`: string map of attributes
    - `content`: child nodes, string, raw bytes, or None
    """

    tag: str
    attrs: dict[str, str]
    content: BinaryNodeData = None
