from __future__ import annotations

from dataclasses import dataclass

from ..wabinary.types import BinaryNode

ALL_WA_PATCH_NAMES: tuple[str, ...] = (
    "critical_block",
    "critical_unblock_low",
    "regular_low",
    "regular_high",
    "regular",
)


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


@dataclass(frozen=True, slots=True)
class SyncdCollection:
    name: str
    has_more_patches: bool
    version_attr: int | None
    snapshot_bytes: bytes | None
    patch_bytes: list[bytes]


def extract_syncd_patches(result: BinaryNode) -> list[SyncdCollection]:
    """
    Extract raw snapshot & patch protobuf bytes from an app-state IQ response.

    This mirrors Baileys' `extractSyncdPatches` but does *not* download external
    blobs; it only returns the raw bytes present in the stanza.
    """

    sync = _child(result, "sync")
    collections: list[SyncdCollection] = []
    for col in _children(sync, "collection"):
        name = str(col.attrs.get("name") or "")
        has_more = str(col.attrs.get("has_more_patches") or "").lower() == "true"
        ver_attr: int | None = None
        try:
            if col.attrs.get("version") is not None:
                ver_attr = int(col.attrs["version"])
        except Exception:
            ver_attr = None

        snapshot_bytes: bytes | None = None
        snap = _child(col, "snapshot")
        if snap and isinstance(snap.content, (bytes, bytearray, memoryview)):
            snapshot_bytes = bytes(snap.content)

        patches_node = _child(col, "patches") or col
        patch_nodes = _children(patches_node, "patch")
        patch_bytes: list[bytes] = []
        for p in patch_nodes:
            if isinstance(p.content, (bytes, bytearray, memoryview)):
                patch_bytes.append(bytes(p.content))

        collections.append(
            SyncdCollection(
                name=name,
                has_more_patches=has_more,
                version_attr=ver_attr,
                snapshot_bytes=snapshot_bytes,
                patch_bytes=patch_bytes,
            )
        )

    return collections
