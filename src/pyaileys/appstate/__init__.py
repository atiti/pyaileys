"""
App state sync (w:sync:app:state).

This package implements WhatsApp's "app state" snapshot/patch mechanism used to
sync chat/contact state between devices.

Portions of the algorithms (key expansion, LT-hash update and MAC validation)
are based on the MIT-licensed `wacore-appstate` crate from:
https://github.com/jlucaso1/whatsapp-rust
"""

from __future__ import annotations

from .keys import ExpandedAppStateKeys, expand_app_state_keys
from .lthash import WAPATCH_INTEGRITY, WAPATCH_INTEGRITY_INFO, LTHash
from .processor import (
    AppStateMutationMAC,
    HashState,
    Mutation,
    PatchProcessingResult,
    ProcessedSnapshot,
    generate_content_mac,
    generate_patch_mac,
    process_patch,
    process_snapshot,
    validate_index_mac,
    validate_patch_macs,
    validate_snapshot_mac,
)
from .sync import ALL_WA_PATCH_NAMES, extract_syncd_patches

__all__ = [
    "ALL_WA_PATCH_NAMES",
    "WAPATCH_INTEGRITY",
    "WAPATCH_INTEGRITY_INFO",
    "AppStateMutationMAC",
    "ExpandedAppStateKeys",
    "HashState",
    "LTHash",
    "Mutation",
    "PatchProcessingResult",
    "ProcessedSnapshot",
    "expand_app_state_keys",
    "extract_syncd_patches",
    "generate_content_mac",
    "generate_patch_mac",
    "process_patch",
    "process_snapshot",
    "validate_index_mac",
    "validate_patch_macs",
    "validate_snapshot_mac",
]
