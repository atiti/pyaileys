from __future__ import annotations

import base64
import dataclasses
import json
from typing import Any


def _default(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return {"type": "Buffer", "data": base64.b64encode(bytes(obj)).decode("ascii")}
    # `dataclasses.is_dataclass()` is true for both instances and dataclass *types*.
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _object_hook(obj: dict[str, Any]) -> Any:
    if obj.get("type") == "Buffer" and isinstance(obj.get("data"), str):
        return base64.b64decode(obj["data"].encode("ascii"))
    return obj


def dumps(obj: Any, *, indent: int | None = None) -> str:
    """JSON serialize with Baileys-compatible Buffer encoding."""

    return json.dumps(obj, default=_default, indent=indent, sort_keys=True)


def loads(data: str) -> Any:
    """JSON deserialize with Baileys-compatible Buffer decoding."""

    return json.loads(data, object_hook=_object_hook)
