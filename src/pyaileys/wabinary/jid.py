from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Literal, TypeAlias, cast

S_WHATSAPP_NET = "@s.whatsapp.net"

JidServer: TypeAlias = Literal[
    "c.us",
    "g.us",
    "broadcast",
    "s.whatsapp.net",
    "call",
    "lid",
    "newsletter",
    "bot",
    "hosted",
    "hosted.lid",
]


class WAJIDDomains(IntEnum):
    WHATSAPP = 0
    LID = 1
    HOSTED = 128
    HOSTED_LID = 129


@dataclass(slots=True)
class FullJid:
    user: str
    server: JidServer
    device: int | None = None
    domain_type: int | None = None


def jid_encode(
    user: str | int | None, server: JidServer, device: int | None = None, agent: int | None = None
) -> str:
    u = "" if user is None else str(user)
    # Match Baileys jidEncode: omit agent/device when falsy (device=0 => no ":0").
    a = f"_{agent}" if agent else ""
    d = f":{device}" if device else ""
    return f"{u}{a}{d}@{server}"


def jid_decode(jid: str | None) -> FullJid | None:
    if not jid:
        return None
    sep = jid.find("@")
    if sep < 0:
        return None

    server = cast(JidServer, jid[sep + 1 :])
    user_combined = jid[:sep]
    user_agent, *device_parts = user_combined.split(":")
    user, *agent_parts = user_agent.split("_")

    device = int(device_parts[0]) if device_parts and device_parts[0] else None
    agent = agent_parts[0] if agent_parts else None

    domain_type: int = int(WAJIDDomains.WHATSAPP)
    if server == "lid":
        domain_type = int(WAJIDDomains.LID)
    elif server == "hosted":
        domain_type = int(WAJIDDomains.HOSTED)
    elif server == "hosted.lid":
        domain_type = int(WAJIDDomains.HOSTED_LID)
    elif agent:
        try:
            domain_type = int(agent)
        except ValueError:
            domain_type = int(WAJIDDomains.WHATSAPP)

    return FullJid(user=user, server=server, device=device, domain_type=domain_type)


def jid_normalized_user(jid: str | None) -> str:
    decoded = jid_decode(jid)
    if not decoded:
        return ""
    server = "s.whatsapp.net" if decoded.server == "c.us" else decoded.server
    return jid_encode(decoded.user, server)


def is_lid_user(jid: str | None) -> bool:
    return bool(jid and jid.endswith("@lid"))
