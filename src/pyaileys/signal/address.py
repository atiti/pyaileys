from __future__ import annotations

from dataclasses import dataclass

from ..wabinary.jid import WAJIDDomains, jid_decode


@dataclass(frozen=True, slots=True)
class SignalAddress:
    """
    Signal Protocol address (name + device id).

    Matches libsignal's `ProtocolAddress.toString()` format: `{name}.{device}`.
    """

    name: str
    device: int

    def __str__(self) -> str:
        return f"{self.name}.{self.device}"


def jid_to_signal_address(jid: str) -> SignalAddress:
    decoded = jid_decode(jid)
    if not decoded or not decoded.user:
        raise ValueError(f"invalid JID: {jid!r}")

    domain_type = int(decoded.domain_type or int(WAJIDDomains.WHATSAPP))
    signal_user = (
        decoded.user
        if domain_type == int(WAJIDDomains.WHATSAPP)
        else f"{decoded.user}_{domain_type}"
    )
    device = int(decoded.device or 0)
    return SignalAddress(name=signal_user, device=device)
