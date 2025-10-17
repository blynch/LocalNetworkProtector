"""Helper utilities for dealing with packets."""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

try:
    from scapy.packet import Packet
    from scapy.layers.inet import TCP, UDP, IP
    from scapy.layers.l2 import Ether
    from scapy.layers.inet6 import IPv6
    from scapy.layers.http import HTTPRequest, HTTPResponse  # type: ignore
    from scapy.layers.dns import DNS  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Packet = Any  # type: ignore
    TCP = UDP = IP = Ether = IPv6 = HTTPRequest = HTTPResponse = DNS = None  # type: ignore
    log.warning("Scapy not available; packet summaries will be limited.")


def summarize_packet(packet: Any) -> str:
    """Return a readable summary string for a packet."""
    if packet is None:
        return "No packet data"

    try:
        if hasattr(packet, "summary"):
            return packet.summary()  # type: ignore[return-value]
    except Exception:  # pragma: no cover - defensive guard
        pass

    # Fall back to manual extraction when scapy is available.
    layers = []
    layer = packet
    idx = 0
    while layer is not None and idx < 5:  # limit depth to avoid long summaries
        layer_name = layer.__class__.__name__
        attrs = []
        for key in ("src", "dst", "sport", "dport", "method", "Host", "Path"):
            if hasattr(layer, key):
                attrs.append(f"{key}={getattr(layer, key)}")
        layers.append(f"{layer_name}({', '.join(attrs)})" if attrs else layer_name)
        layer = getattr(layer, "payload", None)
        if layer in (b"", None):
            break
        idx += 1

    if not layers:
        return repr(packet)
    return " -> ".join(layers)

