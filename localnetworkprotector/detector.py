"""Detection engine and heuristic rules for malicious traffic patterns."""

from __future__ import annotations

import logging
import time
import fnmatch
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .alerts import Alert
from .packet_utils import summarize_packet
from .config import (
    DetectionConfig,
    PortScanRuleConfig,
    SuspiciousPortRuleConfig,
    SuspiciousPayloadRuleConfig,
    DnsExfilRuleConfig,
)

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS  # type: ignore
    from scapy.packet import Packet
    from scapy.all import Raw  # type: ignore
except Exception:  # pragma: no cover - scapy optional
    Packet = Any  # type: ignore
    IP = TCP = UDP = IPv6 = DNS = Raw = None  # type: ignore


class DetectionRule:
    """Base class for detection rules."""

    name: str = "base_rule"

    def check(self, packet: Any) -> Optional[Alert]:
        raise NotImplementedError


class PortScanRule(DetectionRule):
    """Detects port scans from a remote host."""

    name = "port_scan"

    def __init__(self, config: PortScanRuleConfig):
        self.config = config
        self._events: Dict[str, List[Tuple[float, int]]] = defaultdict(list)

    def check(self, packet: Any) -> Optional[Alert]:
        if not self.config.enabled or TCP is None:
            return None

        ip_layer = _get_ip_layer(packet)
        transport_layer = _get_transport_layer(packet, (TCP, UDP))
        if ip_layer is None or transport_layer is None:
            return None

        src_ip = getattr(ip_layer, "src", None)
        dst_port = getattr(transport_layer, "dport", None)
        if src_ip is None or dst_port is None:
            return None

        now = time.time()
        timeline = self._events[src_ip]
        timeline.append((now, int(dst_port)))
        window = self.config.time_window_seconds
        cutoff = now - window
        # Trim old entries
        while timeline and timeline[0][0] < cutoff:
            timeline.pop(0)

        unique_ports = {entry[1] for entry in timeline}
        if len(unique_ports) >= self.config.max_unique_ports:
            summary = summarize_packet(packet)
            desc = (
                f"Potential port scan: {src_ip} hit {len(unique_ports)} ports "
                f"in {window}s window. Last port {dst_port}."
            )
            alert = Alert(
                rule_name=self.name,
                description=desc,
                severity=self.config.severity,
                packet_summary=summary,
                source_ip=src_ip,
            )
            return alert
        return None


class SuspiciousPortRule(DetectionRule):
    """Detects connections to known risky ports."""

    name = "suspicious_port"

    def __init__(self, config: SuspiciousPortRuleConfig):
        self.config = config
        self._port_set = {int(p) for p in config.ports}

    def check(self, packet: Any) -> Optional[Alert]:
        if not self.config.enabled:
            return None

        transport_layer = _get_transport_layer(packet, (TCP, UDP))
        if transport_layer is None:
            return None

        ip_layer = _get_ip_layer(packet)
        src_ip = getattr(ip_layer, "src", None) if ip_layer else None

        dst_port = getattr(transport_layer, "dport", None)
        if dst_port is None:
            return None

        try:
            dst_port_int = int(dst_port)
        except Exception:
            return None

        if dst_port_int not in self._port_set:
            return None

        summary = summarize_packet(packet)
        desc = f"Connection to suspicious port {dst_port_int} detected."
        return Alert(
            rule_name=self.name,
            description=desc,
            severity=self.config.severity,
            packet_summary=summary,
            source_ip=src_ip,
        )


class SuspiciousPayloadRule(DetectionRule):
    """Detects suspicious keywords in payloads."""

    name = "suspicious_payload"

    def __init__(self, config: SuspiciousPayloadRuleConfig):
        self.config = config
        self._patterns = [pattern.lower() for pattern in config.patterns]

    def check(self, packet: Any) -> Optional[Alert]:
        if not self.config.enabled:
            return None

        # Check for excluded source ports (e.g. trusted services like Grafana on 3000)
        if TCP is None or UDP is None: # Ensure TCP/UDP are available for getlayer
            pass # Cannot check excluded ports if scapy transport layers are not available
        else:
            tcp_layer = packet.getlayer(TCP) if hasattr(packet, "getlayer") else None
            udp_layer = packet.getlayer(UDP) if hasattr(packet, "getlayer") else None
            
            sport = getattr(tcp_layer, "sport", None) or getattr(udp_layer, "sport", None)
            if sport and sport in self.config.excluded_ports:
                return None

        if Raw is None: # Raw layer is needed for payload inspection
            return None

        raw_layer = packet.getlayer(Raw) if hasattr(packet, "getlayer") else None
        payload_bytes = getattr(raw_layer, "load", b"") if raw_layer else b""
        if not payload_bytes:
            return None

        ip_layer = _get_ip_layer(packet)
        src_ip = getattr(ip_layer, "src", None) if ip_layer else None

        payload_lower = payload_bytes.lower()
        for pattern in self._patterns:
            if pattern.encode("utf-8") in payload_lower:
                summary = summarize_packet(packet)
                desc = f"Payload contains pattern '{pattern}'."
                return Alert(
                    rule_name=self.name,
                    description=desc,
                    severity=self.config.severity,
                    packet_summary=summary,
                    source_ip=src_ip,
                )
        return None


class DnsExfiltrationRule(DetectionRule):
    """Detects unusually long DNS labels that may indicate exfiltration."""

    name = "dns_exfiltration"

    def __init__(self, config: DnsExfilRuleConfig):
        self.config = config

    def check(self, packet: Any) -> Optional[Alert]:
        if not self.config.enabled or DNS is None:
            return None

        dns_layer = packet.getlayer(DNS) if hasattr(packet, "getlayer") else None
        if dns_layer is None or not getattr(dns_layer, "qd", None):
            return None

        qname = getattr(dns_layer.qd, "qname", b"") or b""
        try:
            decoded_name = qname.decode(errors="ignore")
            labels = decoded_name.split(".")
        except Exception:
            return None

        normalized_name = decoded_name.rstrip(".").lower()
        for pattern in self.config.allow_patterns:
            if fnmatch.fnmatch(normalized_name, pattern.lower()):
                return None

        ip_layer = _get_ip_layer(packet)
        src_ip = getattr(ip_layer, "src", None) if ip_layer else None

        ip_layer = _get_ip_layer(packet)
        src_ip = getattr(ip_layer, "src", None) if ip_layer else None

        for label in labels:
            if len(label) >= self.config.max_label_length:
                summary = summarize_packet(packet)
                desc = (
                    "DNS label length exceeds threshold; possible data exfiltration."
                )
                return Alert(
                    rule_name=self.name,
                    description=desc,
                    severity=self.config.severity,
                    packet_summary=summary,
                    source_ip=src_ip,
                )
        return None


class DetectionEngine:
    """Runs packets through multiple detection rules."""

    def __init__(self, config: DetectionConfig):
        self.config = config
        self.rules: List[DetectionRule] = [
            PortScanRule(config.port_scan),
            SuspiciousPortRule(config.suspicious_ports),
            SuspiciousPayloadRule(config.suspicious_payload),
            DnsExfiltrationRule(config.dns_exfiltration),
        ]
        self._active_alerts: Dict[
            Tuple[str, str, str], Alert
        ] = {}  # keyed by (rule, desc, summary)
        self._cache_ttl = timedelta(minutes=10)

    def inspect(self, packet: Any) -> List[Alert]:
        fresh_alerts: List[Alert] = []
        for rule in self.rules:
            try:
                alert = rule.check(packet)
            except Exception as exc:  # pragma: no cover - defensive logging
                log.exception("Rule %s failed: %s", rule.name, exc)
                continue

            if not alert:
                continue

            key = (alert.rule_name, alert.description, alert.packet_summary)
            existing = self._active_alerts.get(key)
            if existing:
                existing.bump()
                continue

            self._active_alerts[key] = alert
            fresh_alerts.append(alert)

        self._prune_cache()
        return fresh_alerts

    def _prune_cache(self) -> None:
        cutoff = datetime.now(tz=timezone.utc) - self._cache_ttl
        expired = [
            key for key, alert in self._active_alerts.items() if alert.last_seen < cutoff
        ]
        for key in expired:
            self._active_alerts.pop(key, None)


def severity_is_at_least(severity: str, minimum: str) -> bool:
    """Return True if severity >= minimum using configured order."""
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)


def _get_ip_layer(packet: Any):
    if IP and hasattr(packet, "getlayer"):
        layer = packet.getlayer(IP)
        if layer:
            return layer
    if IPv6 and hasattr(packet, "getlayer"):
        layer6 = packet.getlayer(IPv6)
        if layer6:
            return layer6
    # Last resort: try attributes
    for attr in ("ip", "ipv6", "IP", "IPv6"):
        candidate = getattr(packet, attr, None)
        if candidate:
            return candidate
    return None


def _get_transport_layer(packet: Any, candidates: Iterable[Any]):
    if hasattr(packet, "getlayer"):
        for candidate in candidates:
            if candidate is None:
                continue
            layer = packet.getlayer(candidate)
            if layer:
                return layer
    # Attempt attributes if scapy not available
    for name in ("tcp", "udp", "TCP", "UDP"):
        layer = getattr(packet, name, None)
        if layer:
            return layer
    return None
