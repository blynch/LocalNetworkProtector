"""Packet capture orchestration."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from .alerts import Alert
from .config import AppConfig
from .detector import DetectionEngine
from .scanner import ActiveScanner
from .vulnerability import VulnerabilityManager

log = logging.getLogger(__name__)

try:
    from scapy.all import sniff, rdpcap  # type: ignore
except Exception:  # pragma: no cover - scapy optional dependency
    sniff = None  # type: ignore
    rdpcap = None  # type: ignore


class MonitorService:
    """Service responsible for capturing packets and invoking detectors."""

    def __init__(
        self,
        config: AppConfig,
        detection_engine: DetectionEngine,
        active_scanner: ActiveScanner,
        vulnerability_manager: VulnerabilityManager,
        alert_callback: Callable[[Alert], None],
    ) -> None:
        self.config = config
        self.detection_engine = detection_engine
        self.active_scanner = active_scanner
        self.vulnerability_manager = vulnerability_manager
        self.alert_callback = alert_callback
        self._running = False
        self._scanned_ips = set()

    def start(self) -> None:
        """Start sniffing packets using scapy."""
        if sniff is None:
            raise RuntimeError(
                "Scapy is required for live capture. Please install scapy on the "
                "Raspberry Pi (pip install scapy) and run with sudo."
            )

        if self._running:
            log.debug("MonitorService already running.")
            return
        self._running = True

        capture_cfg = self.config.capture
        log.info(
            "Starting packet capture on interface=%s filter=%s promisc=%s",
            capture_cfg.interface or "default",
            capture_cfg.bpf_filter or "None",
            capture_cfg.promisc,
        )
        try:
            sniff(
                iface=capture_cfg.interface,
                prn=self._process_packet,
                filter=capture_cfg.bpf_filter,
                store=capture_cfg.store_packets,
                promisc=capture_cfg.promisc,
                count=0,
            )
        except KeyboardInterrupt:
            log.info("Capture interrupted by user.")
        finally:
            self._running = False

    def _trigger_scan(self, ip: str) -> None:
        """Trigger active scan and vulnerability check for an IP."""
        if not self.config.active_scanning.enabled:
            return
        if not ip or ip in self._scanned_ips:
            return
        
        # Only scan private IPs to avoid scanning the internet
        # Simple check for 192.168, 10., 172.16-31.
        # For now we assume local network usage as per tool name.
        
        self._scanned_ips.add(ip)
        services = self.active_scanner.scan_host(ip)
        if not services:
            return

        for svc in services:
            vulns = self.vulnerability_manager.check_service(
                product=svc.get("product", ""),
                version=svc.get("version", ""),
                cpe=svc.get("cpe", "")
            )
            
            for v in vulns:
                desc = f"Vulnerability {v.id} ({v.severity}) found on port {svc['port']} ({svc['service']}): {v.description}"
                alert = Alert(
                    rule_name="vulnerability_scanner",
                    description=desc,
                    severity=v.severity,
                    packet_summary=f"Host: {ip}, Service: {svc['product']} {svc['version']}",
                    source_ip=ip
                )
                log.warning(desc)
                self.alert_callback(alert)

    def _process_packet(self, packet: Any) -> Optional[Any]:
        alerts = self.detection_engine.inspect(packet)
        for alert in alerts:
            log.warning(
                "Alert triggered: %s | severity=%s | desc=%s",
                alert.rule_name,
                alert.severity,
                alert.description,
            )
            self.alert_callback(alert)
            
            # Trigger active scan if suspicious
            if alert.source_ip and self.config.active_scanning.enabled:
                self._trigger_scan(alert.source_ip)
                
        return packet

    def process_pcap(self, path: str) -> None:
        """Replay packets from a PCAP capture for analysis."""
        if rdpcap is None:
            raise RuntimeError(
                "Scapy (with rdpcap) is required to replay PCAP files."
            )

        log.info("Processing packets from %s", path)
        packets = rdpcap(path)
        for packet in packets:
            self._process_packet(packet)
