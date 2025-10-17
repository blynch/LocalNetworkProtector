"""Packet capture orchestration."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from .alerts import Alert
from .config import AppConfig
from .detector import DetectionEngine

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
        alert_callback: Callable[[Alert], None],
    ) -> None:
        self.config = config
        self.detection_engine = detection_engine
        self.alert_callback = alert_callback
        self._running = False

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
