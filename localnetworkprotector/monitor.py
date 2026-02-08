"""Packet capture orchestration."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from .alerts import Alert
from .eero_manager import EeroManager
import threading
import time
import sys
from .tsunami import TsunamiScanner
from .config import Config

try:
    import schedule
except ImportError:
    schedule = None

try:
    from scapy.all import sniff, rdpcap, get_if_addr, conf
except ImportError:
    sniff = None
    rdpcap = None
    get_if_addr = None
    conf = None

log = logging.getLogger(__name__)

class MonitorService:
    """Service responsible for capturing packets and invoking detectors."""

    def __init__(
        self,
        config: Config,
        detection_engine: DetectionEngine,
        active_scanner: ActiveScanner,
        vulnerability_manager: VulnerabilityManager,
        alert_callback: Callable[[Alert], None],
        database: Optional[DatabaseManager] = None,
        telemetry: Optional[TelemetryManager] = None,
        eero_manager: Optional[EeroManager] = None,
        tsunami_scanner: Optional[TsunamiScanner] = None,
    ) -> None:
        self.config = config
        self.detection_engine = detection_engine
        self.active_scanner = active_scanner
        self.vulnerability_manager = vulnerability_manager
        self.tsunami_scanner = tsunami_scanner
        self.alert_callback = alert_callback
        self.database = database
        self.telemetry = telemetry
        self.eero_manager = eero_manager
        self._running = False
        self._scan_history: dict[str, float] = {}  # IP -> timestamp of last scan
        self._local_ip = None

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

        # Start Eero polling thread
        if self.eero_manager and self.config.eero.enabled:
            self._eero_thread = threading.Thread(target=self._poll_eero, daemon=True)
            self._eero_thread.start()
            log.info("Started Eero polling thread.")

        # Start Scheduled Scan thread
        if self.config.scheduled_scan.enabled:
            if schedule is None:
                log.warning("Schedule library not found. Scheduled scanning disabled.")
            else:
                schedule.every().day.at(self.config.scheduled_scan.schedule_time).do(self._run_scheduled_scan)
                self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
                self._scheduler_thread.start()
                log.info("Scheduled scanning enabled. Next run at %s", self.config.scheduled_scan.schedule_time)

        capture_cfg = self.config.capture

        capture_cfg = self.config.capture
        
        # Determine local IP to ignore self-generated traffic
        if get_if_addr:
             try:
                 # 1. Try configured interface
                 if capture_cfg.interface:
                     self._local_ip = get_if_addr(capture_cfg.interface)
                 
                 # 2. Try default scapy interface if not found
                 if not self._local_ip and getattr(conf, "iface", None):
                      self._local_ip = get_if_addr(conf.iface)

                 log.info("Identified local IP as %s", self._local_ip)
             except Exception as e:
                 log.warning("Could not determine local IP: %s", e)
        
                 log.warning("Could not determine local IP: %s", e)
        
        # Merge configured trusted IPs
        self._trusted_ips = set(self.config.detection.trusted_ips)
        if self._local_ip:
            self._trusted_ips.add(self._local_ip)
            
        log.info("Trusted IPs (ignored for alerts): %s", self._trusted_ips)

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
        if not ip:
            return

        import time
        now = time.time()
        last_scan = self._scan_history.get(ip, 0)
        interval_seconds = self.config.active_scanning.rescan_interval_minutes * 60

        if (now - last_scan) < interval_seconds:
            # Already scanned recently
            return
        
        # Only scan private IPs to avoid scanning the internet
        # Simple check for 192.168, 10., 172.16-31.
        # For now we assume local network usage as per tool name.
        
        self._scan_history[ip] = now
        
        if self.database:
            scan_id = self.database.record_scan(ip, status="STARTED")
        else:
            scan_id = None
            
        services = self.active_scanner.scan_host(ip)
        
        status = "FAILED"
        port_count = 0
        if services is not None:
             status = "COMPLETED"
             port_count = len(services)
             
        if self.telemetry:
            self.telemetry.record_scan(status, ip)
            if status == "COMPLETED":
                self.telemetry.record_open_ports(ip, port_count)
            
        # Run Tsunami if configured
        if self.tsunami_scanner:
             try:
                 tsunami_vulns = self.tsunami_scanner.scan(ip)
                 if tsunami_vulns:
                     self._report_vulns(tsunami_vulns, ip, port="0", product="Tsunami", services={'service': 'tsunami-scanner'}, scan_id=scan_id)
             except Exception as e:
                 log.error("Tsunami scan error for %s: %s", ip, e)

        if not services:
            return

        for svc in services:
            vulns = self.vulnerability_manager.check_service(
                product=svc.get("product", ""),
                version=svc.get("version", ""),
                cpe=svc.get("cpe", "")
            )
            self._report_vulns(vulns, ip, svc['port'], svc['product'], services={'port': svc['port'], 'service': svc['service']}, scan_id=scan_id)

    def _report_vulns(self, vulns: list, ip: str, port: str, product: str, services: dict, scan_id: Optional[int] = None):
        for v in vulns:
            desc = f"Vulnerability {v.id} ({v.severity}) found on port {port} ({services['service']}): {v.description}"
            if self.telemetry:
                self.telemetry.record_vulnerability(v.severity, product)
            
            if self.database:
                self.database.record_finding(
                    scan_id=scan_id,
                    type_="vulnerability",
                    severity=v.severity,
                    description=desc,
                    details={"vuln_id": v.id, "port": port, "service": services['service']}
                )

            alert = Alert(
                rule_name="vulnerability_scanner",
                description=desc,
                severity=v.severity,
                packet_summary=f"Host: {ip}, Service: {product}",
                source_ip=ip
            )
            log.warning(desc)
            self.alert_callback(alert)

    def _process_packet(self, packet: Any) -> Optional[Any]:
        if self.telemetry:
            self.telemetry.record_packet()
            
        alerts = self.detection_engine.inspect(packet)
        for alert in alerts:
            # Filter out alerts caused by our own active scanning or trusted IPs
            if alert.source_ip in self._trusted_ips:
                continue

            log.warning(
                "Alert triggered: %s | severity=%s | desc=%s",
                alert.rule_name,
                alert.severity,
                alert.description,
            )
            
            if self.telemetry:
                self.telemetry.record_alert(alert.rule_name, alert.severity)
            
            if self.database:
                self.database.record_finding(
                    scan_id=None,
                    type_="alert",
                    severity=alert.severity,
                    description=alert.description,
                    details=alert.to_dict()
                )

            self.alert_callback(alert)
            
            if alert.source_ip and self.config.active_scanning.enabled:
                self._trigger_scan(alert.source_ip)
        
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Packet: %s", packet.summary())
            
        # Returning None suppresses Scapy's automatic printing
        return None

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

    def _poll_eero(self) -> None:
        """Background loop to poll Eero for devices."""
        log.info("Eero polling thread running. Interval: %ds", self.config.eero.check_interval_seconds)
        
        # Initial poll immediately
        self._run_eero_check()
        
        while self._running:
            sys.stdout.flush()
            sys.stderr.flush()
            time.sleep(self.config.eero.check_interval_seconds)
            if self._running:
                self._run_eero_check()

    def _run_eero_check(self):
        try:
            if self.telemetry and self.eero_manager:
                 count = self.eero_manager.get_total_device_count()
                 log.debug("Eero polling: Found %d devices", count)
                 self.telemetry.record_eero_devices(count)
                 
            new_devices = self.eero_manager.check_for_new_devices()
            for dev in new_devices:
                name = dev.get('nickname') or dev.get('hostname') or "Unknown"
                mac = dev.get('mac')
                desc = f"New device detected on Eero: {name} ({mac})"
                
                if self.telemetry:
                    self.telemetry.record_alert("eero_new_device", "medium")
                    
                alert = Alert(
                    rule_name="eero_new_device",
                    description=desc,
                    severity="medium",
                    packet_summary=f"Device: {dev}",
                    source_ip=dev.get('ip', '0.0.0.0')
                )
                log.info(desc)
                if self.config.active_scanning.enabled and dev.get('ip'):
                     self._trigger_scan(dev['ip'])
                     
                self.alert_callback(alert)
                
        except Exception as e:
            log.error("Error in Eero polling: %s", e, exc_info=True)

    def _scheduler_loop(self):
        """Background loop for the scheduler."""
        while self._running:
            schedule.run_pending()
            sys.stdout.flush()
            sys.stderr.flush()
            time.sleep(60)

    def _run_scheduled_scan(self):
        """Execute the configured scheduled scan."""
        log.info("Starting SCHEDULED NETWORK SCAN...")
        
        subnets = self.config.scheduled_scan.target_subnets
        if not subnets:
            log.warning("Scheduled scan triggered but no target_subnets configured.")
            return

        total_hosts = 0
        for subnet in subnets:
            hosts = self.active_scanner.discover_hosts(subnet)
            total_hosts += len(hosts)
            for ip in hosts:
                # Trigger full scan and vuln check
                self._trigger_scan(ip)
                # Sleep a bit to be gentle?
                time.sleep(5) 
        
        log.info("Scheduled scan completed. Discovered and scanned %d hosts.", total_hosts)

