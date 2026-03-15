"""Packet capture orchestration."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Callable, Optional

from .alerts import Alert
from .eero_manager import EeroManager
import threading
import time
import sys
from .tsunami import TsunamiScanner
from .config import Config
from .repo_scanner import RepoScanner

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
        repo_scanner: Optional[RepoScanner] = None,
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
        self.repo_scanner = repo_scanner
        self._running = False
        self._scan_history: dict[str, float] = {}  # IP -> timestamp of last scan
        self._local_ip = None

    def request_scan(self, ip: str, source: str = "manual") -> tuple[bool, str]:
        """Validate and trigger a scan request."""
        return self._trigger_scan(ip, source=source)

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
        if self.config.scheduled_scan.enabled or self.config.repo_scanning.enabled:
            if schedule is None:
                log.warning("Schedule library not found. Scheduled jobs disabled.")
            else:
                if self.config.scheduled_scan.enabled:
                    schedule.every().day.at(self.config.scheduled_scan.schedule_time).do(self._run_scheduled_scan)
                    log.info("Scheduled scanning enabled. Next run at %s", self.config.scheduled_scan.schedule_time)
                if self.config.repo_scanning.enabled:
                    schedule.every().day.at(self.config.repo_scanning.schedule_time).do(self._run_repo_scan)
                    log.info("Repository scanning enabled. Next run at %s", self.config.repo_scanning.schedule_time)
                self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
                self._scheduler_thread.start()

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

    def _is_private_or_local_target(self, target: ipaddress._BaseAddress | ipaddress._BaseNetwork) -> bool:
        if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return (
                target.is_private
                or target.is_loopback
                or target.is_link_local
                or target.is_reserved
            )
        return (
            target.is_private
            or target.is_loopback
            or target.is_link_local
            or target.is_reserved
        )

    def _matches_allowed_target(self, ip: ipaddress._BaseAddress) -> bool:
        for entry in self.config.active_scanning.allowed_targets:
            try:
                candidate = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                try:
                    candidate_ip = ipaddress.ip_address(entry)
                except ValueError:
                    log.warning("Ignoring invalid allowed_targets entry: %s", entry)
                    continue
                if ip == candidate_ip:
                    return True
                continue

            if ip in candidate:
                return True
        return False

    def _scan_target_allowed(self, ip: str) -> tuple[bool, str]:
        try:
            target_ip = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"Invalid IP address: {ip}"

        if self._is_private_or_local_target(target_ip):
            return True, "allowed private/local target"

        if self._matches_allowed_target(target_ip):
            return True, "allowed by active_scanning.allowed_targets"

        if self.config.active_scanning.allow_public_targets:
            return True, "allowed by allow_public_targets"

        return (
            False,
            "Target is not private/local and is not allowlisted in active_scanning.allowed_targets",
        )

    def _trigger_scan(self, ip: str, source: str = "automatic") -> tuple[bool, str]:
        """Trigger active scan and vulnerability check for an IP."""
        if not self.config.active_scanning.enabled:
            return False, "Active scanning is disabled"
        if not ip:
            return False, "No IP address provided"

        allowed, reason = self._scan_target_allowed(ip)
        if not allowed:
            log.warning("Rejected %s scan request for %s: %s", source, ip, reason)
            return False, reason

        now = time.time()
        last_scan = self._scan_history.get(ip, 0)
        interval_seconds = self.config.active_scanning.rescan_interval_minutes * 60

        if (now - last_scan) < interval_seconds:
            return False, "Target was scanned recently and is still in cooldown"
        
        self._scan_history[ip] = now
        
        if self.database:
            scan_id = self.database.record_scan(ip, status="STARTED")
        else:
            scan_id = None

        services = self.active_scanner.scan_host(
            ip,
            ports=self.config.active_scanning.ports,
            arguments=self.config.active_scanning.arguments,
        )

        status = "FAILED"
        port_count = 0
        if services is not None:
            status = "COMPLETED"
            port_count = len(services)
        if self.database:
            self.database.update_scan_status(scan_id, status)

        if self.telemetry:
            self.telemetry.record_scan(status, ip)
            if status == "COMPLETED":
                self.telemetry.record_open_ports(ip, port_count)
            
        # Run Tsunami if configured
        if self.tsunami_scanner:
            try:
                tsunami_vulns = self.tsunami_scanner.scan(ip)
                if tsunami_vulns:
                    self._report_vulns(
                        tsunami_vulns,
                        ip,
                        port="0",
                        product="Tsunami",
                        services={"service": "tsunami-scanner"},
                        scan_id=scan_id,
                    )
            except Exception as e:
                log.error("Tsunami scan error for %s: %s", ip, e)

        if not services:
            return status == "COMPLETED", "Scan completed"

        for svc in services:
            vulns = self.vulnerability_manager.check_service(
                product=svc.get("product", ""),
                version=svc.get("version", ""),
                cpe=svc.get("cpe", ""),
            )
            self._report_vulns(
                vulns,
                ip,
                svc["port"],
                svc["product"],
                services={"port": svc["port"], "service": svc["service"]},
                scan_id=scan_id,
            )
        return True, "Scan completed"

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
                    self._trigger_scan(dev["ip"], source="eero")
                     
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
            try:
                network = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                log.warning("Skipping invalid scheduled_scan target_subnets entry: %s", subnet)
                continue
            if not self._is_private_or_local_target(network) and not self.config.active_scanning.allow_public_targets:
                log.warning(
                    "Skipping scheduled scan for %s because it is public and allow_public_targets is disabled.",
                    subnet,
                )
                continue
            hosts = self.active_scanner.discover_hosts(subnet)
            total_hosts += len(hosts)
            for ip in hosts:
                # Trigger full scan and vuln check
                self._trigger_scan(ip, source="scheduled")
                # Sleep a bit to be gentle?
                time.sleep(5) 
        
        log.info("Scheduled scan completed. Discovered and scanned %d hosts.", total_hosts)

    def _run_repo_scan(self):
        """Synchronize GitHub repos and scan them with SCALIBR."""
        if not self.repo_scanner or not self.config.repo_scanning.enabled:
            return

        log.info("Starting scheduled repository scan job...")
        results = self.repo_scanner.run_all()
        for result in results:
            repo_scan_id = -1
            if self.database:
                repo_scan_id = self.database.record_repo_scan(
                    repo_name=result.repo_name,
                    repo_url=result.repo_url,
                    local_path=result.local_path,
                    status=result.status,
                    vulnerability_count=result.vulnerability_count,
                    result_path=result.result_path,
                )
                for finding in result.findings:
                    self.database.record_repo_scan_finding(
                        repo_scan_id=repo_scan_id,
                        vulnerability_id=finding.vulnerability_id,
                        severity=finding.severity,
                        package_name=finding.package_name,
                        details=finding.details or {},
                    )

            if result.status == "COMPLETED" and result.vulnerability_count > 0:
                desc = f"Repo scan found {result.vulnerability_count} potential vulnerabilities in {result.repo_name}"
                alert = Alert(
                    rule_name="repo_vulnerability_scanner",
                    description=desc,
                    severity="high",
                    packet_summary=f"Repository: {result.repo_name}",
                    source_ip=None,
                )
                log.warning(desc)
                self.alert_callback(alert)
        log.info("Repository scanning job finished. Scanned %d repos.", len(results))
