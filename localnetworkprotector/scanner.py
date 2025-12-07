"""Active network scanner using python-nmap."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

try:
    import nmap
except ImportError:
    nmap = None

log = logging.getLogger(__name__)


class ActiveScanner:
    """Uses nmap to scan hosts and detect service versions."""

    def __init__(self):
        if nmap is None:
            log.warning("python-nmap module not found. Active scanning disabled.")
            self._nm = None
        else:
            try:
                self._nm = nmap.PortScanner()
            except nmap.PortScannerError:
                log.error(
                    "nmap binary not found. Please install nmap. Active scanning disabled."
                )
                self._nm = None
            except Exception as e:
                log.error("Failed to initialize nmap: %s", e)
                self._nm = None

    def is_available(self) -> bool:
        return self._nm is not None

    def scan_host(self, ip: str, ports: str = "22-1024") -> List[Dict[str, str]]:
        """
        Scan a single host for service versions.
        Returns a list of dictionaries with keys: port, service, product, version, cpe.
        """
        if not self.is_available():
            return []

        log.info("Starting active scan on %s ports %s", ip, ports)
        try:
            # -sV: Version detection
            self._nm.scan(ip, ports, arguments="-sV --version-light")
        except Exception as e:
            log.error("Scan failed for %s: %s", ip, e)
            return []

        results = []
        if ip not in self._nm.all_hosts():
            log.info("No host found at %s", ip)
            return []

        host_entry = self._nm[ip]
        for proto in host_entry.all_protocols():
            if proto not in ("tcp", "udp"):
                continue
            
            lport = sorted(host_entry[proto].keys())
            for port in lport:
                service_info = host_entry[proto][port]
                # filter for open ports
                if service_info["state"] != "open":
                    continue

                item = {
                    "port": str(port),
                    "protocol": proto,
                    "service": service_info.get("name", "unknown"),
                    "product": service_info.get("product", ""),
                    "version": service_info.get("version", ""),
                    "cpe": service_info.get("cpe", ""),
                }
                results.append(item)
        
        return results
