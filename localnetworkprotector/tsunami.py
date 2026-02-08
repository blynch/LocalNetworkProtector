"""Integration with Google Tsunami Security Scanner via Docker."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from typing import List, Optional
from pathlib import Path

from .config import TsunamiConfig
from .vulnerability import Vulnerability

log = logging.getLogger(__name__)


class TsunamiScanner:
    """Runs Tsunami Security Scanner in a Docker container."""

    def __init__(self, config: TsunamiConfig):
        self.config = config

    def is_available(self) -> bool:
        """Check if Docker is available and the image exists."""
        try:
            subprocess.run(
                ["docker", "--version"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Optionally check if image exists?
            # subprocess.run(["docker", "inspect", self.config.docker_image], ...)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def scan(self, ip: str) -> List[Vulnerability]:
        """Run Tsunami scan against a target IP."""
        if not self.config.enabled:
            return []

        if not self.is_available():
            log.warning("Tsunami scan requested but Docker is not available.")
            return []

        log.info("Starting Tsunami scan for %s", ip)
        vulnerabilities = []

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            output_file = temp_path / "tsunami-output.json"
            
            # Ensure the directory exists (it should, but good practice)
            temp_path.mkdir(parents=True, exist_ok=True)

            cmd = [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_path}:/usr/tsunami/logs",
                self.config.docker_image,
                "java",
                "-cp",
                "tsunami-main-*-cli.jar:plugins/*",
                "-Dtsunami-config.location=/usr/tsunami/tsunami.yaml",
                "com.google.tsunami.main.cli.TsunamiCli",
                f"--ip-v4-target={ip}",
                "--scan-results-local-output-format=JSON",
                "--scan-results-local-output-filename=/usr/tsunami/logs/tsunami-output.json",
            ]

            try:
                subprocess.run(
                    cmd,
                    check=True,
                    timeout=self.config.scan_timeout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                
                if output_file.exists():
                    with open(output_file, "r") as f:
                        data = json.load(f)
                        vulnerabilities = self._parse_results(data)
                else:
                    log.warning("Tsunami scan finished but no output file found.")

            except subprocess.TimeoutExpired:
                log.error("Tsunami scan timed out for %s", ip)
            except subprocess.CalledProcessError as e:
                log.error("Tsunami scan failed for %s: %s", ip, e.stderr.decode())
            except Exception as e:
                log.error("Unexpected error running Tsunami for %s: %s", ip, e)

        return vulnerabilities

    def _parse_results(self, data: dict) -> List[Vulnerability]:
        """Parse Tsunami JSON output into Vulnerability objects."""
        vulns = []
        scan_findings = data.get("scanFindings", [])
        
        for finding in scan_findings:
            vuln_details = finding.get("vulnerability", {})
            title = vuln_details.get("title", "Unknown Vulnerability")
            desc = vuln_details.get("description", "No description provided.")
            rating = vuln_details.get("severity", "UNKNOWN")
            
            # Map Tsunami severity to ours
            # Tsunami: CRITICAL, HIGH, MEDIUM, LOW, INFO
            severity = rating.lower()
            
            vulns.append(
                Vulnerability(
                    id=title, # Tsunami doesn't always give a CVE ID cleanly, title is usually the identifier
                    source="Tsunami",
                    severity=severity,
                    description=desc,
                )
            )
            
        return vulns
