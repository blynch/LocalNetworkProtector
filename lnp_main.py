#!/usr/bin/env python3
"""LocalNetworkProtector entrypoint script."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from pathlib import Path

from localnetworkprotector.config import load_config
from localnetworkprotector.detector import DetectionEngine
from localnetworkprotector.monitor import MonitorService
from localnetworkprotector.notifier import EmailNotifier
from localnetworkprotector.scanner import ActiveScanner
from localnetworkprotector.tsunami import TsunamiScanner
from localnetworkprotector.vulnerability import VulnerabilityManager
from localnetworkprotector.database import DatabaseManager
from localnetworkprotector.telemetry import TelemetryManager
from localnetworkprotector.repo_scanner import RepoScanner
import threading
from localnetworkprotector import web


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor local network traffic and report suspicious activity."
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration YAML file.",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        help="Optional path to a PCAP file to replay instead of live capture.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        help="Override log level (DEBUG, INFO, WARNING, ERROR).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load configuration and exit without starting capture.",
    )
    return parser.parse_args(argv)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    )


def validate_web_config(config, log: logging.Logger) -> bool:
    """Validate web/HTTPS configuration before starting the servers."""
    if not config.web or not config.web.enabled:
        return True

    log.info(
        "Effective web config: host=%s http_port=%s ssl_enabled=%s ssl_port=%s cert=%s key=%s",
        config.web.host,
        config.web.port,
        config.web.ssl_enabled,
        config.web.ssl_port,
        config.web.ssl_cert,
        config.web.ssl_key,
    )

    if not config.web.ssl_enabled:
        return True

    cert = config.web.ssl_cert
    key = config.web.ssl_key
    missing = []
    if not cert:
        missing.append("ssl_cert is not configured")
    elif not Path(cert).exists():
        missing.append(f"ssl_cert does not exist: {cert}")

    if not key:
        missing.append("ssl_key is not configured")
    elif not Path(key).exists():
        missing.append(f"ssl_key does not exist: {key}")

    if missing:
        log.error("HTTPS startup blocked: %s", "; ".join(missing))
        return False

    return True


from localnetworkprotector.eero_manager import EeroManager

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    config = load_config(args.config)

    log_level = args.log_level or config.log_level
    configure_logging(log_level)
    log = logging.getLogger("lnp")
    log.info("LocalNetworkProtector starting up.")

    if not validate_web_config(config, log):
        return 1

    detection_engine = DetectionEngine(config.detection)
    notifier = EmailNotifier(config.notification)
    
    active_scanner = ActiveScanner()
    vulnerability_manager = VulnerabilityManager(config.vulnerability_scanning)
    tsunami_scanner = TsunamiScanner(config.detection.tsunami)

    # Observability
    db = DatabaseManager(config.database_path)
    db.init_db()
    
    telemetry = TelemetryManager()
    telemetry.initialize(prometheus_port=9464)
    # Initialize Eero Manager
    eero_manager = EeroManager(config.eero, database=db)
    repo_scanner = RepoScanner(config.repo_scanning)
    
    monitor = MonitorService(
        config=config,
        detection_engine=detection_engine,
        active_scanner=active_scanner,
        vulnerability_manager=vulnerability_manager,
        alert_callback=notifier.handle_alert,
        database=db,
        telemetry=telemetry,
        eero_manager=eero_manager,
        tsunami_scanner=tsunami_scanner,
        repo_scanner=repo_scanner,
    )

    # Start Web Console
    if config.web and config.web.enabled:
        log.info("Starting Web Admin Console on HTTP port %d", config.web.port)
        log.info("SSL Enabled: %s, SSL Port: %s", config.web.ssl_enabled, config.web.ssl_port)
        app = web.create_app(config, db, monitor)
        
        # Start HTTP Server
        http_thread = threading.Thread(
            target=app.run, 
            kwargs={
                'host': config.web.host, 
                'port': config.web.port, 
                'debug': False, 
                'use_reloader': False
            },
            daemon=True
        )
        http_thread.start()

        # Start HTTPS Server if enabled
        if config.web.ssl_enabled:
            cert = config.web.ssl_cert
            key = config.web.ssl_key
            log.info("Starting Web Admin Console on HTTPS port %d", config.web.ssl_port)
            ssl_context = (cert, key)
            https_thread = threading.Thread(
                target=app.run,
                kwargs={
                    'host': config.web.host,
                    'port': config.web.ssl_port,
                    'debug': False,
                    'use_reloader': False,
                    'ssl_context': ssl_context
                },
                daemon=True
            )
            https_thread.start()

    def _graceful_shutdown(signum, frame):  # type: ignore[unused-argument]
        log.info("Received signal %s; flushing notifications and exiting.", signum)
        notifier.flush()
        sys.exit(0)

    signal.signal(signal.SIGINT, _graceful_shutdown)
    signal.signal(signal.SIGTERM, _graceful_shutdown)

    if args.dry_run:
        log.info("Dry run complete. Configuration loaded successfully.")
        return 0

    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            log.error("PCAP file %s does not exist.", pcap_path)
            return 1
        monitor.process_pcap(str(pcap_path))
        notifier.flush()
        return 0

    monitor.start()
    notifier.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
