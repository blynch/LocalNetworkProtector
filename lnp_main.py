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


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    config = load_config(args.config)

    log_level = args.log_level or config.log_level
    configure_logging(log_level)
    log = logging.getLogger("lnp")
    log.info("LocalNetworkProtector starting up.")

    detection_engine = DetectionEngine(config.detection)
    notifier = EmailNotifier(config.notification)
    monitor = MonitorService(
        config=config,
        detection_engine=detection_engine,
        alert_callback=notifier.handle_alert,
    )

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
