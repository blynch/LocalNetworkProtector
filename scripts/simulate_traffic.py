#!/usr/bin/env python3
"""
Simulate suspicious network traffic to exercise LocalNetworkProtector rules.

Requires root privileges and scapy.
"""

from __future__ import annotations

import argparse
import random
import sys
import time

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, send
except Exception as exc:  # pragma: no cover - runtime dependency
    print("Scapy is required to run this script: pip install scapy", file=sys.stderr)
    raise


def send_port_scan(target: str, ports: list[int], source_port: int) -> None:
    print(f"[+] Simulating port scan to {target} on ports {ports}")
    for port in ports:
        packet = IP(dst=target) / TCP(sport=source_port, dport=port, flags="S")
        send(packet, verbose=False)
        time.sleep(0.05)


def send_suspicious_port(target: str, port: int, source_port: int) -> None:
    print(f"[+] Sending packet to suspicious port {port} on {target}")
    payload = Raw(load=b" benign ping ")
    packet = IP(dst=target) / TCP(sport=source_port, dport=port, flags="PA") / payload
    send(packet, verbose=False)


def send_suspicious_payload(target: str, port: int, source_port: int) -> None:
    pattern = b"malware beacon checking in"
    print(f"[+] Sending suspicious payload to {target}:{port}")
    packet = IP(dst=target) / TCP(sport=source_port, dport=port, flags="PA") / Raw(
        load=pattern
    )
    send(packet, verbose=False)


def send_dns_exfil(target_dns_server: str) -> None:
    long_label = "data" + "x" * 50
    domain = f"{long_label}.example.com"
    print(f"[+] Sending DNS query with long label to {target_dns_server}")
    packet = IP(dst=target_dns_server) / UDP(dport=53) / DNS(
        rd=1, qd=DNSQR(qname=domain)
    )
    send(packet, verbose=False)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate suspicious traffic for LocalNetworkProtector."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address (your Raspberry Pi).",
    )
    parser.add_argument(
        "--target-dns",
        default=None,
        help="DNS server to target for exfil example (defaults to target).",
    )
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        type=int,
        # Default enough ports to trigger the 30-port threshold
        default=[p for p in range(5000, 5040)],
        help="Ports to scan/simulate.",
        help="Ports to scan/simulate.",
    )
    parser.add_argument(
        "--suspicious-port",
        type=int,
        default=23,
        help="Port considered suspicious.",
    )
    parser.add_argument(
        "--payload-port",
        type=int,
        default=8080,
        help="Port to send suspicious payload to.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    target_dns = args.target_dns or args.target
    src_port = random.randint(20000, 65000)

    send_port_scan(args.target, args.ports, src_port)
    send_suspicious_port(args.target, args.suspicious_port, src_port)
    send_suspicious_payload(args.target, args.payload_port, src_port)
    send_dns_exfil(target_dns)

    print("[+] Simulation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
