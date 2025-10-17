# LocalNetworkProtector v0.1.0

Initial release targeting Raspberry Pi deployments.

## Highlights
- Live packet capture via Scapy with optional PCAP replay.
- Heuristic detection for port scans, suspicious ports, payload keywords, and DNS exfiltration indicators.
- Configurable YAML-driven settings with environment variable overrides.
- Batched email notifications with severity filtering and cooldown.
- CLI entrypoint with dry-run validation and logging customization.
- Sample configuration, traffic simulation helper, and deployment guidance.

## Known Considerations
- Requires root privileges (or appropriate capabilities) for live packet sniffing.
- Email delivery depends on accessible SMTP credentials; consider app passwords for Gmail.
- Detection heuristics are intentionally conservative and may need tuning for noisy networks.
- Scapy must be installed on the Raspberry Pi (`pip install scapy` inside a virtualenv or via apt).

## Upgrade Notes
- When upgrading from development snapshots, refresh the virtualenv dependencies and redeploy `config.yaml` changes if new options are introduced.
