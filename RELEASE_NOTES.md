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

- When upgrading from development snapshots, refresh the virtualenv dependencies and redeploy `config.yaml` changes if new options are introduced.

# LocalNetworkProtector v0.1.1

## Changes
- **Fix**: Corrected configuration loading to properly respect `trusted_ips` in `DetectionConfig`.
- **Config**: Added `config.yaml` with whitelisted IP `192.168.4.38` to prevent self-scanning alerts.

# LocalNetworkProtector v0.2.0

## Changes
- **Feature**: Integrated Google Tsunami Security Scanner for advanced vulnerability detection.
- **Config**: Added `tsunami` configuration section (disabled by default).
- **Setup**: Added `scripts/install_tsunami.sh` to build scanner Docker image.
- **Requirement**: Docker must be installed on the host system for Tsunami support.
- **Web Console**: Added dedicated section to view Tsunami findings and dashboard summary.

