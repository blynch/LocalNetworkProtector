# LocalNetworkProtector

LocalNetworkProtector is a lightweight Python application intended for Raspberry Pi deployments. It monitors local network traffic, applies heuristic rules to spot suspicious or malicious patterns, and alerts you by email when something looks wrong.

## Features
- Live packet capture via Scapy with optional PCAP replay for offline analysis
- Heuristics for port scans, risky ports, suspicious payload keywords, and DNS data exfiltration indicators
- Configurable severity thresholds and capture parameters
- Email notification with batching and cooldown to avoid alert storms
- YAML configuration with environment variable overrides (prefix `LNP_`)

## Requirements
- Raspberry Pi running a recent Raspberry Pi OS (Bullseye or later recommended)
- Python 3.9+
- Scapy (`pip install scapy`) and PyYAML (`pip install pyyaml`)
- Root privileges for live packet capture (`sudo`)
- An SMTP account (e.g., Gmail with app password) to send alerts

## Installation
1. Install system dependencies:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip tcpdump
   ```
2. Install Python packages:
   ```bash
   python3 -m pip install --upgrade pip
   python3 -m pip install scapy pyyaml
   ```
3. Clone or copy this repository onto your Raspberry Pi.

## Quick Start
1. Copy the sample configuration and adjust values:
   ```bash
   cp config.sample.yaml config.yaml
   nano config.yaml
   ```
   At minimum set:
   - `capture.interface` to your network interface (e.g. `eth0` or `wlan0`)
   - `notification.username`, `notification.password`, `notification.sender`
   - `notification.recipients`
2. Test configuration loading:
   ```bash
   python3 lnp_main.py --dry-run --config config.yaml
   ```
3. Start monitoring (requires sudo for packet capture):
   ```bash
   sudo -E python3 lnp_main.py --config config.yaml
   ```
   Use `-E` to preserve environment variables such as `LNP_NOTIFICATION__PASSWORD`.

## Email Notifications
- The notifier batches alerts and enforces a cooldown window (`notification.cool_down_seconds`).
- Alerts below `notification.min_severity` are ignored.
- Sender defaults to `notification.sender` or falls back to `notification.username`.
- Sensitive fields can be provided via environment variables, e.g.:
  ```bash
  export LNP_NOTIFICATION__PASSWORD="app-password"
  ```

## PCAP Replay (Offline Testing)
You can replay a captured PCAP file to validate detection rules without live traffic:
```bash
python3 lnp_main.py --config config.yaml --pcap samples/suspicious.pcap
```
The notifier still enforces cooldowns; call `--dry-run` if you only want console logs.

## Running on Boot (Optional)
Create a systemd service file `/etc/systemd/system/localnetworkprotector.service`:
```ini
[Unit]
Description=Local Network Protector
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/path/to/LocalNetworkProtector
ExecStart=/usr/bin/python3 lnp_main.py --config /path/to/config.yaml
Restart=on-failure
User=root
Environment=LNP_NOTIFICATION__PASSWORD=app-password

[Install]
WantedBy=multi-user.target
```
Then enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now localnetworkprotector.service
```

## Logging
- By default the application logs to stdout. When running under systemd, capture logs with `journalctl -u localnetworkprotector`.
- To write to a dedicated file, create a writable directory (e.g. `/var/log/localnetworkprotector`) and point your service or shell redirection there:
  ```bash
  sudo mkdir -p /var/log/localnetworkprotector
  sudo chown pi:pi /var/log/localnetworkprotector
  sudo -E .venv/bin/python lnp_main.py --config config.yaml \
    >> /var/log/localnetworkprotector/app.log 2>&1 &
  ```
- Adjust ownership to match the user running the service. Avoid writing directly to `/var/log` without setting permissions.

## Simulating Suspicious Traffic
The `scripts/simulate_traffic.py` helper sends packets that should trigger each rule. Run it from another machine or adapt the targets to your Pi:
```bash
python3 scripts/simulate_traffic.py --target 192.168.1.10
```
This helper requires scapy and root privileges on the machine sending packets.

## Development Notes
- Logging level is controlled by `log_level` in the config or `--log-level` CLI flag.
- The detector contains stateful heuristics and keeps alerts cached for 10 minutes to reduce duplicate emails.
- Add new rules by extending `DetectionRule` in `localnetworkprotector/detector.py`.
