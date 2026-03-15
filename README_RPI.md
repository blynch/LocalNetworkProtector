# LocalNetworkProtector - Raspberry Pi Installation Guide

## 1. Requirements
- Raspberry Pi 3B+ / 4 / 5 running Raspberry Pi OS.
- Python 3.9+.
- Internet access for `apt` and `pip` during install.

## 2. Build The Release Archive On Your Dev Machine
From the repository root:

```bash
bash scripts/build_release.sh
```

This produces:

```bash
dist/LocalNetworkProtector_v70.tar.gz
```

## 3. Copy The Archive To The Pi
Example:

```bash
scp dist/LocalNetworkProtector_v70.tar.gz pi@<pi-ip>:/home/pi/
```

## 4. Extract And Install On The Pi
On the Raspberry Pi:

```bash
mkdir LocalNetworkProtector
tar -xzf LocalNetworkProtector_v70.tar.gz -C LocalNetworkProtector
cd LocalNetworkProtector
sudo bash scripts/install_rpi.sh --enable-service
```

This installs the app under `/opt/LocalNetworkProtector`, creates a virtualenv, installs the package, copies the systemd unit, and rolls out only `/etc/localnetworkprotector/config.yaml.sample`.

## 5. Configure The Pi
Create and edit the installed config:

```bash
sudo cp /etc/localnetworkprotector/config.yaml.sample /etc/localnetworkprotector/config.yaml
sudo nano /etc/localnetworkprotector/config.yaml
```

At minimum:
- Set `capture.interface` to the correct network interface such as `eth0` or `wlan0`.
- Enable `active_scanning` only if you want active probing.
- Keep `active_scanning.allow_public_targets: false` unless you intentionally want to scan public IPs.
- If enabling web auth, set `web.session_secret` and either `web.password_hash` or `web.password`.

To generate a password hash:

```bash
cd /opt/LocalNetworkProtector
./venv/bin/python scripts/generate_password_hash.py
```

## 6. Validate The Service
Check status:

```bash
sudo systemctl status localnetworkprotector
```

Stream logs:

```bash
sudo journalctl -u localnetworkprotector -f
```

Smoke test the HTTP UI:
- Open `http://<pi-ip>:5000`
- If auth is enabled, sign in with the configured credentials.

Smoke test the API:

```bash
curl http://<pi-ip>:5000/api/scans
```

If `web.api_tokens` is configured:

```bash
curl -H "Authorization: Bearer <token>" http://<pi-ip>:5000/api/scans
```

## 7. Optional: Observability Stack
If you want Grafana and Prometheus:

```bash
sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
```

Then from `/opt/LocalNetworkProtector`:

```bash
docker compose up -d
```

Grafana will be available at `http://<pi-ip>:3000`.

## 8. Updating A Pi
Copy a newer release archive to the Pi, extract it, and rerun:

```bash
sudo bash scripts/install_rpi.sh --enable-service
```

The installer preserves an existing `/etc/localnetworkprotector/config.yaml`.

## 9. Troubleshooting
- If the service fails immediately, check `sudo journalctl -u localnetworkprotector -n 200`.
- If packet capture fails, confirm the configured interface exists with `ip addr`.
- If the web UI is unreachable, confirm port `5000` is open and the service is running.
- If `nmap` scans fail, confirm `nmap` is installed and callable with `nmap --version`.
