# LocalNetworkProtector

LocalNetworkProtector is a lightweight application designed for Raspberry Pi deployments. It monitors local network traffic for suspicious patterns (passive heuristic detection), performs active scanning to identify vulnerable services, and provides a dashboard for network observability.

## Features
- **Passive Monitoring**: Detects port scans, risky ports, suspicious payloads, and DNS exfiltration using Scapy.
    - *New*: Supports filtering trusted source ports (e.g. ignoring Grafana traffic) to reduce false positives.
- **Active Scanning & Vulnerability Detection**:
    - Automatically scans suspicious IPs (or manually configured ranges) using `nmap`.
    - *New*: Configurable re-scan interval to prevent flooding (default: 60 mins).
    - Checks detected services against the **NVD** (CPE) and **OSV.dev** (OSS-Fuzz) databases for known vulnerabilities.
- **GitHub Repo Scanning**:
    - Periodically syncs repos from a configured GitHub account using `gh`.
    - Runs **OSV-SCALIBR** against each repo checkout and stores potential findings.

- **Observability**:
    - **OpenTelemetry** metrics for scans, vulnerabilities, and alerts.
    - **Grafana Dashboard** (via Docker) to visualize network security posture.
    - **SQLite** database for storing detailed finding history.
- **Alerting**: Email notifications with batching and cooldowns to prevent fatigue.

## Requirements
- **Hardware**: Raspberry Pi (3B+/4/5 recommended).
- **OS**: Raspberry Pi OS (Debian-based).
- **Software**: Python 3.9+, standard build tools.
- **Optional**: Docker & Docker Compose (for the Observability Dashboard).

## Quick Start (Raspberry Pi)

See the **[Raspberry Pi Installation Guide](README_RPI.md)** for detailed, step-by-step setup instructions including virtual environments and Docker setup.

### Basic Usage (Native)

1.  **Install dependencies**:
    ```bash
    sudo apt-get install nmap libpcap0.8-dev
    ./setup.sh
    ```

2.  **Configure**:
    ```bash
    cp config.yaml.sample config.yaml
    nano config.yaml
    ```
    Enable active scanning, vulnerability checks, and optional repo scanning in the config if desired.

3.  **Run**:
    ```bash
    ./run.sh --config config.yaml
    ```

### Build A Release Archive

To create a deployable archive for Raspberry Pi:

```bash
bash scripts/build_release.sh
```

The release archive is written as `dist/LocalNetworkProtector_v<release>.tar.gz` with flat root-level contents.
The current packaged release is `dist/LocalNetworkProtector_v72.tar.gz`.

### GitHub Repo Scanning

1. Authenticate GitHub CLI:
   ```bash
   gh auth login
   ```
2. Enable `repo_scanning` in `config.yaml`.
3. Ensure `repo_scanning.scalibr_binary` points at your installed `scalibr` binary.
4. If you are using the systemd service on Raspberry Pi, edit `/etc/localnetworkprotector/config.yaml`, not the copy under `/opt/LocalNetworkProtector`.
5. View the results in the `Repo Scans` page or `/api/repo-scans`.

## Observability Stack

The application integrates with Prometheus and Grafana to visualize data.

1.  **Start the stack**:
    ```bash
    docker compose up -d
    ```
2.  **Access Dashboard**:
    - Open `http://<pi-ip>:3000`
    - Login: `admin` / `admin` (default)
    - View **LocalNetworkProtector Dashboard** to see real-time scan metrics and vulnerability counts.

## Development

### Running Tests
```bash
python3 -m unittest discover -s tests -v
```

### Data & Logs
- **Logs**: Output to stdout by default.
- **Database**: `lnp.db` (SQLite) contains the history of all active scans and findings.
- **Metrics**: Exposed at `http://<host>:9464/metrics` for Prometheus.
- **Repo Scan Results**: SCALIBR textproto results are stored in the configured `repo_scanning.results_dir`.

## License
MIT
