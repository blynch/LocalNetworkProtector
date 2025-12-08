# LocalNetworkProtector

LocalNetworkProtector is a lightweight application designed for Raspberry Pi deployments. It monitors local network traffic for suspicious patterns (passive heuristic detection), performs active scanning to identify vulnerable services, and provides a dashboard for network observability.

## Features
- **Passive Monitoring**: Detects port scans, risky ports, suspicious payloads, and DNS exfiltration using Scapy.
- **Active Scanning & Vulnerability Detection**:
    - Automatically scans suspicious IPs (or manually configured ranges) using `nmap`.
    - Checks detected services against the **NVD** (CPE) and **OSV.dev** (OSS-Fuzz) databases for known vulnerabilities.
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
    pip install -r requirements.txt
    ```

2.  **Configure**:
    ```bash
    cp config.sample.yaml config.yaml
    nano config.yaml
    ```
    Enable active scanning and vulnerability checks in the config if desired.

3.  **Run**:
    ```bash
    sudo python3 lnp_main.py --config config.yaml
    ```

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
(Add instructions for running tests if applicable, or remove this section)

### Data & Logs
- **Logs**: Output to stdout by default.
- **Database**: `lnp.db` (SQLite) contains the history of all active scans and findings.
- **Metrics**: Exposed at `http://<host>:9464/metrics` for Prometheus.

## License
MIT
