# LocalNetworkProtector - Raspberry Pi Installation Guide

## 1. System Requirements
- Raspberry Pi (3B+ or 4 recommended) running Raspberry Pi OS (latest).
- Internet connection.

## 2. Install System Dependencies
Update your system and install required tools:
```bash
sudo apt-get update
sudo apt-get install -y nmap libpcap0.8-dev
```

## 3. Systemd Service (Auto-Start)
To run as a system service (so it starts on boot and logs to journald):

1.  **Copy the service file**:
    ```bash
    sudo cp localnetworkprotector.service /etc/systemd/system/
    ```
2.  **Reload Daemon**:
    ```bash
    sudo systemctl daemon-reload
    ```
3.  **Enable & Start**:
    ```bash
    sudo systemctl enable localnetworkprotector
    sudo systemctl start localnetworkprotector
    ```
4.  **View Logs**:
    ```bash
    # View live logs
    sudo journalctl -u localnetworkprotector -f
    ```

## 4. Install Docker (For Observability)
If you want to use the Grafana dashboard, you need Docker and Docker Compose.
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to the docker group (so you don't need sudo for docker commands)
sudo usermod -aG docker $USER

# Install Docker Compose (if not included in newer docker plugins)
sudo apt-get install -y docker-compose-plugin
```
*Note: You may need to log out and back in for the group change to take effect.*

## 4. Install Application
1.  **Extract the archive**:
    ```bash
    tar -xzvf LocalNetworkProtector_v54.tar.gz
    cd LocalNetworkProtector
    ```

2.  **Authenticate (One-Time)**:
    Run the login script (requires sudo to save session file):
    ```bash
    sudo ./venv/bin/python3 scripts/eero_login.py
    ```
    Follow the prompts to enter your email/phone and the verification code.s.
    ```bash
    chmod +x setup.sh run.sh
    ```bash
    chmod +x setup.sh run.sh
    ./setup.sh
    ```

3.  **Enable HTTPS (Optional)**:
    Run the certificate generation script:
    ```bash
    ./scripts/generate_cert.sh
    ```
    Then update `config.yaml` with the paths output by the script.

## 5. Configuration
1.  Copy the sample config:
    ```bash
    cp config.sample.yaml config.yaml
    ```
2.  Edit `config.yaml`:
    - Enable `active_scanning` if desired.
    - Enable `vulnerability_scanning`.
    - Set `interface` (e.g., `wlan0` or `eth0`).

## 6. Running

### Start Observability Stack (Optional)
This starts Prometheus and Grafana in the background.
```bash
docker compose up -d
```
- Dashboards available at: `http://<pi-ip>:3000` (Default user/pass: `admin`/`admin`)

### Start Protector
Run the main application using the wrapper script:
```bash
./run.sh --config config.yaml
```
*Note: `run.sh` uses `sudo` internally because packet capture requires root privileges.*

## 7. Troubleshooting
- **"externally-managed-environment"**: Ensure you used `./setup.sh` and are running with `./run.sh`.
- **Permission denied**: Make sure scripts are executable (`chmod +x ...`) and `run.sh` is used.
- **Dependency Errors**: The `setup.sh` script should automatically pull compatible versions of libraries.
- **Port 3000 not open**:
    1. Check if containers are running: `docker compose ps`
    2. Check logs: `docker compose logs grafana`
    3. If permission errors occur, we have switched to named volumes in V7 to fix this.

