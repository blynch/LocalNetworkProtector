#!/bin/bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/LocalNetworkProtector}"
CONFIG_DIR="${CONFIG_DIR:-/etc/localnetworkprotector}"
SERVICE_NAME="${SERVICE_NAME:-localnetworkprotector}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_SERVICE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable-service)
      INSTALL_SERVICE=1
      shift
      ;;
    --app-dir)
      APP_DIR="$2"
      shift 2
      ;;
    --config-dir)
      CONFIG_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo ./scripts/install_rpi.sh [--enable-service]" >&2
  exit 1
fi

apt-get update
apt-get install -y python3 python3-venv python3-pip nmap libpcap0.8-dev rsync

mkdir -p "$APP_DIR" "$CONFIG_DIR"
rsync -a \
  --delete \
  --exclude '.git' \
  --exclude 'dist' \
  --exclude 'config.yaml' \
  --exclude 'venv' \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "$REPO_DIR"/ "$APP_DIR"/

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$APP_DIR/venv/bin/pip" install "$APP_DIR"

cp "$APP_DIR/config.yaml.sample" "$CONFIG_DIR/config.yaml.sample"

cp "$APP_DIR/localnetworkprotector.service" "/etc/systemd/system/${SERVICE_NAME}.service"
sed -i "s|/opt/LocalNetworkProtector|$APP_DIR|g" "/etc/systemd/system/${SERVICE_NAME}.service"
sed -i "s|--config config.yaml|--config $CONFIG_DIR/config.yaml|g" "/etc/systemd/system/${SERVICE_NAME}.service"

systemctl daemon-reload
if [[ "$INSTALL_SERVICE" -eq 1 ]]; then
  systemctl enable --now "${SERVICE_NAME}.service"
fi

echo "Installed to $APP_DIR"
echo "Sample config: $CONFIG_DIR/config.yaml.sample"
if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
  echo "Active config: $CONFIG_DIR/config.yaml"
else
  echo "Active config not found yet. Create it from the sample before starting the service:"
  echo "  sudo cp $CONFIG_DIR/config.yaml.sample $CONFIG_DIR/config.yaml"
fi
if [[ "$INSTALL_SERVICE" -eq 1 ]]; then
  echo "Service started: ${SERVICE_NAME}.service"
else
  echo "Service installed but not started. Run:"
  echo "  sudo systemctl enable --now ${SERVICE_NAME}.service"
fi
