#!/bin/bash
set -e

echo "Creating virtual environment..."
python3 -m venv venv

echo "Installing dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "Ensuring nmap is installed..."
sudo apt-get install -y nmap || echo "Warning: Failed to install nmap. Please ensure it is installed."

if command -v nmap &> /dev/null; then
    echo "SUCCESS: Nmap installed."
    nmap --version | head -n 1
else
    echo "ERROR: Nmap binary NOT found in PATH."
fi

echo "Installing Tsunami Scanner (Docker required)..."
chmod +x scripts/install_tsunami.sh
./scripts/install_tsunami.sh || echo "Warning: Tsunami installation failed. Docker may be missing."

echo "Setup complete. Use ./run.sh to start the application."
