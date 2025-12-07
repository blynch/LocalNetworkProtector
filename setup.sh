#!/bin/bash
set -e

echo "Creating virtual environment..."
python3 -m venv venv

echo "Installing dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "Do not forget to install nmap: sudo apt-get install nmap"
echo "Setup complete. Use ./run.sh to start the application."
