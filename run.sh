#!/bin/bash
# Run the application using the virtual environment's Python interpreter.
# sudo is often required for raw socket access (sniffing).

# ensure we are in the script's directory
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run ./setup.sh first."
    exit 1
fi

echo "Starting LocalNetworkProtector..."
# Using the installed console script keeps runtime aligned with the packaged app
sudo ./venv/bin/lnp "$@"
