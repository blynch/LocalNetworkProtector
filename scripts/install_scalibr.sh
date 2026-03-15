#!/bin/bash
set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "Installing Go..."
  sudo apt-get update
  sudo apt-get install -y golang-go
fi

echo "Installing SCALIBR..."
GO111MODULE=on go install github.com/google/osv-scalibr/binary/scalibr@latest

echo "SCALIBR installed at:"
go env GOPATH
echo "Make sure \$(go env GOPATH)/bin is in PATH for the LocalNetworkProtector service user."
