#!/bin/bash
set -e

# Directory to store certificates
CERT_DIR="certs"
mkdir -p "$CERT_DIR"

CERT_FILE="$CERT_DIR/lnp-cert.pem"
KEY_FILE="$CERT_DIR/lnp-key.pem"

echo "Generating self-signed certificate for LocalNetworkProtector..."
openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 -subj "/CN=LocalNetworkProtector"

echo "Certificate generated:"
echo "  Cert: $CERT_FILE"
echo "  Key:  $KEY_FILE"
echo ""
echo "To enable HTTPS, update your config.yaml:"
echo "web:"
echo "  ssl_enabled: true"
echo "  ssl_cert: \"$(pwd)/$CERT_FILE\""
echo "  ssl_key: \"$(pwd)/$KEY_FILE\""
