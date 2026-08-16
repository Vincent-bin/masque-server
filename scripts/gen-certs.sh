#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="${1:-certs}"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    echo "Certs already exist in $CERT_DIR, skipping generation."
    exit 0
fi

echo "Generating self-signed ECDSA P-256 certificate in $CERT_DIR ..."

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CERT_DIR/server.key.pkcs8" \
    -out "$CERT_DIR/server.crt" \
    -days 365 -nodes \
    -subj "/CN=masque-server" \
    -addext "subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1"

# Convert PKCS#8 key to SEC1/traditional EC format (required by BoringSSL/quiche).
openssl ec -in "$CERT_DIR/server.key.pkcs8" -out "$CERT_DIR/server.key" 2>/dev/null
rm -f "$CERT_DIR/server.key.pkcs8"

echo "Done: $CERT_DIR/server.crt  $CERT_DIR/server.key"
