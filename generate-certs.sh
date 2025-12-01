#!/bin/bash

# Script per generare certificati self-signed per testing locale

set -e

CERT_DIR="certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

echo "🔐 Generating self-signed TLS certificates for local development..."

# Crea la directory se non esiste
mkdir -p "$CERT_DIR"

# Genera certificato self-signed
openssl req -x509 \
    -newkey rsa:4096 \
    -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "✅ Certificates generated successfully!"
echo ""
echo "Certificate: $CERT_FILE"
echo "Private key: $KEY_FILE"
echo ""
echo "⚠️  These are self-signed certificates for TESTING ONLY!"
echo "    Your browser will show a security warning - this is expected."
echo "    Click 'Advanced' and 'Proceed' to continue."
echo ""
