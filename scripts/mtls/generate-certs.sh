#!/bin/bash
# NHI Shield — mTLS Certificate Generation
# Generates a private CA + service certificates for mutual TLS between all services
# Usage: bash scripts/mtls/generate-certs.sh
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/certs"
CA_DIR="$CERT_DIR/ca"
VALIDITY_DAYS=825  # ~2 years

SERVICES=("api" "discovery" "anomaly" "risk" "policy" "security" "postgres" "neo4j" "redis" "influxdb" "qdrant")

echo "🔐 NHI Shield mTLS Certificate Generator"
echo "========================================="
echo "Output directory: $CERT_DIR"
echo ""

mkdir -p "$CA_DIR"
for svc in "${SERVICES[@]}"; do
  mkdir -p "$CERT_DIR/$svc"
done

# ─── Generate Root CA ────────────────────────────────────────────────────────
echo "1/3  Generating Root CA..."
openssl genrsa -out "$CA_DIR/ca.key" 4096

openssl req -new -x509 -days $VALIDITY_DAYS \
  -key "$CA_DIR/ca.key" \
  -out "$CA_DIR/ca.crt" \
  -subj "/C=US/ST=CA/O=NHI Shield/CN=NHI Shield Root CA" \
  -extensions v3_ca

echo "     ✅ Root CA created: $CA_DIR/ca.crt"

# ─── Generate Service Certificates ──────────────────────────────────────────
echo ""
echo "2/3  Generating service certificates..."

for SERVICE in "${SERVICES[@]}"; do
  DIR="$CERT_DIR/$SERVICE"

  # Generate private key
  openssl genrsa -out "$DIR/$SERVICE.key" 2048

  # Generate CSR with SAN
  cat > "$DIR/$SERVICE.ext" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
[alt_names]
DNS.1 = $SERVICE
DNS.2 = nhi-$SERVICE
DNS.3 = $SERVICE.nhi-shield.svc.cluster.local
DNS.4 = localhost
IP.1 = 127.0.0.1
EOF

  openssl req -new \
    -key "$DIR/$SERVICE.key" \
    -out "$DIR/$SERVICE.csr" \
    -subj "/C=US/ST=CA/O=NHI Shield/CN=$SERVICE"

  openssl x509 -req \
    -in "$DIR/$SERVICE.csr" \
    -CA "$CA_DIR/ca.crt" \
    -CAkey "$CA_DIR/ca.key" \
    -CAcreateserial \
    -out "$DIR/$SERVICE.crt" \
    -days $VALIDITY_DAYS \
    -extfile "$DIR/$SERVICE.ext" \
    -extensions v3_req

  # Cleanup CSR and ext
  rm "$DIR/$SERVICE.csr" "$DIR/$SERVICE.ext"

  # Create full chain
  cat "$DIR/$SERVICE.crt" "$CA_DIR/ca.crt" > "$DIR/$SERVICE.chain.crt"

  echo "     ✅ $SERVICE"
done

# ─── Set Permissions ─────────────────────────────────────────────────────────
echo ""
echo "3/3  Setting permissions..."
chmod 600 "$CERT_DIR"/**/*.key "$CA_DIR/ca.key"
chmod 644 "$CERT_DIR"/**/*.crt "$CA_DIR/ca.crt"

# ─── Output Summary ──────────────────────────────────────────────────────────
echo ""
echo "🎉 Certificates generated successfully!"
echo ""
echo "Certificate Summary:"
echo "  Root CA:      $CA_DIR/ca.crt"
echo "  Services:     ${SERVICES[*]}"
echo "  Validity:     $VALIDITY_DAYS days"
echo ""
echo "Next steps:"
echo "  1. docker-compose uses certs from ./certs/ (already configured)"
echo "  2. Rotate certs before expiry: bash scripts/mtls/generate-certs.sh"
echo "  3. For K8s: kubectl create secret generic nhi-mtls-certs --from-file=certs/ -n nhi-shield"
echo ""

# Write verification script
cat > "$CERT_DIR/verify.sh" << 'VERIFY'
#!/bin/bash
# Verify mTLS certificates
CERT_DIR="$(dirname "$0")"
echo "Verifying NHI Shield certificates..."
for crt in "$CERT_DIR"/**/*.crt; do
  echo -n "  $crt: "
  if openssl verify -CAfile "$CERT_DIR/ca/ca.crt" "$crt" > /dev/null 2>&1; then
    EXP=$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2)
    echo "✅ Valid (expires: $EXP)"
  else
    echo "❌ INVALID"
  fi
done
VERIFY
chmod +x "$CERT_DIR/verify.sh"
echo "  Verify anytime: bash certs/verify.sh"
