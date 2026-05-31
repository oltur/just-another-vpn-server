#!/usr/bin/env bash
# Add a new client to an existing PKI and generate a .ovpn profile.
#
# Assumes generate-certs.sh has already been run (CA already exists in PKI_DIR).
#
# Usage:
#
#   ./scripts/add-client.sh <client-cn> <server-public-ip>
#
# Examples:
#
#   ./scripts/add-client.sh alice 203.0.113.10
#   ./scripts/add-client.sh bob   myvpn.example.com
#
# Environment overrides:
#   PKI_DIR   where the existing PKI lives (default: configs/pki)
#   DAYS      cert validity in days       (default: 3650)
#
set -euo pipefail

CN_CLIENT="${1:?Usage: $0 <client-cn> <server-public-ip>}"
SERVER_IP="${2:?Usage: $0 <client-cn> <server-public-ip>}"
PKI_DIR="${PKI_DIR:-configs/pki}"
DAYS="${DAYS:-3650}"
KEY_ALG="${KEY_ALG:-ED25519}"

if [[ ! -f "$PKI_DIR/ca.key" ]]; then
    echo "Error: CA not found at $PKI_DIR/ca.key" >&2
    echo "Run ./scripts/make-client.sh first to initialise the PKI." >&2
    exit 1
fi

if [[ -f "$PKI_DIR/${CN_CLIENT}.crt" ]]; then
    echo "Error: $PKI_DIR/${CN_CLIENT}.crt already exists." >&2
    echo "Choose a different CN or remove the existing files." >&2
    exit 1
fi

cd "$PKI_DIR"

echo "==> Generating client cert for $CN_CLIENT"

if [[ "$KEY_ALG" == "ED25519" ]]; then
    openssl genpkey -algorithm ED25519 -out "${CN_CLIENT}.key"
else
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${CN_CLIENT}.key"
fi

openssl req -new -key "${CN_CLIENT}.key" -subj "/CN=${CN_CLIENT}" -out "${CN_CLIENT}.csr"

cat > client.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "${CN_CLIENT}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "${CN_CLIENT}.crt" -days "$DAYS" -extfile client.ext

rm -f "${CN_CLIENT}.csr" client.ext

cd - >/dev/null

# Build the .ovpn profile.
OUT="${CN_CLIENT}.ovpn"
echo "==> Building $OUT"

cat > "$OUT" <<EOF
client
dev tun
proto udp
remote $SERVER_IP 1194
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
tls-version-min 1.2
resolv-retry infinite
nobind
persist-key
persist-tun
verb 3
<ca>
$(cat "$PKI_DIR/ca.crt")
</ca>
<cert>
$(cat "$PKI_DIR/${CN_CLIENT}.crt")
</cert>
<key>
$(cat "$PKI_DIR/${CN_CLIENT}.key")
</key>
EOF

if [[ -f "$PKI_DIR/tc.key" ]]; then
    printf '<tls-crypt>\n%s\n</tls-crypt>\n' "$(cat "$PKI_DIR/tc.key")" >> "$OUT"
    echo "    tls-crypt PSK embedded"
fi

echo
echo "==> $OUT is ready."
echo "    Transfer it to the client over a secure channel; it contains the private key."
