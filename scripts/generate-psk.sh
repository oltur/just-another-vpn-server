#!/usr/bin/env bash
# Generate an OpenVPN static key (256 bytes) for --tls-auth / --tls-crypt.
#
# This produces the exact "OpenVPN Static key V1" PEM format that both javs
# and the openvpn client accept, without needing the openvpn binary installed
# (`openvpn --genkey --secret <file>` does the same thing).
#
#   ./scripts/generate-psk.sh                 # writes configs/pki/tc.key
#   ./scripts/generate-psk.sh configs/ta.key  # custom path
set -euo pipefail

OUT="${1:-configs/pki/tc.key}"
mkdir -p "$(dirname "$OUT")"

{
    echo "-----BEGIN OpenVPN Static key V1-----"
    openssl rand -hex 256 | fold -w 32
    echo "-----END OpenVPN Static key V1-----"
} > "$OUT"
chmod 600 "$OUT"

echo "wrote $OUT"
echo
echo "Server: set tls_crypt_key (or tls_auth_key) to this path in server.toml."
echo "Client: paste the contents into a <tls-crypt> (or <tls-auth>) block."
