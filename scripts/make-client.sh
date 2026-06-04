#!/usr/bin/env bash
# Create a complete PKI and a ready-to-import client1.ovpn profile.
#
# Run this once on the machine where you manage the PKI (your laptop or the
# server). It generates a CA + server cert + one client cert, copies the
# server-side keys to /etc/javs/pki, and writes client1.ovpn to the current
# directory.
#
# Usage:
#
#   ./scripts/make-client.sh <server-public-ip> [client-cn]
#
#   server-public-ip  public IP or hostname clients connect to (required)
#   client-cn         certificate Common Name, default: client1
#
# Environment overrides:
#   PKI_DIR       where to store PKI files   (default: configs/pki)
#   TLS_CRYPT     set to 1 to generate and embed a tls-crypt PSK
#   INSTALL_KEYS  set to 1 to copy server keys to /etc/javs/pki (needs sudo)
#
set -euo pipefail

SERVER_IP="${1:?Usage: $0 <server-public-ip> [client-cn]}"
CN_CLIENT="${2:-client1}"
PKI_DIR="${PKI_DIR:-configs/pki}"
TLS_CRYPT="${TLS_CRYPT:-0}"
INSTALL_KEYS="${INSTALL_KEYS:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prompt for an optional passphrase to encrypt the client private key.
if [[ -z "${CLIENT_KEY_PASS+x}" ]]; then
    read -r -s -p "Client key passphrase (leave empty for no encryption): " CLIENT_KEY_PASS
    echo
    if [[ -n "$CLIENT_KEY_PASS" ]]; then
        read -r -s -p "Confirm passphrase: " _confirm
        echo
        if [[ "$CLIENT_KEY_PASS" != "$_confirm" ]]; then
            echo "Passphrases do not match." >&2; exit 1
        fi
    fi
fi
export CLIENT_KEY_PASS

# Generate CA + server + client cert if not already present.
PKI_DIR="$PKI_DIR" CN_CLIENT="$CN_CLIENT" "$SCRIPT_DIR/generate-certs.sh"

# Optionally generate a tls-crypt PSK.
if [[ "$TLS_CRYPT" == "1" ]] && [[ ! -f "$PKI_DIR/tc.key" ]]; then
    "$SCRIPT_DIR/generate-psk.sh" "$PKI_DIR/tc.key"
fi

# Optionally install server-side keys into /etc/javs/pki.
if [[ "$INSTALL_KEYS" == "1" ]]; then
    echo "==> Installing server keys to /etc/javs/pki"
    sudo mkdir -p /etc/javs/pki
    sudo cp "$PKI_DIR/ca.crt" "$PKI_DIR/server.crt" "$PKI_DIR/server.key" /etc/javs/pki/
    sudo chmod 600 /etc/javs/pki/server.key
    if [[ -f "$PKI_DIR/tc.key" ]]; then
        sudo cp "$PKI_DIR/tc.key" /etc/javs/pki/
        sudo chmod 600 /etc/javs/pki/tc.key
    fi
fi

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
# Keep VPN control traffic on the physical interface when full-tunnel is active.
route $SERVER_IP 255.255.255.255 net_gateway
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
echo "==> $OUT is ready — import it into the OpenVPN app on the client device."
echo "    Transfer it over a secure channel; it contains the client private key."
