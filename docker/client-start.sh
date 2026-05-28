#!/usr/bin/env bash
# Run the OpenVPN client against the javs server inside docker compose.
# Server hostname `vpn-server` is provided by docker's embedded DNS.
set -euo pipefail

exec openvpn \
    --client \
    --dev tun \
    --proto tcp-client \
    --remote vpn-server 1194 \
    --ca /certs/ca.crt \
    --cert /certs/client1.crt \
    --key /certs/client1.key \
    --tls-crypt /certs/tc.key \
    --remote-cert-tls server \
    --cipher AES-256-GCM \
    --data-ciphers AES-256-GCM \
    --auth SHA256 \
    --tls-version-min 1.2 \
    --resolv-retry infinite \
    --persist-key \
    --persist-tun \
    --pull-filter ignore "block-outside-dns" \
    --verb 4
