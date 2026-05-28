#!/usr/bin/env bash
# Stand up the docker stack, wait for the tunnel to come up, then assert
# that the client can reach both the server's TUN address (basic tunnel)
# and the internal-only target (NAT). Tears the stack down on success.
#
# Requires: docker + docker compose.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f configs/pki/ca.crt ]]; then
    echo ">>> generating PKI (configs/pki was empty)"
    bash scripts/generate-certs.sh
fi

if [[ ! -f configs/pki/tc.key ]]; then
    echo ">>> generating tls-crypt static key"
    {
        echo "-----BEGIN OpenVPN Static key V1-----"
        openssl rand -hex 256 | fold -w 32
        echo "-----END OpenVPN Static key V1-----"
    } > configs/pki/tc.key
    chmod 600 configs/pki/tc.key
fi

cd docker
trap 'docker compose down -v --remove-orphans' EXIT

echo ">>> building + bringing up stack"
docker compose up --build -d

echo ">>> waiting up to 60s for client to reach Initialization Sequence Completed"
for i in $(seq 1 60); do
    if docker compose logs vpn-client 2>&1 | grep -q "Initialization Sequence Completed"; then
        echo ">>> client up (after ${i}s)"
        break
    fi
    sleep 1
    if [[ $i -eq 60 ]]; then
        echo "client never came up; dumping logs:"
        docker compose logs
        exit 1
    fi
done

echo ">>> 1) ping server TUN address 10.8.0.1 from client"
docker compose exec -T vpn-client ping -c 3 -W 3 10.8.0.1

echo ">>> 2) ping6 server TUN address fd00:beef::1 from client"
docker compose exec -T vpn-client ping -6 -c 3 -W 3 fd00:beef::1

echo ">>> 3) curl target 10.98.0.3:8080 (only reachable via NAT)"
docker compose exec -T vpn-client curl -sS --max-time 5 http://10.98.0.3:8080/ >/dev/null

echo
echo "PASS"
