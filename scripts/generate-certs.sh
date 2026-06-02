#!/usr/bin/env bash
# Generate a CA, server cert, and one client cert with OpenSSL.
#
#   ./scripts/generate-certs.sh                  # default names
#   CN_CLIENT=alice ./scripts/generate-certs.sh  # custom client cn
#
set -euo pipefail

PKI_DIR="${PKI_DIR:-configs/pki}"
CN_SERVER="${CN_SERVER:-javs-server}"
CN_CLIENT="${CN_CLIENT:-client1}"
DAYS="${DAYS:-3650}"
# Ed25519 is small and fast; switch to "RSA -pkeyopt rsa_keygen_bits:2048" if
# your OpenVPN client doesn't support it.
KEY_ALG="${KEY_ALG:-ED25519}"

mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

genkey() {
  local out="$1" pass="${2:-}"
  local pass_args=()
  if [[ -n "$pass" ]]; then
    pass_args=(-aes-256-cbc -pass "pass:$pass")
  fi
  if [[ "$KEY_ALG" == "ED25519" ]]; then
    openssl genpkey -algorithm ED25519 ${pass_args[@]+"${pass_args[@]}"} -out "$out"
  else
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 ${pass_args[@]+"${pass_args[@]}"} -out "$out"
  fi
}

# --- CA ---
if [[ ! -f ca.key ]]; then
  echo ">>> generating CA"
  genkey ca.key
  openssl req -x509 -new -key ca.key -days "$DAYS" -subj "/CN=javs-ca" -out ca.crt
fi

# --- Server ---
echo ">>> generating server cert ($CN_SERVER)"
genkey server.key
openssl req -new -key server.key -subj "/CN=${CN_SERVER}" -out server.csr
cat > server.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${CN_SERVER}
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -extfile server.ext

# --- Client ---
echo ">>> generating client cert ($CN_CLIENT)"
_client_pass="${CLIENT_KEY_PASS:-}"
genkey "${CN_CLIENT}.key" "$_client_pass"
_passin_args=()
[[ -n "$_client_pass" ]] && _passin_args=(-passin "pass:$_client_pass")
openssl req -new -key "${CN_CLIENT}.key" ${_passin_args[@]+"${_passin_args[@]}"} -subj "/CN=${CN_CLIENT}" -out "${CN_CLIENT}.csr"
cat > client.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF
openssl x509 -req -in "${CN_CLIENT}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out "${CN_CLIENT}.crt" -days "$DAYS" -extfile client.ext

rm -f ./*.csr server.ext client.ext ca.srl
echo
echo "PKI files written to $(pwd):"
ls -1
