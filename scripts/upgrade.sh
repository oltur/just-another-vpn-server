#!/usr/bin/env bash
# Upgrade the javs binary to a specific (or the latest) release.
#
# Run this on the server:
#
#   sudo bash upgrade.sh            # upgrade to latest
#   sudo TAG=v0.1.5 bash upgrade.sh # upgrade to a specific tag
#
# The service is stopped before the binary is replaced and restarted afterwards.
#
set -euo pipefail

REPO="${REPO:-oltur/just-another-vpn-server}"
TAG="${TAG:-}"

if [[ "$EUID" -ne 0 ]]; then
    echo "Run as root (or with sudo)" >&2
    exit 1
fi

if [[ -z "$TAG" ]]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -oP '"tag_name":\s*"\K[^"]+')
fi

CURRENT=""
if command -v javs &>/dev/null; then
    CURRENT=$(javs --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || true)
fi

echo "==> Upgrading javs: ${CURRENT:-unknown} -> $TAG"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TRIPLE="x86_64-unknown-linux-musl" ;;
    aarch64) TRIPLE="aarch64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

BASE="javs-$TAG-$TRIPLE"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "==> Downloading $BASE.tar.gz"
curl -fsSL -O "https://github.com/$REPO/releases/download/$TAG/$BASE.tar.gz"
curl -fsSL -O "https://github.com/$REPO/releases/download/$TAG/$BASE.tar.gz.sha256"
sha256sum -c "$BASE.tar.gz.sha256"

tar xzf "$BASE.tar.gz"

echo "==> Stopping javs.service"
systemctl stop javs || true

install -m 0755 "$BASE/javs" /usr/local/bin/javs

echo "==> Starting javs.service"
systemctl start javs

echo "==> Done. New version:"
javs --version || true
echo
echo "Watch the service:  journalctl -u javs -f"
