#!/usr/bin/env bash
# Install javs on an Ubuntu/Debian server from the latest GitHub release.
#
# Run this on the server over SSH:
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/oltur/just-another-vpn-server/main/scripts/server-install.sh)
#
# Or with a specific version tag:
#
#   TAG=v0.1.5 bash server-install.sh
#
# After it finishes, edit /etc/javs/server.toml as needed and start the service:
#
#   sudo systemctl enable --now javs
#   journalctl -u javs -f
#
set -euo pipefail

REPO="${REPO:-oltur/just-another-vpn-server}"
TAG="${TAG:-}"

# Resolve the tag if not supplied.
if [[ -z "$TAG" ]]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -oP '"tag_name":\s*"\K[^"]+')
fi

echo "==> Installing javs $TAG"

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
cd "$BASE"

echo "==> Installing binary to /usr/local/bin/javs"
sudo install -m 0755 javs /usr/local/bin/javs

echo "==> Installing default config to /etc/javs (skipping existing files)"
sudo mkdir -p /etc/javs/pki
if [[ ! -f /etc/javs/server.toml ]]; then
    sudo cp configs/server.toml /etc/javs/server.toml
    echo "    wrote /etc/javs/server.toml"
else
    echo "    /etc/javs/server.toml already exists — skipping"
fi

echo "==> Installing systemd unit"
sudo tee /etc/systemd/system/javs.service >/dev/null <<'UNIT'
[Unit]
Description=just-another-vpn-server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/javs --config /etc/javs/server.toml --log info
AmbientCapabilities=CAP_NET_ADMIN
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload

echo
echo "==> Done. Next steps:"
echo "    1. Generate PKI (if needed):  ./scripts/make-client.sh -- see the README"
echo "    2. Edit /etc/javs/server.toml (set correct cert paths, IP pool, NAT)"
echo "    3. sudo systemctl enable --now javs"
echo "    4. journalctl -u javs -f"
