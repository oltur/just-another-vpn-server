# just-another-vpn-server (javs)

An OpenVPN-protocol-compatible VPN server written in Rust. It speaks enough of
the OpenVPN 2.6 wire protocol that a **stock `openvpn` client connects to it
unmodified** — TLS-authenticated control channel, AES-256-GCM data channel,
`PUSH_REPLY` address/route assignment, rekeying, `tls-auth`/`tls-crypt`, NAT,
IPv6-in-tunnel, and both UDP and TCP transport.

The binary is `javs`.

> **Scope.** This is a complete, working server suitable for self-hosting and
> learning, not a hardened drop-in replacement for the OpenVPN daemon. It has
> been verified end-to-end against OpenVPN 2.6.14. See
> [Limitations](#limitations).

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Build](#build)
- [Deploy on Ubuntu from a release (recommended)](#deploy-on-ubuntu-x86-64-from-a-release)
- [Build & deploy from source (cross-compile)](#deploying-to-ubuntu-by-cross-compiling-from-macos)
- [Quick start](#quick-start-5-minutes)
- [Configuration reference](#configuration-reference)
- [Client profiles](#client-profiles)
- [Control-channel protection: tls-auth vs tls-crypt](#control-channel-protection-tls-auth-vs-tls-crypt)
- [Full tunnel and NAT](#full-tunnel-and-nat)
- [IPv6 in the tunnel](#ipv6-in-the-tunnel)
- [Per-client configuration](#per-client-configuration)
- [TCP transport](#tcp-transport)
- [Running as a service](#running-as-a-service)
- [Testing with Docker](#testing-with-docker)
- [How it works](#how-it-works)
- [Project layout](#project-layout)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [License](#license)

---

## Features

- **Transport:** UDP and/or TCP (`proto tcp-client`), can run both at once.
- **Control channel:** TLS 1.2/1.3 via `rustls`, mandatory client certificates
  (mutual TLS), full OpenVPN reliability layer (packet IDs, ACKs,
  exponential-backoff retransmit).
- **Data channel:** AES-256-GCM with a sliding replay window. Keys derived with
  OpenVPN's classic `key-method 2` PRF.
- **PSK hardening:** `tls-auth` (HMAC-SHA256 on every control packet) or
  `tls-crypt` (control channel additionally encrypted with AES-256-CTR).
- **Rekey:** client-initiated *and* server-initiated (timer-based) via
  `P_CONTROL_SOFT_RESET_V1`, with two parallel key slots so no packets drop
  during a rotation.
- **Addressing:** IPv4 pool + optional IPv6 pool, pushed routes and DNS,
  per-client static IP / extra routes keyed by certificate CN.
- **Full tunnel:** `enable_nat` installs and cleans up `iptables` MASQUERADE
  rules on Linux.
- **Liveness:** occ-ping keepalive, idle-session reaper, graceful `RESTART` on
  Ctrl-C.
- **Concurrency:** lock-free inbound routing to per-session worker tasks, so
  sessions decrypt in parallel.

---

## Requirements

- Rust (stable, 2024 edition — needs rustc ≥ 1.85; the Docker build uses 1.88).
- A TUN device:
  - **Linux:** the `tun` kernel module and `CAP_NET_ADMIN` (run with `sudo`).
    NAT and IPv6-in-tunnel additionally need `iptables` / `ip` on `PATH`.
  - **macOS:** `utun` (built in); run with `sudo`. NAT is not implemented on
    macOS — use [Docker](#testing-with-docker) for full-tunnel testing there.
- `openssl` for the helper scripts (cert + PSK generation).
- An OpenVPN 2.6 client to connect with.

---

## Build

```bash
cargo build --release
# binary at ./target/release/javs
```

---

## Deploy on Ubuntu (x86-64) from a release

The published releases ship a **prebuilt, statically-linked
`x86_64-unknown-linux-musl` binary** — one self-contained file with no glibc or
other runtime dependency, so it runs on any x86-64 Ubuntu as-is. This is the
easiest path: nothing to compile, nothing extra to install on the server.

> Want to build it yourself instead? See
> [Build & deploy from source](#deploying-to-ubuntu-by-cross-compiling-from-macos).

### A. Server — on the Ubuntu box, over SSH

**1. Download, verify, and install the binary.**

```bash
REPO=oltur/just-another-vpn-server
TAG=$(curl -fsSL https://api.github.com/repos/$REPO/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
BASE="javs-$TAG-x86_64-unknown-linux-musl"

curl -fsSL -O "https://github.com/$REPO/releases/download/$TAG/$BASE.tar.gz"
curl -fsSL -O "https://github.com/$REPO/releases/download/$TAG/$BASE.tar.gz.sha256"
sha256sum -c "$BASE.tar.gz.sha256"     # must print: OK

tar xzf "$BASE.tar.gz"
cd "$BASE"
sudo install -m 0755 javs /usr/local/bin/javs
javs --help                            # sanity check
```

The tarball also unpacks `configs/` (templates) and `scripts/` (cert helpers),
which the next steps use.

**2. Generate the PKI** (Ubuntu ships `openssl`, which the script needs):

```bash
./scripts/generate-certs.sh
# -> configs/pki/{ca.crt, server.crt, server.key, client1.crt, client1.key}

# optional but recommended — a tls-crypt pre-shared key:
./scripts/generate-psk.sh configs/pki/tc.key
```

**3. Install the config and server-side keys under `/etc/javs`:**

```bash
sudo mkdir -p /etc/javs/pki
sudo cp configs/server.toml /etc/javs/server.toml
sudo cp configs/pki/ca.crt configs/pki/server.crt configs/pki/server.key /etc/javs/pki/
# sudo cp configs/pki/tc.key /etc/javs/pki/        # if you made a PSK
sudo chmod 600 /etc/javs/pki/server.key
```

**4. Edit `/etc/javs/server.toml`** — point it at the keys and set your tunnel:

```toml
listen      = "0.0.0.0:1194"
ca          = "/etc/javs/pki/ca.crt"
cert        = "/etc/javs/pki/server.crt"
key         = "/etc/javs/pki/server.key"
tun_ip      = "10.8.0.1"
tun_netmask = "255.255.255.0"
client_pool_start = "10.8.0.2"
client_pool_end   = "10.8.0.254"
# route all client traffic through the server (optional full tunnel):
push_routes = ["0.0.0.0/0"]
push_dns    = ["1.1.1.1"]
enable_nat  = true
# tls_crypt_key = "/etc/javs/pki/tc.key"           # if you made a PSK
```

**5. Run it as a service.** The unit grants only `CAP_NET_ADMIN` (for the TUN
device and the NAT rules), so it doesn't run as full root:

```bash
sudo tee /etc/systemd/system/javs.service >/dev/null <<'EOF'
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
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now javs
journalctl -u javs -f          # watch it start; Ctrl-C stops the tail
```

**6. Open the port.** UDP/1194 must be reachable:

```bash
sudo ufw allow 1194/udp        # if ufw is enabled
```

If the box sits behind a cloud firewall (AWS security group, GCP firewall, …),
allow inbound **UDP 1194** there too.

### B. Connect a client with the OpenVPN GUI

**1. Build a single-file `.ovpn` profile.** On the server (still in the extracted
`$BASE` dir, where `configs/pki` lives), bake the CA, client cert, and client key
into one importable file. Replace `YOUR_SERVER_IP` with the server's public address:

```bash
SERVER_IP=YOUR_SERVER_IP
cat > client1.ovpn <<EOF
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
$(cat configs/pki/ca.crt)
</ca>
<cert>
$(cat configs/pki/client1.crt)
</cert>
<key>
$(cat configs/pki/client1.key)
</key>
EOF
# if you enabled tls-crypt on the server, append the matching PSK:
# printf '<tls-crypt>\n%s\n</tls-crypt>\n' "$(cat configs/pki/tc.key)" >> client1.ovpn
```

**2. Copy `client1.ovpn` to the client device.** It embeds the client's private
key — move it over a secure channel only, and don't share it:

```bash
# from your laptop (the remote shell expands the glob):
scp user@YOUR_SERVER_IP:'~/javs-*-x86_64-unknown-linux-musl/client1.ovpn' .
```

**3. Import it into the OpenVPN app.** The same file works in every GUI:

- **OpenVPN Connect** (official; Windows / macOS / Linux / iOS / Android, from
  <https://openvpn.net/client/>): open the app → **Import Profile → FILE** → drag
  in `client1.ovpn` → toggle the profile **on** to connect.
- **Tunnelblick** (macOS): double-click `client1.ovpn` → install for "Only Me" →
  click the menu-bar icon → **Connect client1**.
- **OpenVPN GUI** (Windows community build): drop `client1.ovpn` into
  `C:\Users\<you>\OpenVPN\config\`, then right-click the tray icon → **Connect**.

**4. Verify.** The app should show **Connected** with an assigned `10.8.0.x`
address. From the client:

```bash
ping 10.8.0.1            # the server's tunnel IP
```

With a full tunnel (`push_routes = ["0.0.0.0/0"]` + `enable_nat = true`) your
public IP should now read as the server's — check at any "what's my IP" site.

---

## Deploying to Ubuntu by cross-compiling from macOS

> **Most users want the [prebuilt release](#deploy-on-ubuntu-x86-64-from-a-release)
> instead** — it's this same static binary, already built. This section is for
> building it yourself from source on an Apple-Silicon Mac.

This builds one self-contained binary on your Mac (Apple Silicon) and ships just
that single file to the server — no Rust toolchain, no compiler, and no shared
libraries needed on the target. We target `x86_64-unknown-linux-musl`, which
links **statically**, so the binary runs on any x86-64 Linux regardless of its
glibc version. The only runtime pieces it ever needs (the `tun` kernel module,
and `iproute2` + `iptables` for NAT) already ship with Ubuntu Server.

### 1. One-time setup on the Mac (M3)

```bash
# Rust std for the static Linux target
rustup target add x86_64-unknown-linux-musl

# Zig provides the cross C compiler + linker that ring (rustls) needs.
brew install zig
# --locked avoids pulling a transitive dep that needs a newer rustc than yours.
cargo install cargo-zigbuild --locked
```

`cargo-zigbuild` drives cargo with `zig cc` as the cross toolchain, which is what
makes the C/assembly bits of `ring` build cleanly from macOS to Linux.

### 2. Build the static x86-64 binary

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl
# -> target/x86_64-unknown-linux-musl/release/javs
```

Confirm it's a static x86-64 ELF (not a Mach-O):

```bash
file target/x86_64-unknown-linux-musl/release/javs
# ELF 64-bit LSB executable, x86-64, ... statically linked, ...
```

### 3. Generate the PKI on the Mac

Keep `openssl` off the server — generate everything locally and copy only what
the server needs:

```bash
./scripts/generate-certs.sh
./scripts/generate-psk.sh configs/pki/tc.key   # optional control-channel PSK
```

The client cert/key stay on your Mac for building client profiles; only
`ca.crt`, `server.crt`, `server.key` (and `tc.key` if used) go to the server.

### 4. Point the config at the server's paths

Edit `configs/server.toml` so the PKI paths match where they'll live on the
server, and set the public bind / tunnel options:

```toml
listen      = "0.0.0.0:1194"
ca          = "/etc/javs/pki/ca.crt"
cert        = "/etc/javs/pki/server.crt"
key         = "/etc/javs/pki/server.key"
tun_ip      = "10.8.0.1"
tun_netmask = "255.255.255.0"
client_pool_start = "10.8.0.2"
client_pool_end   = "10.8.0.254"
# full tunnel (optional):
push_routes = ["0.0.0.0/0"]
push_dns    = ["1.1.1.1"]
enable_nat  = true
```

### 5. Copy the artifacts to the server

```bash
SERVER=user@your.server
scp target/x86_64-unknown-linux-musl/release/javs "$SERVER:/tmp/javs"
scp configs/server.toml "$SERVER:/tmp/server.toml"
scp configs/pki/ca.crt configs/pki/server.crt configs/pki/server.key "$SERVER:/tmp/"
# scp configs/pki/tc.key "$SERVER:/tmp/"      # if using tls-crypt
```

### 6. Install on the server (over SSH)

```bash
ssh "$SERVER"

sudo install -m 0755 /tmp/javs /usr/local/bin/javs
sudo mkdir -p /etc/javs/pki
sudo mv /tmp/server.toml /etc/javs/server.toml
sudo mv /tmp/ca.crt /tmp/server.crt /tmp/server.key /etc/javs/pki/
# sudo mv /tmp/tc.key /etc/javs/pki/          # if using tls-crypt
sudo chmod 600 /etc/javs/pki/server.key

# open the port if a firewall is active
sudo ufw allow 1194/udp
```

### 7. Run it as a service

Install the systemd unit (it sets `AmbientCapabilities=CAP_NET_ADMIN`, so it
doesn't run as full root — that one capability covers the TUN device and the
iptables NAT rules):

```bash
sudo tee /etc/systemd/system/javs.service >/dev/null <<'EOF'
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
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now javs
journalctl -u javs -f          # watch the handshake
```

### 8. Connect from a client

Build a `.ovpn` profile as in [Client profiles](#client-profiles) (set
`remote your.server 1194` and paste in `ca.crt` + `client1.crt` + `client1.key`),
then `sudo openvpn --config client.ovpn`.

> **Prefer Docker over Zig?** `cargo install cross`, then
> `cross build --release --target x86_64-unknown-linux-musl` does the same job in
> a container (needs Docker running).
>
> **`ring` won't link on musl?** Fall back to a glibc target pinned to an old
> version — still a single file, just dynamically linked against the glibc
> already on the server:
> `cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17`.

---

## Quick start (5 minutes)

```bash
# 1. Generate a CA, a server cert, and one client cert (Ed25519 by default).
./scripts/generate-certs.sh
# -> configs/pki/{ca.crt,server.crt,server.key,client1.crt,client1.key}

# 2. The default configs/server.toml is ready for a local trial
#    (UDP :1194, tunnel 10.8.0.0/24, no NAT). Review it if you like.

# 3. Start the server (root needed for the TUN device).
sudo ./target/release/javs --config configs/server.toml --log info

# 4. Build a client profile from the template:
#    - copy configs/client.ovpn somewhere,
#    - set `remote <server-ip> 1194`,
#    - paste configs/pki/ca.crt        into the <ca>   block,
#    -       configs/pki/client1.crt   into the <cert> block,
#    -       configs/pki/client1.key   into the <key>  block.

# 5. Connect.
sudo openvpn --config client.ovpn
# look for: Initialization Sequence Completed
# then:     ping 10.8.0.1
```

`javs` takes only two CLI flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `--config <path>` | `configs/server.toml` | Path to the TOML config. |
| `--log <filter>` | `info` | `RUST_LOG`-style filter, e.g. `info,javs=debug`. |

---

## Configuration reference

`server.toml`. Required keys have no default; everything else may be omitted.

### Listening & PKI

| Key | Default | Description |
|-----|---------|-------------|
| `listen` | — (required) | UDP bind address, e.g. `"0.0.0.0:1194"`. |
| `listen_tcp` | unset | TCP bind address. Omit to disable TCP. May reuse the UDP port number. |
| `ca` | — (required) | PEM file of trusted CA cert(s) used to verify clients. |
| `cert` | — (required) | Server certificate (PEM, chain optional). |
| `key` | — (required) | Server private key (PEM). |

### Tunnel addressing (IPv4)

| Key | Default | Description |
|-----|---------|-------------|
| `tun_name` | `javs0` (Linux) / `utun9` (macOS) | TUN interface name. |
| `tun_ip` | — (required) | Server's tunnel IPv4, e.g. `"10.8.0.1"`. |
| `tun_netmask` | — (required) | Tunnel netmask, e.g. `"255.255.255.0"`. |
| `client_pool_start` | — (required) | First client IPv4 (inclusive). |
| `client_pool_end` | — (required) | Last client IPv4 (inclusive). |
| `tun_mtu` | `1500` | TUN MTU. |
| `cipher` | `AES-256-GCM` | Data cipher. Only `AES-256-GCM` is supported. |

### Pushed routes / DNS

| Key | Default | Description |
|-----|---------|-------------|
| `push_routes` | `[]` | CIDRs pushed as `route` directives. `["0.0.0.0/0"]` = full tunnel. |
| `push_dns` | `[]` | DNS servers pushed via `dhcp-option DNS`. |

### Tunnel addressing (IPv6, Linux only)

| Key | Default | Description |
|-----|---------|-------------|
| `tun_ip6` | unset | Server tunnel IPv6, e.g. `"fd00:beef::1"`. Enables IPv6. |
| `tun_prefix6` | `64` | Prefix length for `tun_ip6`. |
| `client_pool_start_v6` | unset | First client IPv6 (required if `tun_ip6` set). |
| `client_pool_end_v6` | unset | Last client IPv6. |
| `push_routes_v6` | `[]` | IPv6 CIDRs pushed as `route-ipv6`. `["::/0"]` = full v6 tunnel. |

### Keepalive & rekey

| Key | Default | Description |
|-----|---------|-------------|
| `keepalive_ping` | `10` | Seconds between server occ-pings. |
| `keepalive_timeout` | `60` | Drop a session after this many idle seconds. |
| `reneg_sec` | `3600` | Server-initiated rekey interval. `0` disables it. |

### Control-channel PSK

| Key | Default | Description |
|-----|---------|-------------|
| `tls_auth_key` | unset | Static-key file for `--tls-auth` (HMAC). |
| `tls_auth_key_direction` | `1` | Matches client's `key-direction` (`0` or `1`). |
| `tls_crypt_key` | unset | Static-key file for `--tls-crypt` (HMAC + encryption). Wins over `tls_auth_key`. |

### NAT (full tunnel, Linux only)

| Key | Default | Description |
|-----|---------|-------------|
| `enable_nat` | `false` | Install iptables MASQUERADE at start, remove on clean exit. |
| `wan_iface` | auto | Outbound interface to MASQUERADE through; auto-detected from the default route if omitted. |

### Per-client overrides

`[client_configs.<CN>]` tables, keyed by the client certificate's Common Name:

| Key | Description |
|-----|-------------|
| `assign_ip` | Static tunnel IP for this client (bypasses the pool). |
| `push_routes` | Extra CIDRs pushed to this client, merged with the global list. |

A full annotated example lives in [`configs/server.toml`](configs/server.toml).

---

## Client profiles

Start from [`configs/client.ovpn`](configs/client.ovpn). The essentials that
must match the server:

```ini
client
dev tun
proto udp                 # or: proto tcp-client  (if the server has listen_tcp)
remote your.server 1194
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
tls-version-min 1.2
# Do NOT add `tls-ekm` — javs uses the classic key-method-2 PRF.
<ca>…</ca> <cert>…</cert> <key>…</key>
```

GUI clients (Tunnelblick, OpenVPN Connect, NetworkManager) all import the same
`.ovpn` file:

```bash
# Linux/macOS CLI
sudo openvpn --config client.ovpn
# NetworkManager
nmcli connection import type openvpn file client.ovpn
```

---

## Control-channel protection: tls-auth vs tls-crypt

Both add a pre-shared key (PSK) on top of the per-client certificates, dropping
unauthenticated packets before they reach the TLS stack.

- **`tls-auth`** — HMAC-SHA256 stamps every control packet. Cheap; the TLS
  handshake is still visible on the wire.
- **`tls-crypt`** — additionally *encrypts* the control channel (AES-256-CTR),
  hiding the handshake and certificate. Recommended.

Generate a key (no `openvpn` binary required):

```bash
./scripts/generate-psk.sh configs/pki/tc.key
```

Server (`server.toml`):

```toml
tls_crypt_key = "configs/pki/tc.key"
```

Client (`.ovpn`), paste the same file's contents:

```ini
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
…
-----END OpenVPN Static key V1-----
</tls-crypt>
```

For `tls-auth` instead, use `tls_auth_key` on the server and a `<tls-auth>`
block plus `key-direction 1` on the client.

---

## Full tunnel and NAT

To route all client traffic through the server (Linux):

```toml
push_routes = ["0.0.0.0/0"]
push_dns    = ["1.1.1.1"]
enable_nat  = true
# wan_iface = "eth0"   # optional; auto-detected from the default route
```

On startup `javs` enables IP forwarding and installs the MASQUERADE +
FORWARD rules; on a clean Ctrl-C it removes them and restores the previous
`ip_forward` value. Requires root and `iptables`.

macOS does not have a NAT implementation here — run the
[Docker harness](#testing-with-docker) for full-tunnel testing on a Mac.

---

## IPv6 in the tunnel

Linux only (the v6 address is attached with `ip -6 addr add`):

```toml
tun_ip6              = "fd00:beef::1"
tun_prefix6          = 64
client_pool_start_v6 = "fd00:beef::2"
client_pool_end_v6   = "fd00:beef::ff"
push_routes_v6       = ["::/0"]   # optional, for a full v6 tunnel
```

Clients receive an `ifconfig-ipv6` directive and a v6 address from the pool.

---

## Per-client configuration

Pin a client to a fixed IP and give it extra routes, keyed by its certificate
CN (the equivalent of OpenVPN's `client-config-dir`):

```toml
[client_configs.alice]
assign_ip   = "10.8.0.100"
push_routes = ["192.168.50.0/24"]

[client_configs.bob]
assign_ip = "10.8.0.101"
```

The CN is read from the verified client certificate and logged on connect:
`session ESTABLISHED … cn=alice`.

---

## TCP transport

Set `listen_tcp` and point clients at it with `proto tcp-client`:

```toml
listen     = "0.0.0.0:1194"   # UDP
listen_tcp = "0.0.0.0:1194"   # TCP (same number is fine)
```

```ini
# client.ovpn
proto tcp-client
remote your.server 1194
```

UDP and TCP listeners run simultaneously; each TCP connection gets its own
length-prefixed framing and reader/writer tasks.

---

## Running as a service

A minimal systemd unit (Linux):

```ini
# /etc/systemd/system/javs.service
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
```

```bash
sudo cp target/release/javs /usr/local/bin/
sudo mkdir -p /etc/javs && sudo cp -r configs/* /etc/javs/
sudo systemctl enable --now javs
```

---

## Testing with Docker

The `docker/` directory is a self-contained end-to-end harness — a `javs`
server, a real `openvpn` client, and an "internal" target reachable *only*
through the tunnel + NAT. It exercises tls-crypt, IPv6, per-client config,
NAT, and (by default) TCP transport at once.

```bash
./docker/test.sh
```

It generates the PKI and PSK if missing, builds both images, brings up a
two-network compose stack, waits for `Initialization Sequence Completed`, then
asserts:

1. `ping 10.8.0.1` — basic IPv4 tunnel,
2. `ping6 fd00:beef::1` — IPv6 tunnel,
3. `curl 10.98.0.3:8080` — a host reachable only via the server's NAT,

and prints `PASS`. Everything firewall-related happens inside the server
container's network namespace, so your host (and, on macOS, the host kernel
outside Docker Desktop's VM) is untouched.

---

## How it works

1. **Handshake.** The client opens the connection with a `HARD_RESET`; `javs`
   replies and runs a mutual-TLS handshake over the OpenVPN control/reliability
   layer (`rustls`, client certs required).
2. **Key exchange.** After TLS, the peers exchange `key-method 2` packets.
   `javs` derives the AES-256-GCM data keys with the classic TLS-1.0 PRF over
   `pre_master`/`random1`/`random2`/session-IDs (the same layout OpenVPN uses
   when `tls-ekm` is *off* — see the note below).
3. **Push.** On `PUSH_REQUEST` the server allocates an IP (pool or per-client
   static) and returns `ifconfig`, routes, DNS, keepalive, and `peer-id`.
4. **Data plane.** `P_DATA_V2` packets are AEAD-sealed (tag-before-ciphertext,
   implicit IV from the key material). Inbound packets are routed lock-free by
   `peer-id` to a per-session worker that decrypts and writes to the TUN; a
   single writer task fans everything onto the device.
5. **Rekey / liveness.** Keys rotate on a timer or on client request via a
   second key slot; occ-pings and an idle reaper keep the session table clean.

> **Why classic PRF and not `tls-ekm`?** `rustls`'s TLS key exporter does not
> produce byte-identical output to OpenSSL's for the same session, so EKM-based
> keys wouldn't match a stock client. The PRF path derives keys purely from the
> key-method-2 material and interoperates correctly.

---

## Project layout

```
src/
├── main.rs            # CLI / startup
├── config.rs          # TOML schema + loader
├── protocol.rs        # OpenVPN packet codecs, P_DATA_V2, ping magic
├── control_channel.rs # key-method-2 codec, options/peer_info builders
├── crypto.rs          # AES-256-GCM data channel (OpenVPN wire layout)
├── prf.rs             # TLS-1.0 PRF key derivation
├── tls.rs             # rustls wrapper + peer-cert CN extraction
├── tls_auth.rs        # HMAC-SHA256 control-channel envelope
├── tls_crypt.rs       # encrypted+authenticated control-channel envelope
├── static_key.rs      # OpenVPN --secret static-key parser
├── replay.rs          # 64-bit sliding replay window
├── session.rs         # per-client state machine, key slots, rekey track
├── server.rs          # listeners, dispatch, TUN forwarder, timers, NAT wiring
├── transport.rs       # UDP/TCP send abstraction
├── nat.rs             # Linux iptables MASQUERADE + cleanup-on-drop
└── tun_dev.rs         # TUN device creation (+ IPv6 attach)
configs/
├── server.toml        # annotated example server config
└── client.ovpn        # client profile template
scripts/
├── generate-certs.sh  # CA + server + client certs (OpenSSL)
└── generate-psk.sh    # tls-auth / tls-crypt static key
docker/                # end-to-end test harness (see above)
```

---

## Development

```bash
cargo fmt
cargo clippy --no-deps
cargo test          # unit tests (codec, crypto, PRF, replay, envelopes)
./docker/test.sh    # end-to-end against a real openvpn client
```

The unit tests don't need a TUN device or root. End-to-end behaviour is covered
by the Docker harness.

---

## Troubleshooting

- **Client loops on "Initialization Sequence Completed" then restarts** —
  almost always a data-channel key/parameter mismatch. Confirm the client uses
  `cipher AES-256-GCM`, `auth SHA256`, and **no `tls-ekm`**.
- **`AEAD Decrypt error` on the client** — cipher/PSK mismatch; make sure
  `tls_crypt_key`/`tls_auth_key` (and key-direction) match on both sides.
- **No traffic but the tunnel is "up"** — for a full tunnel you need
  `push_routes = ["0.0.0.0/0"]` *and* `enable_nat = true` (Linux), and the
  server must have a working WAN route.
- **`bind … : Address already in use`** — another process holds the port, or
  `listen` and `listen_tcp` collide on the same protocol.
- **Permission denied creating the TUN** — run as root / with `CAP_NET_ADMIN`.
- Raise verbosity with `--log info,javs=debug` (or `=trace`) on the server and
  `verb 4` on the client.

---

## Limitations

- macOS NAT (`pfctl`) is not implemented; IPv6-in-tunnel and NAT are Linux-only.
- Only `AES-256-GCM` is supported on the data channel.
- Username/password auth is not implemented — authentication is by client
  certificate (CN is available for per-client policy).
- Not security-audited. Use behind appropriate network controls.

---

## License

MIT.
