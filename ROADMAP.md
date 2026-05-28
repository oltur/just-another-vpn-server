# Roadmap to a functioning OpenVPN-compatible server

**Status: feature-complete.** All phases below are done except macOS `pfctl`
NAT (Phase 3) — every other item interoperates end-to-end with OpenVPN 2.6.14,
verified by `./docker/test.sh`. This file is kept as an implementation record;
the user-facing guide is [`README.md`](README.md).

The phases are ordered by what had to work first. Each phase ends in a
testable milestone you can run against a real client.

---

## Phase 1 — Post-TLS handshake (key-method 2 + PUSH) ✅ done

**Tasks.**
- [x] Rewrite `crypto.rs` to use the 256-byte EKM layout that matches
      OpenVPN 2.6 (`client.cipher/hmac` and `server.cipher/hmac` at offsets
      0/64/128/192, each 64-byte slot — first 32 bytes are the AES key,
      first 8 bytes of the "hmac" slot are the implicit IV).
- [x] `src/control_channel.rs`: key-method-2 parse + serialize, ASCII helper.
- [x] `session.rs` state machine
      (`WaitingHardReset → Handshaking → KeyExchange → PushPending → Established`).
- [x] `server.rs` drives key-method-2 reply and `PUSH_REPLY`.
- [x] Plaintext channel uses raw TLS bytes (no u16-length framing).
- [x] Options string + `peer_info` with `IV_PROTO` (`TLS_KEY_EXPORT` set).

**Milestone (pending live test).** `sudo openvpn --config client.ovpn` reaches
`Initialization Sequence Completed` and the client's TUN device gets the
IP we hand it (`10.8.0.2/24` by default).

---

## Phase 2 — Verified data-plane round-trip ✅ done

- [x] AAD matches OpenVPN's P_DATA_V2 first 8 header bytes (no extra fields).
- [x] Sliding replay window (default 64) for inbound `packet_id`s.
- [x] Drop sessions with no inbound traffic for `keepalive_timeout`.
- [x] Send periodic server pings (OpenVPN's "occ-ping" payload over the
      data channel) every `keepalive_ping` seconds.

**Milestone.** A connected client can `ping 10.8.0.1` for >2 minutes with
zero drops; `iperf3 -c 10.8.0.1` over the tunnel survives.

---

## Phase 3 — Outbound "full tunnel"

- [x] Optional `enable_nat = true` flag that wires `iptables` MASQUERADE on
      Linux at start, and removes it on `Ctrl-C` via a `NatGuard` Drop.
- [x] Detect the default-route interface automatically (`/proc/net/route`).
- [ ] `pfctl` equivalent for macOS.

**Milestone.** `curl ifconfig.me` from a connected client returns the
server's public IP.

---

## Phase 4 — Robustness

- [x] Control-channel retransmission: track unacked P_CONTROL_V1 packets
      and resend on a backoff (~2s, exp).
- [x] Background cleanup task that walks `sessions` and evicts dead ones.
      (Implemented as the idle-timeout reaper in Phase 2.)
- [x] Graceful shutdown: send `RESTART,N` on Ctrl-C so clients reconnect.
- [x] Rekey via `P_CONTROL_SOFT_RESET_V1` with parallel `key_id` slots.
      Inbound + server-initiated (every `reneg_sec`, default 3600). Spins up
      a fresh TLS context, runs a parallel key-method-2 exchange under the
      new `key_id`, installs the new `KeySlot` on completion, and promotes
      it to active for sending. Old slot stays installed so in-flight
      inbound packets still decrypt.

---

## Phase 5 — Security extras

- [x] `tls-auth` (HMAC-SHA256 on every control packet — pre-shared key).
- [x] `tls-crypt` (control channel encrypted *and* authenticated with a PSK
      — AES-256-CTR + HMAC-SHA256, IV derived from the HMAC tag).
- [x] X.509 Common Name extraction (via `x509-parser`); stored on `Session`
      and logged on ESTABLISHED.
- [x] Per-client overrides keyed by CN — `[client_configs.<cn>]` with
      `assign_ip` (static tunnel IP, bypasses pool) and `push_routes`
      (merged with the global `push_routes` in PUSH_REPLY).

---

## Phase 6 — Polish

- [x] IPv6 inside the tunnel — `tun_ip6`, `client_pool_*_v6`,
      `ifconfig-ipv6` / `route-ipv6` PUSH directives, second
      `routes_v6` map, TUN-side dispatch on the IP-header version nibble.
      Linux only (v6 address attached via `ip -6 addr add`).
- [x] TCP transport (`proto tcp-server`). `listen_tcp` accepts stream
      clients; per-connection reader+writer tasks frame packets with a
      u16-BE length prefix. A `Transport` enum on `Session` unifies UDP
      and TCP send paths. Can run alongside UDP.
- [x] Multi-threaded data-plane. Inbound data packets are routed lock-free
      by peer_id (a `data_routes` DashMap) to a per-session worker task that
      decrypts and forwards; the recv loop never blocks on AES-GCM. TUN
      writes fan in through one mpsc-fed writer task. Different sessions
      decrypt in parallel; within a session packets stay ordered.
- [ ] CI integration test: spawn the binary + a real `openvpn` client in
      a Linux netns and run `ping` through the tunnel. (The
      `docker/test.sh` harness already exercises this end-to-end.)

---

## Resolved interop notes

- The first end-to-end run against `openvpn 2.6.14` revealed that rustls'
  `export_keying_material` doesn't agree with OpenSSL byte-for-byte for the
  same TLS 1.2 session (verified by dumping EKM bytes on both sides).
  Fix: bypass TLS-EKM entirely and use OpenVPN's classic `key-method 2`
  PRF over `pre_master`/`random1`/`random2`/session IDs — see
  [`src/prf.rs`]. We drop the `TLS_KEY_EXPORT` bit from `peer_info` so the
  client switches to the same path.
- Two further off-by-design bugs the docker harness caught:
  - For AEAD ciphers, OpenVPN takes the implicit IV from the **hmac slot**
    (`keys[i].hmac[0..8]`), not from `cipher[32..]` — the `[null-digest]`
    log line is misleading.
  - OpenVPN's wire format is `tag || ciphertext`, the opposite of the
    `aes-gcm` crate's native `ciphertext || tag` output. `seal`/`open`
    splice the bytes into / out of the OpenVPN order.

## Running notes

- Use `--log debug` to trace the control-channel handshake.
- `openvpn` client logs at `verb 4` will show every received key-method
  field and is essential for diagnosing mismatches.
- The OpenVPN protocol doc is the source of truth:
  <https://build.openvpn.net/doxygen/network_protocol.html>.
