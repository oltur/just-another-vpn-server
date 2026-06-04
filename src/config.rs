use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// UDP bind address (e.g. "0.0.0.0:1194").
    pub listen: SocketAddr,
    /// Optional TCP bind address. Set this to accept clients that use
    /// `proto tcp-client` in their `.ovpn` config. Can run alongside UDP.
    #[serde(default)]
    pub listen_tcp: Option<SocketAddr>,

    /// PEM file with the trusted CA cert(s).
    pub ca: PathBuf,
    /// PEM file with the server cert (optionally followed by chain).
    pub cert: PathBuf,
    /// PEM file with the server private key.
    pub key: PathBuf,

    /// Name of the TUN interface to create.
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// IPv4 of the server side of the tunnel (e.g. 10.8.0.1).
    pub tun_ip: IpAddr,
    /// Tunnel netmask (e.g. 255.255.255.0).
    pub tun_netmask: IpAddr,
    /// Inclusive start of the client IP pool.
    pub client_pool_start: IpAddr,
    /// Inclusive end of the client IP pool.
    pub client_pool_end: IpAddr,

    /// Data-channel cipher. Only "AES-256-GCM" is supported.
    #[serde(default = "default_cipher")]
    pub cipher: String,

    /// TUN MTU.
    #[serde(default = "default_mtu")]
    pub tun_mtu: u16,

    /// CIDRs pushed to clients as `route` directives in PUSH_REPLY. Use
    /// `["0.0.0.0/0"]` for a full tunnel (also set `enable_nat`).
    #[serde(default)]
    pub push_routes: Vec<String>,
    /// DNS servers pushed to clients (`dhcp-option DNS`); the client decides
    /// whether to honour them.
    #[serde(default)]
    pub push_dns: Vec<IpAddr>,

    /// Server-side IPv6 address on the tunnel interface (e.g. `fd00:beef::1`).
    /// Leave unset to disable IPv6 in the tunnel.
    #[serde(default)]
    pub tun_ip6: Option<IpAddr>,
    /// Prefix length for `tun_ip6` (default `/64`).
    #[serde(default = "default_tun_prefix6")]
    pub tun_prefix6: u8,
    /// Inclusive start of the IPv6 client pool. Required if `tun_ip6` is set.
    #[serde(default)]
    pub client_pool_start_v6: Option<IpAddr>,
    /// Inclusive end of the IPv6 client pool.
    #[serde(default)]
    pub client_pool_end_v6: Option<IpAddr>,
    /// IPv6 CIDRs to push to clients (`route-ipv6` directives in PUSH_REPLY).
    #[serde(default)]
    pub push_routes_v6: Vec<String>,

    /// Server keepalive ping interval (seconds).
    #[serde(default = "default_keepalive_ping")]
    pub keepalive_ping: u32,
    /// Server keepalive timeout (seconds) — peer is dropped if no traffic for this long.
    #[serde(default = "default_keepalive_timeout")]
    pub keepalive_timeout: u32,

    /// Path to an OpenVPN static-key file enabling `--tls-auth`. When set,
    /// every control packet is HMAC-SHA256'd with this PSK; unauthenticated
    /// packets are dropped before reaching the TLS state machine. Ignored
    /// if `tls_crypt_key` is also set.
    #[serde(default)]
    pub tls_auth_key: Option<PathBuf>,
    /// `key-direction` setting matching the client's `tls-auth ta.key <dir>`.
    /// `0` = same key both ways, `1` = use separate slots per direction
    /// (the OpenVPN client default).
    #[serde(default = "default_tls_auth_direction")]
    pub tls_auth_key_direction: u8,
    /// Path to a static-key file enabling `--tls-crypt`. Like `tls_auth_key`
    /// but the control packets are also encrypted (AES-256-CTR with the IV
    /// derived from the HMAC tag), hiding the TLS handshake from observers.
    /// Mutually exclusive with `tls_auth_key`; takes precedence if both set.
    #[serde(default)]
    pub tls_crypt_key: Option<PathBuf>,

    /// Install iptables MASQUERADE rules at startup so clients reach the
    /// internet through the server's WAN interface. Linux-only; needs root
    /// and `iptables` on PATH. Rules are removed on a clean shutdown.
    #[serde(default)]
    pub enable_nat: bool,
    /// WAN interface to MASQUERADE through. Auto-detected from the default
    /// route when omitted. Only relevant when `enable_nat = true`.
    #[serde(default)]
    pub wan_iface: Option<String>,

    /// Server-initiated rekey interval (seconds). Every `reneg_sec` we kick
    /// off a fresh key-method-2 exchange under a new `key_id` so the
    /// data-channel keys don't sit on the wire forever. Set to 0 to disable.
    #[serde(default = "default_reneg_sec")]
    pub reneg_sec: u32,

    /// Optional per-client overrides keyed by the client cert's CN. For each
    /// matching CN we can hand out a static IP and push additional routes
    /// on top of `push_routes`. OpenVPN's equivalent is `client-config-dir`.
    #[serde(default)]
    pub client_configs: HashMap<String, ClientConfig>,
}

/// Per-client override applied when a peer's leaf-cert CN matches the
/// key of this entry in [`ServerConfig::client_configs`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClientConfig {
    /// Static tunnel IP for this client; bypasses pool allocation.
    #[serde(default)]
    pub assign_ip: Option<IpAddr>,
    /// Extra CIDRs to push to this client on top of the global `push_routes`.
    #[serde(default)]
    pub push_routes: Vec<String>,
}

fn default_tun_name() -> String {
    if cfg!(target_os = "macos") {
        "utun9".to_string()
    } else {
        "javs0".to_string()
    }
}
fn default_cipher() -> String {
    "AES-256-GCM".to_string()
}
fn default_mtu() -> u16 {
    1500
}
fn default_keepalive_ping() -> u32 {
    10
}
fn default_keepalive_timeout() -> u32 {
    120
}
fn default_tls_auth_direction() -> u8 {
    1
}
fn default_reneg_sec() -> u32 {
    3600
}
fn default_tun_prefix6() -> u8 {
    64
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: ServerConfig =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        if !cfg.cipher.eq_ignore_ascii_case("AES-256-GCM") {
            anyhow::bail!(
                "unsupported cipher {:?}; only AES-256-GCM is implemented",
                cfg.cipher
            );
        }
        Ok(cfg)
    }
}
