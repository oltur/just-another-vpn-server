//! Main UDP server loop and per-packet dispatch.

use crate::config::ServerConfig;
use crate::control_channel::{
    ClientKeyMethod2, Pop, ServerKeyMethod2, build_options_string, build_peer_info, try_pop_ascii,
};
use crate::crypto::DataCipher;
use crate::nat::{NatGuard, detect_default_route_iface, enable_masquerade};
use crate::prf::derive_openvpn_key_data;
use crate::protocol::{ControlPacket, DataPacketV2, OpCode, PING_PAYLOAD};
use crate::replay::ReplayWindow;
use crate::session::{
    CONTROL_BASE_RTO, KeySlot, MAX_TLS_PAYLOAD_PER_CONTROL, RekeyState, Session, State,
};
use crate::static_key::parse_static_key_file;
use crate::tls::{TlsSession, build_server_config};
use crate::tls_auth::TlsAuthKey;
use crate::tls_crypt::TlsCryptKey;
use crate::transport::Transport;
use crate::tun_dev::{add_ipv6, create as create_tun};
use anyhow::{Context, Result};
use dashmap::DashMap;
use rand::RngCore;
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tracing::{debug, error, info, trace, warn};

pub struct VpnServer {
    cfg: ServerConfig,
    socket: Arc<UdpSocket>,
    tls_cfg: Arc<rustls::ServerConfig>,
    sessions: Arc<DashMap<SocketAddr, Arc<Mutex<Session>>>>,
    routes: Arc<DashMap<Ipv4Addr, SocketAddr>>,
    /// Same as `routes` but keyed by client v6 (when IPv6 in tunnel is on).
    routes_v6: Arc<DashMap<Ipv6Addr, SocketAddr>>,
    peers: Arc<DashMap<u32, SocketAddr>>,
    next_peer_id: Arc<AtomicU32>,
    next_pool_ip: Arc<parking_lot::Mutex<Ipv4Addr>>,
    pool_end: Ipv4Addr,
    /// IPv6 pool (only set when `tun_ip6` is configured).
    next_pool_ip_v6: Option<Arc<parking_lot::Mutex<Ipv6Addr>>>,
    pool_end_v6: Option<Ipv6Addr>,
    /// Lock-free routing table for the inbound data plane: peer_id → a
    /// per-session worker's raw-packet inlet. The recv path only does a
    /// DashMap lookup + channel send (no decryption, no session lock), so
    /// different sessions' packets decrypt concurrently on their own tasks.
    data_routes: Arc<DashMap<u32, UnboundedSender<Vec<u8>>>>,
    /// Set once in `run()`; per-session workers clone it to push decrypted
    /// IP packets to the single TUN writer task.
    tun_writer_tx: std::sync::OnceLock<UnboundedSender<Vec<u8>>>,
    /// At most one of `tls_crypt` and `tls_auth` is `Some`; tls-crypt takes
    /// precedence in `wrap_for_wire` and on the receive path because it's
    /// the stronger of the two.
    tls_crypt: Option<Arc<TlsCryptKey>>,
    tls_auth: Option<Arc<TlsAuthKey>>,
    /// Holds the iptables MASQUERADE rules when NAT is enabled. The Drop
    /// impl on `NatGuard` removes them, so this fires on a clean Ctrl-C
    /// (which returns from `run()` and drops the server).
    _nat_guard: Option<NatGuard>,
}

impl VpnServer {
    pub async fn new(cfg: ServerConfig) -> Result<Self> {
        let socket = UdpSocket::bind(cfg.listen)
            .await
            .with_context(|| format!("bind {}", cfg.listen))?;
        info!("listening UDP on {}", cfg.listen);
        let tls_cfg = build_server_config(&cfg.ca, &cfg.cert, &cfg.key)?;
        let (tls_crypt, tls_auth) = if let Some(path) = &cfg.tls_crypt_key {
            let km = parse_static_key_file(path)
                .with_context(|| format!("loading tls-crypt key {}", path.display()))?;
            let key = TlsCryptKey::from_static_key_server(&km);
            info!("tls-crypt enabled (HMAC-SHA256 + AES-256-CTR)");
            (Some(Arc::new(key)), None)
        } else if let Some(path) = &cfg.tls_auth_key {
            let km = parse_static_key_file(path)
                .with_context(|| format!("loading tls-auth key {}", path.display()))?;
            let key = TlsAuthKey::from_static_key_server(&km, cfg.tls_auth_key_direction)?;
            info!(
                "tls-auth enabled (HMAC-SHA256, key-direction {})",
                cfg.tls_auth_key_direction
            );
            (None, Some(Arc::new(key)))
        } else {
            (None, None)
        };
        let pool_start = match cfg.client_pool_start {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => anyhow::bail!("client_pool_start must be IPv4 (use *_v6 for IPv6)"),
        };
        let pool_end = match cfg.client_pool_end {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => anyhow::bail!("client_pool_end must be IPv4 (use *_v6 for IPv6)"),
        };
        let (next_pool_ip_v6, pool_end_v6) = match (
            &cfg.tun_ip6,
            &cfg.client_pool_start_v6,
            &cfg.client_pool_end_v6,
        ) {
            (None, _, _) => (None, None),
            (Some(_), Some(IpAddr::V6(s)), Some(IpAddr::V6(e))) => {
                (Some(Arc::new(parking_lot::Mutex::new(*s))), Some(*e))
            }
            (Some(_), _, _) => anyhow::bail!(
                "tun_ip6 is set but client_pool_start_v6 / client_pool_end_v6 is missing or non-v6"
            ),
        };
        let nat_guard = if cfg.enable_nat {
            let wan = match &cfg.wan_iface {
                Some(s) => s.clone(),
                None => detect_default_route_iface().context("auto-detecting WAN interface")?,
            };
            let tun_ip_v4 = match cfg.tun_ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => anyhow::bail!("NAT requires an IPv4 tun_ip"),
            };
            let tun_mask_v4 = match cfg.tun_netmask {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => anyhow::bail!("NAT requires an IPv4 tun_netmask"),
            };
            Some(enable_masquerade(
                &cfg.tun_name,
                &wan,
                tun_ip_v4,
                tun_mask_v4,
            )?)
        } else {
            None
        };
        Ok(Self {
            cfg,
            socket: Arc::new(socket),
            tls_cfg,
            sessions: Arc::new(DashMap::new()),
            routes: Arc::new(DashMap::new()),
            routes_v6: Arc::new(DashMap::new()),
            peers: Arc::new(DashMap::new()),
            next_peer_id: Arc::new(AtomicU32::new(1)),
            next_pool_ip: Arc::new(parking_lot::Mutex::new(pool_start)),
            pool_end,
            next_pool_ip_v6,
            pool_end_v6,
            data_routes: Arc::new(DashMap::new()),
            tun_writer_tx: std::sync::OnceLock::new(),
            tls_crypt,
            tls_auth,
            _nat_guard: nat_guard,
        })
    }

    /// Spawn the per-session inbound data worker and register its inlet in
    /// `data_routes`. The worker owns the session `Arc` and decrypts +
    /// forwards packets to the TUN writer on its own task, so it runs in
    /// parallel with other sessions' workers.
    fn spawn_data_worker(&self, peer_id: u32, sess: Arc<Mutex<Session>>) {
        let Some(tun_tx) = self.tun_writer_tx.get().cloned() else {
            warn!("data worker for peer_id={peer_id}: TUN writer not ready");
            return;
        };
        let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
        self.data_routes.insert(peer_id, tx);
        tokio::spawn(async move {
            while let Some(raw) = rx.recv().await {
                if let Err(e) = decrypt_and_forward(&sess, &raw, &tun_tx).await {
                    trace!("data worker peer_id={peer_id}: {e}");
                }
            }
        });
    }

    /// Wrap an encoded inner control packet with the configured envelope
    /// (tls-crypt > tls-auth > none).
    fn wrap_for_wire(&self, sess: &mut Session, inner: &[u8]) -> Result<Vec<u8>> {
        if let Some(tc) = &self.tls_crypt {
            let pid = sess.next_tls_auth_pid();
            let ts = unix_timestamp_u32();
            tc.wrap(inner, pid, ts)
        } else if let Some(ta) = &self.tls_auth {
            let pid = sess.next_tls_auth_pid();
            let ts = unix_timestamp_u32();
            ta.wrap(inner, pid, ts)
        } else {
            Ok(inner.to_vec())
        }
    }

    /// Unwrap an inbound control packet's outer envelope (tls-crypt or
    /// tls-auth). Returns `(Some(inner_bytes), Some(pid))` when an envelope
    /// is configured, or `(None, None)` when the wire packet *is* already
    /// the inner ControlPacket. `Err` if the envelope's HMAC or padding is
    /// invalid.
    fn unwrap_control(&self, pkt: &[u8]) -> Result<(Option<Vec<u8>>, Option<u32>)> {
        if let Some(tc) = &self.tls_crypt {
            let (inner, pid) = tc.unwrap(pkt)?;
            Ok((Some(inner), Some(pid)))
        } else if let Some(ta) = &self.tls_auth {
            let (inner, pid) = ta.unwrap(pkt)?;
            Ok((Some(inner), Some(pid)))
        } else {
            Ok((None, None))
        }
    }

    pub async fn run(self) -> Result<()> {
        let tun = create_tun(
            &self.cfg.tun_name,
            self.cfg.tun_ip,
            self.cfg.tun_netmask,
            self.cfg.tun_mtu,
        )
        .await?;
        info!(
            "tun {} up at {}/{} mtu={}",
            self.cfg.tun_name, self.cfg.tun_ip, self.cfg.tun_netmask, self.cfg.tun_mtu
        );
        if let Some(IpAddr::V6(v6)) = self.cfg.tun_ip6 {
            add_ipv6(&self.cfg.tun_name, v6, self.cfg.tun_prefix6).context("attaching tun_ip6")?;
            info!(
                "tun {} also has IPv6 {}/{}",
                self.cfg.tun_name, v6, self.cfg.tun_prefix6
            );
        }

        let (mut tun_rx, mut tun_tx) = tokio::io::split(tun);

        // Single writer task draining everyone's decrypted packets onto the
        // TUN. UDP recv loop and TCP per-stream readers both push here.
        let (tun_writer_tx, mut tun_writer_rx) = unbounded_channel::<Vec<u8>>();
        // Publish the writer inlet so per-session data workers can reach it.
        let _ = self.tun_writer_tx.set(tun_writer_tx.clone());
        tokio::spawn(async move {
            while let Some(pkt) = tun_writer_rx.recv().await {
                // Drop non-IP packets that OpenVPN Connect sends via the
                // data channel (e.g. internal control messages). Writing them
                // to a TUN device returns EINVAL and kills the writer.
                match pkt.first().map(|b| b >> 4) {
                    Some(4) | Some(6) => {}
                    other => {
                        trace!(
                            "dropping non-IP data-channel packet: version={other:?} len={}",
                            pkt.len()
                        );
                        continue;
                    }
                }
                if let Err(e) = tun_tx.write_all(&pkt).await {
                    error!("tun write failure: {e}");
                    break;
                }
            }
        });

        // Idle-session reaper. Walks the sessions map every few seconds and
        // evicts any whose last_seen is older than `keepalive_timeout`, also
        // cleaning up the routes and peers maps so a freed IP / peer_id can
        // be reused immediately.
        let sessions_idle = self.sessions.clone();
        let routes_idle = self.routes.clone();
        let routes_v6_idle = self.routes_v6.clone();
        let peers_idle = self.peers.clone();
        let data_routes_idle = self.data_routes.clone();
        let idle_timeout = Duration::from_secs(self.cfg.keepalive_timeout as u64);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                let now = Instant::now();
                let candidates: Vec<SocketAddr> = sessions_idle.iter().map(|e| *e.key()).collect();
                for addr in candidates {
                    let arc = match sessions_idle.get(&addr) {
                        Some(e) => e.value().clone(),
                        None => continue,
                    };
                    let sess = arc.lock().await;
                    let idle_for = now.duration_since(sess.last_seen);
                    let assigned = sess.assigned_ip;
                    let assigned_v6 = sess.assigned_ip_v6;
                    let peer_id = sess.peer_id;
                    drop(sess);
                    if idle_for >= idle_timeout {
                        sessions_idle.remove(&addr);
                        if let Some(IpAddr::V4(ip)) = assigned {
                            routes_idle.remove(&ip);
                        }
                        if let Some(ip6) = assigned_v6 {
                            routes_v6_idle.remove(&ip6);
                        }
                        peers_idle.remove(&peer_id);
                        data_routes_idle.remove(&peer_id);
                        info!(
                            "evicted idle session {addr} peer_id={peer_id} (idle for {:?})",
                            idle_for
                        );
                    }
                }
            }
        });

        // Server-initiated rekey. Walks the sessions map every 30s and, for
        // any Established session older than `reneg_sec`, kicks off a fresh
        // key-method-2 exchange under a new `key_id`. The actual handshake
        // flows through the existing rekey state machine.
        if self.cfg.reneg_sec > 0 {
            let sessions_rk = self.sessions.clone();
            let tls_cfg_rk = self.tls_cfg.clone();
            let tls_crypt_rk = self.tls_crypt.clone();
            let tls_auth_rk = self.tls_auth.clone();
            let reneg = Duration::from_secs(self.cfg.reneg_sec as u64);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(30));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let now = Instant::now();
                    let addrs: Vec<SocketAddr> = sessions_rk.iter().map(|e| *e.key()).collect();
                    for addr in addrs {
                        let Some(arc_ref) = sessions_rk.get(&addr) else {
                            continue;
                        };
                        let arc = arc_ref.value().clone();
                        drop(arc_ref);
                        let mut sess = arc.lock().await;
                        if sess.state != State::Established || sess.rekey.is_some() {
                            continue;
                        }
                        if now.duration_since(sess.last_rekey_at) < reneg {
                            continue;
                        }
                        let active_key_id = sess.active_slot().map(|s| s.key_id).unwrap_or(0);
                        let new_key_id = active_key_id.wrapping_add(1) & 0x07;
                        let new_tls = match TlsSession::new(tls_cfg_rk.clone()) {
                            Ok(t) => t,
                            Err(e) => {
                                trace!("rekey new tls for {addr}: {e}");
                                continue;
                            }
                        };
                        sess.start_rekey(new_key_id, new_tls);
                        // Reset the clock so we don't re-trigger before the
                        // handshake has a chance to finish.
                        sess.last_rekey_at = now;
                        let pkt = sess.make_soft_reset_init(new_key_id);
                        let pid = pkt.packet_id;
                        let encoded = pkt.encode();
                        let wire = if let Some(tc) = &tls_crypt_rk {
                            let p = sess.next_tls_auth_pid();
                            let ts = unix_timestamp_u32();
                            match tc.wrap(&encoded, p, ts) {
                                Ok(b) => b,
                                Err(e) => {
                                    trace!("rekey wrap for {addr}: {e}");
                                    continue;
                                }
                            }
                        } else if let Some(ta) = &tls_auth_rk {
                            let p = sess.next_tls_auth_pid();
                            let ts = unix_timestamp_u32();
                            match ta.wrap(&encoded, p, ts) {
                                Ok(b) => b,
                                Err(e) => {
                                    trace!("rekey wrap for {addr}: {e}");
                                    continue;
                                }
                            }
                        } else {
                            encoded.to_vec()
                        };
                        if let Err(e) = sess.transport.send(&wire).await {
                            trace!("rekey send to {addr}: {e}");
                            continue;
                        }
                        if let Some(p) = pid {
                            sess.record_sent(p, encoded);
                        }
                        info!(
                            "server-initiated rekey for {addr}: {} -> {} key_id",
                            active_key_id, new_key_id
                        );
                    }
                }
            });
        }

        // occ-ping keepalive. For every Established session, send the 16-byte
        // OpenVPN ping payload through the data cipher at `keepalive_ping`
        // intervals so client-side NAT mappings stay alive and the client's
        // ping-restart timer never expires.
        let sessions_p = self.sessions.clone();
        let ping_interval = Duration::from_secs(self.cfg.keepalive_ping.max(1) as u64);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(ping_interval);
            // First tick fires immediately; skip it so we don't ping before
            // any session is up.
            tick.tick().await;
            loop {
                tick.tick().await;
                let addrs: Vec<SocketAddr> = sessions_p.iter().map(|e| *e.key()).collect();
                for addr in addrs {
                    let Some(arc_ref) = sessions_p.get(&addr) else {
                        continue;
                    };
                    let arc = arc_ref.value().clone();
                    drop(arc_ref);
                    let mut sess = arc.lock().await;
                    if sess.state != State::Established || sess.active_slot().is_none() {
                        continue;
                    }
                    let bytes = match sess.build_data_packet(&PING_PAYLOAD) {
                        Ok(b) => b,
                        Err(e) => {
                            trace!("build ping for {addr}: {e}");
                            continue;
                        }
                    };
                    let transport_clone = sess.transport.clone();
                    drop(sess);
                    if let Err(e) = transport_clone.send(&bytes).await {
                        trace!("send ping to {addr}: {e}");
                    }
                }
            }
        });

        // Control-channel retransmit timer
        let sessions_r = self.sessions.clone();
        let tls_crypt_r = self.tls_crypt.clone();
        let tls_auth_r = self.tls_auth.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(500));
            loop {
                tick.tick().await;
                let addrs: Vec<SocketAddr> = sessions_r.iter().map(|e| *e.key()).collect();
                for addr in addrs {
                    let Some(arc_ref) = sessions_r.get(&addr) else {
                        continue;
                    };
                    let arc = arc_ref.value().clone();
                    drop(arc_ref);
                    let mut sess = arc.lock().await;
                    let stale_inner = sess.stale_unacked(Instant::now(), CONTROL_BASE_RTO);
                    // Re-wrap each retransmit so the control-channel replay
                    // pid is fresh — the receiver rejects duplicates.
                    let mut wire_list = Vec::with_capacity(stale_inner.len());
                    for inner in stale_inner {
                        let wire = if let Some(tc) = &tls_crypt_r {
                            let pid = sess.next_tls_auth_pid();
                            let ts = unix_timestamp_u32();
                            match tc.wrap(&inner, pid, ts) {
                                Ok(b) => b,
                                Err(e) => {
                                    trace!("wrap retransmit for {addr}: {e}");
                                    continue;
                                }
                            }
                        } else if let Some(ta) = &tls_auth_r {
                            let pid = sess.next_tls_auth_pid();
                            let ts = unix_timestamp_u32();
                            match ta.wrap(&inner, pid, ts) {
                                Ok(b) => b,
                                Err(e) => {
                                    trace!("wrap retransmit for {addr}: {e}");
                                    continue;
                                }
                            }
                        } else {
                            inner.to_vec()
                        };
                        wire_list.push(wire);
                    }
                    let transport_clone = sess.transport.clone();
                    drop(sess);
                    for bytes in wire_list {
                        if let Err(e) = transport_clone.send(&bytes).await {
                            trace!("retransmit to {addr}: {e}");
                        } else {
                            trace!("retransmitted {} bytes to {addr}", bytes.len());
                        }
                    }
                }
            }
        });

        // TUN -> wire forwarder. Each session carries its own Transport so
        // the same path works for both UDP and TCP clients.
        let sessions_t = self.sessions.clone();
        let routes_t = self.routes.clone();
        let routes_v6_t = self.routes_v6.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match tun_rx.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let pkt = &buf[..n];
                        if let Err(e) =
                            forward_tun_to_client(&sessions_t, &routes_t, &routes_v6_t, pkt).await
                        {
                            trace!("tun->client: {e}");
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        error!("tun read failure: {e}");
                        break;
                    }
                }
            }
        });

        // Wrap server in Arc so both the UDP receive loop and an optional
        // TCP listener task can call `&self` methods on it.
        let server = Arc::new(self);

        // Optional TCP listener. Accepts connections and spawns a per-stream
        // reader+writer pair; both UDP and TCP clients flow through the same
        // dispatch and TUN writer.
        if let Some(tcp_addr) = server.cfg.listen_tcp {
            let listener = TcpListener::bind(tcp_addr)
                .await
                .with_context(|| format!("bind TCP {tcp_addr}"))?;
            info!("listening TCP on {tcp_addr}");
            let server_tcp = server.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            info!("tcp accept from {peer}");
                            let s = server_tcp.clone();
                            tokio::spawn(async move { s.run_tcp_stream(stream, peer).await });
                        }
                        Err(e) => warn!("tcp accept: {e}"),
                    }
                }
            });
        }

        // UDP receive loop. A Ctrl-C arm runs concurrently so we can ask
        // every connected client to reconnect ("RESTART,1") before exiting.
        let mut buf = [0u8; 65535];
        loop {
            tokio::select! {
                biased;
                _ = tokio::signal::ctrl_c() => {
                    info!("shutdown signal received; notifying clients");
                    server.shutdown_clients().await;
                    return Ok(());
                }
                res = server.socket.recv_from(&mut buf) => {
                    let (n, addr) = match res {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("recv_from: {e}");
                            continue;
                        }
                    };
                    if n == 0 {
                        continue;
                    }
                    let pkt = &buf[..n];
                    let first = pkt[0];
                    let op = match OpCode::from_u8(first >> 3) {
                        Ok(o) => o,
                        Err(e) => {
                            trace!("bad opcode from {addr}: {e}");
                            continue;
                        }
                    };

                    if op.is_data() {
                        // Route to the session's worker — no decryption or
                        // session lock on this hot path.
                        server.route_data(pkt);
                        continue;
                    }

                    // Decrypt + verify the control envelope (tls-crypt or
                    // tls-auth) and strip the replay header before the
                    // control packet reaches the parser.
                    let (inner_owned, replay_pid) = match server.unwrap_control(pkt) {
                        Ok(p) => p,
                        Err(e) => {
                            debug!("envelope verify from {addr}: {e}");
                            continue;
                        }
                    };
                    let inner_pkt: &[u8] = inner_owned.as_deref().unwrap_or(pkt);

                    let transport = Transport::Udp {
                        socket: server.socket.clone(),
                        addr,
                    };
                    if let Err(e) = server
                        .handle_control_packet(addr, inner_pkt, replay_pid, &transport)
                        .await
                    {
                        debug!("control from {addr}: {e}");
                    }
                }
            }
        }
    }

    /// Read+dispatch packets off a single accepted TCP stream. Spawns a
    /// short writer task that prefixes outbound bytes with a u16-BE length
    /// (OpenVPN's TCP framing). When the reader hits EOF or an error, the
    /// matching `Session` is evicted and IP/peer maps are cleaned up.
    async fn run_tcp_stream(self: Arc<Self>, stream: tokio::net::TcpStream, peer: SocketAddr) {
        // Turning off Nagle keeps small control packets from being delayed
        // and from being merged with subsequent ones in a way that confuses
        // OpenVPN's stream parser.
        let _ = stream.set_nodelay(true);
        let (reader, mut writer) = stream.into_split();
        let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();
        // Writer task: dequeue Vec<u8>, prepend u16-BE length, push to
        // stream in a SINGLE write to keep length + body atomic.
        tokio::spawn(async move {
            while let Some(bytes) = out_rx.recv().await {
                let len = bytes.len();
                if len > u16::MAX as usize {
                    trace!("tcp out packet > 65535 bytes; dropping");
                    continue;
                }
                let mut framed = Vec::with_capacity(2 + len);
                framed.extend_from_slice(&(len as u16).to_be_bytes());
                framed.extend_from_slice(&bytes);
                if let Err(e) = writer.write_all(&framed).await {
                    trace!("tcp writer EOF: {e}");
                    break;
                }
            }
        });
        let transport = Transport::Tcp { tx: out_tx };

        let mut reader = tokio::io::BufReader::new(reader);
        let mut len_buf = [0u8; 2];
        loop {
            if tokio::io::AsyncReadExt::read_exact(&mut reader, &mut len_buf)
                .await
                .is_err()
            {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            if len == 0 {
                continue;
            }
            let mut pkt = vec![0u8; len];
            if tokio::io::AsyncReadExt::read_exact(&mut reader, &mut pkt)
                .await
                .is_err()
            {
                break;
            }

            let first = pkt[0];
            let op = match OpCode::from_u8(first >> 3) {
                Ok(o) => o,
                Err(e) => {
                    trace!("tcp bad opcode from {peer}: {e}");
                    continue;
                }
            };
            if op.is_data() {
                self.route_data(&pkt);
                continue;
            }
            let (inner_owned, replay_pid) = match self.unwrap_control(&pkt) {
                Ok(p) => p,
                Err(e) => {
                    debug!("tcp envelope verify from {peer}: {e}");
                    continue;
                }
            };
            let inner_pkt: &[u8] = inner_owned.as_deref().unwrap_or(&pkt);
            if let Err(e) = self
                .handle_control_packet(peer, inner_pkt, replay_pid, &transport)
                .await
            {
                debug!("tcp control from {peer}: {e}");
            }
        }
        info!("tcp stream from {peer} closed");
        if let Some((_, arc)) = self.sessions.remove(&peer) {
            let sess = arc.lock().await;
            if let Some(IpAddr::V4(ip)) = sess.assigned_ip {
                self.routes.remove(&ip);
            }
            if let Some(ip6) = sess.assigned_ip_v6 {
                self.routes_v6.remove(&ip6);
            }
            self.peers.remove(&sess.peer_id);
            self.data_routes.remove(&sess.peer_id);
        }
    }

    /// Best-effort: send "RESTART,1" to every Established session so the
    /// client reconnects after 1 second instead of going through its full
    /// ping-restart timeout. Flushes the resulting TLS bytes on the wire
    /// and waits briefly for the kernel to push them out.
    async fn shutdown_clients(&self) {
        let addrs: Vec<SocketAddr> = self.sessions.iter().map(|e| *e.key()).collect();
        for addr in addrs {
            let Some(arc_ref) = self.sessions.get(&addr) else {
                continue;
            };
            let arc = arc_ref.value().clone();
            drop(arc_ref);
            let mut sess = arc.lock().await;
            if sess.state != State::Established {
                continue;
            }
            if let Err(e) = sess.tls.send_plaintext(b"RESTART,1\0") {
                trace!("queue RESTART for {addr}: {e}");
                continue;
            }
            if let Err(e) = self.flush_outgoing(addr, &mut sess).await {
                trace!("flush RESTART to {addr}: {e}");
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    async fn handle_control_packet(
        &self,
        addr: SocketAddr,
        pkt: &[u8],
        replay_pid: Option<u32>,
        transport: &Transport,
    ) -> Result<()> {
        let ctrl = ControlPacket::parse(pkt)?;

        // First packet from this peer is a HARD_RESET — start a new session.
        if matches!(
            ctrl.op,
            OpCode::ControlHardResetClientV2
                | OpCode::ControlHardResetClientV1
                | OpCode::ControlHardResetClientV3
        ) && !self.sessions.contains_key(&addr)
        {
            let tls = TlsSession::new(self.tls_cfg.clone())?;
            let mut sid_bytes = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut sid_bytes);
            let server_sid = u64::from_be_bytes(sid_bytes);
            let peer_id = self.next_peer_id.fetch_add(1, Ordering::SeqCst) & 0x00FF_FFFF;
            let mut sess = Session::new(server_sid, tls, peer_id, transport.clone());
            sess.client_session_id = ctrl.session_id;
            sess.state = State::Handshaking;
            // Seed the inbound tls-auth replay window with the very first id
            // the client used. Empty window always accepts a non-zero pid.
            if let Some(pid) = replay_pid {
                sess.tls_auth_replay.check_and_set(pid);
            }
            let ack_pid = ctrl.packet_id.unwrap_or(0);

            let reply = sess.make_hard_reset_reply(ack_pid);
            self.send_and_track(addr, &mut sess, reply).await?;

            let arc = Arc::new(Mutex::new(sess));
            self.sessions.insert(addr, arc.clone());
            self.peers.insert(peer_id, addr);
            self.spawn_data_worker(peer_id, arc);
            info!("new session from {addr} peer_id={peer_id} server_sid={server_sid:016x}");
            return Ok(());
        }

        let arc = match self.sessions.get(&addr) {
            Some(e) => e.clone(),
            None => {
                debug!("control packet from unknown peer {addr}");
                return Ok(());
            }
        };
        let mut sess = arc.lock().await;
        sess.last_seen = Instant::now();
        // (Don't collapse — `let ... && ...` chains aren't stable until 1.88,
        // and the docker harness builds with 1.85.)
        if let Some(pid) = replay_pid {
            #[allow(clippy::collapsible_if)]
            if !sess.tls_auth_replay.check_and_set(pid) {
                anyhow::bail!("tls-auth replay rejected pid={pid}");
            }
        }

        // Every control packet may carry ACKs in its `acks` field — process
        // them regardless of opcode so retransmits can stop early.
        if !ctrl.acks.is_empty() {
            trace!("acks from {addr}: {:?}", ctrl.acks);
            sess.process_acks(&ctrl.acks);
        }

        if let Some(pid) = ctrl.packet_id {
            sess.note_received(pid);
        }

        match ctrl.op {
            OpCode::AckV1 => {
                // Already processed above.
            }
            OpCode::ControlV1 => {
                // Route by key_id: rekey track or main session.
                let is_rekey = sess.rekey.as_ref().is_some_and(|r| r.key_id == ctrl.key_id);
                if is_rekey {
                    self.handle_rekey_control(addr, &mut sess, &ctrl).await?;
                } else {
                    sess.tls.feed(&ctrl.payload).context("tls feed")?;
                    if sess.state == State::Handshaking && !sess.tls.is_handshaking() {
                        sess.finalize_keys()?;
                        info!("TLS handshake complete with {addr}; awaiting key-method-2");
                    }
                    self.drive_control_plane(addr, &mut sess).await?;
                    self.flush_outgoing(addr, &mut sess).await?;
                }
            }
            OpCode::ControlSoftResetV1 => {
                if sess.rekey.is_some() {
                    debug!("SOFT_RESET from {addr} while rekey already in progress; ignoring");
                } else if sess.state != State::Established {
                    debug!(
                        "SOFT_RESET from {addr} but session not yet established (state={:?})",
                        sess.state
                    );
                } else {
                    let new_key_id = ctrl.key_id;
                    let new_tls = TlsSession::new(self.tls_cfg.clone())?;
                    sess.start_rekey(new_key_id, new_tls);
                    let ack_pid = ctrl.packet_id.unwrap_or(0);
                    let reply = sess.make_soft_reset_reply(new_key_id, ack_pid);
                    self.send_and_track(addr, &mut sess, reply).await?;
                    info!("rekey started with {addr}: new key_id={new_key_id}");
                }
            }
            _ => debug!("unhandled control op {:?} from {addr}", ctrl.op),
        }
        Ok(())
    }

    /// Drain pending outbound TLS bytes, fragment them into control packets,
    /// and put them on the wire. Also flushes pending ACKs if there's nothing
    /// else to send.
    async fn flush_outgoing(&self, addr: SocketAddr, sess: &mut Session) -> Result<()> {
        let out = sess.tls.take_outgoing();
        if !out.is_empty() {
            let key_id = sess.active_slot().map(|s| s.key_id).unwrap_or(0);
            for chunk in out.chunks(MAX_TLS_PAYLOAD_PER_CONTROL) {
                let pkt = sess.make_control(key_id, chunk.to_vec());
                self.send_and_track(addr, sess, pkt).await?;
            }
        } else if !sess.pending_acks.is_empty() {
            let pids = std::mem::take(&mut sess.pending_acks);
            // Ack with the currently-active key_id (rekey, when added,
            // routes its own acks through the rekey track and bypasses here).
            let key_id = sess.active_slot().map(|s| s.key_id).unwrap_or(0);
            let ack = sess.make_ack(key_id, pids);
            // Pure-ack packets don't get a packet_id and don't need tracking,
            // but they still need the tls-auth envelope when configured.
            let bytes = ack.encode();
            let wire = self.wrap_for_wire(sess, &bytes)?;
            sess.transport.send(&wire).await?;
            let _ = addr;
        }
        Ok(())
    }

    /// Encode `pkt`, optionally wrap it with tls-auth, send it on the UDP
    /// socket, and stash the inner (pre-wrap) bytes in the session's unacked
    /// queue. The retransmit task wraps fresh on each resend so the tls-auth
    /// replay counter advances and the receiver never sees a duplicate.
    async fn send_and_track(
        &self,
        _addr: SocketAddr,
        sess: &mut Session,
        pkt: ControlPacket,
    ) -> Result<()> {
        let pid = pkt.packet_id;
        let encoded = pkt.encode();
        let wire = self.wrap_for_wire(sess, &encoded)?;
        sess.transport.send(&wire).await?;
        if let Some(p) = pid {
            sess.record_sent(p, encoded);
        }
        Ok(())
    }

    /// Feed an inbound `P_CONTROL_V1` with the rekey's `key_id` into the
    /// dedicated rekey TLS context, then advance the rekey state machine
    /// (derive new keys → parse client key-method-2 → reply → swap active
    /// slot → drop the rekey track).
    async fn handle_rekey_control(
        &self,
        addr: SocketAddr,
        sess: &mut Session,
        ctrl: &ControlPacket,
    ) -> Result<()> {
        // Phase 1: feed bytes into the rekey TLS. With classic PRF mode the
        // new slot is installed later (after we receive the rekey's
        // key-method-2), so handshake completion only advances state.
        {
            let Some(rk) = sess.rekey.as_mut() else {
                return Ok(());
            };
            rk.tls.feed(&ctrl.payload).context("rekey tls feed")?;
            if rk.state == RekeyState::Handshaking && !rk.tls.is_handshaking() {
                rk.state = RekeyState::KeyExchange;
                info!("rekey TLS handshake complete with {addr}");
            }
        }

        // Phase 2: drive the post-handshake key-method-2 exchange. This is
        // where we now install the new key slot (via PRF on the km2 inputs).
        self.drive_rekey_control_plane(addr, sess).await?;

        // Phase 3: flush any pending rekey TLS bytes (server key-method-2,
        // ack-only packets, etc.) on the wire.
        self.flush_rekey_outgoing(addr, sess).await?;

        // Phase 4: if we've sent our key-method-2 reply the rekey is done —
        // switch the active slot and clear the track.
        let finalize = sess.rekey.as_ref().is_some_and(|r| r.key_method_sent);
        if finalize {
            let new_key_id = sess.rekey.as_ref().unwrap().key_id;
            if sess.promote_slot(new_key_id) {
                info!("rekey complete with {addr}; active key_id={new_key_id}");
            } else {
                warn!("rekey finished but new key_id={new_key_id} missing from slots");
            }
            sess.rekey = None;
            sess.last_rekey_at = Instant::now();
        }
        Ok(())
    }

    /// Once the rekey TLS handshake is up, parse the client's key-method-2,
    /// derive the new data-channel key via PRF, install it as a second key
    /// slot, then send our key-method-2 reply on the rekey TLS.
    async fn drive_rekey_control_plane(&self, addr: SocketAddr, sess: &mut Session) -> Result<()> {
        let state_is_kx = sess
            .rekey
            .as_ref()
            .is_some_and(|r| r.state == RekeyState::KeyExchange);
        if !state_is_kx {
            return Ok(());
        }
        // Try to pop a client key-method-2 out of the rekey TLS plaintext.
        let parse = {
            let rk = sess.rekey.as_ref().unwrap();
            ClientKeyMethod2::try_parse(&rk.tls.plaintext_in)?
        };
        let (km, n) = match parse {
            Pop::NeedMore => return Ok(()),
            Pop::Ready(km, n) => (km, n),
        };
        // Snapshot the bits we need before we mutably re-borrow `sess`.
        let c_sid = sess.client_session_id.to_be_bytes();
        let s_sid = sess.server_session_id.to_be_bytes();
        let (rk_key_id, s_r1, s_r2) = {
            let rk = sess.rekey.as_ref().unwrap();
            (rk.key_id, rk.server_random1, rk.server_random2)
        };

        // Derive the new key from rekey-specific randoms + the OpenVPN
        // session IDs, and install it as the not-currently-active slot.
        let key_data = derive_openvpn_key_data(
            &km.pre_master,
            &km.random1,
            &s_r1,
            &km.random2,
            &s_r2,
            &c_sid,
            &s_sid,
        );
        sess.install_slot(KeySlot {
            key_id: rk_key_id,
            cipher: DataCipher::from_keymat_server(&key_data),
            // See session.rs install_prf_slot for why pid starts at 1.
            data_pid_out: 1,
            replay: ReplayWindow::new(),
        });

        // Now build the km2 reply and queue it on the rekey TLS.
        let link_mtu = self.cfg.tun_mtu.saturating_add(42);
        let opts = build_options_string(link_mtu, self.cfg.tun_mtu);
        let peer_info = build_peer_info();
        let rk = sess.rekey.as_mut().unwrap();
        rk.tls.plaintext_in.drain(..n);
        info!(
            "rekey key-method-2 from {addr}: options={:?} peer_info_len={}",
            km.options,
            km.peer_info.len()
        );
        let reply = ServerKeyMethod2 {
            random1: &s_r1,
            random2: &s_r2,
            options: &opts,
            username: "",
            password: "",
            peer_info: &peer_info,
        }
        .encode();
        rk.tls.send_plaintext(&reply)?;
        rk.key_method_sent = true;
        Ok(())
    }

    /// Drain pending rekey TLS bytes and send them as `P_CONTROL_V1` with
    /// the rekey's `key_id`.
    async fn flush_rekey_outgoing(&self, addr: SocketAddr, sess: &mut Session) -> Result<()> {
        let out = {
            let Some(rk) = sess.rekey.as_mut() else {
                return Ok(());
            };
            rk.tls.take_outgoing()
        };
        if out.is_empty() {
            return Ok(());
        }
        let key_id = sess.rekey.as_ref().unwrap().key_id;
        let chunks: Vec<Vec<u8>> = out
            .chunks(MAX_TLS_PAYLOAD_PER_CONTROL)
            .map(|c| c.to_vec())
            .collect();
        for chunk in chunks {
            let pkt = sess.make_control(key_id, chunk);
            self.send_and_track(addr, sess, pkt).await?;
        }
        Ok(())
    }

    /// Walk the plaintext buffer behind the TLS session and react to whatever
    /// post-TLS messages have arrived (key-method-2, then PUSH_REQUEST).
    async fn drive_control_plane(&self, addr: SocketAddr, sess: &mut Session) -> Result<()> {
        loop {
            match sess.state {
                State::KeyExchange => {
                    let plaintext = sess.tls.plaintext_in.clone();
                    match ClientKeyMethod2::try_parse(&plaintext)? {
                        Pop::NeedMore => return Ok(()),
                        Pop::Ready(km, n) => {
                            sess.tls.plaintext_in.drain(..n);
                            info!(
                                "key-method-2 from {addr}: options={:?} peer_info_len={}",
                                km.options,
                                km.peer_info.len()
                            );
                            sess.client_pre_master = Some(km.pre_master);
                            sess.client_random1 = Some(km.random1);
                            sess.client_random2 = Some(km.random2);
                            sess.client_options = Some(km.options);
                            sess.client_peer_info = Some(km.peer_info);

                            // We now have everything the PRF needs — derive
                            // the data-channel key and install slot 0 (key_id 0
                            // is the initial slot per OpenVPN's convention).
                            sess.install_prf_slot(0)?;

                            let link_mtu = self.cfg.tun_mtu.saturating_add(42);
                            let opts = build_options_string(link_mtu, self.cfg.tun_mtu);
                            let peer_info = build_peer_info();
                            let reply = ServerKeyMethod2 {
                                random1: &sess.server_random1,
                                random2: &sess.server_random2,
                                options: &opts,
                                username: "",
                                password: "",
                                peer_info: &peer_info,
                            }
                            .encode();
                            sess.tls.send_plaintext(&reply)?;
                            sess.state = State::PushPending;
                        }
                    }
                }
                State::PushPending => {
                    let plaintext = sess.tls.plaintext_in.clone();
                    match try_pop_ascii(&plaintext) {
                        Pop::NeedMore => return Ok(()),
                        Pop::Ready(msg, n) => {
                            sess.tls.plaintext_in.drain(..n);
                            debug!("ascii ctrl-msg from {addr}: {msg:?}");
                            if msg == "PUSH_REQUEST" {
                                let cc = sess
                                    .client_cn
                                    .as_ref()
                                    .and_then(|cn| self.cfg.client_configs.get(cn));
                                let ip = match cc.and_then(|c| c.assign_ip) {
                                    Some(IpAddr::V4(v4)) => {
                                        if self.routes.contains_key(&v4) {
                                            anyhow::bail!(
                                                "static IP {v4} for cn={:?} already in use",
                                                sess.client_cn
                                            );
                                        }
                                        v4
                                    }
                                    Some(IpAddr::V6(_)) => {
                                        anyhow::bail!("per-client IPv6 not supported")
                                    }
                                    None => self.allocate_ip()?,
                                };
                                sess.assigned_ip = Some(IpAddr::V4(ip));
                                self.routes.insert(ip, addr);
                                let ip6 = self.allocate_ip_v6()?;
                                if let Some(v6) = ip6 {
                                    sess.assigned_ip_v6 = Some(v6);
                                    self.routes_v6.insert(v6, addr);
                                }
                                let extra_routes: &[String] =
                                    cc.map(|c| c.push_routes.as_slice()).unwrap_or(&[]);
                                let reply = build_push_reply(
                                    &self.cfg,
                                    ip,
                                    ip6,
                                    sess.peer_id,
                                    extra_routes,
                                );
                                sess.tls.send_plaintext(&reply)?;
                                sess.state = State::Established;
                                info!(
                                    "session ESTABLISHED with {addr}: assigned {ip}{} peer_id={} cn={} extra_routes={}",
                                    ip6.map(|v6| format!(" + {v6}")).unwrap_or_default(),
                                    sess.peer_id,
                                    sess.client_cn.as_deref().unwrap_or("<none>"),
                                    extra_routes.len(),
                                );
                            } else {
                                debug!("ignoring unexpected ctrl-msg {msg:?}");
                            }
                        }
                    }
                }
                State::Established => {
                    // Drain any further ASCII control messages (e.g. CC_EXIT_NOTIFY).
                    let plaintext = sess.tls.plaintext_in.clone();
                    match try_pop_ascii(&plaintext) {
                        Pop::Ready(msg, n) => {
                            sess.tls.plaintext_in.drain(..n);
                            debug!("post-established ctrl-msg from {addr}: {msg:?}");
                            if msg == "EXIT" || msg.starts_with("CC_EXIT") {
                                sess.state = State::Closed;
                                return Ok(());
                            }
                        }
                        Pop::NeedMore => return Ok(()),
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    /// Route a raw inbound `P_DATA_V2` packet to its session's worker by
    /// peer_id. Lock-free hot path: a DashMap lookup + channel send, no
    /// decryption here.
    fn route_data(&self, pkt: &[u8]) {
        let Ok(dp) = DataPacketV2::parse(pkt) else {
            // P_DATA_V1 or malformed — log the opcode so we can tell which.
            if !pkt.is_empty() {
                let op = pkt[0] >> 3;
                trace!("route_data: parse failed (op={op:#x} len={})", pkt.len());
            }
            return;
        };
        if let Some(route) = self.data_routes.get(&dp.peer_id) {
            let _ = route.send(pkt.to_vec());
        } else {
            let known: Vec<u32> = self.data_routes.iter().map(|e| *e.key()).collect();
            trace!(
                "route_data: no session for peer_id={} key_id={} (known={:?})",
                dp.peer_id, dp.key_id, known
            );
        }
    }

    fn allocate_ip(&self) -> Result<Ipv4Addr> {
        let mut guard = self.next_pool_ip.lock();
        let ip = *guard;
        if u32::from(ip) > u32::from(self.pool_end) {
            anyhow::bail!("client IP pool exhausted");
        }
        let next = u32::from(ip).wrapping_add(1);
        *guard = Ipv4Addr::from(next);
        Ok(ip)
    }

    /// Hand out the next IPv6 from the pool, if IPv6 is configured.
    /// Returns `Ok(None)` when v6 isn't enabled.
    fn allocate_ip_v6(&self) -> Result<Option<Ipv6Addr>> {
        let Some(slot) = self.next_pool_ip_v6.as_ref() else {
            return Ok(None);
        };
        let pool_end = self
            .pool_end_v6
            .expect("pool_end_v6 set together with next_pool_ip_v6");
        let mut guard = slot.lock();
        let ip = *guard;
        if u128::from(ip) > u128::from(pool_end) {
            anyhow::bail!("client IPv6 pool exhausted");
        }
        *guard = Ipv6Addr::from(u128::from(ip).wrapping_add(1));
        Ok(Some(ip))
    }
}

/// Build a null-terminated `PUSH_REPLY,...` message answering the client's
/// `PUSH_REQUEST`. Comma-separated directives are pushed through to the
/// client. `extra_routes` is appended to the global `push_routes` and is
/// where per-CN overrides land.
fn build_push_reply(
    cfg: &ServerConfig,
    client_ip: Ipv4Addr,
    client_ip6: Option<Ipv6Addr>,
    peer_id: u32,
    extra_routes: &[String],
) -> Vec<u8> {
    let mut s = String::new();
    s.push_str("PUSH_REPLY");
    s.push_str(&format!(
        ",ifconfig {} {}",
        client_ip,
        netmask_of(cfg.tun_netmask)
    ));
    s.push_str(",topology subnet");
    s.push_str(&format!(",route-gateway {}", cfg.tun_ip));
    // IPv6 ifconfig + routes (only when configured).
    if let (Some(IpAddr::V6(server6)), Some(client6)) = (cfg.tun_ip6, client_ip6) {
        s.push_str(&format!(
            ",ifconfig-ipv6 {}/{} {}",
            client6, cfg.tun_prefix6, server6
        ));
    }
    let mut redirect_gateway = false;
    for r in cfg.push_routes.iter().chain(extra_routes.iter()) {
        if r == "0.0.0.0/0" {
            redirect_gateway = true;
        } else if let Some((net, mask)) = cidr_to_route(r) {
            s.push_str(&format!(",route {} {}", net, mask));
        }
    }
    // Push explicit half-default routes instead of redirect-gateway.
    // redirect-gateway def1 causes OpenVPN Connect on macOS to add a bypass
    // host route for the VPN gateway (10.8.0.1) via the physical interface,
    // which makes the /1 routes also resolve via the physical interface and
    // breaks all internet traffic through the tunnel. Explicit route pushes
    // do not trigger that bypass, so the /1 routes correctly resolve through
    // the VPN subnet route on the tun interface.
    if redirect_gateway {
        s.push_str(",route 0.0.0.0 128.0.0.0");
        s.push_str(",route 128.0.0.0 128.0.0.0");
    }
    for r in &cfg.push_routes_v6 {
        s.push_str(&format!(",route-ipv6 {}", r));
    }
    for dns in &cfg.push_dns {
        s.push_str(&format!(",dhcp-option DNS {}", dns));
    }
    s.push_str(&format!(
        ",ping {},ping-restart {}",
        cfg.keepalive_ping, cfg.keepalive_timeout
    ));
    s.push_str(",cipher AES-256-GCM");
    s.push_str(&format!(",peer-id {}", peer_id));
    let mut out = s.into_bytes();
    out.push(0); // OpenVPN ASCII control messages are NUL-terminated
    out
}

fn netmask_of(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => Ipv4Addr::new(255, 255, 255, 0),
    }
}

/// Current Unix time as a u32 (truncates after year 2106). OpenVPN uses this
/// as the `net_time` field in the tls-auth replay header.
fn unix_timestamp_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Convert "10.0.0.0/8" → ("10.0.0.0", "255.0.0.0"). Returns None on bad input.
fn cidr_to_route(cidr: &str) -> Option<(String, String)> {
    let (net, bits) = cidr.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    let mask = if bits == 0 { 0 } else { (!0u32) << (32 - bits) };
    Some((net.to_string(), Ipv4Addr::from(mask).to_string()))
}

/// Decrypt one inbound `P_DATA_V2` packet against `sess` and forward the
/// plaintext IP packet to the TUN writer. Run by the per-session data
/// worker, so two sessions decrypt in parallel (their `Mutex`es differ);
/// packets within a session stay ordered (one worker, one lock).
async fn decrypt_and_forward(
    sess: &Arc<Mutex<Session>>,
    pkt: &[u8],
    tun_tx: &UnboundedSender<Vec<u8>>,
) -> Result<()> {
    let dp = DataPacketV2::parse(pkt)?;
    let mut sess = sess.lock().await;
    let aad = &pkt[..8];
    let plaintext = {
        let slot = sess
            .slot_by_key_id_mut(dp.key_id)
            .ok_or_else(|| anyhow::anyhow!("no key slot for key_id={}", dp.key_id))?;
        let plaintext = slot.cipher.open(dp.packet_id, aad, dp.ciphertext)?;
        // Only feed the replay window after AEAD authentication succeeds —
        // an attacker without the key can't poison the window.
        if !slot.replay.check_and_set(dp.packet_id) {
            anyhow::bail!("replay rejected: key_id={} pid={}", dp.key_id, dp.packet_id);
        }
        plaintext
    };
    sess.last_seen = std::time::Instant::now();
    drop(sess);
    if plaintext == PING_PAYLOAD {
        trace!("occ-ping from peer_id={}", dp.peer_id);
        return Ok(());
    }
    tun_tx
        .send(plaintext)
        .map_err(|_| anyhow::anyhow!("tun writer channel closed"))?;
    Ok(())
}

async fn forward_tun_to_client(
    sessions: &DashMap<SocketAddr, Arc<Mutex<Session>>>,
    routes: &DashMap<Ipv4Addr, SocketAddr>,
    routes_v6: &DashMap<Ipv6Addr, SocketAddr>,
    ip_pkt: &[u8],
) -> Result<()> {
    if ip_pkt.is_empty() {
        return Ok(());
    }
    // First nibble of the IP header tells us v4 (0x4) vs v6 (0x6).
    let addr = match ip_pkt[0] >> 4 {
        4 => {
            if ip_pkt.len() < 20 {
                return Ok(());
            }
            let dst = Ipv4Addr::new(ip_pkt[16], ip_pkt[17], ip_pkt[18], ip_pkt[19]);
            match routes.get(&dst) {
                Some(e) => *e.value(),
                None => return Ok(()),
            }
        }
        6 => {
            if ip_pkt.len() < 40 {
                return Ok(());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&ip_pkt[24..40]);
            let dst = Ipv6Addr::from(octets);
            match routes_v6.get(&dst) {
                Some(e) => *e.value(),
                None => return Ok(()),
            }
        }
        _ => return Ok(()),
    };
    let arc = match sessions.get(&addr) {
        Some(e) => e.clone(),
        None => return Ok(()),
    };
    let mut sess = arc.lock().await;
    if sess.active_slot().is_none() {
        return Ok(());
    }
    let bytes = sess.build_data_packet(ip_pkt)?;
    sess.transport.send(&bytes).await?;
    Ok(())
}
