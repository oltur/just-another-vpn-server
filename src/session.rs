//! Per-client connection state.

use crate::crypto::DataCipher;
use crate::prf::derive_openvpn_key_data;
use crate::protocol::{ControlPacket, OpCode, SessionId};
use crate::replay::ReplayWindow;
use crate::tls::TlsSession;
use crate::transport::Transport;
use anyhow::{Result, anyhow};
use bytes::BytesMut;
use std::collections::{BTreeSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Maximum bytes of TLS payload we'll put inside one `P_CONTROL_V1`. Sized
/// conservatively so the resulting UDP packet (overhead ≤ ~50 bytes) fits
/// inside a 1280-byte path MTU.
pub const MAX_TLS_PAYLOAD_PER_CONTROL: usize = 1100;

/// Base RTO before the first retransmit. Each subsequent attempt doubles up
/// to a cap; OpenVPN's classic timer is similar.
pub const CONTROL_BASE_RTO: Duration = Duration::from_secs(2);

/// Maximum number of retransmit attempts before we give up on a packet
/// (matches OpenVPN's default).
pub const CONTROL_MAX_ATTEMPTS: u32 = 6;

/// One entry in the per-session unacked queue.
#[derive(Debug, Clone)]
pub struct Unacked {
    pub packet_id: u32,
    pub encoded: BytesMut,
    pub sent_at: Instant,
    pub attempts: u32,
}

/// A single data-channel key generation. OpenVPN keeps up to two of these
/// active at a time so that rekey can rotate keys without dropping any
/// in-flight packets.
pub struct KeySlot {
    /// 3-bit identifier copied into outbound `P_DATA_V2` headers and matched
    /// against incoming packets' key_id bits.
    pub key_id: u8,
    pub cipher: DataCipher,
    /// Outbound P_DATA_V2 packet id counter for this slot.
    pub data_pid_out: u32,
    /// Replay window for inbound data packets on this slot.
    pub replay: ReplayWindow,
}

/// State machine for an in-flight rekey on the dedicated rekey TLS context.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RekeyState {
    /// New TLS handshake is in progress.
    Handshaking,
    /// Handshake done; awaiting the client's key-method-2 packet.
    KeyExchange,
}

/// Per-rekey state running alongside the main control track. Lives only
/// while a rekey is in progress; cleared once the new keys are active.
pub struct RekeyTrack {
    /// New 3-bit `key_id` for the slot being negotiated.
    pub key_id: u8,
    /// Fresh TLS context for the rekey handshake.
    pub tls: TlsSession,
    pub state: RekeyState,
    pub server_random1: [u8; 32],
    pub server_random2: [u8; 32],
    /// Flips true once we've sent our key-method-2 reply over `tls`.
    pub key_method_sent: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    /// Waiting for the initial `P_CONTROL_HARD_RESET_CLIENT_*`.
    WaitingHardReset,
    /// TLS handshake is in progress.
    Handshaking,
    /// TLS is up; waiting for the client's key-method-2 packet.
    KeyExchange,
    /// We've replied with our key-method-2; waiting for `PUSH_REQUEST`.
    PushPending,
    /// `PUSH_REPLY` sent; data plane is live.
    Established,
    Closed,
}

pub struct Session {
    pub server_session_id: SessionId,
    pub client_session_id: SessionId,
    pub state: State,

    // Control channel reliability layer
    pub next_packet_id: u32,
    pub pending_acks: Vec<u32>,
    pub received_pids: BTreeSet<u32>,

    pub tls: TlsSession,
    pub assigned_ip: Option<IpAddr>,
    /// IPv6 tunnel address (when v6-in-tunnel is enabled). Kept separately
    /// from `assigned_ip` so v4 and v6 routes can be torn down independently.
    pub assigned_ip_v6: Option<std::net::Ipv6Addr>,
    pub peer_id: u32,
    /// How outbound bytes for this peer reach the wire (UDP socket or per-TCP
    /// stream mpsc).
    pub transport: Transport,

    /// Up to two simultaneous data-channel key generations. During steady
    /// state only one is populated; during a rekey both are live (the new
    /// one starts decrypting inbound traffic immediately, and we switch the
    /// outbound side over once both peers have the new keys).
    pub slots: [Option<KeySlot>; 2],
    /// Index into [`slots`] of the slot we use for **sending** data packets.
    pub active_slot_idx: usize,

    /// Outbound tls-auth replay packet_id. OpenVPN starts at 1 and bumps it
    /// for every control packet (including retransmits, so the receiver's
    /// replay window stays happy).
    pub tls_auth_pid_out: u32,
    /// Replay window for inbound tls-auth packet_ids.
    pub tls_auth_replay: ReplayWindow,

    /// Random material received from the client's key-method-2 packet.
    pub client_random1: Option<[u8; 32]>,
    pub client_random2: Option<[u8; 32]>,
    /// 48-byte pre-master ciphertext the client picks and ships in
    /// key-method-2. Fed into [`derive_openvpn_key_data`] together with
    /// our own randoms.
    pub client_pre_master: Option<[u8; 48]>,
    /// Server's own random material — kept so we can re-send the key-method-2
    /// reply if it gets dropped.
    pub server_random1: [u8; 32],
    pub server_random2: [u8; 32],
    /// Options string the client announced — useful when debugging mismatches.
    pub client_options: Option<String>,
    pub client_peer_info: Option<String>,
    /// Common Name extracted from the peer cert's subject DN. Populated once
    /// the TLS handshake completes (`finalize_keys`).
    pub client_cn: Option<String>,

    /// Control-channel packets we've sent that haven't been ACKed yet.
    pub unacked: VecDeque<Unacked>,

    /// Active rekey, if any. Populated when we receive `ControlSoftResetV1`
    /// and cleared once we install the freshly-derived `KeySlot` as active.
    pub rekey: Option<RekeyTrack>,
    /// Wall-clock of the last rekey (or session creation if no rekey yet).
    /// The server-initiated rekey task uses this to decide when to roll keys.
    pub last_rekey_at: Instant,

    pub last_seen: Instant,
}

impl Session {
    pub fn new(
        server_session_id: SessionId,
        tls: TlsSession,
        peer_id: u32,
        transport: Transport,
    ) -> Self {
        let mut r1 = [0u8; 32];
        let mut r2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut r1);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut r2);
        Self {
            server_session_id,
            client_session_id: 0,
            state: State::WaitingHardReset,
            next_packet_id: 0,
            pending_acks: Vec::new(),
            received_pids: BTreeSet::new(),
            tls,
            assigned_ip: None,
            assigned_ip_v6: None,
            peer_id,
            transport,
            slots: [None, None],
            active_slot_idx: 0,
            tls_auth_pid_out: 1,
            tls_auth_replay: ReplayWindow::new(),
            client_random1: None,
            client_random2: None,
            client_pre_master: None,
            server_random1: r1,
            server_random2: r2,
            client_options: None,
            client_peer_info: None,
            client_cn: None,
            unacked: VecDeque::new(),
            rekey: None,
            last_rekey_at: Instant::now(),
            last_seen: Instant::now(),
        }
    }

    /// Kick off a rekey: stash a fresh TLS context plus the new `key_id`
    /// the client picked on its `ControlSoftResetV1`.
    pub fn start_rekey(&mut self, new_key_id: u8, tls: TlsSession) {
        let mut r1 = [0u8; 32];
        let mut r2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut r1);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut r2);
        self.rekey = Some(RekeyTrack {
            key_id: new_key_id,
            tls,
            state: RekeyState::Handshaking,
            server_random1: r1,
            server_random2: r2,
            key_method_sent: false,
        });
    }

    /// Promote the slot with the given `key_id` to "active" for sending.
    /// Returns false if no slot matches.
    pub fn promote_slot(&mut self, key_id: u8) -> bool {
        if let Some(idx) = self
            .slots
            .iter()
            .position(|s| s.as_ref().map(|k| k.key_id) == Some(key_id))
        {
            self.active_slot_idx = idx;
            true
        } else {
            false
        }
    }

    /// Remember a control packet we just put on the wire so the retransmit
    /// timer (and the next inbound ACK) can find it.
    pub fn record_sent(&mut self, packet_id: u32, encoded: BytesMut) {
        self.unacked.push_back(Unacked {
            packet_id,
            encoded,
            sent_at: Instant::now(),
            attempts: 1,
        });
    }

    /// Drop unacked entries whose `packet_id` shows up in `acks`.
    pub fn process_acks(&mut self, acks: &[u32]) {
        if acks.is_empty() {
            return;
        }
        self.unacked.retain(|u| !acks.contains(&u.packet_id));
    }

    /// Pick out the entries that are due for retransmit and bump their
    /// attempt counter. Returns the encoded bytes to resend.
    pub fn stale_unacked(&mut self, now: Instant, base_rto: Duration) -> Vec<BytesMut> {
        let mut out = Vec::new();
        // Drop any that have exceeded the max-attempts ceiling.
        self.unacked.retain(|u| u.attempts < CONTROL_MAX_ATTEMPTS);
        for u in self.unacked.iter_mut() {
            let shift = u.attempts.saturating_sub(1).min(5);
            let backoff = base_rto * (1u32 << shift);
            if now.duration_since(u.sent_at) >= backoff {
                u.sent_at = now;
                u.attempts = u.attempts.saturating_add(1);
                out.push(u.encoded.clone());
            }
        }
        out
    }

    /// Server's response to a HARD_RESET_CLIENT_V2.
    pub fn make_hard_reset_reply(&mut self, ack_pid: u32) -> ControlPacket {
        let pid = self.alloc_packet_id();
        ControlPacket {
            op: OpCode::ControlHardResetServerV2,
            key_id: 0,
            session_id: self.server_session_id,
            acks: vec![ack_pid],
            remote_session_id: Some(self.client_session_id),
            packet_id: Some(pid),
            payload: vec![],
        }
    }

    /// Server's reply to an inbound `ControlSoftResetV1`. Echoes the new
    /// `key_id` the client picked and acknowledges its packet id.
    pub fn make_soft_reset_reply(&mut self, new_key_id: u8, ack_pid: u32) -> ControlPacket {
        let pid = self.alloc_packet_id();
        ControlPacket {
            op: OpCode::ControlSoftResetV1,
            key_id: new_key_id,
            session_id: self.server_session_id,
            acks: vec![ack_pid],
            remote_session_id: Some(self.client_session_id),
            packet_id: Some(pid),
            payload: vec![],
        }
    }

    /// Server-initiated `ControlSoftResetV1`. No ack — we're the one asking
    /// for a rekey. The client will reply with its own SOFT_RESET acking
    /// this packet id and then start the new TLS handshake.
    pub fn make_soft_reset_init(&mut self, new_key_id: u8) -> ControlPacket {
        let pid = self.alloc_packet_id();
        ControlPacket {
            op: OpCode::ControlSoftResetV1,
            key_id: new_key_id,
            session_id: self.server_session_id,
            acks: vec![],
            remote_session_id: None,
            packet_id: Some(pid),
            payload: vec![],
        }
    }

    pub fn make_ack(&mut self, key_id: u8, pids: Vec<u32>) -> ControlPacket {
        ControlPacket {
            op: OpCode::AckV1,
            key_id,
            session_id: self.server_session_id,
            acks: pids,
            remote_session_id: Some(self.client_session_id),
            packet_id: None,
            payload: vec![],
        }
    }

    pub fn make_control(&mut self, key_id: u8, tls_payload: Vec<u8>) -> ControlPacket {
        let pid = self.alloc_packet_id();
        let acks = std::mem::take(&mut self.pending_acks);
        let remote = if !acks.is_empty() {
            Some(self.client_session_id)
        } else {
            None
        };
        ControlPacket {
            op: OpCode::ControlV1,
            key_id,
            session_id: self.server_session_id,
            acks,
            remote_session_id: remote,
            packet_id: Some(pid),
            payload: tls_payload,
        }
    }

    fn alloc_packet_id(&mut self) -> u32 {
        let p = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        p
    }

    /// Hand out the next outbound tls-auth replay packet_id. Each call returns
    /// a fresh value — retransmits re-wrap so the receiver doesn't see a
    /// duplicate id. Skips 0 on wrap-around (OpenVPN treats it as reserved).
    pub fn next_tls_auth_pid(&mut self) -> u32 {
        let p = self.tls_auth_pid_out;
        self.tls_auth_pid_out = self.tls_auth_pid_out.checked_add(1).unwrap_or(1);
        p
    }

    pub fn note_received(&mut self, pid: u32) {
        if self.received_pids.insert(pid) {
            self.pending_acks.push(pid);
        }
        self.last_seen = Instant::now();
    }

    /// Advance the state machine when the *initial* TLS handshake completes.
    /// With classic PRF key derivation, slot installation happens later (once
    /// we've parsed the client's key-method-2 — see [`install_prf_slot`]),
    /// so this just moves us into `KeyExchange`. Also pulls the peer
    /// certificate's CN out for logging / future per-client config.
    pub fn finalize_keys(&mut self) -> Result<()> {
        let leaf = self
            .tls
            .conn
            .peer_certificates()
            .and_then(|certs| certs.first());
        if let Some(leaf) = leaf {
            match crate::tls::extract_common_name(leaf.as_ref()) {
                Ok(cn) => self.client_cn = cn,
                Err(e) => tracing::debug!("peer cert CN extract failed: {e}"),
            }
        }
        self.state = State::KeyExchange;
        Ok(())
    }

    /// Derive the data-channel key from the inputs in key-method-2 (client's
    /// `pre_master`, both peers' `random1`/`random2`, both session IDs) and
    /// install it as the active key slot.
    pub fn install_prf_slot(&mut self, key_id: u8) -> Result<()> {
        let pre_master = self
            .client_pre_master
            .ok_or_else(|| anyhow!("install_prf_slot: missing client pre_master"))?;
        let c_r1 = self
            .client_random1
            .ok_or_else(|| anyhow!("install_prf_slot: missing client random1"))?;
        let c_r2 = self
            .client_random2
            .ok_or_else(|| anyhow!("install_prf_slot: missing client random2"))?;
        let c_sid = self.client_session_id.to_be_bytes();
        let s_sid = self.server_session_id.to_be_bytes();
        let key_data = derive_openvpn_key_data(
            &pre_master,
            &c_r1,
            &self.server_random1,
            &c_r2,
            &self.server_random2,
            &c_sid,
            &s_sid,
        );
        let slot = KeySlot {
            key_id,
            cipher: DataCipher::from_keymat_server(&key_data),
            // OpenVPN's replay window treats pid 0 as invalid (it's the
            // "not-yet-initialized" sentinel), so the first packet we put
            // on the wire must be pid 1. Over UDP a rejected pid=0 just
            // drops silently; over TCP the client raises "fatal decryption
            // error" and restarts the connection.
            data_pid_out: 1,
            replay: ReplayWindow::new(),
        };
        // For the initial handshake `key_id` is 0 and we put it in slot 0;
        // a rekey lands the new slot in the other position.
        if self.active_slot().is_none() {
            self.slots[0] = Some(slot);
            self.active_slot_idx = 0;
        } else {
            self.install_slot(slot);
        }
        Ok(())
    }

    /// Borrow the slot we send data packets on (whichever one was promoted
    /// to active by the most recent successful rekey, or the initial slot).
    pub fn active_slot(&self) -> Option<&KeySlot> {
        self.slots[self.active_slot_idx].as_ref()
    }
    pub fn active_slot_mut(&mut self) -> Option<&mut KeySlot> {
        self.slots[self.active_slot_idx].as_mut()
    }

    /// Find a slot by its on-the-wire `key_id`. Used by the inbound data path
    /// so old-slot packets in flight during a rekey still decrypt.
    pub fn slot_by_key_id_mut(&mut self, key_id: u8) -> Option<&mut KeySlot> {
        self.slots
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|s| s.key_id == key_id)
    }

    /// Insert a freshly-derived [`KeySlot`] into the non-active position,
    /// evicting whatever was there. Returns the slot index used.
    pub fn install_slot(&mut self, slot: KeySlot) -> usize {
        let idx = 1 - self.active_slot_idx;
        self.slots[idx] = Some(slot);
        idx
    }

    /// Encrypt `plaintext` as the next outbound P_DATA_V2 packet for this
    /// session, bumping the send-side packet id. Returns the full UDP payload
    /// (8-byte header + ciphertext + AEAD tag).
    pub fn build_data_packet(&mut self, plaintext: &[u8]) -> Result<BytesMut> {
        let peer_id = self.peer_id;
        let slot = self
            .active_slot_mut()
            .ok_or_else(|| anyhow!("no active key slot"))?;
        let pid = slot.data_pid_out;
        slot.data_pid_out = slot.data_pid_out.wrapping_add(1);
        let key_id = slot.key_id;
        let mut header = [0u8; 8];
        header[0] = ((OpCode::DataV2 as u8) << 3) | (key_id & 0x07);
        header[1] = ((peer_id >> 16) & 0xFF) as u8;
        header[2] = ((peer_id >> 8) & 0xFF) as u8;
        header[3] = (peer_id & 0xFF) as u8;
        header[4..8].copy_from_slice(&pid.to_be_bytes());
        let ct = slot.cipher.seal(pid, &header, plaintext)?;
        let mut out = BytesMut::with_capacity(8 + ct.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}
