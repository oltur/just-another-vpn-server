//! OpenVPN `--tls-auth` HMAC-SHA256 wrapping for control-channel packets.
//!
//! tls-auth adds a pre-shared-key HMAC and a small replay header to every
//! control packet on the wire. It rejects unauthenticated packets before
//! they touch the TLS state machine, which makes it cheap to drop unwanted
//! traffic and shields the TLS implementation from pre-auth attacks.
//!
//! The wire layout produced by [`TlsAuthKey::wrap`] is:
//!
//! ```text
//!  op (1) | session_id (8) | HMAC (32) | replay_pid (4) | net_time (4) | body...
//! ```
//!
//! The HMAC is computed over
//! `replay_pid || net_time || op || session_id || body`, where `body` is
//! the bytes following `session_id` in the inner control packet
//! (ack_count, acks, optional remote session id, optional message
//! packet_id, payload).

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::static_key::STATIC_KEY_LEN;

type HmacSha256 = Hmac<Sha256>;

/// Size of the HMAC tag we put on the wire (HMAC-SHA256).
pub const HMAC_LEN: usize = 32;

/// Per-slot size in an OpenVPN static key (4 slots of 64 bytes = 256 bytes).
const SLOT_LEN: usize = 64;

/// Length of the fixed prefix (op + session_id) we leave in front of the HMAC.
const HEADER_LEN: usize = 9;

/// Length of the replay-protection header that immediately follows the HMAC.
const REPLAY_HEADER_LEN: usize = 8;

/// HMAC keys used to authenticate the control channel.
pub struct TlsAuthKey {
    out_key: [u8; SLOT_LEN],
    in_key: [u8; SLOT_LEN],
}

impl TlsAuthKey {
    /// Build the server-side keys from a parsed 256-byte static key.
    ///
    /// `direction` follows the OpenVPN `key-direction` directive:
    ///   * `0` — same key both ways (slot 1, bytes 64..128)
    ///   * `1` — server outbound uses slot 3 (bytes 192..256), inbound slot 1.
    ///     Mirrors the typical client config `tls-auth ta.key 1`.
    pub fn from_static_key_server(km: &[u8; STATIC_KEY_LEN], direction: u8) -> Result<Self> {
        let (out_off, in_off) = match direction {
            0 => (SLOT_LEN, SLOT_LEN),
            1 => (SLOT_LEN * 3, SLOT_LEN),
            _ => bail!("invalid tls-auth key-direction {direction}; expected 0 or 1"),
        };
        let mut out_key = [0u8; SLOT_LEN];
        let mut in_key = [0u8; SLOT_LEN];
        out_key.copy_from_slice(&km[out_off..out_off + SLOT_LEN]);
        in_key.copy_from_slice(&km[in_off..in_off + SLOT_LEN]);
        Ok(Self { out_key, in_key })
    }

    /// Wrap an already-encoded inner control packet (`op || session_id || body`)
    /// with the tls-auth envelope.
    pub fn wrap(&self, inner: &[u8], replay_pid: u32, timestamp: u32) -> Result<Vec<u8>> {
        if inner.len() < HEADER_LEN {
            bail!(
                "inner control packet too short ({} < {})",
                inner.len(),
                HEADER_LEN
            );
        }
        let op = inner[0];
        let session_id = &inner[1..HEADER_LEN];
        let body = &inner[HEADER_LEN..];

        let hmac = compute_hmac(&self.out_key, op, session_id, replay_pid, timestamp, body);

        let mut out = Vec::with_capacity(HEADER_LEN + HMAC_LEN + REPLAY_HEADER_LEN + body.len());
        out.push(op);
        out.extend_from_slice(session_id);
        out.extend_from_slice(&hmac);
        out.extend_from_slice(&replay_pid.to_be_bytes());
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.extend_from_slice(body);
        Ok(out)
    }

    /// Verify the HMAC on an inbound control packet and return
    /// `(op || session_id || body, replay_pid)`. The returned bytes are
    /// suitable for `ControlPacket::parse`.
    pub fn unwrap(&self, pkt: &[u8]) -> Result<(Vec<u8>, u32)> {
        const MIN_LEN: usize = HEADER_LEN + HMAC_LEN + REPLAY_HEADER_LEN;
        if pkt.len() < MIN_LEN {
            bail!(
                "packet too short for tls-auth ({} < {})",
                pkt.len(),
                MIN_LEN
            );
        }
        let op = pkt[0];
        let session_id = &pkt[1..HEADER_LEN];
        let hmac_recv = &pkt[HEADER_LEN..HEADER_LEN + HMAC_LEN];
        let after_hmac = HEADER_LEN + HMAC_LEN;
        let replay_pid = u32::from_be_bytes(pkt[after_hmac..after_hmac + 4].try_into().unwrap());
        let timestamp = u32::from_be_bytes(pkt[after_hmac + 4..after_hmac + 8].try_into().unwrap());
        let body = &pkt[after_hmac + REPLAY_HEADER_LEN..];

        let expected = compute_hmac(&self.in_key, op, session_id, replay_pid, timestamp, body);
        // hmac::Mac::verify_slice gives constant-time comparison.
        let mut mac = HmacSha256::new_from_slice(&self.in_key).expect("HMAC key length is fixed");
        mac.update(&compose_hmac_input(
            op, session_id, replay_pid, timestamp, body,
        ));
        mac.verify_slice(hmac_recv)
            .context("tls-auth HMAC mismatch")?;
        // Defensive cross-check — should be identical to verify_slice's result.
        debug_assert_eq!(expected.as_slice(), hmac_recv);

        let mut inner = Vec::with_capacity(HEADER_LEN + body.len());
        inner.push(op);
        inner.extend_from_slice(session_id);
        inner.extend_from_slice(body);
        Ok((inner, replay_pid))
    }
}

fn compose_hmac_input(
    op: u8,
    session_id: &[u8],
    replay_pid: u32,
    timestamp: u32,
    body: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 4 + 1 + session_id.len() + body.len());
    v.extend_from_slice(&replay_pid.to_be_bytes());
    v.extend_from_slice(&timestamp.to_be_bytes());
    v.push(op);
    v.extend_from_slice(session_id);
    v.extend_from_slice(body);
    v
}

fn compute_hmac(
    key: &[u8],
    op: u8,
    session_id: &[u8],
    replay_pid: u32,
    timestamp: u32,
    body: &[u8],
) -> [u8; HMAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is fixed");
    mac.update(&compose_hmac_input(
        op, session_id, replay_pid, timestamp, body,
    ));
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_LEN];
    out.copy_from_slice(&tag);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_static_key() -> [u8; STATIC_KEY_LEN] {
        let mut k = [0u8; STATIC_KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn sample_inner() -> Vec<u8> {
        // Synthetic inner packet: op=0x38 (ControlV1<<3), 8 bytes session id,
        // then body bytes.
        let mut v = vec![0x38];
        v.extend_from_slice(&0x0102030405060708u64.to_be_bytes());
        v.extend_from_slice(b"hello-control-packet-body");
        v
    }

    #[test]
    fn direction_0_round_trip() {
        let km = fake_static_key();
        let server = TlsAuthKey::from_static_key_server(&km, 0).unwrap();
        let inner = sample_inner();
        let wire = server.wrap(&inner, 42, 1_700_000_000).unwrap();
        let (back, pid) = server.unwrap(&wire).unwrap();
        assert_eq!(back, inner);
        assert_eq!(pid, 42);
    }

    #[test]
    fn direction_1_peer_round_trip() {
        let km = fake_static_key();
        let server = TlsAuthKey::from_static_key_server(&km, 1).unwrap();
        // The client mirrors the server: its out_key is the server's in_key
        // and vice versa.
        let client = TlsAuthKey {
            out_key: server.in_key,
            in_key: server.out_key,
        };
        let inner = sample_inner();

        // server -> client
        let wire = server.wrap(&inner, 7, 1_234_567_890).unwrap();
        let (back, pid) = client.unwrap(&wire).unwrap();
        assert_eq!(back, inner);
        assert_eq!(pid, 7);

        // client -> server
        let wire = client.wrap(&inner, 11, 1_234_567_891).unwrap();
        let (back, pid) = server.unwrap(&wire).unwrap();
        assert_eq!(back, inner);
        assert_eq!(pid, 11);
    }

    #[test]
    fn rejects_tampered_hmac() {
        let km = fake_static_key();
        let key = TlsAuthKey::from_static_key_server(&km, 0).unwrap();
        let inner = sample_inner();
        let mut wire = key.wrap(&inner, 1, 0).unwrap();
        let hmac_byte = HEADER_LEN + 5;
        wire[hmac_byte] ^= 0x01;
        assert!(key.unwrap(&wire).is_err());
    }

    #[test]
    fn rejects_tampered_body() {
        let km = fake_static_key();
        let key = TlsAuthKey::from_static_key_server(&km, 0).unwrap();
        let inner = sample_inner();
        let mut wire = key.wrap(&inner, 1, 0).unwrap();
        // last byte of payload
        let last = wire.len() - 1;
        wire[last] ^= 0x80;
        assert!(key.unwrap(&wire).is_err());
    }

    #[test]
    fn rejects_too_short() {
        let km = fake_static_key();
        let key = TlsAuthKey::from_static_key_server(&km, 0).unwrap();
        let short = vec![0u8; HEADER_LEN + HMAC_LEN]; // missing replay header
        assert!(key.unwrap(&short).is_err());
    }

    #[test]
    fn rejects_unknown_direction() {
        let km = fake_static_key();
        assert!(TlsAuthKey::from_static_key_server(&km, 2).is_err());
    }

    /// End-to-end check: take a real `ControlPacket`, encode it, wrap it
    /// with tls-auth, hand the wire bytes to the "peer" key (mirror of the
    /// server), unwrap, and verify the resulting bytes parse back to the
    /// same fields. Catches mistakes at the boundary between the auth layer
    /// and the existing `ControlPacket` parser.
    #[test]
    fn round_trip_through_control_packet() {
        use crate::protocol::{ControlPacket, OpCode};

        let km = fake_static_key();
        let server = TlsAuthKey::from_static_key_server(&km, 1).unwrap();
        let peer = TlsAuthKey {
            out_key: server.in_key,
            in_key: server.out_key,
        };

        let original = ControlPacket {
            op: OpCode::ControlV1,
            key_id: 3,
            session_id: 0xDEAD_BEEF_CAFE_F00D,
            acks: vec![1, 2, 3],
            remote_session_id: Some(0x1122_3344_5566_7788),
            packet_id: Some(0x4242),
            payload: b"some-tls-bytes-here".to_vec(),
        };
        let inner = original.encode();
        let wire = server.wrap(&inner, 99, 1_700_000_000).unwrap();
        let (back, pid) = peer.unwrap(&wire).unwrap();
        assert_eq!(pid, 99);
        let parsed = ControlPacket::parse(&back).unwrap();
        assert_eq!(parsed.op, original.op);
        assert_eq!(parsed.key_id, original.key_id);
        assert_eq!(parsed.session_id, original.session_id);
        assert_eq!(parsed.acks, original.acks);
        assert_eq!(parsed.remote_session_id, original.remote_session_id);
        assert_eq!(parsed.packet_id, original.packet_id);
        assert_eq!(parsed.payload, original.payload);
    }
}
