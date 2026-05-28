//! OpenVPN's `--tls-crypt` envelope for control-channel packets.
//!
//! Unlike [`crate::tls_auth`] (which only HMACs each control packet),
//! tls-crypt also *encrypts* the payload with AES-256-CTR, hiding the
//! TLS handshake itself from a passive observer and giving you a
//! "site-password" style gate that drops attackers before they reach
//! the TLS state machine.
//!
//! The construction is the SIV-style scheme documented in
//! `src/openvpn/tls_crypt.h`:
//!
//! ```text
//! header   = op (1) || session_id (8) || packet_id (8)   // packet_id = pid_u32 || net_time_u32
//! tag      = HMAC-SHA256(Ka, header || plaintext)        // 32 bytes
//! IV       = tag[0..16]
//! ciph     = AES-256-CTR(Ke, IV, plaintext)
//! wire     = header || tag || ciph
//! ```
//!
//! Replay protection lives at the [`crate::session`] layer (same packet_id
//! counter / window used by tls-auth).

use anyhow::{Context, Result, bail};

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::static_key::STATIC_KEY_LEN;

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = Ctr128BE<Aes256>;

/// HMAC-SHA256 tag length.
pub const TAG_LEN: usize = 32;
/// 32-bit packet_id || 32-bit net_time, both big-endian.
pub const PACKET_ID_LEN: usize = 8;
/// op (1) + session_id (8) + packet_id (8).
pub const HEADER_LEN: usize = 1 + 8 + PACKET_ID_LEN;

const KEY_LEN: usize = 32;
const SLOT: usize = 64;

/// Server-side tls-crypt keys. Each direction has its own cipher (`Ke`) and
/// HMAC (`Ka`) key, both extracted from the 256-byte static key file.
pub struct TlsCryptKey {
    enc_cipher_key: [u8; KEY_LEN],
    enc_hmac_key: [u8; KEY_LEN],
    dec_cipher_key: [u8; KEY_LEN],
    dec_hmac_key: [u8; KEY_LEN],
}

impl TlsCryptKey {
    /// Build the server-side keys from a parsed 256-byte static key.
    ///
    /// OpenVPN's `struct key2` memory layout (`keys[0].cipher | keys[0].hmac |
    /// keys[1].cipher | keys[1].hmac`) is what's serialised to the static-key
    /// file. tls-crypt for the server runs with `KEY_DIRECTION_NORMAL`, so
    /// outbound traffic uses `keys[0]` and inbound uses `keys[1]`.
    pub fn from_static_key_server(km: &[u8; STATIC_KEY_LEN]) -> Self {
        let mut enc_cipher_key = [0u8; KEY_LEN];
        let mut enc_hmac_key = [0u8; KEY_LEN];
        let mut dec_cipher_key = [0u8; KEY_LEN];
        let mut dec_hmac_key = [0u8; KEY_LEN];
        // keys[0].cipher @ 0..64    → outbound Ke in 0..32
        enc_cipher_key.copy_from_slice(&km[0..KEY_LEN]);
        // keys[0].hmac   @ 64..128  → outbound Ka in 64..96
        enc_hmac_key.copy_from_slice(&km[SLOT..SLOT + KEY_LEN]);
        // keys[1].cipher @ 128..192 → inbound Ke in 128..160
        dec_cipher_key.copy_from_slice(&km[SLOT * 2..SLOT * 2 + KEY_LEN]);
        // keys[1].hmac   @ 192..256 → inbound Ka in 192..224
        dec_hmac_key.copy_from_slice(&km[SLOT * 3..SLOT * 3 + KEY_LEN]);
        Self {
            enc_cipher_key,
            enc_hmac_key,
            dec_cipher_key,
            dec_hmac_key,
        }
    }

    /// Wrap an inner control packet (`op || session_id || body`) with the
    /// tls-crypt envelope. `body` gets encrypted; the header bytes are
    /// authenticated only.
    pub fn wrap(&self, inner: &[u8], packet_id: u32, timestamp: u32) -> Result<Vec<u8>> {
        if inner.len() < 9 {
            bail!(
                "tls-crypt: inner control packet too short ({})",
                inner.len()
            );
        }
        let op = inner[0];
        let session_id = &inner[1..9];
        let body = &inner[9..];

        // Assemble the AAD header on the wire: op || sid || packet_id_full.
        let mut header = [0u8; HEADER_LEN];
        header[0] = op;
        header[1..9].copy_from_slice(session_id);
        header[9..13].copy_from_slice(&packet_id.to_be_bytes());
        header[13..17].copy_from_slice(&timestamp.to_be_bytes());

        // tag = HMAC-SHA256(Ka, header || plaintext).
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.enc_hmac_key)
            .expect("HMAC accepts any key length");
        mac.update(&header);
        mac.update(body);
        let tag = mac.finalize().into_bytes();

        // IV = tag[0..16]; encrypt body in place with AES-256-CTR.
        let mut ciphertext = body.to_vec();
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(&self.enc_cipher_key),
            GenericArray::from_slice(&tag[..16]),
        );
        cipher.apply_keystream(&mut ciphertext);

        let mut out = Vec::with_capacity(HEADER_LEN + TAG_LEN + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt + verify an inbound tls-crypt packet. Returns
    /// `(op || session_id || plaintext, packet_id)` ready to feed into
    /// [`crate::protocol::ControlPacket::parse`].
    pub fn unwrap(&self, pkt: &[u8]) -> Result<(Vec<u8>, u32)> {
        const MIN_LEN: usize = HEADER_LEN + TAG_LEN;
        if pkt.len() < MIN_LEN {
            bail!("tls-crypt: packet too short ({} < {})", pkt.len(), MIN_LEN);
        }
        let header = &pkt[..HEADER_LEN];
        let op = header[0];
        let session_id = &header[1..9];
        let packet_id = u32::from_be_bytes(header[9..13].try_into().unwrap());
        let tag = &pkt[HEADER_LEN..HEADER_LEN + TAG_LEN];
        let ciphertext = &pkt[HEADER_LEN + TAG_LEN..];

        // Decrypt first so the HMAC has plaintext to authenticate against.
        let mut plaintext = ciphertext.to_vec();
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(&self.dec_cipher_key),
            GenericArray::from_slice(&tag[..16]),
        );
        cipher.apply_keystream(&mut plaintext);

        // tag' = HMAC-SHA256(Ka, header || plaintext); constant-time verify.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.dec_hmac_key)
            .expect("HMAC accepts any key length");
        mac.update(header);
        mac.update(&plaintext);
        mac.verify_slice(tag).context("tls-crypt HMAC mismatch")?;

        let mut inner = Vec::with_capacity(9 + plaintext.len());
        inner.push(op);
        inner.extend_from_slice(session_id);
        inner.extend_from_slice(&plaintext);
        Ok((inner, packet_id))
    }
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
        let mut v = vec![0x38u8]; // op = ControlV1 << 3
        v.extend_from_slice(&0x0102030405060708u64.to_be_bytes());
        v.extend_from_slice(b"hello-tls-crypt-control-body");
        v
    }

    /// The server can wrap its own packet and unwrap it back — the
    /// `dec_*` keys are decoupled from `enc_*`, so this only catches
    /// internal-consistency bugs.
    #[test]
    fn self_unwrap_with_swapped_keys() {
        let km = fake_static_key();
        let server = TlsCryptKey::from_static_key_server(&km);
        // For self-test, build a "peer" that mirrors the server (out↔in
        // swapped). That's what a tls-crypt client would do.
        let peer = TlsCryptKey {
            enc_cipher_key: server.dec_cipher_key,
            enc_hmac_key: server.dec_hmac_key,
            dec_cipher_key: server.enc_cipher_key,
            dec_hmac_key: server.enc_hmac_key,
        };
        let inner = sample_inner();
        let wire = server.wrap(&inner, 42, 1_700_000_000).unwrap();
        let (back, pid) = peer.unwrap(&wire).unwrap();
        assert_eq!(back, inner);
        assert_eq!(pid, 42);

        // Round-trip the other direction too.
        let wire = peer.wrap(&inner, 7, 1_234_567_890).unwrap();
        let (back, pid) = server.unwrap(&wire).unwrap();
        assert_eq!(back, inner);
        assert_eq!(pid, 7);
    }

    #[test]
    fn ciphertext_actually_encrypts() {
        let km = fake_static_key();
        let server = TlsCryptKey::from_static_key_server(&km);
        let inner = sample_inner();
        let wire = server.wrap(&inner, 1, 0).unwrap();
        // The body part of the wire should differ from the plaintext body.
        let wire_body = &wire[HEADER_LEN + TAG_LEN..];
        let plain_body = &inner[9..];
        assert_eq!(wire_body.len(), plain_body.len());
        assert_ne!(
            wire_body, plain_body,
            "ciphertext should not equal plaintext"
        );
    }

    #[test]
    fn rejects_tampered_tag() {
        let km = fake_static_key();
        let server = TlsCryptKey::from_static_key_server(&km);
        let peer = TlsCryptKey {
            enc_cipher_key: server.dec_cipher_key,
            enc_hmac_key: server.dec_hmac_key,
            dec_cipher_key: server.enc_cipher_key,
            dec_hmac_key: server.enc_hmac_key,
        };
        let inner = sample_inner();
        let mut wire = server.wrap(&inner, 1, 0).unwrap();
        // Flip a byte inside the tag region.
        wire[HEADER_LEN + 5] ^= 0x01;
        assert!(peer.unwrap(&wire).is_err());
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let km = fake_static_key();
        let server = TlsCryptKey::from_static_key_server(&km);
        let peer = TlsCryptKey {
            enc_cipher_key: server.dec_cipher_key,
            enc_hmac_key: server.dec_hmac_key,
            dec_cipher_key: server.enc_cipher_key,
            dec_hmac_key: server.enc_hmac_key,
        };
        let inner = sample_inner();
        let mut wire = server.wrap(&inner, 1, 0).unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x80;
        assert!(peer.unwrap(&wire).is_err());
    }

    #[test]
    fn rejects_too_short() {
        let km = fake_static_key();
        let key = TlsCryptKey::from_static_key_server(&km);
        let short = vec![0u8; HEADER_LEN + TAG_LEN - 1];
        assert!(key.unwrap(&short).is_err());
    }

    /// End-to-end: wrap a real ControlPacket, unwrap, parse — verifies the
    /// envelope plays nicely with the existing wire codec.
    #[test]
    fn round_trip_through_control_packet() {
        use crate::protocol::{ControlPacket, OpCode};

        let km = fake_static_key();
        let server = TlsCryptKey::from_static_key_server(&km);
        let peer = TlsCryptKey {
            enc_cipher_key: server.dec_cipher_key,
            enc_hmac_key: server.dec_hmac_key,
            dec_cipher_key: server.enc_cipher_key,
            dec_hmac_key: server.enc_hmac_key,
        };

        let original = ControlPacket {
            op: OpCode::ControlV1,
            key_id: 2,
            session_id: 0xDEAD_BEEF_CAFE_F00D,
            acks: vec![10, 11],
            remote_session_id: Some(0x1122_3344_5566_7788),
            packet_id: Some(0x4242),
            payload: b"encrypted-tls-handshake-bytes".to_vec(),
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
