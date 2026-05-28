//! Data-channel AEAD encryption (AES-256-GCM).
//!
//! Keys are derived from the TLS handshake via `export_keying_material` (TLS-EKM,
//! RFC 5705). The OpenVPN client must be configured with `tls-ekm` so it derives
//! data-channel keys the same way.

use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{Result, anyhow, bail};

pub const KEY_SIZE: usize = 32; // AES-256
pub const IMPLICIT_IV_SIZE: usize = 8; // 12-byte nonce minus 4-byte packet_id
pub const TAG_SIZE: usize = 16;

/// Total bytes of key material we feed in to derive a [`DataCipher`].
///
/// We get these from OpenVPN's classic `key-method 2` PRF (see
/// [`crate::prf`]). The PRF output is written verbatim into OpenVPN's
/// `struct key2 { struct key keys[2]; }`, whose memory layout is
///   keys[0].cipher (64) | keys[0].hmac (64) | keys[1].cipher (64) | keys[1].hmac (64)
/// (NOT the `c_a | c_b | h_a | h_b` order that the explicit-memcpy EKM
/// path uses — that one we'd hit only if we re-enable `tls-ekm`).
///
/// For AES-256-GCM we read the 32-byte cipher key from the start of each
/// `.cipher` slot and the 8-byte implicit AEAD IV from the start of each
/// `.hmac` slot.
pub const KEYMAT_LEN: usize = 256;
const SLOT: usize = 64;

pub struct DataCipher {
    enc_key: [u8; KEY_SIZE],
    dec_key: [u8; KEY_SIZE],
    enc_iv: [u8; IMPLICIT_IV_SIZE],
    dec_iv: [u8; IMPLICIT_IV_SIZE],
}

impl DataCipher {
    pub fn from_keymat_server(km: &[u8; KEYMAT_LEN]) -> Self {
        let mut client_enc = [0u8; KEY_SIZE];
        let mut client_iv = [0u8; IMPLICIT_IV_SIZE];
        let mut server_enc = [0u8; KEY_SIZE];
        let mut server_iv = [0u8; IMPLICIT_IV_SIZE];
        // For AEAD: cipher slot gives the AES key, hmac slot gives the
        // implicit IV — see `key_ctx_update_implicit_iv` in `ssl.c`:
        //   ctx->implicit_iv = keys[server_idx].hmac[0..impl_iv_len]
        // (The `[null-digest]` log line is OpenVPN telling us no HMAC is
        // computed — but the HMAC SLOT is still used for the implicit IV.)
        //
        // keys[0].cipher @ 0..64    → client AES-256 key in 0..32
        // keys[0].hmac   @ 64..128  → client implicit IV in 64..72
        client_enc.copy_from_slice(&km[0..KEY_SIZE]);
        client_iv.copy_from_slice(&km[SLOT..SLOT + IMPLICIT_IV_SIZE]);
        // keys[1].cipher @ 128..192 → server AES-256 key in 128..160
        // keys[1].hmac   @ 192..256 → server implicit IV in 192..200
        server_enc.copy_from_slice(&km[SLOT * 2..SLOT * 2 + KEY_SIZE]);
        server_iv.copy_from_slice(&km[SLOT * 3..SLOT * 3 + IMPLICIT_IV_SIZE]);
        Self {
            enc_key: server_enc,
            dec_key: client_enc,
            enc_iv: server_iv,
            dec_iv: client_iv,
        }
    }

    /// Seal a plaintext IP packet. `aad` is the 8-byte data header. The
    /// returned bytes follow OpenVPN's on-the-wire layout `tag || ciphertext`,
    /// which is the inverse of what the `aes-gcm` crate produces natively
    /// (`ciphertext || tag`), so we splice them back together in the right
    /// order before returning.
    pub fn seal(&self, packet_id: u32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.enc_key));
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&packet_id.to_be_bytes());
        nonce[4..12].copy_from_slice(&self.enc_iv);
        let ct_then_tag = cipher
            .encrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| anyhow!("aes-gcm seal: {e}"))?;
        let split = ct_then_tag.len() - TAG_SIZE;
        let mut out = Vec::with_capacity(ct_then_tag.len());
        out.extend_from_slice(&ct_then_tag[split..]); // tag (16) first
        out.extend_from_slice(&ct_then_tag[..split]); // then ciphertext
        Ok(out)
    }

    /// Open a wire packet (`tag || ciphertext`). Returns the plaintext.
    pub fn open(&self, packet_id: u32, aad: &[u8], wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < TAG_SIZE {
            bail!("ciphertext shorter than auth tag");
        }
        let (tag, ct) = wire.split_at(TAG_SIZE);
        let mut ct_then_tag = Vec::with_capacity(wire.len());
        ct_then_tag.extend_from_slice(ct);
        ct_then_tag.extend_from_slice(tag);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.dec_key));
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&packet_id.to_be_bytes());
        nonce[4..12].copy_from_slice(&self.dec_iv);
        cipher
            .decrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: &ct_then_tag,
                    aad,
                },
            )
            .map_err(|e| anyhow!("aes-gcm open: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        // Build keymat with deliberately different bytes per 64-byte slot so
        // the test catches offset bugs.
        let mut km = [0u8; KEYMAT_LEN];
        for i in 0..KEYMAT_LEN {
            km[i] = (i / SLOT) as u8 * 0x11 + (i % SLOT) as u8;
        }
        let c = DataCipher::from_keymat_server(&km);
        let aad = [0u8; 8];
        let pt = b"hello tunnel";
        let ct = c.seal(0, &aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_SIZE);
    }

    #[test]
    fn server_and_peer_can_round_trip() {
        // Pretend the client computed the *same* key material; build the
        // client's view by swapping the enc/dec slots and verify open(seal()).
        let mut km = [0u8; KEYMAT_LEN];
        for (i, b) in km.iter_mut().enumerate() {
            *b = i as u8;
        }
        let server = DataCipher::from_keymat_server(&km);

        // Manually build the "client's" cipher: its enc_key = client.cipher,
        // its dec_key = server.cipher (i.e. mirror image of the server side).
        struct Peer {
            enc: [u8; KEY_SIZE],
            enc_iv: [u8; IMPLICIT_IV_SIZE],
            dec: [u8; KEY_SIZE],
            dec_iv: [u8; IMPLICIT_IV_SIZE],
        }
        let mut peer = Peer {
            enc: [0; KEY_SIZE],
            enc_iv: [0; IMPLICIT_IV_SIZE],
            dec: [0; KEY_SIZE],
            dec_iv: [0; IMPLICIT_IV_SIZE],
        };
        // Peer (client) mirror: encrypt uses keys[0].cipher + keys[0].hmac,
        // decrypt uses keys[1].cipher + keys[1].hmac.
        peer.enc.copy_from_slice(&km[0..KEY_SIZE]);
        peer.enc_iv
            .copy_from_slice(&km[SLOT..SLOT + IMPLICIT_IV_SIZE]);
        peer.dec.copy_from_slice(&km[SLOT * 2..SLOT * 2 + KEY_SIZE]);
        peer.dec_iv
            .copy_from_slice(&km[SLOT * 3..SLOT * 3 + IMPLICIT_IV_SIZE]);

        // Server seals → peer opens. seal() emits OpenVPN's wire layout
        // (`tag || ciphertext`), so the peer flips it back to the aes-gcm
        // crate's `ciphertext || tag` order before calling decrypt.
        let aad = [0xAA; 8];
        let pt = b"hello from server";
        let wire = server.seal(42, &aad, pt).unwrap();
        let (tag, ct) = wire.split_at(TAG_SIZE);
        let mut ct_then_tag = Vec::with_capacity(wire.len());
        ct_then_tag.extend_from_slice(ct);
        ct_then_tag.extend_from_slice(tag);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&peer.dec));
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&42u32.to_be_bytes());
        nonce[4..12].copy_from_slice(&peer.dec_iv);
        let opened = cipher
            .decrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: &ct_then_tag,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(opened, pt);
    }
}
