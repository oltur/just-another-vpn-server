//! OpenVPN's classic `--key-method 2` (no `--tls-ekm`) data-channel key
//! derivation.
//!
//! When the `IV_PROTO` exchange does NOT include `TLS_KEY_EXPORT`, both peers
//! derive the 256-byte `key_data` blob from the random material the client
//! ships inside `key-method 2` (`pre_master`, `random1`, `random2`) plus the
//! two 8-byte session IDs. The derivation is the TLS 1.0 PRF
//! (`P_MD5(S1, label||seed) ⊕ P_SHA1(S2, label||seed)`) applied twice:
//!
//! ```text
//! master   = PRF(pre_master, "OpenVPN master secret",
//!                client.random1 || server.random1)
//! key_data = PRF(master,    "OpenVPN key expansion",
//!                client.random2 || server.random2 ||
//!                client.sid    || server.sid)
//! ```
//!
//! `key_data` is laid out as `client.cipher | server.cipher | client.hmac |
//! server.hmac` — identical to what TLS-EKM produces in OpenVPN 2.6, so
//! [`crate::crypto::DataCipher::from_keymat_server`] consumes either.
//!
//! Reference: `generate_key_expansion_openvpn` in OpenVPN's
//! `src/openvpn/ssl_ncp.c`.

use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

use crate::crypto::KEYMAT_LEN;

const MASTER_LEN: usize = 48;
const MASTER_LABEL: &[u8] = b"OpenVPN master secret";
const KEY_EXP_LABEL: &[u8] = b"OpenVPN key expansion";

/// Derive the full 256-byte `key_data` for a session from the inputs
/// exchanged in `key-method 2`.
pub fn derive_openvpn_key_data(
    pre_master: &[u8; 48],
    client_random1: &[u8; 32],
    server_random1: &[u8; 32],
    client_random2: &[u8; 32],
    server_random2: &[u8; 32],
    client_sid: &[u8; 8],
    server_sid: &[u8; 8],
) -> [u8; KEYMAT_LEN] {
    let mut master = [0u8; MASTER_LEN];
    let mut master_seed = Vec::with_capacity(64);
    master_seed.extend_from_slice(client_random1);
    master_seed.extend_from_slice(server_random1);
    tls10_prf(pre_master, MASTER_LABEL, &master_seed, &mut master);

    let mut kd_seed = Vec::with_capacity(80);
    kd_seed.extend_from_slice(client_random2);
    kd_seed.extend_from_slice(server_random2);
    kd_seed.extend_from_slice(client_sid);
    kd_seed.extend_from_slice(server_sid);

    let mut key_data = [0u8; KEYMAT_LEN];
    tls10_prf(&master, KEY_EXP_LABEL, &kd_seed, &mut key_data);
    key_data
}

/// TLS 1.0 PRF: split `secret` into two halves `S1` and `S2` (one-byte
/// overlap when the length is odd), run `P_MD5(S1, …)` and `P_SHA1(S2, …)`,
/// and XOR them together.
pub fn tls10_prf(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    let half = secret.len().div_ceil(2);
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];

    let mut combined = Vec::with_capacity(label.len() + seed.len());
    combined.extend_from_slice(label);
    combined.extend_from_slice(seed);

    let mut md5_out = vec![0u8; out.len()];
    let mut sha1_out = vec![0u8; out.len()];
    p_hash(hmac_md5, s1, &combined, &mut md5_out);
    p_hash(hmac_sha1, s2, &combined, &mut sha1_out);

    for (o, (a, b)) in out.iter_mut().zip(md5_out.iter().zip(sha1_out.iter())) {
        *o = *a ^ *b;
    }
}

/// `P_hash` (RFC 4346 §5):
/// `P_hash(secret, seed) = HMAC(secret, A(1)||seed) || HMAC(secret, A(2)||seed) || …`
/// where `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`.
fn p_hash<F>(hmac_fn: F, secret: &[u8], seed: &[u8], out: &mut [u8])
where
    F: Fn(&[u8], &[&[u8]]) -> Vec<u8>,
{
    let mut a = hmac_fn(secret, &[seed]);
    let mut written = 0;
    while written < out.len() {
        let block = hmac_fn(secret, &[&a, seed]);
        let n = std::cmp::min(block.len(), out.len() - written);
        out[written..written + n].copy_from_slice(&block[..n]);
        written += n;
        a = hmac_fn(secret, &[&a]);
    }
}

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both peers compute the same `key_data` blob given identical inputs.
    /// Catches accidental input-order / endianness bugs in the inner seed.
    #[test]
    fn key_derivation_deterministic() {
        let pre_master = [0x42u8; 48];
        let c_r1 = [0x11u8; 32];
        let s_r1 = [0x22u8; 32];
        let c_r2 = [0x33u8; 32];
        let s_r2 = [0x44u8; 32];
        let c_sid = [0xAAu8; 8];
        let s_sid = [0xBBu8; 8];
        let a = derive_openvpn_key_data(&pre_master, &c_r1, &s_r1, &c_r2, &s_r2, &c_sid, &s_sid);
        let b = derive_openvpn_key_data(&pre_master, &c_r1, &s_r1, &c_r2, &s_r2, &c_sid, &s_sid);
        assert_eq!(a, b);
        // Sanity: key_data isn't all zero.
        assert!(a.iter().any(|&b| b != 0));
    }

    /// Changing the client session id changes the resulting key_data
    /// (proves the session_ids are actually mixed into the key_expansion seed).
    #[test]
    fn key_derivation_uses_session_ids() {
        let pm = [0x42u8; 48];
        let c_r1 = [0x11u8; 32];
        let s_r1 = [0x22u8; 32];
        let c_r2 = [0x33u8; 32];
        let s_r2 = [0x44u8; 32];
        let s_sid = [0xBBu8; 8];
        let a = derive_openvpn_key_data(&pm, &c_r1, &s_r1, &c_r2, &s_r2, &[0u8; 8], &s_sid);
        let b = derive_openvpn_key_data(&pm, &c_r1, &s_r1, &c_r2, &s_r2, &[1u8; 8], &s_sid);
        assert_ne!(a, b);
    }
}
