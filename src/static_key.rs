//! Parse OpenVPN `--secret` static-key files.
//!
//! The format produced by `openvpn --genkey --secret ta.key` looks like
//! a PEM block surrounding 256 bytes of key material printed as 16 lines
//! of 32 hex characters each:
//!
//! ```text
//! -----BEGIN OpenVPN Static key V1-----
//! 0123456789abcdef...   (16 lines)
//! -----END OpenVPN Static key V1-----
//! ```

use anyhow::{Context, Result, bail};
use std::path::Path;

/// Number of bytes in an OpenVPN static key.
pub const STATIC_KEY_LEN: usize = 256;

/// Parse a static-key file from disk.
pub fn parse_static_key_file(path: &Path) -> Result<[u8; STATIC_KEY_LEN]> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_static_key_text(&text)
}

/// Parse a static-key block from text. Tolerates leading/trailing whitespace,
/// `#` comments and stray blank lines.
pub fn parse_static_key_text(text: &str) -> Result<[u8; STATIC_KEY_LEN]> {
    let mut hex_buf = String::with_capacity(STATIC_KEY_LEN * 2);
    let mut inside = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("-----BEGIN") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END") {
            inside = false;
            continue;
        }
        if inside && !line.is_empty() && !line.starts_with('#') {
            hex_buf.push_str(line);
        }
    }
    if hex_buf.len() != STATIC_KEY_LEN * 2 {
        bail!(
            "OpenVPN static key: expected {} hex chars, got {}",
            STATIC_KEY_LEN * 2,
            hex_buf.len()
        );
    }
    let bytes = hex::decode(&hex_buf).context("decoding key hex")?;
    let mut out = [0u8; STATIC_KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pem(bytes: &[u8; STATIC_KEY_LEN]) -> String {
        let mut s = String::from("-----BEGIN OpenVPN Static key V1-----\n");
        for chunk in bytes.chunks(16) {
            for b in chunk {
                s.push_str(&format!("{:02x}", b));
            }
            s.push('\n');
        }
        s.push_str("-----END OpenVPN Static key V1-----\n");
        s
    }

    #[test]
    fn round_trip_known_bytes() {
        let mut km = [0u8; STATIC_KEY_LEN];
        for (i, b) in km.iter_mut().enumerate() {
            *b = i as u8;
        }
        let pem = build_pem(&km);
        let parsed = parse_static_key_text(&pem).unwrap();
        assert_eq!(parsed, km);
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let mut km = [0u8; STATIC_KEY_LEN];
        for (i, b) in km.iter_mut().enumerate() {
            *b = (255 - i) as u8;
        }
        let mut pem = String::from("-----BEGIN OpenVPN Static key V1-----\n");
        pem.push_str("# this is a comment\n");
        pem.push('\n');
        for chunk in km.chunks(16) {
            for b in chunk {
                pem.push_str(&format!("{:02X}", b)); // upper hex
            }
            pem.push('\n');
        }
        pem.push_str("-----END OpenVPN Static key V1-----\n");
        let parsed = parse_static_key_text(&pem).unwrap();
        assert_eq!(parsed, km);
    }

    #[test]
    fn rejects_wrong_length() {
        let pem =
            "-----BEGIN OpenVPN Static key V1-----\n00112233\n-----END OpenVPN Static key V1-----";
        assert!(parse_static_key_text(pem).is_err());
    }
}
