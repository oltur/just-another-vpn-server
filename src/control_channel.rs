//! Plaintext OpenVPN control-channel messages that flow inside the TLS stream.
//!
//! After the TLS handshake completes the client sends a binary "key-method 2"
//! packet. The server replies with its own key-method-2 packet, then both sides
//! exchange null-terminated ASCII messages (`PUSH_REQUEST`, `PUSH_REPLY`, ...).

use anyhow::{Result, bail};

const KEY_METHOD_2: u8 = 2;
const PRE_MASTER_LEN: usize = 48;
const RANDOM_LEN: usize = 32;

/// Result of trying to parse a message out of a still-streaming buffer.
pub enum Pop<T> {
    /// Parsed a value; the caller should drop this many bytes from the front of
    /// the buffer.
    Ready(T, usize),
    /// Not enough bytes yet — try again after more plaintext arrives.
    NeedMore,
}

/// Client → server key-method 2 packet.
///
/// `username`/`password` are parsed off the wire (OpenVPN sends them even
/// when no `auth-user-pass` is configured, just as empty strings) but we
/// don't use them — we don't implement username/password auth, only
/// certificate auth via the TLS layer.
#[derive(Debug, Clone)]
pub struct ClientKeyMethod2 {
    pub pre_master: [u8; PRE_MASTER_LEN],
    pub random1: [u8; RANDOM_LEN],
    pub random2: [u8; RANDOM_LEN],
    pub options: String,
    #[allow(dead_code)]
    pub username: String,
    #[allow(dead_code)]
    pub password: String,
    pub peer_info: String,
}

impl ClientKeyMethod2 {
    pub fn try_parse(buf: &[u8]) -> Result<Pop<Self>> {
        // 4 zero bytes + 1 byte key_method + 48 pre_master + 32 + 32 = 117 fixed
        if buf.len() < 117 {
            return Ok(Pop::NeedMore);
        }
        if buf[0..4] != [0, 0, 0, 0] {
            bail!(
                "key-method 2: expected 4 zero bytes, got {:02x?}",
                &buf[0..4]
            );
        }
        if buf[4] != KEY_METHOD_2 {
            bail!("unsupported key_method {}, only 2 is implemented", buf[4]);
        }
        let mut pre_master = [0u8; PRE_MASTER_LEN];
        pre_master.copy_from_slice(&buf[5..5 + PRE_MASTER_LEN]);
        let mut random1 = [0u8; RANDOM_LEN];
        random1.copy_from_slice(&buf[53..53 + RANDOM_LEN]);
        let mut random2 = [0u8; RANDOM_LEN];
        random2.copy_from_slice(&buf[85..85 + RANDOM_LEN]);

        let mut off = 117;
        let options = match read_lp_string(buf, &mut off)? {
            Some(s) => s,
            None => return Ok(Pop::NeedMore),
        };
        let username = match read_lp_string(buf, &mut off)? {
            Some(s) => s,
            None => return Ok(Pop::NeedMore),
        };
        let password = match read_lp_string(buf, &mut off)? {
            Some(s) => s,
            None => return Ok(Pop::NeedMore),
        };
        let peer_info = match read_lp_string(buf, &mut off)? {
            Some(s) => s,
            None => return Ok(Pop::NeedMore),
        };
        Ok(Pop::Ready(
            Self {
                pre_master,
                random1,
                random2,
                options,
                username,
                password,
                peer_info,
            },
            off,
        ))
    }
}

/// Server → client key-method 2 packet. No `pre_master` field (only the client
/// contributes one).
pub struct ServerKeyMethod2<'a> {
    pub random1: &'a [u8; RANDOM_LEN],
    pub random2: &'a [u8; RANDOM_LEN],
    pub options: &'a str,
    pub username: &'a str, // usually ""
    pub password: &'a str, // usually ""
    pub peer_info: &'a str,
}

impl<'a> ServerKeyMethod2<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(4 + 1 + 32 + 32 + 64 + self.options.len() + self.peer_info.len());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.push(KEY_METHOD_2);
        out.extend_from_slice(self.random1);
        out.extend_from_slice(self.random2);
        write_lp_string(&mut out, self.options);
        write_lp_string(&mut out, self.username);
        write_lp_string(&mut out, self.password);
        write_lp_string(&mut out, self.peer_info);
        out
    }
}

/// Pop a single null-terminated ASCII message (e.g. `PUSH_REQUEST`) from the
/// front of `buf`.
pub fn try_pop_ascii(buf: &[u8]) -> Pop<String> {
    if let Some(idx) = buf.iter().position(|&b| b == 0) {
        let text = String::from_utf8_lossy(&buf[..idx]).into_owned();
        Pop::Ready(text, idx + 1)
    } else {
        Pop::NeedMore
    }
}

/// Length-prefixed string (u16 BE length, includes the trailing NUL).
fn read_lp_string(buf: &[u8], off: &mut usize) -> Result<Option<String>> {
    if buf.len() < *off + 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buf[*off], buf[*off + 1]]) as usize;
    if buf.len() < *off + 2 + len {
        return Ok(None);
    }
    let start = *off + 2;
    let end = start + len;
    *off = end;
    if len == 0 {
        return Ok(Some(String::new()));
    }
    // strings include the trailing NUL byte in the length
    let bytes = &buf[start..end];
    let text = if bytes.last() == Some(&0) {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    Ok(Some(String::from_utf8_lossy(text).into_owned()))
}

fn write_lp_string(out: &mut Vec<u8>, s: &str) {
    // OpenVPN's buf_write_string writes (strlen + 1) bytes including the NUL.
    let len = s.len() + 1;
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// Build the canonical options string this server announces. The client checks
/// the safe-to-compare fields against its own; NCP (negotiable crypto) handles
/// cipher negotiation regardless of what we put here.
pub fn build_options_string(link_mtu: u16, tun_mtu: u16) -> String {
    format!(
        "V4,dev-type tun,link-mtu {},tun-mtu {},proto UDPv4,cipher AES-256-GCM,auth SHA256,keysize 256,key-method 2,tls-server",
        link_mtu, tun_mtu
    )
}

bitflags::bitflags! {
    pub struct IvProto: u32 {
        const REQUEST_PUSH    = 1 << 2;
        const TLS_KEY_EXPORT  = 1 << 3; // signals tls-ekm support
        const AUTH_PENDING_KW = 1 << 4;
        const NCP_P2P         = 1 << 5;
        const DNS_OPTION      = 1 << 6;
        const CC_EXIT_NOTIFY  = 1 << 7;
    }
}

/// Build a minimal peer_info string the server advertises. Lines are LF-separated.
///
/// `TLS_KEY_EXPORT` is intentionally NOT set: rustls and OpenSSL produce
/// different bytes from `export_keying_material`, so we run the classic
/// `key-method 2` PRF path (see [`crate::prf`]) instead and the client falls
/// back to that automatically when this bit is absent.
pub fn build_peer_info() -> String {
    let proto = IvProto::REQUEST_PUSH | IvProto::CC_EXIT_NOTIFY;
    format!(
        "IV_VER=javs-0.1.0\nIV_PLAT=server\nIV_PROTO={}\nIV_CIPHERS=AES-256-GCM\n",
        proto.bits()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lp_string_round_trip() {
        let mut buf = Vec::new();
        write_lp_string(&mut buf, "hello");
        // u16=6, 'h','e','l','l','o',0
        assert_eq!(buf, vec![0, 6, b'h', b'e', b'l', b'l', b'o', 0]);
        let mut off = 0;
        let s = read_lp_string(&buf, &mut off).unwrap().unwrap();
        assert_eq!(s, "hello");
        assert_eq!(off, 8);
    }

    #[test]
    fn pop_ascii_split() {
        let buf = b"PUSH_REQUEST\0PUSH_REQUEST\0";
        match try_pop_ascii(buf) {
            Pop::Ready(s, n) => {
                assert_eq!(s, "PUSH_REQUEST");
                assert_eq!(n, 13);
            }
            Pop::NeedMore => panic!("expected Ready"),
        }
    }

    #[test]
    fn pop_ascii_needs_more() {
        let buf = b"PUSH_REQ"; // no NUL yet
        assert!(matches!(try_pop_ascii(buf), Pop::NeedMore));
    }

    #[test]
    fn client_key_method_2_round_trip_basic() {
        // Build a representative client packet and parse it back.
        let mut buf = vec![0u8; 4];
        buf.push(KEY_METHOD_2);
        buf.extend_from_slice(&[0xAB; PRE_MASTER_LEN]);
        buf.extend_from_slice(&[0xCD; RANDOM_LEN]);
        buf.extend_from_slice(&[0xEF; RANDOM_LEN]);
        write_lp_string(&mut buf, "V4,proto UDPv4,key-method 2,tls-client");
        write_lp_string(&mut buf, "");
        write_lp_string(&mut buf, "");
        write_lp_string(&mut buf, "IV_VER=2.6.0\nIV_PROTO=998");

        match ClientKeyMethod2::try_parse(&buf).unwrap() {
            Pop::Ready(km, n) => {
                assert_eq!(n, buf.len());
                assert_eq!(km.pre_master, [0xAB; PRE_MASTER_LEN]);
                assert_eq!(km.random1, [0xCD; RANDOM_LEN]);
                assert_eq!(km.random2, [0xEF; RANDOM_LEN]);
                assert!(km.options.contains("tls-client"));
                assert!(km.peer_info.contains("IV_PROTO"));
            }
            Pop::NeedMore => panic!("expected Ready"),
        }
    }

    #[test]
    fn client_key_method_2_partial_returns_need_more() {
        let buf = vec![0u8; 50]; // too short
        assert!(matches!(
            ClientKeyMethod2::try_parse(&buf).unwrap(),
            Pop::NeedMore
        ));
    }
}
