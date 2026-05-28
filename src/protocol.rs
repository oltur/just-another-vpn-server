//! OpenVPN wire-format packet parsing and serialization (UDP transport).
//!
//! References:
//!  * https://build.openvpn.net/doxygen/network_protocol.html
//!  * https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-ovpn

use anyhow::{Result, bail};
use bytes::{Buf, BufMut, BytesMut};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    ControlHardResetClientV1 = 1,
    ControlHardResetServerV1 = 2,
    ControlSoftResetV1 = 3,
    ControlV1 = 4,
    AckV1 = 5,
    DataV1 = 6,
    ControlHardResetClientV2 = 7,
    ControlHardResetServerV2 = 8,
    DataV2 = 9,
    ControlHardResetClientV3 = 10,
    ControlWkcV1 = 11,
}

impl OpCode {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::ControlHardResetClientV1,
            2 => Self::ControlHardResetServerV1,
            3 => Self::ControlSoftResetV1,
            4 => Self::ControlV1,
            5 => Self::AckV1,
            6 => Self::DataV1,
            7 => Self::ControlHardResetClientV2,
            8 => Self::ControlHardResetServerV2,
            9 => Self::DataV2,
            10 => Self::ControlHardResetClientV3,
            11 => Self::ControlWkcV1,
            _ => bail!("unknown opcode {v}"),
        })
    }
    pub fn is_control(self) -> bool {
        !matches!(self, Self::DataV1 | Self::DataV2)
    }
    pub fn is_data(self) -> bool {
        matches!(self, Self::DataV1 | Self::DataV2)
    }
}

pub type SessionId = u64;

/// Parsed control-channel packet (no tls-auth / tls-crypt HMAC support yet).
#[derive(Debug, Clone)]
pub struct ControlPacket {
    pub op: OpCode,
    pub key_id: u8,
    pub session_id: SessionId,
    pub acks: Vec<u32>,
    pub remote_session_id: Option<SessionId>,
    /// `None` only for `P_ACK_V1`.
    pub packet_id: Option<u32>,
    pub payload: Vec<u8>,
}

impl ControlPacket {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            bail!("empty packet");
        }
        let mut b = buf;
        let first = b.get_u8();
        let op = OpCode::from_u8(first >> 3)?;
        let key_id = first & 0x07;
        if !op.is_control() {
            bail!("not a control opcode: {op:?}");
        }
        if b.remaining() < 8 {
            bail!("missing session id");
        }
        let session_id = b.get_u64();
        if b.remaining() < 1 {
            bail!("missing ack count");
        }
        let ack_count = b.get_u8();
        if b.remaining() < ack_count as usize * 4 {
            bail!("truncated ack array");
        }
        let mut acks = Vec::with_capacity(ack_count as usize);
        for _ in 0..ack_count {
            acks.push(b.get_u32());
        }
        let remote_session_id = if ack_count > 0 {
            if b.remaining() < 8 {
                bail!("missing remote session id");
            }
            Some(b.get_u64())
        } else {
            None
        };
        let packet_id = if !matches!(op, OpCode::AckV1) {
            if b.remaining() < 4 {
                bail!("missing packet id");
            }
            Some(b.get_u32())
        } else {
            None
        };
        let payload = b.to_vec();
        Ok(Self {
            op,
            key_id,
            session_id,
            acks,
            remote_session_id,
            packet_id,
            payload,
        })
    }

    pub fn encode(&self) -> BytesMut {
        let mut out = BytesMut::with_capacity(32 + self.payload.len());
        let first = ((self.op as u8) << 3) | (self.key_id & 0x07);
        out.put_u8(first);
        out.put_u64(self.session_id);
        out.put_u8(self.acks.len() as u8);
        for a in &self.acks {
            out.put_u32(*a);
        }
        if !self.acks.is_empty() {
            out.put_u64(self.remote_session_id.unwrap_or(0));
        }
        if let Some(pid) = self.packet_id {
            out.put_u32(pid);
        }
        out.extend_from_slice(&self.payload);
        out
    }
}

/// 16-byte payload OpenVPN uses for its data-channel keepalive ("occ-ping").
/// Matches `ping_string[]` in OpenVPN's `ping.h`. Sent through the data
/// cipher just like a normal IP packet; on receipt the decrypted plaintext
/// is recognized by exact match and not forwarded to the TUN device.
pub const PING_PAYLOAD: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

/// P_DATA_V2 header layout: op(1) | peer_id(3) | packet_id(4) | aead-ciphertext.
#[derive(Debug)]
pub struct DataPacketV2<'a> {
    pub key_id: u8,
    pub peer_id: u32, // 24-bit
    pub packet_id: u32,
    pub ciphertext: &'a [u8],
}

impl<'a> DataPacketV2<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 8 {
            bail!("data v2 too short");
        }
        let first = buf[0];
        let op = first >> 3;
        if op != OpCode::DataV2 as u8 {
            bail!("not P_DATA_V2 (op={op})");
        }
        let key_id = first & 0x07;
        let peer_id = (u32::from(buf[1]) << 16) | (u32::from(buf[2]) << 8) | u32::from(buf[3]);
        let packet_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Ok(Self {
            key_id,
            peer_id,
            packet_id,
            ciphertext: &buf[8..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hard_reset() {
        // op=7 (HARD_RESET_CLIENT_V2), key_id=0
        let mut buf = vec![7 << 3];
        buf.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes()); // session id
        buf.push(0); // ack count
        buf.extend_from_slice(&0u32.to_be_bytes()); // packet id 0
        let pkt = ControlPacket::parse(&buf).unwrap();
        assert_eq!(pkt.op, OpCode::ControlHardResetClientV2);
        assert_eq!(pkt.session_id, 0x1122_3344_5566_7788);
        assert_eq!(pkt.packet_id, Some(0));
        assert!(pkt.acks.is_empty());
    }

    #[test]
    fn round_trip_control() {
        let p = ControlPacket {
            op: OpCode::ControlV1,
            key_id: 0,
            session_id: 42,
            acks: vec![1, 2],
            remote_session_id: Some(99),
            packet_id: Some(7),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = p.encode();
        let parsed = ControlPacket::parse(&encoded).unwrap();
        assert_eq!(parsed.session_id, 42);
        assert_eq!(parsed.acks, vec![1, 2]);
        assert_eq!(parsed.remote_session_id, Some(99));
        assert_eq!(parsed.packet_id, Some(7));
        assert_eq!(parsed.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn data_v2_parse() {
        let mut buf = vec![(OpCode::DataV2 as u8) << 3];
        buf.extend_from_slice(&[0x00, 0x12, 0x34]); // peer_id = 0x001234
        buf.extend_from_slice(&7u32.to_be_bytes()); // packet_id = 7
        buf.extend_from_slice(&[1, 2, 3, 4]);
        let d = DataPacketV2::parse(&buf).unwrap();
        assert_eq!(d.peer_id, 0x1234);
        assert_eq!(d.packet_id, 7);
        assert_eq!(d.ciphertext, &[1, 2, 3, 4]);
    }
}
