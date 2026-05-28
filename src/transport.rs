//! Per-session outbound transport abstraction.
//!
//! UDP and TCP differ in how outbound bytes reach a peer:
//!   * UDP: one shared [`UdpSocket`], with `send_to(addr)` per packet — the
//!     kernel demuxes by 5-tuple. Cheap to send from anywhere.
//!   * TCP: one [`TcpStream`] per peer. Only one task may write at a time,
//!     and bytes must be framed (we use a `u16-BE length || payload` prefix
//!     so the receiver can recover packet boundaries inside the byte
//!     stream).
//!
//! [`Transport`] hides those differences behind a single async `send`,
//! letting the rest of the server (tun forwarder, retransmit timer, ping
//! task, rekey, etc.) treat both transports identically.

use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;

/// What protocol carries this session's packets. Cheap to clone — UDP is
/// just `Arc<UdpSocket>` + addr, TCP is the mpsc sender's `Arc` internals.
#[derive(Clone)]
pub enum Transport {
    Udp {
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
    },
    /// `tx` is drained by the per-stream writer task spawned when the TCP
    /// connection was accepted; the writer prepends the u16 length prefix
    /// and writes to the TcpStream.
    Tcp { tx: UnboundedSender<Vec<u8>> },
}

impl Transport {
    pub async fn send(&self, bytes: &[u8]) -> Result<()> {
        match self {
            Transport::Udp { socket, addr } => {
                socket.send_to(bytes, *addr).await.context("udp send_to")?;
            }
            Transport::Tcp { tx } => {
                tx.send(bytes.to_vec())
                    .map_err(|_| anyhow!("tcp writer channel closed"))?;
            }
        }
        Ok(())
    }
}
