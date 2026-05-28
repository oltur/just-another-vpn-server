//! Thin wrapper over rustls for the OpenVPN control channel.
//!
//! rustls normally drives I/O through a stream; the OpenVPN control channel
//! framing is more like a packet queue, so we feed and drain bytes manually
//! via `read_tls` / `write_tls`.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

/// Pull the Common Name out of a DER-encoded X.509 certificate's subject.
/// Returns `None` if the cert parses but has no CN attribute, or `Err` if
/// the bytes aren't a valid certificate.
pub fn extract_common_name(cert_der: &[u8]) -> Result<Option<String>> {
    use x509_parser::prelude::*;
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| anyhow::anyhow!("x509 parse: {e}"))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string());
    Ok(cn)
}

pub fn build_server_config(ca: &Path, cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    // Install the default ring crypto provider exactly once.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_chain = load_certs(cert)?;
    let private_key = load_private_key(key)?;
    let mut roots = RootCertStore::empty();
    for c in load_certs(ca)? {
        roots.add(c).context("adding ca to root store")?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("building client cert verifier")?;
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .context("with_single_cert")?;
    Ok(Arc::new(cfg))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut r = std::io::BufReader::new(f);
    let certs = rustls_pemfile::certs(&mut r)
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("parsing certs from {}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut r = std::io::BufReader::new(f);
    let key = rustls_pemfile::private_key(&mut r)
        .with_context(|| format!("reading private key {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", path.display()))?;
    Ok(key)
}

/// Buffer-backed wrapper used by the per-client session.
pub struct TlsSession {
    pub conn: ServerConnection,
    /// Plaintext bytes received from the peer (OpenVPN control messages after
    /// the TLS handshake completes — PUSH_REQUEST etc.).
    pub plaintext_in: Vec<u8>,
}

impl TlsSession {
    pub fn new(cfg: Arc<ServerConfig>) -> Result<Self> {
        let conn = ServerConnection::new(cfg).context("new ServerConnection")?;
        Ok(Self {
            conn,
            plaintext_in: Vec::new(),
        })
    }

    /// Feed inbound TLS bytes (the payload of a `P_CONTROL_V1` packet).
    pub fn feed(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let n = self.conn.read_tls(&mut data).context("read_tls")?;
            if n == 0 {
                break;
            }
            self.conn
                .process_new_packets()
                .context("process_new_packets")?;
        }
        // Drain any plaintext that's available now.
        let mut tmp = [0u8; 4096];
        loop {
            match self.conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => self.plaintext_in.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        Ok(())
    }

    /// Drain pending outbound TLS bytes (handshake records or app data).
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = self.conn.write_tls(&mut buf);
        buf
    }

    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// Send plaintext (OpenVPN control-channel message) over TLS.
    pub fn send_plaintext(&mut self, data: &[u8]) -> Result<()> {
        use std::io::Write;
        self.conn
            .writer()
            .write_all(data)
            .context("tls write_all")?;
        Ok(())
    }
}
