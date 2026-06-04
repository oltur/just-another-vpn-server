//! javs — just-another-vpn-server
//!
//! OpenVPN-compatible VPN server in Rust. See README.md for what is implemented
//! and which protocol features are stubbed.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod config;
mod control_channel;
mod crypto;
mod nat;
mod prf;
mod protocol;
mod replay;
mod server;
mod session;
mod static_key;
mod tls;
mod tls_auth;
mod tls_crypt;
mod transport;
mod tun_dev;

use crate::config::ServerConfig;
use crate::server::VpnServer;

#[derive(Parser, Debug)]
#[command(
    name = "javs",
    version,
    about = "OpenVPN-compatible VPN server (just-another-vpn-server)"
)]
struct Args {
    /// Path to server TOML config.
    #[arg(short, long, default_value = "configs/server.toml")]
    config: PathBuf,

    /// Optional RUST_LOG-style log filter (e.g. "info,javs=debug").
    #[arg(long)]
    log: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if let Some(l) = &args.log {
        EnvFilter::new(l.clone())
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!("javs {} starting", env!("CARGO_PKG_VERSION"));
    info!("loading config from {}", args.config.display());
    let cfg = ServerConfig::load(&args.config)?;

    let server = VpnServer::new(cfg).await?;
    server.run().await
}
