//! Thin wrapper around the `tun` crate so the rest of the code doesn't need to
//! care about platform differences.

use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv6Addr};
use tun::AsyncDevice;

pub async fn create(name: &str, ip: IpAddr, netmask: IpAddr, mtu: u16) -> Result<AsyncDevice> {
    let mut config = tun::Configuration::default();
    config
        .tun_name(name)
        .address(ip)
        .netmask(netmask)
        .mtu(mtu)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|p| {
        p.packet_information(false);
    });

    let dev = tun::create_as_async(&config).context("create tun")?;
    Ok(dev)
}

/// Add an IPv6 address to an existing TUN interface. The `tun` crate's
/// `Configuration::address` is IPv4-only, so we shell out to `ip -6 addr
/// add` on Linux. (Other platforms aren't supported yet — bails on macOS.)
#[cfg(target_os = "linux")]
pub fn add_ipv6(iface: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
    use std::process::Command;
    let cidr = format!("{}/{}", addr, prefix);
    let out = Command::new("ip")
        .args(["-6", "addr", "add", &cidr, "dev", iface])
        .output()
        .context("running ip -6 addr add")?;
    if !out.status.success() {
        bail!(
            "ip -6 addr add {cidr} dev {iface} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn add_ipv6(_iface: &str, _addr: Ipv6Addr, _prefix: u8) -> Result<()> {
    bail!("IPv6 in tunnel only implemented on Linux");
}
