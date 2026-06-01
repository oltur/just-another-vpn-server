//! Optional NAT/full-tunnel plumbing for the host kernel.
//!
//! When enabled, on startup we:
//!   * enable IPv4 forwarding,
//!   * install an `iptables -t nat -A POSTROUTING ... -j MASQUERADE` rule
//!     so client traffic exits via the chosen WAN interface,
//!   * permit the matching FORWARD rules.
//!
//! All of that is undone by the [`NatGuard`] returned from [`enable_masquerade`]:
//! its `Drop` removes the rules and restores the prior `ip_forward` setting.
//! Stuffing it as a field on [`crate::server::VpnServer`] means it fires on a
//! clean `Ctrl-C` (which returns from `run()`). It does *not* fire on a
//! `SIGKILL` — that's an inherent limitation of any host-state cleanup.
//!
//! Linux-only for now. On macOS the equivalent would be `pfctl` rules;
//! that's deferred until someone needs it.

use anyhow::{Result, bail};
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

/// Holds the configuration we need to undo at drop time. On non-Linux
/// targets the struct is unreachable (the constructor bails) but its
/// fields are kept for symmetry, hence the allow(dead_code).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct NatGuard {
    tun_iface: String,
    wan_iface: String,
    cidr: String,
    prior_ip_forward: Option<bool>,
}

#[cfg(target_os = "linux")]
pub fn enable_masquerade(
    tun_iface: &str,
    wan_iface: &str,
    tun_ip: Ipv4Addr,
    tun_netmask: Ipv4Addr,
) -> Result<NatGuard> {
    let cidr = subnet_to_cidr(tun_ip, tun_netmask);
    let prior = read_ip_forward().ok();
    // /proc/sys/net/ipv4/ip_forward is read-only when running inside a
    // container that didn't get `--privileged` (Docker mounts /proc that
    // way for security). If forwarding is already on — typically via the
    // compose `sysctls:` knob — skip the write rather than fail.
    if prior != Some(true) {
        set_ip_forward(true).context("enable net.ipv4.ip_forward")?;
    }

    // Remove any stale rules from a previous run before adding fresh ones.
    // Uses -D (delete) which exits non-zero if the rule doesn't exist — that's
    // fine, so we ignore errors here.
    let _ = iptables_run(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        &cidr,
        "-o",
        wan_iface,
        "-j",
        "MASQUERADE",
    ]);
    let _ = iptables_run(&[
        "-D", "FORWARD", "-i", tun_iface, "-o", wan_iface, "-j", "ACCEPT",
    ]);
    let _ = iptables_run(&[
        "-D",
        "FORWARD",
        "-i",
        wan_iface,
        "-o",
        tun_iface,
        "-m",
        "state",
        "--state",
        "RELATED,ESTABLISHED",
        "-j",
        "ACCEPT",
    ]);

    iptables_run(&[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        &cidr,
        "-o",
        wan_iface,
        "-j",
        "MASQUERADE",
    ])
    .context("install MASQUERADE")?;
    iptables_run(&[
        "-A", "FORWARD", "-i", tun_iface, "-o", wan_iface, "-j", "ACCEPT",
    ])
    .context("install FORWARD tun->wan")?;
    iptables_run(&[
        "-A",
        "FORWARD",
        "-i",
        wan_iface,
        "-o",
        tun_iface,
        "-m",
        "state",
        "--state",
        "RELATED,ESTABLISHED",
        "-j",
        "ACCEPT",
    ])
    .context("install FORWARD wan->tun (established)")?;

    info!(
        "nat: enabled MASQUERADE on {} for {} (tun={}, ip_forward was {:?})",
        wan_iface, cidr, tun_iface, prior
    );
    Ok(NatGuard {
        tun_iface: tun_iface.to_string(),
        wan_iface: wan_iface.to_string(),
        cidr,
        prior_ip_forward: prior,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn enable_masquerade(
    _tun_iface: &str,
    _wan_iface: &str,
    _tun_ip: Ipv4Addr,
    _tun_netmask: Ipv4Addr,
) -> Result<NatGuard> {
    bail!("enable_nat is only implemented on Linux; pfctl support TBD");
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let r1 = iptables_run(&[
                "-D",
                "FORWARD",
                "-i",
                &self.wan_iface,
                "-o",
                &self.tun_iface,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]);
            let r2 = iptables_run(&[
                "-D",
                "FORWARD",
                "-i",
                &self.tun_iface,
                "-o",
                &self.wan_iface,
                "-j",
                "ACCEPT",
            ]);
            let r3 = iptables_run(&[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &self.cidr,
                "-o",
                &self.wan_iface,
                "-j",
                "MASQUERADE",
            ]);
            for (label, r) in [("forward-rev", r1), ("forward-fwd", r2), ("masquerade", r3)] {
                if let Err(e) = r {
                    warn!("nat: cleanup {label}: {e}");
                }
            }
            if let Some(prev) = self.prior_ip_forward {
                // Best-effort: skip silently if /proc is read-only.
                let _ = set_ip_forward(prev);
            }
            info!("nat: rules removed");
        }
    }
}

/// Auto-detect the iface backing the IPv4 default route. Parses
/// `/proc/net/route` directly so we don't depend on `ip` being installed.
#[cfg(target_os = "linux")]
pub fn detect_default_route_iface() -> Result<String> {
    let text = std::fs::read_to_string("/proc/net/route").context("read /proc/net/route")?;
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        if cols[1] == "00000000" {
            return Ok(cols[0].to_string());
        }
    }
    bail!("no default route in /proc/net/route");
}

#[cfg(not(target_os = "linux"))]
pub fn detect_default_route_iface() -> Result<String> {
    bail!("default-route detection only implemented on Linux");
}

#[cfg(target_os = "linux")]
fn iptables_run(args: &[&str]) -> Result<()> {
    let out = Command::new("iptables")
        .args(args)
        .output()
        .with_context(|| format!("running iptables {:?}", args))?;
    if !out.status.success() {
        bail!(
            "iptables {:?} failed (status {:?}): {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_ip_forward() -> Result<bool> {
    let s = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").context("read ip_forward")?;
    Ok(s.trim() == "1")
}

#[cfg(target_os = "linux")]
fn set_ip_forward(on: bool) -> Result<()> {
    std::fs::write(
        "/proc/sys/net/ipv4/ip_forward",
        if on { "1\n" } else { "0\n" },
    )
    .context("write ip_forward")?;
    Ok(())
}

/// `(10.8.0.1, 255.255.255.0)` → `"10.8.0.0/24"`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn subnet_to_cidr(ip: Ipv4Addr, mask: Ipv4Addr) -> String {
    let prefix = u32::from(mask).leading_ones();
    let network = Ipv4Addr::from(u32::from(ip) & u32::from(mask));
    format!("{}/{}", network, prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_basic() {
        assert_eq!(
            subnet_to_cidr(Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::new(255, 255, 255, 0)),
            "10.8.0.0/24"
        );
        assert_eq!(
            subnet_to_cidr(
                Ipv4Addr::new(192, 168, 5, 50),
                Ipv4Addr::new(255, 255, 0, 0)
            ),
            "192.168.0.0/16"
        );
        assert_eq!(
            subnet_to_cidr(
                Ipv4Addr::new(172, 16, 200, 1),
                Ipv4Addr::new(255, 240, 0, 0)
            ),
            "172.16.0.0/12"
        );
    }
}
