//! Linux route bypass: fwmark policy routing.
//!
//! On Linux, `SO_BINDTODEVICE` / `SO_BINDTOIFINDEX` is sufficient for
//! per-socket bypass.  However, for defense-in-depth this module also
//! installs policy routing rules so that packets marked with
//! [`BYPASS_FWMARK`] use the main routing table directly, bypassing any
//! full-tunnel routing table that directs traffic into the TUN.
//!
//! The scheme mirrors clash-rs and WireGuard's `wg-quick`:
//!
//! 1. `ip rule add not fwmark <MARK> table <TABLE>` — unmarked traffic goes to
//!    the TUN table.
//! 2. `ip rule add table main suppress_prefixlength 0` — local/LAN routes in
//!    the main table take precedence.
//! 3. `ip route add default dev <tun> table <TABLE>` — is handled by the
//!    existing `route::apply` in the tunnel crate, NOT here.
//!
//! The dialer already calls `SO_BINDTOIFINDEX` so adding fwmark is
//! technically redundant, but it ensures kernel-level bypass even if a
//! future code path forgets the socket option.

use std::process::Stdio;

use snafu::prelude::*;

use crate::OutboundInterface;

/// The fwmark value used to tag bypass-traffic sockets.
///
/// Any non-zero value that doesn't collide with other marks on the system.
/// The same value used by clash-rs (0x162E = 5678 decimal).
pub const BYPASS_FWMARK: u32 = 0x162E;

/// The routing table ID for TUN-directed traffic.
///
/// Packets without the bypass fwmark are routed through this table,
/// which contains a default route via the TUN device.
pub const BYPASS_TABLE: u32 = 0x162E;

/// Priority for the fwmark-based policy rule.
const RULE_PRIORITY_FWMARK: u32 = 9000;

/// Priority for the main-table suppress rule.
const RULE_PRIORITY_MAIN_SUPPRESS: u32 = 9001;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to add policy routing rule: {detail}"))]
    AddRule { detail: String },

    #[snafu(display("failed to run `ip` command: {source}"))]
    IpCommand { source: std::io::Error },
}

// ---------------------------------------------------------------------------
// RouteBypass
// ---------------------------------------------------------------------------

pub struct RouteBypass {
    /// Whether rules were actually installed (only in full-tunnel mode).
    installed: bool,
}

#[async_trait::async_trait]
impl super::RouteBypassT for RouteBypass {
    type Error = Error;

    async fn setup(interface: &OutboundInterface, full_tunnel: bool) -> Result<Self, Error> {
        if !full_tunnel {
            return Ok(Self { installed: false });
        }

        // Install ip rules for fwmark-based bypass.
        // Rule 1: packets WITHOUT the fwmark go to the TUN table.
        ip_rule_add(&[
            "add",
            "not",
            "fwmark",
            &format!("{BYPASS_FWMARK:#x}"),
            "table",
            &BYPASS_TABLE.to_string(),
            "priority",
            &RULE_PRIORITY_FWMARK.to_string(),
        ])
        .await?;

        // Rule 2: main table with suppress_prefixlength 0 so LAN routes
        // in the main table take precedence over the TUN default.
        ip_rule_add(&[
            "add",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
            "priority",
            &RULE_PRIORITY_MAIN_SUPPRESS.to_string(),
        ])
        .await?;

        tracing::info!(
            interface = %interface.name,
            fwmark = BYPASS_FWMARK,
            table = BYPASS_TABLE,
            "route bypass installed (Linux fwmark policy routing)"
        );

        Ok(Self { installed: true })
    }

    async fn teardown(self) -> Result<(), Error> {
        if !self.installed {
            return Ok(());
        }

        // Remove rules (best-effort; ignore errors if already gone).
        ip_rule_del(&[
            "del",
            "not",
            "fwmark",
            &format!("{BYPASS_FWMARK:#x}"),
            "table",
            &BYPASS_TABLE.to_string(),
            "priority",
            &RULE_PRIORITY_FWMARK.to_string(),
        ])
        .await;

        ip_rule_del(&[
            "del",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
            "priority",
            &RULE_PRIORITY_MAIN_SUPPRESS.to_string(),
        ])
        .await;

        tracing::info!("route bypass removed (Linux fwmark policy routing)");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

async fn ip_rule_add(args: &[&str]) -> Result<(), Error> {
    use tokio::process::Command;

    tracing::debug!(cmd = %format!("ip rule {}", args.join(" ")), "adding policy rule");

    let output = Command::new("ip")
        .arg("rule")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .context(IpCommandSnafu)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        // "File exists" / "RTNETLINK answers: File exists" is harmless.
        if !stderr.contains("File exists") {
            return AddRuleSnafu {
                detail: stderr.trim().to_string(),
            }
            .fail();
        }
        tracing::debug!("policy rule already exists");
    }

    Ok(())
}

async fn ip_rule_del(args: &[&str]) {
    use tokio::process::Command;

    tracing::debug!(cmd = %format!("ip rule {}", args.join(" ")), "removing policy rule");

    match Command::new("ip")
        .arg("rule")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
    {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::debug!(%stderr, "policy rule removal note");
        }
        Err(e) => {
            tracing::warn!(%e, "failed to run ip rule del command");
        }
        _ => {}
    }
}
