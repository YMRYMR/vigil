//! Cross-platform firewall backend abstraction.
//!
//! Phase 19: Native OS Firewall Engine. Replaces the `netsh advfirewall` /
//! inline iptables calls in `active_response_platform.rs` with a unified
//! `FirewallBackend` trait backed by WFP (Windows) or nftables/iptables (Linux).

use std::net::IpAddr;

pub mod state;

/// A single firewall rule managed by Vigil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub id: String,
    pub rule_name: String,
    pub direction: Direction,
    pub action: Action,
    pub filter: Filter,
    pub created_at_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub profile: Profile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Block,
    Allow,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    RemoteIp(IpAddr),
    Program { pid: u32, path: String },
    All,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Domain,
    Private,
    Public,
    Any,
}

/// A snapshot of the current firewall profile state (used for isolation restore).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallProfileState {
    pub name: String,
    pub enabled: bool,
    pub inbound_action: String,
    pub outbound_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallSnapshot {
    pub profiles: Vec<FirewallProfileState>,
}

/// The core firewall engine trait.
///
/// Each platform implements this trait using its native API:
/// - **Windows**: `WfpBackend` - direct WFP user-mode API (`fwpmu.dll`)
/// - **Linux**: `NftablesBackend` - nftables via `nft` CLI (with iptables fallback)
#[allow(dead_code)]
pub trait FirewallBackend: Send + Sync {
    /// Unique label for this backend (e.g. "WFP", "nftables", "iptables").
    fn label(&self) -> &'static str;

    /// Whether this backend is available on the current system.
    fn is_available(&self) -> bool;

    /// Snapshot current firewall profiles for later restore.
    fn snapshot_profiles(&self) -> Result<FirewallSnapshot, String>;

    /// Apply full firewall isolation (block all in/out).
    fn apply_isolation(&self, rule_name: &str) -> Result<(), String>;

    /// Restore firewall profiles from a snapshot.
    fn restore_profiles(&self, snapshot: &FirewallSnapshot) -> Result<(), String>;

    /// Add a rule blocking a remote IP.
    fn add_block_rule(&self, rule_name: &str, target: &str) -> Result<(), String>;

    /// Add a rule blocking a program (by PID for WFP, by UID for nftables).
    fn add_block_program_rule(
        &self,
        rule_name: &str,
        pid: u32,
        path: &str,
        direction: &str,
    ) -> Result<(), String>;

    /// Remove a rule by name.
    fn delete_rule(&self, rule_name: &str) -> Result<(), String>;

    /// Check if a specific rule exists and is enabled.
    fn rule_present(&self, rule_name: &str) -> Result<bool, String>;

    /// Check whether isolation controls (rules that block all traffic) are still active.
    fn isolation_controls_active(
        &self,
        firewall_snapshot: Option<&FirewallSnapshot>,
    ) -> Result<bool, String>;

    /// Whether the platform supports outbound blocking (as opposed to inbound-only).
    /// Returns None if the capability cannot be determined.
    fn outbound_block_supported(&self) -> Option<bool> {
        Some(true)
    }

    /// Kill a live TCP connection by address/port.
    fn kill_tcp_connection(&self, local: &str, remote: &str) -> Result<(), String>;

    /// Terminate all active TCP connections.
    fn terminate_active_connections(&self) -> Result<usize, String>;

    /// Add a domain block via hosts file.
    fn add_domain_block(&self, domain: &str, marker: &str) -> Result<(), String>;

    /// Remove a domain block from hosts file.
    fn remove_domain_block(&self, domain: &str, marker: &str) -> Result<(), String>;

    /// Flush DNS cache.
    fn flush_dns(&self) -> Result<(), String>;

    /// Save current firewall rules to a boot-persistent config.
    /// Default: no-op. Implemented by nftables backend.
    fn save_boot_config(&self) {}

    /// Load persisted firewall rules from boot config.
    /// Default: no-op. Implemented by nftables backend.
    fn load_boot_config(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(windows)]
mod wfp;
#[cfg(windows)]
pub use wfp::WfpBackend;

#[cfg(target_os = "linux")]
mod nftables;
#[cfg(target_os = "linux")]
mod xdp;
#[cfg(target_os = "linux")]
pub use nftables::NftablesBackend;
#[cfg(target_os = "linux")]
pub use xdp::XdpBackend;

/// Global firewall backend instance, lazily created on first access.
pub fn get_backend() -> &'static dyn FirewallBackend {
    use std::sync::OnceLock;
    static BACKEND: OnceLock<Box<dyn FirewallBackend + Send + Sync>> = OnceLock::new();
    BACKEND
        .get_or_init(|| {
            #[cfg(windows)]
            {
                Box::new(WfpBackend::new())
            }
            #[cfg(target_os = "linux")]
            {
                let xdp = Box::new(XdpBackend::new());
                if xdp.is_available() {
                    return xdp;
                }
                Box::new(NftablesBackend::new())
            }
            #[cfg(not(any(windows, target_os = "linux")))]
            {
                compile_error!("Unsupported platform");
            }
        })
        .as_ref()
}

/// Remove all Vigil-owned firewall rules during uninstall.
/// Called from --uninstall-service and the GUI uninstall flow.
/// Best-effort: logs failures but does not block the uninstall.
pub fn cleanup_on_uninstall() {
    let b = get_backend();
    if !b.is_available() {
        return;
    }
    let status = crate::security::active_response::status();
    tracing::info!(
        blocked_ips = status.blocked_rules,
        blocked_processes = status.blocked_processes,
        blocked_domains = status.blocked_domains,
        isolated = status.isolated,
        "cleanup_on_uninstall: starting firewall rule removal"
    );

    // Delete known isolation rules
    let _ = b.delete_rule("Vigil Isolate In");
    let _ = b.delete_rule("Vigil Isolate Out");

    // Restore OS firewall profiles to defaults
    match b.snapshot_profiles() {
        Ok(snapshot) => {
            let defaults: Vec<_> = snapshot
                .profiles
                .iter()
                .map(|p| FirewallProfileState {
                    name: p.name.clone(),
                    enabled: p.enabled,
                    inbound_action: "Allow".into(),
                    outbound_action: "Allow".into(),
                })
                .collect();
            if let Err(e) = b.restore_profiles(&FirewallSnapshot { profiles: defaults }) {
                tracing::warn!("uninstall profile restore: {e}");
            }
        }
        Err(e) => tracing::warn!("uninstall profile snapshot: {e}"),
    }

    // Clean up any remaining state from active_response
    let status = crate::security::active_response::status();
    tracing::info!(
        "uninstall: {} blocked IPs, {} blocked processes, {} blocked domains remaining after rule cleanup",
        status.blocked_rules, status.blocked_processes, status.blocked_domains
    );
}

/// CLI firewall subcommand dispatcher. Returns an exit code (0 = success).
pub fn run_cli(args: &[String]) -> i32 {
    let backend = get_backend();
    match args.first().map(|s| s.as_str()) {
        Some("status") | None => {
            println!("Firewall backend: {}", backend.label());
            println!("Available: {}", backend.is_available());
            match backend.snapshot_profiles() {
                Ok(snapshot) => {
                    println!("Profiles:");
                    for profile in &snapshot.profiles {
                        println!(
                            "  {}: enabled={}, inbound={}, outbound={}",
                            profile.name,
                            profile.enabled,
                            profile.inbound_action,
                            profile.outbound_action
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Profile snapshot failed: {e}");
                    return 1;
                }
            }
            match backend.isolation_controls_active(None) {
                Ok(active) => println!("Isolation active: {active}"),
                Err(e) => eprintln!("Isolation check failed: {e}"),
            }
            let status = crate::security::active_response::status();
            println!("Performance:");
            println!(
                "  Active rules: {} ({} IP + {} process)",
                status.blocked_rules,
                status
                    .blocked_rules
                    .saturating_sub(status.blocked_processes),
                status.blocked_processes
            );
            println!("  Blocked domains: {}", status.blocked_domains);
            println!("  Suspended processes: {}", status.suspended_processes);
            println!("  Autoruns frozen: {}", status.frozen_autoruns);
            0
        }
        Some("panic") => {
            println!("Firewall panic: dropping all Vigil firewall rules...");
            let mut had_error = false;
            // Full emergency restore via active_response if possible
            match crate::security::active_response::restore_machine() {
                Ok(msg) => println!("{msg}"),
                Err(e) => {
                    eprintln!("active_response restore_machine failed: {e}");
                    eprintln!("Falling back to brute-force cleanup...");
                    // Brute-force: delete all known Vigil rule names
                    for name in &["Vigil Isolate In", "Vigil Isolate Out"] {
                        if let Err(e) = backend.delete_rule(name) {
                            eprintln!("  Warning: could not delete rule '{name}': {e}");
                        }
                    }
                    // Restore profiles to default-allow
                    match backend.snapshot_profiles() {
                        Ok(snapshot) => {
                            let defaulted: Vec<_> = snapshot
                                .profiles
                                .iter()
                                .map(|p| FirewallProfileState {
                                    name: p.name.clone(),
                                    enabled: true,
                                    inbound_action: "Allow".into(),
                                    outbound_action: "Allow".into(),
                                })
                                .collect();
                            if let Err(e) = backend.restore_profiles(&FirewallSnapshot {
                                profiles: defaulted,
                            }) {
                                eprintln!("  Warning: could not restore profiles: {e}");
                            }
                        }
                        Err(e) => eprintln!("  Warning: could not snapshot profiles: {e}"),
                    }
                    had_error = true;
                }
            }
            if had_error {
                eprintln!("Panic completed with warnings - network may not be fully restored.");
                1
            } else {
                println!("Panic complete. Network restored to OS defaults.");
                0
            }
        }
        Some("list") => {
            let status = crate::security::active_response::status();
            println!("Firewall rules (managed by active_response state):");
            println!(
                "  Active rules: {} ({} IP + {} process)",
                status.blocked_rules,
                status
                    .blocked_rules
                    .saturating_sub(status.blocked_processes),
                status.blocked_processes
            );
            println!("  Blocked domains: {}", status.blocked_domains);
            println!("  Suspended processes: {}", status.suspended_processes);
            println!("  Isolated: {}", status.isolated);
            0
        }
        Some("export") => {
            let rules = crate::security::active_response::list_rules();
            match serde_json::to_string_pretty(&rules) {
                Ok(json) => {
                    println!("{json}");
                    0
                }
                Err(e) => {
                    eprintln!("Failed to serialize firewall rules: {e}");
                    1
                }
            }
        }
        Some("help") => {
            println!("Vigil firewall commands:");
            println!("  status    Show backend, profiles, isolation state");
            println!("  list      Show active rules summary (IPs, processes, domains)");
            println!("  export    Dump full firewall state as JSON");
            println!("  panic     Emergency restore — drop all Vigil rules");
            println!();
            println!("Firewall rules are managed through the GUI Inspector tab");
            println!("or the auto-response engine (block_remote, block_process,");
            println!("isolate_machine, etc.). Use --uninstall-firewall to");
            println!("clean up all rules before removing Vigil.");
            0
        }
        Some(other) => {
            eprintln!("Unknown firewall subcommand: {other}");
            eprintln!("Usage: vigil --firewall <status|list|export|panic|help>");
            1
        }
    }
}
