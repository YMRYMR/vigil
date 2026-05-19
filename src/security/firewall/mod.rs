//! Cross-platform firewall backend abstraction.
//!
//! Phase 19: Native OS Firewall Engine. Replaces the `netsh advfirewall` /
//! inline iptables calls in `active_response_platform.rs` with a unified
//! `FirewallBackend` trait backed by WFP (Windows) or nftables/iptables (Linux).

use std::net::IpAddr;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    RemoteIp(IpAddr),
    Program { pid: u32, path: String },
    All,
}

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
/// - **Windows**: `WfpBackend` — direct WFP user-mode API (`fwpmu.dll`)
/// - **Linux**: `NftablesBackend` — nftables via `nft` CLI (with iptables fallback pub trait FirewallBackend {
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
}

#[cfg(windows)]
mod wfp;
#[cfg(windows)]
pub use wfp::WfpBackend;

#[cfg(target_os = "linux")]
mod nftables;
#[cfg(target_os = "linux")]
pub use nftables::NftablesBackend;
