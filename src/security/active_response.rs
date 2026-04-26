//! Active response: reversible, auditable intervention actions.
//!
//! Phase 11 starts with practical controls for blocking traffic, killing a
//! live socket, suspending a suspicious process, blocking a suspicious domain,
//! and isolating the machine. The module persists a tiny state file so rules
//! can be reconciled and the UI can reflect the current status after restarts.

use crate::{audit, quarantine, types::ConnInfo};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STATE_FILE: &str = "vigil-active-response.json";
const BLOCK_RULE_PREFIX: &str = "Vigil Block";
const PROCESS_BLOCK_RULE_PREFIX: &str = "Vigil Proc Block";
const DOMAIN_MARKER_PREFIX: &str = "# Vigil Domain Block";
const ISOLATE_RULE_IN: &str = "Vigil Isolate In";
const ISOLATE_RULE_OUT: &str = "Vigil Isolate Out";
const ISOLATION_MAX_SECS: u64 = 60 * 60;
const ISOLATION_ACTIVATION_GRACE_SECS: u64 = 20;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Status {
    pub blocked_rules: usize,
    pub blocked_processes: usize,
    pub blocked_domains: usize,
    pub suspended_processes: usize,
    pub frozen_autoruns: bool,
    pub isolated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct State {
    blocked: Vec<BlockedTarget>,
    #[serde(default)]
    blocked_processes: Vec<BlockedProcess>,
    #[serde(default)]
    blocked_domains: Vec<BlockedDomain>,
    #[serde(default)]
    suspended_processes: Vec<SuspendedProcess>,
    #[serde(default)]
    autorun_snapshot: Option<AutorunSnapshot>,
    #[serde(default)]
    firewall_snapshot: Option<FirewallSnapshot>,
    #[serde(default)]
    network_snapshot: Option<NetworkSnapshot>,
    #[serde(default)]
    isolation_started_unix: Option<u64>,
    #[serde(default)]
    isolation_expires_unix: Option<u64>,
    isolated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockedTarget {
    target: String,
    rule_name: String,
    expires_at_unix: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockedProcess {
    #[serde(default)]
    pid: u32,
    path: String,
    inbound_rule_name: String,
    outbound_rule_name: String,
    expires_at_unix: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockedDomain {
    domain: String,
    marker: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SuspendedProcess {
    pid: u32,
    path: String,
    proc_name: String,
    suspended_at_unix: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutorunSnapshot {
    captured_at_unix: u64,
    entries: Vec<AutorunEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AutorunEntry {
    hive: String,
    key_path: String,
    value_name: String,
    value_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FirewallProfileState {
    name: String,
    enabled: bool,
    inbound_action: String,
    outbound_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FirewallSnapshot {
    profiles: Vec<FirewallProfileState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NetworkAdapterState {
    name: String,
    #[serde(default)]
    is_wireless: bool,
    #[serde(default)]
    wifi_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NetworkSnapshot {
    adapters: Vec<NetworkAdapterState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(dead_code)]
struct TcpSessionState {
    local_address: String,
    local_port: u16,
    remote_address: String,
    remote_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketKillError {
    UnsupportedStatus(String),
    InvalidLocalAddr(String),
    InvalidRemoteAddr(String),
    UnsupportedAddressFamily,
    PlatformUnsupported,
    PermissionDenied,
    OsError(String),
}
impl std::fmt::Display for SocketKillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedStatus(status) => write!(f, "cannot kill a socket in {status} state"),
            Self::InvalidLocalAddr(addr) => write!(f, "invalid local address: {addr}"),
            Self::InvalidRemoteAddr(addr) => write!(f, "invalid remote address: {addr}"),
            Self::UnsupportedAddressFamily => write!(
                f,
                "live socket kill currently supports IPv4 TCP only on Windows"
            ),
            Self::PlatformUnsupported => {
                write!(f, "socket kill is currently only implemented on Windows")
            }
            Self::PermissionDenied => write!(
                f,
                "administrator privileges are required to kill a TCP connection"
            ),
            Self::OsError(msg) => write!(f, "OS error: {msg}"),
        }
    }
}
impl std::error::Error for SocketKillError {}
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketKillTarget {
    local: SocketAddr,
    remote: SocketAddr,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationPreset {
    OneHour,
    OneDay,
    Permanent,
}
impl DurationPreset {
    fn ttl(self) -> Option<Duration> {
        match self {
            Self::OneHour => Some(Duration::from_secs(60 * 60)),
            Self::OneDay => Some(Duration::from_secs(60 * 60 * 24)),
            Self::Permanent => None,
        }
    }
}

pub fn status() -> Status {
    let state = match load_state() {
        Ok(state) => state,
        Err(err) => {
            note_state_load_error_once("status", &err);
            return Status {
                isolated: platform::isolation_controls_active(&State::default()).unwrap_or(false),
                ..Status::default()
            };
        }
    };
    let now = unix_now();
    Status {
        blocked_rules: state.blocked.len() + state.blocked_processes.len(),
        blocked_processes: state.blocked_processes.len(),
        blocked_domains: state.blocked_domains.len(),
        suspended_processes: state.suspended_processes.len(),
        frozen_autoruns: state.autorun_snapshot.is_some(),
        // Reflect effective containment state, not just persisted intent.
        isolated: isolation_effective_now(&state, now),
    }
}
pub fn has_frozen_autoruns() -> bool {
    load_state_for_query("has_frozen_autoruns")
        .and_then(|s| s.autorun_snapshot)
        .is_some()
}
pub fn can_modify_firewall() -> bool {
    platform::is_supported() && platform::is_elevated()
}
pub fn can_isolate_network() -> bool {
    platform::supports_isolation() && platform::is_elevated()
}
pub fn can_kill_connection(conn: &ConnInfo) -> bool {
    if !platform::is_supported() || !platform::is_elevated() {
        return false;
    }
    socket_kill_target(conn).is_ok()
}
pub fn can_suspend_process(pid: u32) -> bool {
    platform::is_supported() && platform::is_elevated() && pid != 0
}
pub fn can_block_domain() -> bool {
    platform::is_supported() && platform::is_elevated()
}
pub fn can_apply_quarantine_profile(pid: u32, path: &str) -> bool {
    platform::is_supported() && platform::is_elevated() && (pid != 0 || !path.trim().is_empty())
}

pub fn freeze_autoruns() -> Result<String, String> {
    ensure_modifiable()?;
    let snapshot = platform::snapshot_autoruns()?;
    let mut state = load_state()?;
    let count = snapshot.entries.len();
    state.autorun_snapshot = Some(snapshot);
    save_state(&state)?;
    audit::record("freeze_autoruns", "success", json!({ "entries": count }));
    Ok(format!(
        "Captured autorun baseline with {count} entr{}.",
        if count == 1 { "y" } else { "ies" }
    ))
}
pub fn revert_frozen_autoruns() -> Result<String, String> {
    ensure_modifiable()?;
    let mut state = load_state()?;
    let Some(snapshot) = state.autorun_snapshot.clone() else {
        return Err("No autorun baseline has been captured yet.".into());
    };
    let result = platform::revert_autorun_changes(&snapshot.entries)?;
    state.autorun_snapshot = None;
    save_state(&state)?;
    audit::record(
        "revert_frozen_autoruns",
        "success",
        json!({ "removed_additions": result.removed_additions, "restored_entries": result.restored_entries }),
    );
    Ok(format!(
        "Reverted autorun changes: removed {} added entr{} and restored {} baseline entr{}.",
        result.removed_additions,
        if result.removed_additions == 1 {
            "y"
        } else {
            "ies"
        },
        result.restored_entries,
        if result.restored_entries == 1 {
            "y"
        } else {
            "ies"
        }
    ))
}
pub fn kill_connection(conn: &ConnInfo) -> Result<String, SocketKillError> {
    if !platform::is_supported() {
        return Err(SocketKillError::PlatformUnsupported);
    }
    if !platform::is_elevated() {
        return Err(SocketKillError::PermissionDenied);
    }
    let target = socket_kill_target(conn)?;
    platform::kill_tcp_connection(&target)?;
    let message = format!(
        "Killed TCP connection {} -> {}.",
        target.local, target.remote
    );
    audit::record(
        "kill_connection",
        "success",
        json!({ "local_addr": target.local.to_string(), "remote_addr": target.remote.to_string(), "pid": conn.pid, "proc_name": conn.proc_name }),
    );
    Ok(message)
}
pub fn suspend_process(pid: u32, path: &str, proc_name: &str) -> Result<String, String> {
    ensure_modifiable()?;
    if pid == 0 {
        return Err("Cannot suspend PID 0.".into());
    }
    platform::suspend_process(pid)?;
    let path = path.trim().to_string();
    let proc_name = proc_name.trim().to_string();
    let mut state = load_state()?;
    state
        .suspended_processes
        .retain(|entry| !suspended_process_matches(entry, pid, &path));
    state.suspended_processes.push(SuspendedProcess {
        pid,
        path: path.clone(),
        proc_name: proc_name.clone(),
        suspended_at_unix: unix_now(),
    });
    save_state(&state)?;
    let message = if path.is_empty() {
        format!("Suspended PID {pid}.")
    } else {
        format!("Suspended PID {pid} ({path}).")
    };
    audit::record(
        "suspend_process",
        "success",
        json!({ "pid": pid, "path": path, "proc_name": proc_name }),
    );
    Ok(message)
}
pub fn resume_process(pid: u32, path: &str) -> Result<String, String> {
    ensure_modifiable()?;
    if pid == 0 {
        return Err("Cannot resume PID 0.".into());
    }
    platform::resume_process(pid)?;
    let path = path.trim().to_string();
    let mut state = load_state()?;
    let before = state.suspended_processes.len();
    state
        .suspended_processes
        .retain(|entry| !suspended_process_matches(entry, pid, &path));
    let removed = before.saturating_sub(state.suspended_processes.len());
    save_state(&state)?;
    let message = if path.is_empty() {
        format!("Resumed PID {pid}.")
    } else {
        format!("Resumed PID {pid} ({path}).")
    };
    audit::record(
        "resume_process",
        if removed > 0 { "success" } else { "noop" },
        json!({ "pid": pid, "path": path, "removed_entries": removed }),
    );
    Ok(message)
}
pub fn block_domain(domain: &str) -> Result<String, String> {
    ensure_modifiable()?;
    let domain = normalise_domain(domain)?;
    let marker = domain_marker(&domain);
    platform::add_domain_block(&domain, &marker)?;
    let mut state = load_state()?;
    state.blocked_domains.retain(|entry| entry.domain != domain);
    state.blocked_domains.push(BlockedDomain {
        domain: domain.clone(),
        marker: marker.clone(),
    });
    save_state(&state)?;
    audit::record(
        "block_domain",
        "success",
        json!({ "domain": domain, "marker": marker }),
    );
    Ok(format!("Blocked domain {domain} via the local hosts file."))
}
pub fn unblock_domain(domain: &str) -> Result<String, String> {
    ensure_modifiable()?;
    let domain = normalise_domain(domain)?;
    let marker = domain_marker(&domain);
    platform::remove_domain_block(&domain, &marker)?;
    let mut state = load_state()?;
    let before = state.blocked_domains.len();
    state.blocked_domains.retain(|entry| entry.domain != domain);
    let removed = before.saturating_sub(state.blocked_domains.len());
    save_state(&state)?;
    audit::record(
        "unblock_domain",
        if removed > 0 { "success" } else { "noop" },
        json!({ "domain": domain, "marker": marker, "removed_entries": removed }),
    );
    Ok(if removed > 0 {
        format!("Removed the hosts-file block for {domain}.")
    } else {
        format!("No hosts-file block found for {domain}.")
    })
}

pub fn apply_quarantine_profile(pid: u32, path: &str, proc_name: &str) -> Result<String, String> {
    ensure_modifiable()?;
    if pid == 0 && path.trim().is_empty() {
        return Err("Quarantine profile requires a real PID or a known executable path.".into());
    }
    let mut applied = Vec::new();
    let mut warnings = Vec::new();
    match isolate_machine() {
        Ok(_) => applied.push("network isolated".to_string()),
        Err(err) => warnings.push(format!("network isolation failed: {err}")),
    }
    if !path.trim().is_empty() {
        match block_process(pid, path, DurationPreset::Permanent) {
            Ok(_) => applied.push("process traffic blocked".to_string()),
            Err(err) => warnings.push(format!("process block failed: {err}")),
        }
    }
    if pid != 0 {
        match suspend_process(pid, path, proc_name) {
            Ok(_) => applied.push("process suspended".to_string()),
            Err(err) => warnings.push(format!("process suspend failed: {err}")),
        }
    }
    let (extended_applied, extended_warnings) = quarantine::apply();
    applied.extend(extended_applied);
    warnings.extend(extended_warnings);
    if applied.is_empty() {
        return Err(if warnings.is_empty() {
            "Quarantine profile could not apply any containment step.".into()
        } else {
            warnings.join("; ")
        });
    }
    let message = if warnings.is_empty() {
        format!("Applied quarantine profile: {}.", applied.join(", "))
    } else {
        format!(
            "Applied quarantine profile: {}. Warnings: {}.",
            applied.join(", "),
            warnings.join("; ")
        )
    };
    audit::record(
        "quarantine_profile",
        if warnings.is_empty() {
            "success"
        } else {
            "partial"
        },
        json!({ "pid": pid, "path": path, "proc_name": proc_name, "applied": applied, "warnings": warnings }),
    );
    Ok(message)
}

pub fn clear_quarantine_profile(pid: u32, path: &str) -> Result<String, String> {
    ensure_modifiable()?;
    let mut cleared = Vec::new();
    let mut warnings = Vec::new();
    match restore_machine() {
        Ok(_) => cleared.push("network restored".to_string()),
        Err(err) => warnings.push(format!("network restore failed: {err}")),
    }
    if !path.trim().is_empty() {
        match unblock_process(pid, path) {
            Ok(_) => cleared.push("process block removed".to_string()),
            Err(err) => warnings.push(format!("process unblock failed: {err}")),
        }
    }
    if pid != 0 {
        match resume_process(pid, path) {
            Ok(_) => cleared.push("process resumed".to_string()),
            Err(err) => warnings.push(format!("process resume failed: {err}")),
        }
    }
    let (extended_cleared, extended_warnings) = quarantine::clear();
    cleared.extend(extended_cleared);
    warnings.extend(extended_warnings);
    if cleared.is_empty() {
        return Err(if warnings.is_empty() {
            "Quarantine clear did not change any containment step.".into()
        } else {
            warnings.join("; ")
        });
    }
    let message = if warnings.is_empty() {
        format!("Cleared quarantine profile: {}.", cleared.join(", "))
    } else {
        format!(
            "Cleared quarantine profile: {}. Warnings: {}.",
            cleared.join(", "),
            warnings.join("; ")
        )
    };
    audit::record(
        "clear_quarantine_profile",
        if warnings.is_empty() {
            "success"
        } else {
            "partial"
        },
        json!({ "pid": pid, "path": path, "cleared": cleared, "warnings": warnings }),
    );
    Ok(message)
}

pub fn reconcile() {
    if !platform::is_elevated() {
        return;
    }
    if !platform::is_supported() && !platform::supports_isolation() {
        return;
    }
    let Ok(mut state) = load_state() else {
        note_state_load_error_once(
            "reconcile",
            "failed to load protected active-response state",
        );
        return;
    };
    let now = unix_now();
    let isolation_active =
        state.isolated || state.firewall_snapshot.is_some() || state.network_snapshot.is_some();
    let isolation_arming = isolation_active
        && state
            .isolation_started_unix
            .is_some_and(|started| now.saturating_sub(started) < ISOLATION_ACTIVATION_GRACE_SECS);
    let probe_reachable = outbound_probe_reachable();
    let controls_active = isolation_controls_active_best_effort(&state, probe_reachable);
    if isolation_active && !isolation_arming && !controls_active && probe_reachable {
        state.isolated = false;
        state.firewall_snapshot = None;
        state.network_snapshot = None;
        state.isolation_started_unix = None;
        state.isolation_expires_unix = None;
        if let Err(err) = save_state(&state) {
            note_state_load_error_once("reconcile_stale_isolation_state_save", &err);
         }
        match crate::config::Config::load() {
            Ok(cfg) => {
                let _ = crate::break_glass::sync_watchdog(&cfg);
            }
            Err(err) => note_state_load_error_once("reconcile_config", &err),
        }
        audit::record(
            "reconcile_stale_isolation_state",
            "success",
            json!({
                "reason": "local isolation controls are no longer active and connectivity probe is reachable"
            }),
        );
        return;
    }
    let isolation_expired = isolation_active
        && state
            .isolation_expires_unix
            .is_some_and(|expires_at| 