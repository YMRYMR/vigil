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
use std::sync::{OnceLock, RwLock};
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
    OsError(u32),
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
            Self::OsError(code) => write!(f, "Windows returned error code {code}"),
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
    let state = load_state().unwrap_or_default();
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
    load_state().ok().and_then(|s| s.autorun_snapshot).is_some()
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
    let mut state = load_state().unwrap_or_default();
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
    let mut state = load_state().unwrap_or_default();
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
    let mut state = load_state().unwrap_or_default();
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
    let mut state = load_state().unwrap_or_default();
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
    let mut state = load_state().unwrap_or_default();
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
    let mut state = load_state().unwrap_or_default();
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
        let _ = save_state(&state);
        let cfg = crate::config::Config::load();
        let _ = crate::break_glass::sync_watchdog(&cfg);
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
            .is_some_and(|expires_at| now >= expires_at);
    if isolation_expired {
        if let Err(err) = restore_machine() {
            audit::record(
                "reconcile_isolation_timeout",
                "error",
                json!({
                    "error": err,
                    "expires_at_unix": state.isolation_expires_unix,
                    "now_unix": now,
                }),
            );
        } else if let Ok(restored_state) = load_state() {
            state = restored_state;
        }
    }
    let changed = reconcile_state(&mut state, now, |rule_name| {
        platform::delete_rule(rule_name).is_ok()
    });
    if changed {
        let _ = save_state(&state);
    }
}
pub fn block_remote(target: &str, preset: DurationPreset) -> Result<String, String> {
    ensure_modifiable()?;
    let target = normalise_target(target)?;
    let rule_name = rule_name_for_target(&target);
    let expires_at_unix = preset
        .ttl()
        .map(|ttl| unix_now().saturating_add(ttl.as_secs()));
    let _ = platform::delete_rule(&rule_name);
    platform::add_block_rule(&rule_name, &target)?;
    let mut state = load_state().unwrap_or_default();
    state.blocked.retain(|rule| rule.target != target);
    state.blocked.push(BlockedTarget {
        target: target.clone(),
        rule_name: rule_name.clone(),
        expires_at_unix,
    });
    save_state(&state)?;
    let message = match preset {
        DurationPreset::OneHour => format!("Blocked {target} for 1 hour."),
        DurationPreset::OneDay => format!("Blocked {target} for 24 hours."),
        DurationPreset::Permanent => format!("Blocked {target} until removed."),
    };
    audit::record(
        "block_remote",
        "success",
        json!({ "target": target, "duration": format!("{:?}", preset), "rule_name": rule_name }),
    );
    Ok(message)
}
pub fn unblock_remote(target: &str) -> Result<String, String> {
    ensure_modifiable()?;
    let target = normalise_target(target)?;
    let mut state = load_state().unwrap_or_default();
    let mut removed = 0usize;
    let mut kept = Vec::with_capacity(state.blocked.len());
    let mut delete_failed = false;
    for rule in state.blocked.drain(..) {
        if rule.target == target {
            if platform::delete_rule(&rule.rule_name).is_ok() {
                removed += 1;
            } else {
                delete_failed = true;
                kept.push(rule);
            }
        } else {
            kept.push(rule);
        }
    }
    state.blocked = kept;
    if delete_failed {
        return Err(format!("Could not remove the firewall rule for {target}; it was kept in state so Vigil can retry."));
    }
    let message = if removed > 0 {
        save_state(&state)?;
        format!("Removed {removed} block rule(s) for {target}.")
    } else {
        format!("No active block rule found for {target}.")
    };
    audit::record(
        "unblock_remote",
        if removed > 0 { "success" } else { "noop" },
        json!({ "target": target, "removed_rules": removed }),
    );
    Ok(message)
}
pub fn block_process(pid: u32, path: &str, preset: DurationPreset) -> Result<String, String> {
    ensure_modifiable()?;
    let path = normalise_target(path)?;
    let rule_suffix = rule_suffix_for_process(&path);
    let outbound_rule_name = format!("{PROCESS_BLOCK_RULE_PREFIX} Out {rule_suffix}");
    let inbound_rule_name = format!("{PROCESS_BLOCK_RULE_PREFIX} In {rule_suffix}");
    let expires_at_unix = preset
        .ttl()
        .map(|ttl| unix_now().saturating_add(ttl.as_secs()));
    let _ = platform::delete_rule(&outbound_rule_name);
    let _ = platform::delete_rule(&inbound_rule_name);
    platform::add_block_program_rule(&outbound_rule_name, pid, &path, "out")?;
    if let Err(err) = platform::add_block_program_rule(&inbound_rule_name, pid, &path, "in") {
        let _ = platform::delete_rule(&outbound_rule_name);
        return Err(err);
    }
    let mut state = load_state().unwrap_or_default();
    state
        .blocked_processes
        .retain(|rule| !process_block_matches(rule, &path));
    state.blocked_processes.push(BlockedProcess {
        pid,
        path: path.clone(),
        inbound_rule_name: inbound_rule_name.clone(),
        outbound_rule_name: outbound_rule_name.clone(),
        expires_at_unix,
    });
    save_state(&state)?;
    let message = match preset {
        DurationPreset::OneHour => format!("Blocked {path} for 1 hour."),
        DurationPreset::OneDay => format!("Blocked {path} for 24 hours."),
        DurationPreset::Permanent => format!("Blocked {path} until removed."),
    };
    audit::record(
        "block_process",
        "success",
        json!({ "pid": pid, "path": path, "duration": format!("{:?}", preset), "inbound_rule_name": inbound_rule_name, "outbound_rule_name": outbound_rule_name }),
    );
    Ok(message)
}
pub fn unblock_process(pid: u32, path: &str) -> Result<String, String> {
    ensure_modifiable()?;
    let path = normalise_target(path)?;
    let mut state = load_state().unwrap_or_default();
    let mut removed = 0usize;
    let mut kept = Vec::with_capacity(state.blocked_processes.len());
    let mut delete_failed = false;
    for rule in state.blocked_processes.drain(..) {
        if process_block_matches(&rule, &path) {
            let inbound_deleted = platform::delete_rule(&rule.inbound_rule_name).is_ok();
            let outbound_deleted = platform::delete_rule(&rule.outbound_rule_name).is_ok();
            if inbound_deleted && outbound_deleted {
                removed += 1;
            } else {
                delete_failed = true;
                kept.push(rule);
            }
        } else {
            kept.push(rule);
        }
    }
    state.blocked_processes = kept;
    if delete_failed {
        return Err(format!("Could not remove the firewall rules for PID {pid} ({path}); they were kept in state so Vigil can retry."));
    }
    let message = if removed > 0 {
        save_state(&state)?;
        format!("Removed {removed} process block(s) for PID {pid} ({path}).")
    } else {
        format!("No active process block found for PID {pid} ({path}).")
    };
    audit::record(
        "unblock_process",
        if removed > 0 { "success" } else { "noop" },
        json!({ "pid": pid, "path": path, "removed_rules": removed }),
    );
    Ok(message)
}

pub fn isolate_machine() -> Result<String, String> {
    ensure_isolation_modifiable()?;
    let now = unix_now();
    let cfg = crate::config::Config::load();
    let timeout_secs = (cfg.break_glass_timeout_mins.clamp(1, 240) * 60).min(ISOLATION_MAX_SECS);
    let mut state = load_state().unwrap_or_default();
    let controls_active = platform::isolation_controls_active(&state).unwrap_or(false);
    if controls_active {
        state.isolated = true;
        state.isolation_started_unix.get_or_insert(now);
        state.isolation_expires_unix = Some(now.saturating_add(timeout_secs));
        save_state(&state)?;
        if let Err(err) = crate::break_glass::sync_watchdog(&cfg) {
            return Err(format!(
                "Isolation already active, but watchdog refresh failed: {err}"
            ));
        }
        return Ok(format!(
            "Network isolation already active (failsafe recovery armed: {} minute{} stale-heartbeat timeout).",
            timeout_secs / 60,
            if timeout_secs / 60 == 1 { "" } else { "s" }
        ));
    }
    if state.isolated {
        // Stale persisted marker: the machine is not currently isolated, so clear old state
        // and perform a fresh isolation attempt.
        state.isolated = false;
        state.firewall_snapshot = None;
        state.network_snapshot = None;
        state.isolation_started_unix = None;
        state.isolation_expires_unix = None;
        let _ = save_state(&state);
    }
    let firewall_snapshot = platform::snapshot_firewall_profiles().ok();
    state.firewall_snapshot = firewall_snapshot.clone();
    state.network_snapshot = None;
    state.isolation_started_unix = Some(now);
    state.isolation_expires_unix = Some(now.saturating_add(timeout_secs));
    state.isolated = true;
    save_state(&state)?;
    if let Err(err) = crate::break_glass::sync_watchdog(&cfg) {
        state.firewall_snapshot = None;
        state.network_snapshot = None;
        state.isolation_started_unix = None;
        state.isolation_expires_unix = None;
        state.isolated = false;
        let _ = save_state(&state);
        return Err(format!(
            "Could not arm crash-recovery watchdog; isolation aborted: {err}"
        ));
    }
    let mut applied = Vec::new();
    let mut warnings = Vec::new();
    match platform::apply_firewall_isolation() {
        Ok(()) => applied.push("firewall profiles hardened".to_string()),
        Err(err) => warnings.push(format!("firewall profile update failed: {err}")),
    }
    match platform::add_block_all_rule(ISOLATE_RULE_IN, "in") {
        Ok(()) => applied.push("legacy inbound firewall rule added".to_string()),
        Err(err) => warnings.push(format!("legacy inbound rule failed: {err}")),
    }
    match platform::add_block_all_rule(ISOLATE_RULE_OUT, "out") {
        Ok(()) => applied.push("legacy outbound firewall rule added".to_string()),
        Err(err) => warnings.push(format!("legacy outbound rule failed: {err}")),
    }
    match platform::terminate_active_tcp_connections() {
        Ok(0) => applied.push("no established TCP sessions were found".to_string()),
        Ok(count) => applied.push(format!(
            "reset {count} established TCP session{}",
            if count == 1 { "" } else { "s" }
        )),
        Err(err) => warnings.push(format!("active TCP reset skipped: {err}")),
    }
    let mut fallback_used = false;
    if outbound_probe_reachable() {
        match platform::snapshot_active_adapters() {
            Ok(snapshot) => {
                if snapshot.adapters.is_empty() {
                    warnings.push("no active adapters were available for emergency cutoff".into());
                } else {
                    state.network_snapshot = Some(snapshot.clone());
                    save_state(&state)?;
                    match platform::disable_active_adapters(&snapshot) {
                        Ok(()) => {
                            fallback_used = true;
                            applied.push("emergency adapter cutoff applied".to_string());
                        }
                        Err(err) => {
                            warnings.push(format!("emergency adapter cutoff failed: {err}"));
                        }
                    }
                }
            }
            Err(err) => warnings.push(format!("adapter snapshot failed: {err}")),
        }
    }
    if outbound_probe_reachable() {
        if let Some(snapshot) = firewall_snapshot.as_ref() {
            let _ = platform::restore_firewall_profiles(snapshot);
        }
        let recovery_state = load_state().unwrap_or_default();
        if let Some(snapshot) = recovery_state.network_snapshot.as_ref() {
            let _ = platform::enable_active_adapters(snapshot);
        }
        let _ = platform::delete_rule(ISOLATE_RULE_IN);
        let _ = platform::delete_rule(ISOLATE_RULE_OUT);

        let mut state = recovery_state;
        state.firewall_snapshot = None;
        state.network_snapshot = None;
        state.isolation_started_unix = None;
        state.isolation_expires_unix = None;
        state.isolated = false;
        let _ = save_state(&state);
        let _ = crate::break_glass::sync_watchdog(&cfg);
        let details = if warnings.is_empty() {
            "outbound connectivity is still reachable".to_string()
        } else {
            warnings.join("; ")
        };
        return Err(format!("Could not isolate the machine: {details}"));
    }
    if let Err(err) = crate::break_glass::sync_watchdog(&cfg) {
        warnings.push(format!("failsafe watchdog refresh failed: {err}"));
    }
    audit::record(
        "isolate_machine",
        "success",
        json!({
            "firewall_profiles": firewall_snapshot
                .as_ref()
                .map(|snapshot| snapshot.profiles.len())
                .unwrap_or(0),
            "applied": applied,
            "warnings": warnings,
        }),
    );
    if warnings.is_empty() && !fallback_used {
        Ok(format!(
            "Network isolation enabled (failsafe recovery armed: {} minute{} stale-heartbeat timeout).",
            timeout_secs / 60,
            if timeout_secs / 60 == 1 { "" } else { "s" }
        ))
    } else if warnings.is_empty() && fallback_used {
        Ok(format!(
            "Network isolation enabled via emergency adapter cutoff (failsafe recovery armed: {} minute{} stale-heartbeat timeout).",
            timeout_secs / 60,
            if timeout_secs / 60 == 1 { "" } else { "s" }
        ))
    } else if fallback_used {
        Ok(format!(
            "Network isolation enabled via emergency adapter cutoff with warnings: {} (failsafe recovery armed: {} minute{} stale-heartbeat timeout)",
            warnings.join("; ")
            , timeout_secs / 60
            , if timeout_secs / 60 == 1 { "" } else { "s" }
        ))
    } else {
        Ok(format!(
            "Network isolation enabled with warnings: {} (failsafe recovery armed: {} minute{} stale-heartbeat timeout)",
            warnings.join("; "),
            timeout_secs / 60,
            if timeout_secs / 60 == 1 { "" } else { "s" }
        ))
    }
}
pub fn restore_machine() -> Result<String, String> {
    ensure_isolation_modifiable()?;
    let mut state = load_state().unwrap_or_default();
    let had_isolation_intent =
        state.isolated || state.firewall_snapshot.is_some() || state.network_snapshot.is_some();
    let firewall_snapshot = state.firewall_snapshot.clone();
    let network_snapshot = state.network_snapshot.clone();
    let mut warnings = Vec::new();
    let mut critical_failure = false;
    let in_deleted = platform::delete_rule(ISOLATE_RULE_IN).is_ok();
    let out_deleted = platform::delete_rule(ISOLATE_RULE_OUT).is_ok();
    if !(in_deleted && out_deleted) {
        warnings.push(
            "Could not remove all legacy isolation firewall rules; will retry from saved state"
                .into(),
        );
    }
    if let Some(snapshot) = firewall_snapshot.as_ref() {
        if let Err(err) = platform::restore_firewall_profiles(snapshot) {
            critical_failure = true;
            warnings.push(format!("firewall profile restore failed: {err}"));
        }
    }
    if let Some(snapshot) = network_snapshot.as_ref() {
        if let Err(err) = platform::enable_active_adapters(snapshot) {
            critical_failure = true;
            warnings.push(format!("adapter restore failed: {err}"));
        }
    }
    let mut connectivity_reachable = outbound_probe_reachable();
    if had_isolation_intent && !connectivity_reachable {
        match platform::enable_all_network_adapters() {
            Ok(0) => {}
            Ok(count) => warnings.push(format!(
                "fallback adapter recovery enabled {count} additional adapter{}",
                if count == 1 { "" } else { "s" }
            )),
            Err(err) => warnings.push(format!("fallback adapter recovery failed: {err}")),
        }
        // Wi-Fi reassociation can take a few seconds after interfaces are re-enabled.
        connectivity_reachable = wait_for_outbound_probe(Duration::from_secs(2));
        if !connectivity_reachable {
            match platform::isolation_controls_active(&state) {
                Ok(true) => {
                    critical_failure = true;
                    warnings.push(
                        "local isolation controls are still active after restore attempts"
                            .to_string(),
                    );
                }
                Ok(false) => warnings.push(
                    "connectivity probe is still failing after restore attempts; local isolation controls are no longer active"
                        .to_string(),
                ),
                Err(err) => warnings.push(format!(
                    "connectivity probe is still failing after restore attempts; could not verify local isolation controls: {err}"
                )),
            }
        }
    }
    if critical_failure {
        let controls_active_result = platform::isolation_controls_active(&state);
        let controls_active = match controls_active_result {
            Ok(active) => active,
            Err(err) => {
                warnings.push(format!(
                    "could not verify local isolation controls after restore: {err}"
                ));
                true
            }
        };
        if !controls_active || connectivity_reachable || outbound_probe_reachable() {
            warnings.push(
                if controls_active {
                    "connectivity probe succeeded; clearing stale isolation state despite restore warnings"
                        .into()
                } else {
                    "local isolation controls are no longer active; clearing stale isolation state despite restore warnings"
                        .into()
                },
            );
            state.isolated = false;
            state.firewall_snapshot = None;
            state.network_snapshot = None;
            state.isolation_started_unix = None;
            state.isolation_expires_unix = None;
            save_state(&state)?;
            let cfg = crate::config::Config::load();
            if let Err(err) = crate::break_glass::sync_watchdog(&cfg) {
                warnings.push(format!("break-glass watchdog cleanup failed: {err}"));
            }
            audit::record(
                "restore_machine_stale_state_cleared",
                "partial",
                json!({ "warnings": warnings }),
            );
            return Ok(format!(
                "Network isolation removed with warnings: {}",
                warnings.join("; ")
            ));
        }
        return Err(warnings.join("; "));
    }
    state.isolated = false;
    state.firewall_snapshot = None;
    state.network_snapshot = None;
    state.isolation_started_unix = None;
    state.isolation_expires_unix = None;
    save_state(&state)?;
    let cfg = crate::config::Config::load();
    if let Err(err) = crate::break_glass::sync_watchdog(&cfg) {
        warnings.push(format!("break-glass watchdog cleanup failed: {err}"));
    }
    audit::record(
        "restore_machine",
        "success",
        json!({ "warnings": warnings }),
    );
    if warnings.is_empty() {
        Ok("Network isolation removed.".into())
    } else {
        Ok(format!(
            "Network isolation removed with warnings: {}",
            warnings.join("; ")
        ))
    }
}

pub fn is_blocked(target: &str) -> bool {
    let Ok(target) = normalise_target(target) else {
        return false;
    };
    load_state()
        .ok()
        .map(|state| state.blocked.iter().any(|r| r.target == target))
        .unwrap_or(false)
}
pub fn is_domain_blocked(domain: &str) -> bool {
    let Ok(domain) = normalise_domain(domain) else {
        return false;
    };
    load_state()
        .ok()
        .map(|state| {
            state
                .blocked_domains
                .iter()
                .any(|entry| entry.domain == domain)
        })
        .unwrap_or(false)
}
pub fn remote_block_remaining(target: &str) -> Option<Duration> {
    let target = normalise_target(target).ok()?;
    let now = unix_now();
    load_state()
        .ok()
        .and_then(|state| {
            state
                .blocked
                .into_iter()
                .find(|r| r.target == target)
                .and_then(|rule| rule.expires_at_unix)
        })
        .and_then(|expires_at_unix| expires_at_unix.checked_sub(now))
        .map(Duration::from_secs)
}
pub fn is_process_blocked(_pid: u32, path: &str) -> bool {
    let Ok(path) = normalise_target(path) else {
        return false;
    };
    load_state()
        .ok()
        .map(|state| {
            state
                .blocked_processes
                .iter()
                .any(|r| process_block_matches(r, &path))
        })
        .unwrap_or(false)
}
pub fn process_block_remaining(_pid: u32, path: &str) -> Option<Duration> {
    let path = normalise_target(path).ok()?;
    let now = unix_now();
    load_state()
        .ok()
        .and_then(|state| {
            state
                .blocked_processes
                .into_iter()
                .find(|r| process_block_matches(r, &path))
                .and_then(|rule| rule.expires_at_unix)
        })
        .and_then(|expires_at_unix| expires_at_unix.checked_sub(now))
        .map(Duration::from_secs)
}
pub fn is_process_suspended(pid: u32, path: &str) -> bool {
    load_state()
        .ok()
        .map(|state| {
            state
                .suspended_processes
                .iter()
                .any(|entry| suspended_process_matches(entry, pid, path))
        })
        .unwrap_or(false)
}

pub fn extract_remote_target(remote_addr: &str) -> Option<String> {
    if let Ok(addr) = socket_addr_from_text(remote_addr) {
        return Some(addr.ip().to_string());
    }
    let trimmed = remote_addr.trim();
    let (host, port) = trimmed.rsplit_once(':')?;
    if host.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.parse::<IpAddr>().is_ok() {
        Some(host.to_string())
    } else {
        None
    }
}
pub fn extract_domain_target(conn: &ConnInfo) -> Option<String> {
    conn.hostname
        .as_deref()
        .and_then(extract_domain_from_hostname)
}
pub fn extract_domain_from_hostname(hostname: &str) -> Option<String> {
    let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return None;
    }
    if host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        Some(host)
    } else {
        None
    }
}

fn ensure_modifiable() -> Result<(), String> {
    if !platform::is_supported() {
        return Err(
            "Active response requires elevated privileges (run as root or grant CAP_NET_ADMIN)."
                .into(),
        );
    }
    if !platform::is_elevated() {
        return Err("Administrator privileges are required for active response.".into());
    }
    Ok(())
}
fn ensure_isolation_modifiable() -> Result<(), String> {
    if !platform::supports_isolation() {
        return Err("Network isolation is not implemented on this platform.".into());
    }
    if !platform::is_elevated() {
        return Err("Administrator privileges are required for network isolation.".into());
    }
    Ok(())
}
fn isolation_effective_now(state: &State, now: u64) -> bool {
    let isolation_intent =
        state.isolated || state.firewall_snapshot.is_some() || state.network_snapshot.is_some();
    if !isolation_intent {
        return false;
    }
    let probe_reachable = outbound_probe_reachable();
    // UI and tray state should only flip to isolated once outbound connectivity is
    // effectively cut, not merely when an isolation attempt has started.
    if probe_reachable {
        return false;
    }
    let isolation_arming = state
        .isolation_started_unix
        .is_some_and(|started| now.saturating_sub(started) < ISOLATION_ACTIVATION_GRACE_SECS);
    if isolation_arming {
        return true;
    }
    isolation_controls_active_best_effort(state, probe_reachable)
}
fn isolation_controls_active_best_effort(state: &State, probe_reachable: bool) -> bool {
    match platform::isolation_controls_active(state) {
        Ok(active) => active,
        Err(_) => !probe_reachable,
    }
}
fn outbound_probe_reachable() -> bool {
    const PROBE_TARGETS: [&str; 3] = ["1.1.1.1:443", "8.8.8.8:53", "9.9.9.9:443"];
    let timeout = Duration::from_millis(250);
    PROBE_TARGETS.iter().any(|target| {
        target
            .parse::<SocketAddr>()
            .ok()
            .is_some_and(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
    })
}
fn wait_for_outbound_probe(timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    loop {
        if outbound_probe_reachable() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(650));
    }
}
fn socket_kill_target(conn: &ConnInfo) -> Result<SocketKillTarget, SocketKillError> {
    if !conn.status.eq_ignore_ascii_case("ESTABLISHED")
        && !conn.status.eq_ignore_ascii_case("SYN_SENT")
        && !conn.status.eq_ignore_ascii_case("SYN_RECEIVED")
        && !conn.status.eq_ignore_ascii_case("FIN_WAIT_1")
        && !conn.status.eq_ignore_ascii_case("FIN_WAIT_2")
        && !conn.status.eq_ignore_ascii_case("CLOSE_WAIT")
        && !conn.status.eq_ignore_ascii_case("CLOSING")
        && !conn.status.eq_ignore_ascii_case("LAST_ACK")
        && !conn.status.eq_ignore_ascii_case("TIME_WAIT")
    {
        return Err(SocketKillError::UnsupportedStatus(conn.status.clone()));
    }
    let local = socket_addr_from_text(&conn.local_addr)
        .map_err(|_| SocketKillError::InvalidLocalAddr(conn.local_addr.clone()))?;
    let remote = socket_addr_from_text(&conn.remote_addr)
        .map_err(|_| SocketKillError::InvalidRemoteAddr(conn.remote_addr.clone()))?;
    match (local.ip(), remote.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Ok(SocketKillTarget { local, remote }),
        _ => Err(SocketKillError::UnsupportedAddressFamily),
    }
}
fn socket_addr_from_text(text: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    text.trim().parse::<SocketAddr>()
}
fn normalise_target(target: &str) -> Result<String, String> {
    let target = target.trim();
    if target.is_empty() {
        Err("Target cannot be empty.".into())
    } else {
        Ok(target.to_string())
    }
}
fn normalise_domain(domain: &str) -> Result<String, String> {
    extract_domain_from_hostname(domain).ok_or_else(|| "Domain is empty or invalid.".into())
}
fn process_block_matches(rule: &BlockedProcess, path: &str) -> bool {
    rule.path == path
}
fn suspended_process_matches(entry: &SuspendedProcess, pid: u32, path: &str) -> bool {
    entry.pid == pid && (path.is_empty() || entry.path == path)
}
fn domain_marker(domain: &str) -> String {
    format!("{DOMAIN_MARKER_PREFIX}:{}", sanitise_rule_suffix(domain))
}
fn rule_name_for_target(target: &str) -> String {
    format!("{BLOCK_RULE_PREFIX} {}", sanitise_rule_suffix(target))
}
fn rule_suffix_for_process(path: &str) -> String {
    let base = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("process");
    format!("{}-{:016x}", sanitise_rule_suffix(base), stable_hash(path))
}
fn sanitise_rule_suffix(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
fn stable_hash(text: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for b in text.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
fn state_path() -> PathBuf {
    crate::config::data_dir().join(STATE_FILE)
}
fn load_state() -> Result<State, String> {
    if let Some(state) = state_cache().read().unwrap().clone() {
        return Ok(state);
    }

    let path = state_path();
    let state = if !path.exists() {
        State::default()
    } else {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))?
    };
    *state_cache().write().unwrap() = Some(state.clone());
    Ok(state)
}
fn save_state(state: &State) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("failed to serialise active-response state: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    *state_cache().write().unwrap() = Some(state.clone());
    Ok(())
}
fn state_cache() -> &'static RwLock<Option<State>> {
    static CACHE: OnceLock<RwLock<Option<State>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(None))
}
fn reconcile_state<F>(state: &mut State, now: u64, mut delete_rule: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    let mut changed = false;
    state.blocked.retain(|rule| {
        let expired = rule.expires_at_unix.is_some_and(|ts| ts <= now);
        if expired {
            if delete_rule(&rule.rule_name) {
                changed = true;
                false
            } else {
                true
            }
        } else {
            true
        }
    });
    state.blocked_processes.retain(|rule| {
        let expired = rule.expires_at_unix.is_some_and(|ts| ts <= now);
        if expired {
            let inbound_deleted = delete_rule(&rule.inbound_rule_name);
            let outbound_deleted = delete_rule(&rule.outbound_rule_name);
            if inbound_deleted && outbound_deleted {
                changed = true;
                false
            } else {
                true
            }
        } else {
            true
        }
    });
    state.suspended_processes.retain(|entry| {
        if platform::process_exists(entry.pid) {
            true
        } else {
            changed = true;
            false
        }
    });
    changed
}
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::windows::process::CommandExt;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCP_STATE_DELETE_TCB,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, ResumeThread, SuspendThread,
        PROCESS_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::{RegKey, HKEY};
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    pub struct AutorunRevertResult {
        pub removed_additions: usize,
        pub restored_entries: usize,
    }
    const RUN_KEYS: [(&str, HKEY, &str); 4] = [
        (
            "HKCU",
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            "HKLM",
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            "HKCU",
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            "HKLM",
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ];
    pub fn is_supported() -> bool {
        true
    }
    pub fn supports_isolation() -> bool {
        true
    }
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut bytes = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut bytes,
            )
            .is_ok();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }
    pub fn process_exists(pid: u32) -> bool {
        unsafe {
            match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(handle) => {
                    let _ = CloseHandle(handle);
                    true
                }
                Err(_) => false,
            }
        }
    }
    pub fn snapshot_autoruns() -> Result<AutorunSnapshot, String> {
        let mut entries = Vec::new();
        for (label, hive, key_path) in RUN_KEYS {
            let root = RegKey::predef(hive);
            let key = match root.open_subkey(key_path) {
                Ok(k) => k,
                Err(_) => continue,
            };
            for item in key.enum_values() {
                let Ok((name, _value)) = item else { continue };
                let value_data = key.get_value::<String, _>(&name).unwrap_or_default();
                entries.push(AutorunEntry {
                    hive: label.to_string(),
                    key_path: key_path.to_string(),
                    value_name: name,
                    value_data,
                });
            }
        }
        entries.sort_by(|a, b| {
            (&a.hive, &a.key_path, &a.value_name).cmp(&(&b.hive, &b.key_path, &b.value_name))
        });
        Ok(AutorunSnapshot {
            captured_at_unix: unix_now(),
            entries,
        })
    }
    pub fn revert_autorun_changes(
        baseline: &[AutorunEntry],
    ) -> Result<AutorunRevertResult, String> {
        let current = snapshot_autoruns()?;
        let mut baseline_map: BTreeMap<(String, String, String), String> = BTreeMap::new();
        for entry in baseline {
            baseline_map.insert(
                (
                    entry.hive.clone(),
                    entry.key_path.clone(),
                    entry.value_name.clone(),
                ),
                entry.value_data.clone(),
            );
        }
        let mut current_map: BTreeMap<(String, String, String), String> = BTreeMap::new();
        for entry in &current.entries {
            current_map.insert(
                (
                    entry.hive.clone(),
                    entry.key_path.clone(),
                    entry.value_name.clone(),
                ),
                entry.value_data.clone(),
            );
        }
        let mut removed_additions = 0usize;
        let mut restored_entries = 0usize;
        for (label, hive, key_path) in RUN_KEYS {
            let root = RegKey::predef(hive);
            let key = match root.create_subkey(key_path) {
                Ok((k, _)) => k,
                Err(e) => {
                    return Err(format!(
                        "failed to open autorun key {}\\{}: {e}",
                        label, key_path
                    ))
                }
            };
            for ((entry_hive, entry_path, value_name), current_value) in current_map.iter() {
                if entry_hive != label || entry_path != key_path {
                    continue;
                }
                let lookup = (entry_hive.clone(), entry_path.clone(), value_name.clone());
                if !baseline_map.contains_key(&lookup) {
                    key.delete_value(value_name).map_err(|e| {
                        format!(
                            "failed to delete autorun value {}\\{}\\{}: {e}",
                            label, key_path, value_name
                        )
                    })?;
                    removed_additions += 1;
                } else if baseline_map.get(&lookup) != Some(current_value) {
                    let baseline_value = baseline_map.get(&lookup).cloned().unwrap_or_default();
                    key.set_value(value_name, &baseline_value).map_err(|e| {
                        format!(
                            "failed to restore autorun value {}\\{}\\{}: {e}",
                            label, key_path, value_name
                        )
                    })?;
                    restored_entries += 1;
                }
            }
            for ((entry_hive, entry_path, value_name), baseline_value) in baseline_map.iter() {
                if entry_hive != label || entry_path != key_path {
                    continue;
                }
                let lookup = (entry_hive.clone(), entry_path.clone(), value_name.clone());
                if !current_map.contains_key(&lookup) {
                    key.set_value(value_name, baseline_value).map_err(|e| {
                        format!(
                            "failed to restore missing autorun value {}\\{}\\{}: {e}",
                            label, key_path, value_name
                        )
                    })?;
                    restored_entries += 1;
                }
            }
        }
        Ok(AutorunRevertResult {
            removed_additions,
            restored_entries,
        })
    }
    pub fn snapshot_firewall_profiles() -> Result<FirewallSnapshot, String> {
        let output = run_powershell_json(
            "Get-NetFirewallProfile | Where-Object { $_.Name -in 'Domain','Private','Public' } | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Depth 2 -Compress",
        )?;
        parse_firewall_snapshot(&output)
    }
    pub fn apply_firewall_isolation() -> Result<(), String> {
        for profile in ["Domain", "Private", "Public"] {
            run_powershell(&format!(
                "Set-NetFirewallProfile -Profile {} -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop",
                ps_quoted(profile)
            ))?;
        }
        let snapshot = snapshot_firewall_profiles()?;
        if snapshot.profiles.is_empty()
            || snapshot.profiles.iter().any(|profile| {
                !profile.enabled
                    || !profile.inbound_action.eq_ignore_ascii_case("Block")
                    || !profile.outbound_action.eq_ignore_ascii_case("Block")
            })
        {
            return Err("firewall policy is not fully enabled and blocked".into());
        }
        Ok(())
    }
    pub fn restore_firewall_profiles(snapshot: &FirewallSnapshot) -> Result<(), String> {
        for profile in &snapshot.profiles {
            run_powershell(&format!(
                "Set-NetFirewallProfile -Profile {} -Enabled {} -DefaultInboundAction {} -DefaultOutboundAction {} -ErrorAction Stop",
                ps_quoted(&profile.name),
                if profile.enabled { "True" } else { "False" },
                profile.inbound_action,
                profile.outbound_action,
            ))?;
        }
        Ok(())
    }
    pub fn isolation_controls_active(state: &State) -> Result<bool, String> {
        if firewall_rule_present(ISOLATE_RULE_IN)? || firewall_rule_present(ISOLATE_RULE_OUT)? {
            return Ok(true);
        }
        let current_profiles = snapshot_firewall_profiles()?;
        let profiles_fully_blocked = firewall_profiles_fully_blocked(&current_profiles);
        let firewall_controls_active = if let Some(snapshot) = state.firewall_snapshot.as_ref() {
            current_profiles != *snapshot && profiles_fully_blocked
        } else {
            profiles_fully_blocked
        };
        if firewall_controls_active {
            return Ok(true);
        }
        if let Some(snapshot) = state.network_snapshot.as_ref() {
            if !snapshot.adapters.is_empty() && !snapshot_adapters_are_enabled(snapshot)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn snapshot_active_adapters() -> Result<NetworkSnapshot, String> {
        let wifi_profiles = snapshot_connected_wifi_profiles();
        let output = run_powershell_json(
            "$if_indexes = @(); $if_indexes += Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -or $_.IPv6DefaultGateway -ne $null } | Select-Object -ExpandProperty InterfaceIndex; $if_indexes += Get-NetRoute -DestinationPrefix '0.0.0.0/0' -State Alive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceIndex; $if_indexes += Get-NetRoute -DestinationPrefix '::/0' -State Alive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceIndex; $if_indexes = @($if_indexes | Where-Object { $_ -ne $null } | Sort-Object -Unique); if ($if_indexes.Count -eq 0) { @() | ConvertTo-Json -Compress } else { Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne 'Loopback Pseudo-Interface 1' -and $if_indexes -contains $_.ifIndex } | Select-Object Name,InterfaceDescription,NdisPhysicalMedium | ConvertTo-Json -Compress }",
        )?;
        let adapters = parse_adapter_snapshot(&output, &wifi_profiles)?;
        Ok(NetworkSnapshot { adapters })
    }
    pub fn disable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        for adapter in &snapshot.adapters {
            run_powershell(&format!(
                "Disable-NetAdapter -Name {} -Confirm:$false -ErrorAction Stop",
                ps_quoted(&adapter.name)
            ))?;
        }
        Ok(())
    }
    pub fn enable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        let mut warnings = Vec::new();
        let mut recovered_any = false;
        for adapter in &snapshot.adapters {
            let result = run_powershell(&format!(
                "$adapter = Get-NetAdapter -Name {} -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $adapter) {{ 'MISSING' }} else {{ if ($adapter.Status -ne 'Up') {{ Enable-NetAdapter -Name {} -Confirm:$false -ErrorAction Stop }}; 'READY' }}",
                ps_quoted(&adapter.name),
                ps_quoted(&adapter.name)
            ));
            let output = match result {
                Ok(output) => output,
                Err(err) => {
                    warnings.push(format!("{}: {err}", adapter.name));
                    continue;
                }
            };
            if output.trim().eq_ignore_ascii_case("MISSING") {
                warnings.push(format!(
                    "{}: adapter not found during restore",
                    adapter.name
                ));
                continue;
            }
            recovered_any = true;
            if adapter.is_wireless {
                schedule_wireless_reconnect(adapter.name.clone(), adapter.wifi_profile.clone());
            }
        }
        if recovered_any {
            return Ok(());
        }
        if let Ok(current) = snapshot_active_adapters() {
            if !current.adapters.is_empty() {
                return Ok(());
            }
        }
        if warnings.is_empty() {
            Err("no saved adapters could be restored".into())
        } else {
            Err(warnings.join("; "))
        }
    }
    pub fn enable_all_network_adapters() -> Result<usize, String> {
        let wifi_profiles = snapshot_connected_wifi_profiles();
        let output = run_powershell_json(
            "Get-NetAdapter | Where-Object { $_.Name -ne 'Loopback Pseudo-Interface 1' -and $_.Status -ne 'Up' -and $_.HardwareInterface -eq $true } | Select-Object Name,InterfaceDescription,NdisPhysicalMedium | ConvertTo-Json -Compress",
        )?;
        let adapters = parse_adapter_snapshot(&output, &wifi_profiles)?;
        let mut enabled = 0usize;
        for adapter in adapters {
            run_powershell(&format!(
                "Enable-NetAdapter -Name {} -Confirm:$false -ErrorAction Stop",
                ps_quoted(&adapter.name)
            ))?;
            enabled += 1;
            if adapter.is_wireless {
                schedule_wireless_reconnect(adapter.name.clone(), adapter.wifi_profile.clone());
            }
        }
        Ok(enabled)
    }
    pub fn terminate_active_tcp_connections() -> Result<usize, String> {
        let output = run_powershell_json(
            "Get-NetTCPConnection -State Established | Where-Object { $_.LocalAddress -notmatch ':' -and $_.RemoteAddress -notmatch ':' } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json -Compress",
        )?;
        let targets = parse_tcp_session_snapshot(&output)?;
        let mut reset = 0usize;
        for target in targets {
            let local = SocketAddr::new(
                target
                    .local_address
                    .parse()
                    .map_err(|e| format!("invalid local address {}: {e}", target.local_address))?,
                target.local_port,
            );
            let remote = SocketAddr::new(
                target.remote_address.parse().map_err(|e| {
                    format!("invalid remote address {}: {e}", target.remote_address)
                })?,
                target.remote_port,
            );
            if let Err(err) = kill_tcp_connection(&SocketKillTarget { local, remote }) {
                match err {
                    // Some Windows builds report 317 for already-closed sockets;
                    // it is noisy but does not prevent isolation.
                    SocketKillError::OsError(317) => continue,
                    SocketKillError::UnsupportedAddressFamily => continue,
                    other => return Err(other.to_string()),
                }
            }
            reset += 1;
        }
        Ok(reset)
    }
    pub fn suspend_process(pid: u32) -> Result<(), String> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| format!("failed to snapshot threads for PID {pid}: {e}"))?
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("failed to snapshot threads for PID {pid}"));
        }
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut success_count = 0usize;
        let first = unsafe { Thread32First(snapshot, &mut entry).is_ok() };
        if first {
            loop {
                if entry.th32OwnerProcessID == pid {
                    unsafe {
                        if let Ok(thread) =
                            OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                        {
                            let result = SuspendThread(thread);
                            let _ = CloseHandle(thread);
                            if result != u32::MAX {
                                success_count += 1;
                            }
                        }
                    }
                }
                if unsafe { Thread32Next(snapshot, &mut entry).is_err() } {
                    break;
                }
            }
        }
        let _ = unsafe { CloseHandle(snapshot) };
        if success_count == 0 {
            Err(format!("no suspendable threads were found for PID {pid}"))
        } else {
            Ok(())
        }
    }
    pub fn resume_process(pid: u32) -> Result<(), String> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| format!("failed to snapshot threads for PID {pid}: {e}"))?
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("failed to snapshot threads for PID {pid}"));
        }
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut success_count = 0usize;
        let first = unsafe { Thread32First(snapshot, &mut entry).is_ok() };
        if first {
            loop {
                if entry.th32OwnerProcessID == pid {
                    unsafe {
                        if let Ok(thread) =
                            OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                        {
                            let result = ResumeThread(thread);
                            let _ = CloseHandle(thread);
                            if result != u32::MAX {
                                success_count += 1;
                            }
                        }
                    }
                }
                if unsafe { Thread32Next(snapshot, &mut entry).is_err() } {
                    break;
                }
            }
        }
        let _ = unsafe { CloseHandle(snapshot) };
        if success_count == 0 {
            Err(format!("no resumable threads were found for PID {pid}"))
        } else {
            Ok(())
        }
    }
    pub fn add_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        let path = hosts_path()?;
        let existing = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if existing.contains(marker) {
            return Ok(());
        }
        let addition = format!("\r\n{marker}\r\n127.0.0.1 {domain}\r\n::1 {domain}\r\n");
        fs::write(&path, format!("{existing}{addition}"))
            .map_err(|e| format!("failed to update {}: {e}", path.display()))?;
        let _ = flush_dns();
        Ok(())
    }
    pub fn remove_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        let path = hosts_path()?;
        let existing = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let target_v4 = format!("127.0.0.1 {domain}");
        let target_v6 = format!("::1 {domain}");
        let mut lines = Vec::new();
        let mut skipping = false;
        for line in existing.lines() {
            let trimmed = line.trim();
            if trimmed == marker {
                skipping = true;
                continue;
            }
            if skipping && (trimmed == target_v4 || trimmed == target_v6) {
                continue;
            }
            if skipping && !trimmed.is_empty() {
                skipping = false;
            }
            if !skipping || trimmed.is_empty() {
                lines.push(line);
            }
        }
        fs::write(&path, lines.join("\r\n"))
            .map_err(|e| format!("failed to update {}: {e}", path.display()))?;
        let _ = flush_dns();
        Ok(())
    }
    fn flush_dns() -> Result<(), String> {
        let status = hidden_command("ipconfig")
            .arg("/flushdns")
            .status()
            .map_err(|e| format!("failed to spawn ipconfig: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("ipconfig /flushdns failed".into())
        }
    }
    fn hosts_path() -> Result<PathBuf, String> {
        let windows_dir = windows_directory()
            .ok_or_else(|| "failed to resolve the Windows directory".to_string())?;
        Ok(windows_dir
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts"))
    }
    fn windows_directory() -> Option<PathBuf> {
        let mut buffer = vec![0u16; 260];
        unsafe {
            let len = GetSystemWindowsDirectoryW(Some(&mut buffer));
            if len == 0 {
                return None;
            }
            let len = len as usize;
            if len >= buffer.len() {
                buffer.resize(len + 1, 0);
                let retry_len = GetSystemWindowsDirectoryW(Some(&mut buffer));
                if retry_len == 0 {
                    return None;
                }
                return Some(PathBuf::from(String::from_utf16_lossy(
                    &buffer[..retry_len as usize],
                )));
            }
            Some(PathBuf::from(String::from_utf16_lossy(&buffer[..len])))
        }
    }
    pub fn kill_tcp_connection(target: &SocketKillTarget) -> Result<(), SocketKillError> {
        let local = match target.local {
            SocketAddr::V4(local) => local,
            SocketAddr::V6(_) => return Err(SocketKillError::UnsupportedAddressFamily),
        };
        let remote = match target.remote {
            SocketAddr::V4(remote) => remote,
            SocketAddr::V6(_) => return Err(SocketKillError::UnsupportedAddressFamily),
        };
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 {
                State: MIB_TCP_STATE_DELETE_TCB,
            },
            dwLocalAddr: u32::from_be_bytes(local.ip().octets()),
            dwLocalPort: u32::from(local.port().to_be()),
            dwRemoteAddr: u32::from_be_bytes(remote.ip().octets()),
            dwRemotePort: u32::from(remote.port().to_be()),
        };
        let status = unsafe { SetTcpEntry(&row) };
        if status == NO_ERROR.0 {
            Ok(())
        } else if status == ERROR_ACCESS_DENIED.0 {
            Err(SocketKillError::PermissionDenied)
        } else {
            Err(SocketKillError::OsError(status))
        }
    }
    pub fn add_block_rule(rule_name: &str, target: &str) -> Result<(), String> {
        let status = hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                "dir=out",
                "action=block",
                &format!("remoteip={target}"),
                "profile=any",
                "enable=yes",
            ])
            .status()
            .map_err(|e| format!("failed to spawn netsh: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("failed to add firewall rule for {target}"))
        }
    }
    pub fn add_block_all_rule(rule_name: &str, dir: &str) -> Result<(), String> {
        let status = hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                &format!("dir={dir}"),
                "action=block",
                "remoteip=any",
                "profile=any",
                "enable=yes",
            ])
            .status()
            .map_err(|e| format!("failed to spawn netsh: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("failed to add isolation rule {rule_name}"))
        }
    }
    pub fn add_block_program_rule(
        rule_name: &str,
        _pid: u32,
        path: &str,
        dir: &str,
    ) -> Result<(), String> {
        let status = hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                &format!("dir={dir}"),
                "action=block",
                &format!("program={path}"),
                "profile=any",
                "enable=yes",
            ])
            .status()
            .map_err(|e| format!("failed to spawn netsh: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("failed to add process firewall rule {rule_name}"))
        }
    }
    pub fn delete_rule(rule_name: &str) -> Result<(), String> {
        let status = hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={rule_name}"),
            ])
            .status()
            .map_err(|e| format!("failed to spawn netsh: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("failed to delete firewall rule {rule_name}"))
        }
    }
    fn firewall_rule_present(rule_name: &str) -> Result<bool, String> {
        let output = hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={rule_name}"),
            ])
            .output()
            .map_err(|e| format!("failed to spawn netsh: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        let merged = format!("{stdout}\n{stderr}");
        if merged.contains("no rules match") {
            return Ok(false);
        }
        Ok(output.status.success())
    }
    fn firewall_profiles_fully_blocked(snapshot: &FirewallSnapshot) -> bool {
        !snapshot.profiles.is_empty()
            && snapshot.profiles.iter().all(|profile| {
                profile.enabled
                    && profile.inbound_action.eq_ignore_ascii_case("Block")
                    && profile.outbound_action.eq_ignore_ascii_case("Block")
            })
    }
    fn snapshot_adapters_are_enabled(snapshot: &NetworkSnapshot) -> Result<bool, String> {
        let mut saw_known_adapter = false;
        let mut saw_enabled_adapter = false;
        for adapter in &snapshot.adapters {
            let status = run_powershell(&format!(
                "(Get-NetAdapter -Name {} -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Status)",
                ps_quoted(&adapter.name)
            ))?;
            let status = status.trim();
            if status.is_empty() {
                continue;
            }
            saw_known_adapter = true;
            // "Disconnected" still means the adapter is enabled; only treat
            // explicit "Disabled" as still being isolated by adapter cutoff.
            if !status.eq_ignore_ascii_case("Disabled") {
                saw_enabled_adapter = true;
                break;
            }
        }
        if saw_enabled_adapter {
            return Ok(true);
        }
        if saw_known_adapter {
            return Ok(false);
        }
        Ok(true)
    }
    fn schedule_wireless_reconnect(name: String, profile: Option<String>) {
        let _ = std::thread::Builder::new()
            .name("vigil-wifi-reconnect".into())
            .spawn(move || {
                let _ = reconnect_wireless_adapter(&name, profile.as_deref());
            });
    }
    fn run_powershell(script: &str) -> Result<String, String> {
        let script = format!("$ErrorActionPreference = 'Stop'; {script}");
        let output = hidden_command("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .output()
            .map_err(|e| format!("failed to spawn powershell: {e}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(format!(
                "powershell failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
    fn run_powershell_json(script: &str) -> Result<String, String> {
        run_powershell(script)
    }
    fn snapshot_connected_wifi_profiles() -> BTreeMap<String, String> {
        let output = hidden_command("netsh")
            .args(["wlan", "show", "interfaces"])
            .output();
        let Ok(output) = output else {
            return BTreeMap::new();
        };
        if !output.status.success() {
            return BTreeMap::new();
        }
        parse_wifi_profile_map(&String::from_utf8_lossy(&output.stdout))
    }
    fn reconnect_wireless_adapter(name: &str, profile: Option<&str>) -> Result<(), String> {
        // Give Windows a brief moment to bring the radio interface fully up.
        std::thread::sleep(Duration::from_millis(900));
        if let Some(profile) = profile {
            let status = hidden_command("netsh")
                .args([
                    "wlan",
                    "connect",
                    &format!("name={profile}"),
                    &format!("interface={name}"),
                ])
                .status()
                .map_err(|e| format!("failed to spawn netsh wlan connect: {e}"))?;
            if status.success() {
                return Ok(());
            }
        }
        for _ in 0..4 {
            let status = hidden_command("netsh")
                .args(["wlan", "reconnect", &format!("interface={name}")])
                .status()
                .map_err(|e| format!("failed to spawn netsh wlan reconnect: {e}"))?;
            if status.success() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(900));
        }
        Err(format!("netsh wlan reconnect failed for {name}"))
    }
    fn hidden_command<S: AsRef<OsStr>>(program: S) -> Command {
        let mut cmd = Command::new(program);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }
    fn ps_quoted(text: &str) -> String {
        format!("'{}'", text.replace('\'', "''"))
    }
    fn parse_firewall_snapshot(text: &str) -> Result<FirewallSnapshot, String> {
        if text.trim().is_empty() {
            return Ok(FirewallSnapshot { profiles: vec![] });
        }
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| format!("failed to parse firewall profile snapshot: {e}"))?;
        let mut profiles = Vec::new();
        let items = match value {
            serde_json::Value::Array(items) => items,
            serde_json::Value::Object(map) => vec![serde_json::Value::Object(map)],
            serde_json::Value::Null => Vec::new(),
            other => {
                return Err(format!(
                    "unexpected firewall profile snapshot shape: {other}"
                ))
            }
        };
        for item in items {
            let Some(name) = item.get("Name").and_then(|v| v.as_str()) else {
                continue;
            };
            let enabled = item
                .get("Enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let inbound_action = item
                .get("DefaultInboundAction")
                .and_then(|v| v.as_str())
                .unwrap_or("Block")
                .to_string();
            let outbound_action = item
                .get("DefaultOutboundAction")
                .and_then(|v| v.as_str())
                .unwrap_or("Block")
                .to_string();
            profiles.push(FirewallProfileState {
                name: name.to_string(),
                enabled,
                inbound_action,
                outbound_action,
            });
        }
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(FirewallSnapshot { profiles })
    }
    fn parse_tcp_session_snapshot(text: &str) -> Result<Vec<TcpSessionState>, String> {
        if text.trim().is_empty() {
            return Ok(vec![]);
        }
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| format!("failed to parse TCP session snapshot: {e}"))?;
        let items = match value {
            serde_json::Value::Array(items) => items,
            serde_json::Value::Object(map) => vec![serde_json::Value::Object(map)],
            serde_json::Value::Null => Vec::new(),
            other => {
                return Err(format!("unexpected TCP session snapshot shape: {other}"));
            }
        };
        let mut sessions = Vec::new();
        for item in items {
            let local_address = item
                .get("LocalAddress")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let remote_address = item
                .get("RemoteAddress")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let local_port = item
                .get("LocalPort")
                .and_then(|v| v.as_u64())
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(0);
            let remote_port = item
                .get("RemotePort")
                .and_then(|v| v.as_u64())
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(0);
            if !local_address.trim().is_empty()
                && !remote_address.trim().is_empty()
                && local_port != 0
                && remote_port != 0
            {
                sessions.push(TcpSessionState {
                    local_address,
                    local_port,
                    remote_address,
                    remote_port,
                });
            }
        }
        Ok(sessions)
    }
    fn parse_adapter_snapshot(
        text: &str,
        wifi_profiles: &BTreeMap<String, String>,
    ) -> Result<Vec<NetworkAdapterState>, String> {
        if text.trim().is_empty() {
            return Ok(vec![]);
        }
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("failed to parse adapter list: {e}"))?;
        let items = match value {
            serde_json::Value::Array(items) => items,
            serde_json::Value::Object(map) => vec![serde_json::Value::Object(map)],
            serde_json::Value::Null => Vec::new(),
            other => {
                return Err(format!("unexpected adapter list shape: {other}"));
            }
        };
        let mut adapters = Vec::new();
        for item in items {
            let Some(name) = item.get("Name").and_then(|v| v.as_str()) else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let medium = item
                .get("NdisPhysicalMedium")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let description = item
                .get("InterfaceDescription")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let is_wireless = medium.contains("802")
                || medium.contains("wireless")
                || description.contains("wi-fi")
                || description.contains("wifi")
                || description.contains("wireless")
                || description.contains("wlan");
            adapters.push(NetworkAdapterState {
                name: name.to_string(),
                is_wireless,
                wifi_profile: wifi_profiles.get(name).cloned(),
            });
        }
        Ok(adapters)
    }
    fn parse_wifi_profile_map(text: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut current_name: Option<String> = None;
        let mut current_profile: Option<String> = None;
        let mut current_ssid: Option<String> = None;
        let mut connected = false;
        let flush = |out: &mut BTreeMap<String, String>,
                     name: &mut Option<String>,
                     profile: &mut Option<String>,
                     ssid: &mut Option<String>,
                     connected: &mut bool| {
            if *connected {
                if let Some(iface) = name.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
                    if let Some(value) = profile
                        .as_ref()
                        .or(ssid.as_ref())
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                    {
                        out.insert(iface.to_string(), value.to_string());
                    }
                }
            }
            *name = None;
            *profile = None;
            *ssid = None;
            *connected = false;
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some((key, value)) = trimmed.split_once(':') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            let is_name_key = key == "name" || key == "nombre";
            if is_name_key {
                flush(
                    &mut out,
                    &mut current_name,
                    &mut current_profile,
                    &mut current_ssid,
                    &mut connected,
                );
                current_name = Some(value.to_string());
                continue;
            }
            if key == "state" || key == "estado" {
                let lower = value.to_ascii_lowercase();
                connected = lower.starts_with("connected") || lower.starts_with("conectad");
                continue;
            }
            if key == "profile" || key == "perfil" {
                current_profile = Some(value.to_string());
                continue;
            }
            if key == "ssid" {
                current_ssid = Some(value.to_string());
            }
        }
        flush(
            &mut out,
            &mut current_name,
            &mut current_profile,
            &mut current_ssid,
            &mut connected,
        );
        out
    }
}
#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::path::Path;
    use std::process::Stdio;
    pub struct AutorunRevertResult {
        pub removed_additions: usize,
        pub restored_entries: usize,
    }
    pub fn is_supported() -> bool {
        cfg!(target_os = "linux")
    }
    pub fn supports_isolation() -> bool {
        cfg!(target_os = "linux") || cfg!(target_os = "macos")
    }
    pub fn is_elevated() -> bool {
        // Root always has privileges.
        if unsafe { libc::geteuid() == 0 } {
            return true;
        }
        // Check CAP_NET_ADMIN (bit 12) from /proc/self/status CapEff.
        check_capability(12)
    }
    /// Check whether a specific Linux capability (by bit index) is present in
    /// the effective capability set of the current process.
    #[cfg(target_os = "linux")]
    fn check_capability(bit: u8) -> bool {
        let Ok(data) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        for line in data.lines() {
            let Some(rest) = line.strip_prefix("CapEff:\t") else {
                continue;
            };
            let Ok(val) = u64::from_str_radix(rest.trim(), 16) else {
                return false;
            };
            return val & (1u64 << bit) != 0;
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    fn check_capability(_bit: u8) -> bool {
        false
    }
    pub fn process_exists(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        command_base("kill", &["-0", &pid.to_string()])
            .and_then(|mut cmd| {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                cmd.status()
                    .map_err(|e| format!("failed to spawn kill: {e}"))
            })
            .map(|status| status.success())
            .unwrap_or(false)
    }
    pub fn snapshot_autoruns() -> Result<AutorunSnapshot, String> {
        Err("Autorun freezing is not implemented on this platform.".into())
    }
    pub fn revert_autorun_changes(
        _baseline: &[AutorunEntry],
    ) -> Result<AutorunRevertResult, String> {
        Err("Autorun revert is not implemented on this platform.".into())
    }

    // ── Firewall / iptables operations (Linux) ─────────────────────────────

    const IPTABLES_COMMENT_PREFIX: &str = "Vigil:";

    pub fn snapshot_firewall_profiles() -> Result<FirewallSnapshot, String> {
        #[cfg(target_os = "linux")]
        {
            let output = command_stdout("iptables", &["-L", "-n"])?;
            let mut profiles = Vec::new();
            for line in output.lines() {
                let l = line.trim();
                // Default policy lines look like: "Chain INPUT (policy DROP)"
                if let Some(rest) = l.strip_prefix("Chain ") {
                    let mut parts = rest.splitn(2, ' ');
                    let chain = parts.next().unwrap_or("");
                    let policy_part = parts.next().unwrap_or("");
                    if let Some(policy) = policy_part
                        .trim_start_matches('(')
                        .strip_prefix("policy ")
                        .and_then(|s| s.strip_suffix(')'))
                    {
                        profiles.push(format!("{chain}:{policy}"));
                    }
                }
            }
            return Ok(FirewallSnapshot { profiles });
        }
        #[allow(unreachable_code)]
        Ok(FirewallSnapshot { profiles: vec![] })
    }
    pub fn apply_firewall_isolation() -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            for chain in &["INPUT", "FORWARD", "OUTPUT"] {
                command_status("iptables", &["-P", chain, "DROP"])?;
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err("firewall backend unavailable; falling back to emergency adapter cutoff".into())
    }
    pub fn restore_firewall_profiles(_snapshot: &FirewallSnapshot) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            for entry in &_snapshot.profiles {
                let mut parts = entry.splitn(2, ':');
                let chain = parts.next().unwrap_or("");
                let policy = parts.next().unwrap_or("ACCEPT");
                if !chain.is_empty() {
                    command_status("iptables", &["-P", chain, policy])?;
                }
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Ok(())
    }
    pub fn isolation_controls_active(state: &State) -> Result<bool, String> {
        // If firewall snapshot exists with non-empty profiles, iptables isolation is active.
        if let Some(snapshot) = state.firewall_snapshot.as_ref() {
            if !snapshot.profiles.is_empty() {
                // Check if current iptables policies are DROP.
                let current = snapshot_firewall_profiles()?;
                let all_drop = current.profiles.iter().all(|p| p.ends_with(":DROP"));
                if all_drop {
                    return Ok(true);
                }
            }
        }
        // Adapter-level fallback.
        let Some(snapshot) = state.network_snapshot.as_ref() else {
            return Ok(false);
        };
        if snapshot.adapters.is_empty() {
            return Ok(false);
        }
        let current = snapshot_active_adapters()?;
        let mut saw_known_adapter = false;
        for adapter in &snapshot.adapters {
            if current
                .adapters
                .iter()
                .any(|item| item.name == adapter.name)
            {
                saw_known_adapter = true;
                return Ok(false);
            }
        }
        Ok(saw_known_adapter)
    }
    pub fn add_block_all_rule(rule_name: &str, dir: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let chain = match dir {
                "out" => "OUTPUT",
                "in" => "INPUT",
                _ => "OUTPUT",
            };
            let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
            command_status(
                "iptables",
                &[
                    "-I",
                    chain,
                    "1",
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rule_name, dir);
            Err("Active response is not implemented on this platform.".into())
        }
    }
    pub fn add_block_rule(rule_name: &str, target: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
            command_status(
                "iptables",
                &[
                    "-I",
                    "OUTPUT",
                    "1",
                    "-d",
                    target,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rule_name, target);
            Err("Active response is not implemented on this platform.".into())
        }
    }
    pub fn add_block_program_rule(
        rule_name: &str,
        pid: u32,
        path: &str,
        dir: &str,
    ) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let chain = match dir {
                "out" => "OUTPUT",
                "in" => "INPUT",
                _ => "OUTPUT",
            };
            let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
            let mut args = vec!["-I", chain, "1"];
            if chain == "OUTPUT" {
                let uid = process_effective_uid(pid)?;
                args.extend_from_slice(&["-m", "owner", "--uid-owner"]);
                let uid_string = uid.to_string();
                args.push(uid_string.as_str());
                args.extend_from_slice(&["-m", "comment", "--comment", &comment, "-j", "DROP"]);
                return command_status("iptables", &args);
            }
            args.extend_from_slice(&["-m", "comment", "--comment", &comment, "-j", "DROP"]);
            command_status("iptables", &args)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rule_name, path, dir);
            Err("Active response is not implemented on this platform.".into())
        }
    }
    pub fn delete_rule(rule_name: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
            let mut failures = Vec::new();
            let mut deleted = 0usize;
            for chain in &["INPUT", "OUTPUT", "FORWARD"] {
                match command_status(
                    "iptables",
                    &[
                        "-D",
                        chain,
                        "-m",
                        "comment",
                        "--comment",
                        &comment,
                        "-j",
                        "DROP",
                    ],
                ) {
                    Ok(()) => deleted += 1,
                    Err(err) => failures.push(format!("{chain}: {err}")),
                }
            }
            if deleted > 0 {
                Ok(())
            } else {
                Err(format!(
                    "failed to delete firewall rule {rule_name}: {}",
                    failures.join("; ")
                ))
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = rule_name;
            Ok(())
        }
    }

    // ── Process control (Linux: SIGSTOP / SIGCONT) ─────────────────────────

    pub fn suspend_process(pid: u32) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            command_status("kill", &["-STOP", &pid.to_string()])
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Err("Process suspension is not implemented on this platform.".into())
        }
    }
    pub fn resume_process(pid: u32) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            command_status("kill", &["-CONT", &pid.to_string()])
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Err("Process resume is not implemented on this platform.".into())
        }
    }

    // ── TCP connection kill (Linux: ss -K) ─────────────────────────────────

    pub fn kill_tcp_connection(target: &SocketKillTarget) -> Result<(), SocketKillError> {
        #[cfg(target_os = "linux")]
        {
            let status = Command::new("ss")
                .args([
                    "-K",
                    "dst",
                    &target.remote_ip.to_string(),
                    "dport",
                    "=",
                    &target.remote_port.to_string(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|_| SocketKillError::OsError("failed to spawn ss".into()))?;
            if status.success() {
                Ok(())
            } else {
                Err(SocketKillError::OsError("ss -K failed".into()))
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            Err(SocketKillError::PlatformUnsupported)
        }
    }
    pub fn terminate_active_tcp_connections() -> Result<usize, String> {
        #[cfg(target_os = "linux")]
        {
            let data = std::fs::read_to_string("/proc/net/tcp")
                .map_err(|e| format!("read /proc/net/tcp: {e}"))?;
            let mut count = 0usize;
            for line in data.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                // State 01 = ESTABLISHED in /proc/net/tcp.
                if parts[3] != "01" {
                    continue;
                }
                let Some((lip, lport)) = parse_hex_addr_port(parts[1]) else {
                    continue;
                };
                let Some((rip, rport)) = parse_hex_addr_port(parts[2]) else {
                    continue;
                };
                let status = Command::new("ss")
                    .args([
                        "-K",
                        "dst",
                        &rip,
                        "dport",
                        "=",
                        &rport.to_string(),
                        "src",
                        &lip,
                        "sport",
                        "=",
                        &lport.to_string(),
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                if status.map(|s| s.success()).unwrap_or(false) {
                    count += 1;
                }
            }
            Ok(count)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("TCP termination is not implemented on this platform.".into())
        }
    }
    /// Parse "AABBCCDD:PPPP" hex format from /proc/net/tcp into (ip_string, port).
    /// The IP is little-endian hex (e.g. "0100007F" = 127.0.0.1).
    #[cfg(target_os = "linux")]
    fn parse_hex_addr_port(s: &str) -> Option<(String, u16)> {
        let (hex_ip, hex_port) = s.split_once(':')?;
        let port = u16::from_str_radix(hex_port, 16).ok()?;
        if hex_ip.len() != 8 {
            return None;
        }
        let bytes = [
            u8::from_str_radix(&hex_ip[6..8], 16).ok()?,
            u8::from_str_radix(&hex_ip[4..6], 16).ok()?,
            u8::from_str_radix(&hex_ip[2..4], 16).ok()?,
            u8::from_str_radix(&hex_ip[0..2], 16).ok()?,
        ];
        Some((
            format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
            port,
        ))
    }

    // ── Domain blocking via /etc/hosts ─────────────────────────────────────

    pub fn add_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let entry = format!("\n{marker}\n127.0.0.1 {domain}\n::1 {domain}\n");
            std::fs::OpenOptions::new()
                .append(true)
                .open("/etc/hosts")
                .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()))
                .map_err(|e| format!("failed to update /etc/hosts: {e}"))?;
            flush_dns();
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (domain, marker);
            Err("Domain blocking is not implemented on this platform.".into())
        }
    }
    pub fn remove_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let content = std::fs::read_to_string("/etc/hosts")
                .map_err(|e| format!("failed to read /etc/hosts: {e}"))?;
            let filtered: String = content
                .lines()
                .filter(|line| {
                    line.trim() != marker && !line.trim().ends_with(&format!(" {domain}"))
                })
                .collect::<Vec<&str>>()
                .join("\n");
            std::fs::write("/etc/hosts", filtered)
                .map_err(|e| format!("failed to write /etc/hosts: {e}"))?;
            flush_dns();
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (domain, marker);
            Err("Domain blocking is not implemented on this platform.".into())
        }
    }
    #[cfg(target_os = "linux")]
    fn flush_dns() {
        // Try systemd-resolve first (older Ubuntu), then resolvectl.
        let _ = command_status("resolvectl", &["flush-caches"]);
        let _ = command_status("systemd-resolve", &["--flush-caches"]);
    }

    // ── Network adapter management ─────────────────────────────────────────

    pub fn snapshot_active_adapters() -> Result<NetworkSnapshot, String> {
        #[cfg(target_os = "linux")]
        {
            let output = command_stdout("ip", &["-o", "link", "show", "up"])?;
            let mut adapters = Vec::new();
            for line in output.lines() {
                let mut parts = line.splitn(3, ':');
                let _ = parts.next();
                let Some(name) = parts.next().map(|p| p.trim()) else {
                    continue;
                };
                if !name.is_empty() && name != "lo" {
                    adapters.push(NetworkAdapterState {
                        name: name.to_string(),
                        is_wireless: false,
                        wifi_profile: None,
                    });
                }
            }
            return Ok(NetworkSnapshot { adapters });
        }
        #[cfg(target_os = "macos")]
        {
            let output = command_stdout("ifconfig", &["-l"])?;
            let mut adapters = Vec::new();
            for name in output.split_whitespace() {
                if name == "lo0" {
                    continue;
                }
                let details = command_stdout("ifconfig", &[name])?;
                if details.contains("status: active") {
                    adapters.push(NetworkAdapterState {
                        name: name.to_string(),
                        is_wireless: false,
                        wifi_profile: None,
                    });
                }
            }
            return Ok(NetworkSnapshot { adapters });
        }
        #[allow(unreachable_code)]
        Err("Network adapter snapshots are not implemented on this platform.".into())
    }
    pub fn disable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            for adapter in &snapshot.adapters {
                command_status("ip", &["link", "set", "dev", &adapter.name, "down"])?;
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            for adapter in &snapshot.adapters {
                command_status("ifconfig", &[&adapter.name, "down"])?;
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err("Network adapter isolation is not implemented on this platform.".into())
    }
    pub fn enable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            for adapter in &snapshot.adapters {
                command_status("ip", &["link", "set", "dev", &adapter.name, "up"])?;
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            for adapter in &snapshot.adapters {
                command_status("ifconfig", &[&adapter.name, "up"])?;
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err("Network adapter restoration is not implemented on this platform.".into())
    }
    pub fn enable_all_network_adapters() -> Result<usize, String> {
        #[cfg(target_os = "linux")]
        {
            let output = command_stdout("ip", &["-o", "link", "show"])?;
            let mut names = Vec::new();
            for line in output.lines() {
                let mut parts = line.splitn(3, ':');
                let _ = parts.next();
                let Some(name) = parts.next().map(|p| p.trim()) else {
                    continue;
                };
                if !name.is_empty() && name != "lo" {
                    names.push(name.to_string());
                }
            }
            let mut enabled = 0usize;
            for name in names {
                if command_status("ip", &["link", "set", "dev", &name, "up"]).is_ok() {
                    enabled += 1;
                }
            }
            return Ok(enabled);
        }
        #[cfg(target_os = "macos")]
        {
            let output = command_stdout("ifconfig", &["-l"])?;
            let mut enabled = 0usize;
            for name in output.split_whitespace() {
                if name == "lo0" {
                    continue;
                }
                if command_status("ifconfig", &[name, "up"]).is_ok() {
                    enabled += 1;
                }
            }
            return Ok(enabled);
        }
        #[allow(unreachable_code)]
        Ok(0)
    }

    // ── Command helpers ────────────────────────────────────────────────────

    fn command_stdout(program: &str, args: &[&str]) -> Result<String, String> {
        let output = command_base(program, args)?
            .output()
            .map_err(|e| format!("failed to spawn {program}: {e}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(format!(
                "{program} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
    fn command_status(program: &str, args: &[&str]) -> Result<(), String> {
        let status = command_base(program, args)?
            .status()
            .map_err(|e| format!("failed to spawn {program}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{program} failed with status {status}"))
        }
    }
    fn command_base(program: &str, args: &[&str]) -> Result<Command, String> {
        let resolved = resolve_program_path(program)?;
        let mut cmd = Command::new(resolved);
        cmd.args(args);
        Ok(cmd)
    }
    fn resolve_program_path(program: &str) -> Result<&'static str, String> {
        let candidates: &[&str] = match program {
            "kill" => &["/bin/kill", "/usr/bin/kill"],
            #[cfg(target_os = "linux")]
            "iptables" => &["/usr/sbin/iptables", "/sbin/iptables"],
            #[cfg(target_os = "linux")]
            "ip" => &["/usr/sbin/ip", "/sbin/ip"],
            #[cfg(target_os = "macos")]
            "ifconfig" => &["/sbin/ifconfig"],
            _ => &[],
        };
        candidates
            .iter()
            .copied()
            .find(|path| Path::new(path).exists())
            .ok_or_else(|| format!("required system binary for {program} not found"))
    }

    #[cfg(target_os = "linux")]
    fn process_effective_uid(pid: u32) -> Result<u32, String> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|e| format!("read /proc/{pid}/status: {e}"))?;
        for line in status.lines() {
            let Some(rest) = line.strip_prefix("Uid:") else {
                continue;
            };
            let mut fields = rest.split_whitespace();
            let _real = fields.next();
            let Some(effective) = fields.next() else {
                return Err(format!("malformed Uid line for pid {pid}"));
            };
            return effective
                .parse::<u32>()
                .map_err(|e| format!("parse effective uid for pid {pid}: {e}"));
        }
        Err(format!("could not read effective uid for pid {pid}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn blocked_target(target: &str, expires_at_unix: Option<u64>) -> BlockedTarget {
        BlockedTarget {
            target: target.to_string(),
            rule_name: format!("rule-{target}"),
            expires_at_unix,
        }
    }
    fn blocked_process(path: &str, expires_at_unix: Option<u64>) -> BlockedProcess {
        BlockedProcess {
            pid: 1234,
            path: path.to_string(),
            inbound_rule_name: format!("in-{path}"),
            outbound_rule_name: format!("out-{path}"),
            expires_at_unix,
        }
    }
    fn blocked_domain(domain: &str) -> BlockedDomain {
        BlockedDomain {
            domain: domain.to_string(),
            marker: domain_marker(domain),
        }
    }
    fn suspended_process(pid: u32, path: &str) -> SuspendedProcess {
        SuspendedProcess {
            pid,
            path: path.to_string(),
            proc_name: "app.exe".into(),
            suspended_at_unix: 10,
        }
    }
    fn conn(local: &str, remote: &str, status: &str) -> ConnInfo {
        ConnInfo {
            timestamp: "12:00:00".into(),
            proc_name: "evil.exe".into(),
            pid: 4242,
            proc_path: "C:/Temp/evil.exe".into(),
            proc_user: "user".into(),
            parent_name: "cmd.exe".into(),
            parent_pid: 123,
            parent_user: "user".into(),
            service_name: String::new(),
            publisher: String::new(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            status: status.into(),
            score: 9,
            reasons: vec!["test".into()],
            ancestor_chain: vec![("cmd.exe".into(), 123)],
            pre_login: false,
            hostname: Some("c2.bad.example".into()),
            country: None,
            asn: None,
            asn_org: None,
            reputation_hit: None,
            recently_dropped: false,
            long_lived: false,
            dga_like: false,
            baseline_deviation: false,
            script_host_suspicious: false,
            command_line: String::new(),
            attack_tags: Vec::new(),
            tls_sni: None,
            tls_ja3: None,
        }
    }
    #[test]
    fn reconcile_keeps_expired_entries_when_deletion_fails() {
        let mut state = State {
            blocked: vec![blocked_target("10.0.0.1", Some(10))],
            blocked_processes: vec![blocked_process("C:/app.exe", Some(10))],
            blocked_domains: vec![blocked_domain("bad.example")],
            suspended_processes: vec![],
            autorun_snapshot: None,
            firewall_snapshot: None,
            network_snapshot: None,
            isolated: false,
            isolation_started_unix: None,
            isolation_expires_unix: None,
        };
        let changed = reconcile_state(&mut state, 100, |_| false);
        assert!(!changed);
        assert_eq!(state.blocked.len(), 1);
        assert_eq!(state.blocked_processes.len(), 1);
        assert_eq!(state.blocked_domains.len(), 1);
    }
    #[test]
    fn reconcile_removes_expired_entries_after_successful_deletion() {
        let mut deleted = Vec::new();
        let mut state = State {
            blocked: vec![blocked_target("10.0.0.1", Some(10))],
            blocked_processes: vec![blocked_process("C:/app.exe", Some(10))],
            blocked_domains: vec![],
            suspended_processes: vec![],
            autorun_snapshot: None,
            firewall_snapshot: None,
            network_snapshot: None,
            isolated: false,
            isolation_started_unix: None,
            isolation_expires_unix: None,
        };
        let changed = reconcile_state(&mut state, 100, |rule| {
            deleted.push(rule.to_string());
            true
        });
        assert!(changed);
        assert!(state.blocked.is_empty());
        assert!(state.blocked_processes.is_empty());
        assert_eq!(
            deleted,
            vec![
                "rule-10.0.0.1".to_string(),
                "in-C:/app.exe".to_string(),
                "out-C:/app.exe".to_string()
            ]
        );
    }
    #[test]
    fn process_blocks_match_by_path_only() {
        let rule = BlockedProcess {
            pid: 1234,
            path: "C:/app.exe".into(),
            inbound_rule_name: "in".into(),
            outbound_rule_name: "out".into(),
            expires_at_unix: Some(200),
        };
        assert!(process_block_matches(&rule, "C:/app.exe"));
        assert!(!process_block_matches(&rule, "C:/other.exe"));
    }
    #[test]
    fn suspended_processes_match_on_pid_and_optional_path() {
        let entry = suspended_process(1234, "C:/app.exe");
        assert!(suspended_process_matches(&entry, 1234, "C:/app.exe"));
        assert!(suspended_process_matches(&entry, 1234, ""));
        assert!(!suspended_process_matches(&entry, 9999, "C:/app.exe"));
    }
    #[test]
    fn socket_kill_target_accepts_established_ipv4_connections() {
        let parsed =
            socket_kill_target(&conn("192.168.1.10:50000", "8.8.8.8:443", "ESTABLISHED")).unwrap();
        assert_eq!(parsed.local.to_string(), "192.168.1.10:50000");
        assert_eq!(parsed.remote.to_string(), "8.8.8.8:443");
    }
    #[test]
    fn socket_kill_target_rejects_listen_rows() {
        let err = socket_kill_target(&conn("0.0.0.0:80", "0.0.0.0:0", "LISTEN")).unwrap_err();
        assert!(matches!(err, SocketKillError::UnsupportedStatus(_)));
    }
    #[test]
    fn socket_kill_target_rejects_invalid_remote() {
        let err = socket_kill_target(&conn(
            "192.168.1.10:50000",
            "not-an-endpoint",
            "ESTABLISHED",
        ))
        .unwrap_err();
        assert!(matches!(err, SocketKillError::InvalidRemoteAddr(_)));
    }
    #[test]
    fn socket_kill_target_rejects_ipv6_for_now() {
        let err = socket_kill_target(&conn(
            "[::1]:50000",
            "[2606:4700:4700::1111]:443",
            "ESTABLISHED",
        ))
        .unwrap_err();
        assert!(matches!(err, SocketKillError::UnsupportedAddressFamily));
    }
    #[test]
    fn extract_remote_target_supports_ipv4_and_ipv6() {
        assert_eq!(
            extract_remote_target("8.8.8.8:443").as_deref(),
            Some("8.8.8.8")
        );
        assert_eq!(
            extract_remote_target("[2606:4700:4700::1111]:443").as_deref(),
            Some("2606:4700:4700::1111")
        );
        assert_eq!(
            extract_remote_target("2606:4700:4700::1111:443").as_deref(),
            Some("2606:4700:4700::1111")
        );
    }
    #[test]
    fn extract_domain_target_uses_hostname() {
        let sample = conn("192.168.1.10:50000", "8.8.8.8:443", "ESTABLISHED");
        assert_eq!(
            extract_domain_target(&sample).as_deref(),
            Some("c2.bad.example")
        );
        assert_eq!(extract_domain_from_hostname("8.8.8.8"), None);
    }
}
