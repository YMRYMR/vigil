//! Active response: reversible, auditable intervention actions.
//!
//! Phase 11 starts with practical controls for blocking traffic, killing a
//! live socket, suspending a suspicious process, blocking a suspicious domain,
//! and isolating the machine. The module persists a tiny state file so rules
//! can be reconciled and the UI can reflect the current status after restarts.

use crate::{audit, quarantine, types::ConnInfo};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const STATE_FILE: &str = "vigil-active-response.json";
const BLOCK_RULE_PREFIX: &str = "Vigil Block";
const PROCESS_BLOCK_RULE_PREFIX: &str = "Vigil Proc Block";
const DOMAIN_MARKER_PREFIX: &str = "# Vigil Domain Block";
const ISOLATE_RULE_IN: &str = "Vigil Isolate In";
const ISOLATE_RULE_OUT: &str = "Vigil Isolate Out";
const ISOLATION_MAX_SECS: u64 = 60 * 60;
const ISOLATION_ACTIVATION_GRACE_SECS: u64 = 20;
const PROCESS_RULE_PREFIX_LEN: usize = 48;
const PROCESS_RULE_FINGERPRINT_LEN: usize = 16;
const QUERY_STATE_CACHE_TTL: Duration = Duration::from_millis(250);

#[path = "active_response_platform.rs"]
mod platform;

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
        format!("No hosts-file block found for {domain}." )
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
        if let Err(err) = save_state(&state) {
            note_state_load_error_once("reconcile_save", &err);
        }
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
    let mut state = load_state()?;
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
    let mut state = load_state()?;
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
        format!("Removed {removed} block rule(s) for {target}." )
    } else {
        format!("No active block rule found for {target}." )
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
    let mut state = load_state()?;
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
    let mut state = load_state()?;
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
        return Err(format!("Could not remove all firewall rules for {path}; the remaining state was preserved so Vigil can retry."));
    }
    let message = if removed > 0 {
        save_state(&state)?;
        format!("Removed {removed} process block rule set(s) for PID {pid} ({path}).")
    } else {
        format!("No process block rule found for PID {pid} ({path}).")
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
    let timeout_secs = isolation_timeout_secs(crate::config::Config::load().map(|cfg| cfg.sanitised_lockdown_timeout_mins()).unwrap_or(60));
    let previous_state = load_state()?;
    let now = unix_now();
    let firewall_snapshot = platform::snapshot_firewall()?;
    let network_snapshot = platform::snapshot_network()?;
    platform::apply_isolation(&firewall_snapshot, &network_snapshot).map_err(|err| {
        with_isolation_rollback(err, &previous_state, &firewall_snapshot)
    })?;
    let mut state = previous_state.clone();
    stage_isolation_state(
        &mut state,
        firewall_snapshot,
        network_snapshot,
        now,
        timeout_secs,
    );
    if let Err(err) = save_state(&state) {
        return Err(with_isolation_rollback(err, &previous_state, state.firewall_snapshot.as_ref().unwrap()));
    }
    match crate::config::Config::load() {
        Ok(cfg) => {
            let _ = crate::break_glass::sync_watchdog(&cfg);
        }
        Err(err) => note_state_load_error_once("isolate_config", &err),
    }
    audit::record(
        "isolate_machine",
        "success",
        json!({ "timeout_secs": timeout_secs, "expires_at_unix": state.isolation_expires_unix }),
    );
    Ok(format!(
        "Machine isolation enabled for {} minute(s).",
        timeout_secs / 60
    ))
}

pub fn restore_machine() -> Result<String, String> {
    ensure_isolation_modifiable()?;
    let mut state = load_state()?;
    let Some(firewall_snapshot) = state.firewall_snapshot.clone() else {
        state.isolated = false;
        state.isolation_started_unix = None;
        state.isolation_expires_unix = None;
        state.network_snapshot = None;
        save_state(&state)?;
        match crate::config::Config::load() {
            Ok(cfg) => {
                let _ = crate::break_glass::sync_watchdog(&cfg);
            }
            Err(err) => note_state_load_error_once("restore_config", &err),
        }
        return Ok("Machine isolation was already cleared.".into());
    };
    let network_snapshot = state.network_snapshot.clone();
    platform::restore_isolation(&firewall_snapshot, network_snapshot.as_ref())?;
    state.firewall_snapshot = None;
    state.network_snapshot = None;
    state.isolated = false;
    state.isolation_started_unix = None;
    state.isolation_expires_unix = None;
    save_state(&state)?;
    match crate::config::Config::load() {
        Ok(cfg) => {
            let _ = crate::break_glass::sync_watchdog(&cfg);
        }
        Err(err) => note_state_load_error_once("restore_config", &err),
    }
    audit::record("restore_machine", "success", json!({}));
    Ok("Machine isolation cleared.".into())
}

pub fn is_blocked(target: &str) -> bool {
    let Ok(target) = normalise_target(target) else {
        return false;
    };
    load_state_for_query("is_blocked")
        .map(|state| state.blocked.iter().any(|rule| rule.target == target))
        .unwrap_or(false)
}

pub fn is_domain_blocked(domain: &str) -> bool {
    let Ok(domain) = normalise_domain(domain) else {
        return false;
    };
    load_state_for_query("is_domain_blocked")
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
    load_state_for_query("remote_block_remaining")
        .and_then(|state| {
            state
                .blocked
                .iter()
                .find(|rule| rule.target == target)
                .and_then(|rule| rule.expires_at_unix)
        })
        .and_then(|expires_at_unix| expires_at_unix.checked_sub(now))
        .map(Duration::from_secs)
}

pub fn is_process_blocked(_pid: u32, path: &str) -> bool {
    let Ok(path) = normalise_target(path) else {
        return false;
    };
    load_state_for_query("is_process_blocked")
        .map(|state| {
            state
                .blocked_processes
                .iter()
                .any(|rule| process_block_matches(rule, &path))
        })
        .unwrap_or(false)
}

pub fn process_block_remaining(_pid: u32, path: &str) -> Option<Duration> {
    let path = normalise_target(path).ok()?;
    let now = unix_now();
    load_state_for_query("process_block_remaining")
        .and_then(|state| {
            state
                .blocked_processes
                .iter()
                .find(|rule| process_block_matches(rule, &path))
                .and_then(|rule| rule.expires_at_unix)
        })
        .and_then(|expires_at_unix| expires_at_unix.checked_sub(now))
        .map(Duration::from_secs)
}

pub fn is_process_suspended(pid: u32, path: &str) -> bool {
    load_state_for_query("is_process_suspended")
        .map(|state| {
            state
                .suspended_processes
                .iter()
                .any(|entry| suspended_process_matches(entry, pid, path))
        })
        .unwrap_or(false)
}

fn ensure_modifiable() -> Result<(), String> {
    if !platform::is_supported() {
        return Err("Active response is only implemented on supported operating systems.".into());
    }
    if !platform::is_elevated() {
        return Err("Administrator or root privileges are required for active response.".into());
    }
    Ok(())
}
fn ensure_isolation_modifiable() -> Result<(), String> {
    if !platform::supports_isolation() {
        return Err(
            "Machine isolation is not available on this operating system or backend yet.".into(),
        );
    }
    if !platform::is_elevated() {
        return Err("Administrator or root privileges are required for network isolation.".into());
    }
    Ok(())
}
fn normalise_target(target: &str) -> Result<String, String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("Target cannot be empty.".into());
    }
    Ok(trimmed.to_string())
}
fn normalise_domain(domain: &str) -> Result<String, String> {
    let trimmed = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err("Domain cannot be empty.".into());
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return Err("Domain blocking expects a hostname, not an IP address.".into());
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
    {
        return Err("Domain contains unsupported characters.".into());
    }
    if !trimmed.contains('.') {
        return Err("Domain must contain at least one dot.".into());
    }
    Ok(trimmed)
}
fn rule_name_for_target(target: &str) -> String {
    format!("{BLOCK_RULE_PREFIX} {target}")
}
fn rule_suffix_for_process(path: &str) -> String {
    let normalized_path = path.to_ascii_lowercase();
    let readable_prefix: String = normalized_path
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .take(PROCESS_RULE_PREFIX_LEN)
        .collect();
    let readable_prefix = readable_prefix.trim_matches('_');
    let readable_prefix = if readable_prefix.is_empty() {
        "process"
    } else {
        readable_prefix
    };
    let fingerprint = hex_prefix(
        &Sha256::digest(normalized_path.as_bytes()),
        PROCESS_RULE_FINGERPRINT_LEN,
    );
    format!("{readable_prefix}_{fingerprint}")
}
fn domain_marker(domain: &str) -> String {
    format!("{DOMAIN_MARKER_PREFIX} {domain}")
}
fn reconcile_state<F>(state: &mut State, now: u64, mut delete_rule: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    let mut changed = false;
    let mut kept = Vec::with_capacity(state.blocked.len());
    for rule in state.blocked.drain(..) {
        let expired = rule.expires_at_unix.is_some_and(|deadline| deadline <= now);
        if expired && delete_rule(&rule.rule_name) {
            changed = true;
            continue;
        }
        kept.push(rule);
    }
    state.blocked = kept;

    let mut kept_processes = Vec::with_capacity(state.blocked_processes.len());
    for rule in state.blocked_processes.drain(..) {
        let expired = rule.expires_at_unix.is_some_and(|deadline| deadline <= now);
        if expired {
            let inbound_deleted = delete_rule(&rule.inbound_rule_name);
            let outbound_deleted = delete_rule(&rule.outbound_rule_name);
            if inbound_deleted && outbound_deleted {
                changed = true;
                continue;
            }
        }
        kept_processes.push(rule);
    }
    state.blocked_processes = kept_processes;
    changed
}
fn process_block_matches(rule: &BlockedProcess, path: &str) -> bool {
    rule.path.eq_ignore_ascii_case(path)
}
fn suspended_process_matches(entry: &SuspendedProcess, pid: u32, path: &str) -> bool {
    entry.pid == pid && (path.is_empty() || entry.path.eq_ignore_ascii_case(path))
}
pub fn extract_remote_target(addr: &str) -> Option<String> {
    addr.rsplit_once(':').and_then(|(host, _)| {
        if host.starts_with('[') && host.ends_with(']') {
            Some(host.trim_matches(&['[', ']'][..]).to_string())
        } else if host.contains(':') {
            Some(host.to_string())
        } else {
            host.parse::<IpAddr>().ok().map(|_| host.to_string())
        }
    })
}
pub fn extract_domain_target(conn: &ConnInfo) -> Option<String> {
    conn.hostname
        .as_deref()
        .and_then(extract_domain_from_hostname)
}
fn extract_domain_from_hostname(hostname: &str) -> Option<String> {
    let trimmed = hostname.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}
fn parse_socket_addr(addr: &str, label: &str) -> Result<SocketAddr, SocketKillError> {
    addr.parse::<SocketAddr>().map_err(|_| match label {
        "local" => SocketKillError::InvalidLocalAddr(addr.into()),
        _ => SocketKillError::InvalidRemoteAddr(addr.into()),
    })
}
#[allow(dead_code)]
fn socket_addr_from_text(text: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    text.trim().parse::<SocketAddr>()
}
fn socket_kill_target(conn: &ConnInfo) -> Result<SocketKillTarget, SocketKillError> {
    let status = conn.status.trim();
    if status != "ESTABLISHED" {
        return Err(SocketKillError::UnsupportedStatus(status.into()));
    }
    let local = parse_socket_addr(&conn.local_addr, "local")?;
    let remote = parse_socket_addr(&conn.remote_addr, "remote")?;
    if !matches!(local.ip(), IpAddr::V4(_)) || !matches!(remote.ip(), IpAddr::V4(_)) {
        return Err(SocketKillError::UnsupportedAddressFamily);
    }
    Ok(SocketKillTarget { local, remote })
}
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn isolation_timeout_secs(timeout_mins: u64) -> u64 {
    timeout_mins.clamp(1, ISOLATION_MAX_SECS / 60) * 60
}

fn stage_isolation_state(
    state: &mut State,
    firewall_snapshot: FirewallSnapshot,
    network_snapshot: NetworkSnapshot,
    now: u64,
    timeout_secs: u64,
) {
    state.firewall_snapshot = Some(firewall_snapshot);
    state.network_snapshot = Some(network_snapshot);
    state.isolated = true;
    state.isolation_started_unix = Some(now);
    state.isolation_expires_unix = Some(now.saturating_add(timeout_secs));
}

fn rollback_isolation_state(
    previous_state: &State,
    firewall_snapshot: &FirewallSnapshot,
) -> Result<(), String> {
    let mut rollback_errors = Vec::new();
    if let Err(err) = platform::restore_firewall(firewall_snapshot) {
        rollback_errors.push(format!("restore firewall: {err}"));
    }
    if let Err(err) = save_state(previous_state) {
        rollback_errors.push(format!("restore saved state: {err}"));
    }
    if rollback_errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "failed to roll back partial isolation attempt: {}",
            rollback_errors.join("; ")
        ))
    }
}

fn with_isolation_rollback(
    err: String,
    previous_state: &State,
    firewall_snapshot: &FirewallSnapshot,
) -> String {
    match rollback_isolation_state(previous_state, firewall_snapshot) {
        Ok(()) => err,
        Err(rollback_err) => format!("{err}; {rollback_err}"),
    }
}

fn outbound_probe_reachable() -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([1, 1, 1, 1], 443)),
        Duration::from_secs(2),
    )
    .is_ok()
}
#[allow(dead_code)]
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
fn isolation_effective_now(state: &State, now: u64) -> bool {
    if state
        .isolation_expires_unix
        .is_some_and(|deadline| deadline <= now)
    {
        return false;
    }
    if !state.isolated && state.firewall_snapshot.is_none() && state.network_snapshot.is_none() {
        return false;
    }
    let probe_reachable = state.network_snapshot.is_some() && outbound_probe_reachable();
    isolation_controls_active_best_effort(state, probe_reachable)
}
fn isolation_controls_active_best_effort(state: &State, probe_reachable: bool) -> bool {
    let controls_active = match platform::isolation_controls_active(state) {
        Ok(active) => active,
        Err(_) => state.firewall_snapshot.is_some() || state.network_snapshot.is_some(),
    };
    isolation_controls_still_effective(state, controls_active, probe_reachable)
}
fn isolation_controls_still_effective(
    state: &State,
    controls_active: bool,
    probe_reachable: bool,
) -> bool {
    if !controls_active {
        return false;
    }
    if state.network_snapshot.is_some() && probe_reachable {
        return false;
    }
    true
}

fn hex_prefix(bytes: &[u8], hex_len: usize) -> String {
    let mut out = String::with_capacity(hex_len);
    for byte in bytes.iter().take(hex_len.div_ceil(2)) {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out.push(char::from(b"0123456789abcdef"[hi as usize]));
        if out.len() == hex_len {
            break;
        }
        out.push(char::from(b"0123456789abcdef"[lo as usize]));
        if out.len() == hex_len {
            break;
        }
    }
    out
}

static STATE_LOAD_WARNING_ONCE: OnceLock<Mutex<std::collections::HashSet<String>>> =
    OnceLock::new();
fn note_state_load_error_once(context: &str, err: &str) {
    let seen = STATE_LOAD_WARNING_ONCE.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    let key = format!("{context}:{err}");
    let mut seen = seen.lock().unwrap();
    if seen.insert(key) {
        tracing::warn!(context, %err, "active-response state load failed");
    }
}

static STATE_PATH_OVERRIDE: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
#[derive(Clone)]
struct QueryStateCache {
    path: PathBuf,
    signature: Option<StateFileSignature>,
    loaded_at: Instant,
    state: State,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateFileSignature {
    modified: Option<SystemTime>,
    len: u64,
}

static QUERY_STATE_CACHE: OnceLock<RwLock<Option<QueryStateCache>>> = OnceLock::new();

fn state_path() -> PathBuf {
    let override_lock = STATE_PATH_OVERRIDE.get_or_init(|| RwLock::new(None));
    if let Some(path) = override_lock.read().unwrap().clone() {
        return path;
    }
    crate::config::data_dir().join(STATE_FILE)
}
fn load_state() -> Result<State, String> {
    let path = state_path();
    load_state_from_path(&path)
}
fn load_state_for_query(context: &str) -> Option<State> {
    let path = state_path();
    let cache_lock = QUERY_STATE_CACHE.get_or_init(|| RwLock::new(None));
    {
        let cache = cache_lock.read().unwrap();
        if let Some(cache) = cache.as_ref() {
            if cache.path == path && cache.loaded_at.elapsed() <= QUERY_STATE_CACHE_TTL {
                return Some(cache.state.clone());
            }
        }
    }

    let signature = state_file_signature(&path);
    {
        let mut cache = cache_lock.write().unwrap();
        if let Some(existing) = cache.as_mut() {
            if existing.path == path && existing.signature == signature {
                existing.loaded_at = Instant::now();
                return Some(existing.state.clone());
            }
        }
    }

    match load_state_from_path(&path) {
        Ok(state) => Some(state),
        Err(err) => {
            note_state_load_error_once(context, &err);
            None
        }
    }
    .inspect(|state| {
        let mut cache = cache_lock.write().unwrap();
        *cache = Some(QueryStateCache {
            path,
            signature,
            loaded_at: Instant::now(),
            state: state.clone(),
        });
    })
}

fn state_file_signature(path: &Path) -> Option<StateFileSignature> {
    path.metadata().ok().map(|metadata| StateFileSignature {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

fn update_query_state_cache(path: &Path, state: &State) {
    let cache_lock = QUERY_STATE_CACHE.get_or_init(|| RwLock::new(None));
    let mut cache = cache_lock.write().unwrap();
    *cache = Some(QueryStateCache {
        path: path.to_path_buf(),
        signature: state_file_signature(path),
        loaded_at: Instant::now(),
        state: state.clone(),
    });
}

fn clear_query_state_cache() {
    let cache_lock = QUERY_STATE_CACHE.get_or_init(|| RwLock::new(None));
    let mut cache = cache_lock.write().unwrap();
    *cache = None;
}

fn save_state(state: &State) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(state)
        .map_err(|e| format!("serialize active response state: {e}"))?;
    let path = state_path();
    match crate::security::policy::save_json_with_integrity(&path, &data) {
        Ok(()) => {
            update_query_state_cache(&path, state);
            Ok(())
        }
        Err(err) => {
            clear_query_state_cache();
            Err(err)
        }
    }
}

fn load_state_from_path(path: &std::path::Path) -> Result<State, String> {
    let existed = path.exists();
    match crate::security::policy::load_struct_with_integrity::<State>(path) {
        Ok(Some(state)) => Ok(state),
        Ok(None) => {
            if existed {
                Err(format!(
                    "active-response state {} exists but could not be verified or restored",
                    path.display()
                ))
            } else {
                Ok(State::default())
            }
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    struct StatePathGuard;
    impl StatePathGuard {
        fn set(path: PathBuf) -> Self {
            let lock = STATE_PATH_OVERRIDE.get_or_init(|| RwLock::new(None));
            *lock.write().unwrap() = Some(path);
            Self
        }
    }
    impl Drop for StatePathGuard {
        fn drop(&mut self) {
            if let Some(lock) = STATE_PATH_OVERRIDE.get() {
                *lock.write().unwrap() = None;
            }
        }
    }

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
    #[test]
    fn process_rule_suffix_keeps_readable_prefix_and_unique_fingerprint() {
        let left = rule_suffix_for_process("/tmp/a-b");
        let right = rule_suffix_for_process("/tmp/a_b");

        assert!(left.starts_with("tmp_a_b_"));
        assert!(right.starts_with("tmp_a_b_"));
        assert_ne!(left, right);
    }
    #[test]
    fn isolation_controls_guard_uses_live_probe_for_network_snapshots() {
        let state = State {
            blocked: vec![],
            blocked_processes: vec![],
            blocked_domains: vec![],
            suspended_processes: vec![],
            autorun_snapshot: None,
            firewall_snapshot: None,
            network_snapshot: Some(NetworkSnapshot {
                adapters: vec![NetworkAdapterState {
                    name: "Ethernet".into(),
                    is_wireless: false,
                    wifi_profile: None,
                }],
            }),
            isolated: false,
            isolation_started_unix: None,
            isolation_expires_unix: None,
        };

        assert!(isolation_controls_still_effective(&state, true, false));
        assert!(!isolation_controls_still_effective(&state, true, true));
        assert!(!isolation_controls_still_effective(&state, false, false));
    }

    #[test]
    fn isolation_timeout_preserves_existing_one_hour_cap() {
        assert_eq!(isolation_timeout_secs(0), 60);
        assert_eq!(isolation_timeout_secs(10), 600);
        assert_eq!(isolation_timeout_secs(60), ISOLATION_MAX_SECS);
        assert_eq!(isolation_timeout_secs(240), ISOLATION_MAX_SECS);
    }

    #[test]
    fn staging_isolation_state_sets_timeout_and_snapshots() {
        let mut state = State::default();
        let firewall_snapshot = FirewallSnapshot { profiles: vec![] };
        let network_snapshot = NetworkSnapshot { adapters: vec![] };

        stage_isolation_state(
            &mut state,
            firewall_snapshot.clone(),
            network_snapshot.clone(),
            100,
            600,
        );

        assert!(state.isolated);
        assert_eq!(state.isolation_started_unix, Some(100));
        assert_eq!(state.isolation_expires_unix, Some(700));
        assert_eq!(state.firewall_snapshot, Some(firewall_snapshot));
        assert_eq!(state.network_snapshot, Some(network_snapshot));
    }
}
