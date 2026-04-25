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
            if platform::delete_rule(&rule.inbound_rule_name).is_ok()
                && platform::delete_rule(&rule.outbound_rule_name).is_ok()
            {
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
        return Err(format!(
            "Could not remove all firewall rules for {path}; they were kept in state so Vigil can retry."
        ));
    }
    let message = if removed > 0 {
        save_state(&state)?;
        format!("Removed {removed} process block rule(s) for {path}.")
    } else {
        format!("No active process block found for {path}.")
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
    let mut state = load_state()?;
    if state.isolated {
        return Ok("Network isolation is already active.".into());
    }

    let timeout_secs = crate::config::Config::load()
        .map(|cfg| cfg.break_glass_timeout_mins.max(1) * 60)
        .unwrap_or(300);

    let now = unix_now();
    let firewall_snapshot = platform::snapshot_firewall()?;
    let network_snapshot = platform::snapshot_active_adapters()?;
    let mut warnings = Vec::new();

    let firewall_ok = match platform::isolation_works_via_firewall_only() {
        Some(true) => {
            platform::apply_firewall_isolation()?;
            true
        }
        Some(false) => {
            warnings.push(
                "firewall-only isolation did not block outbound connectivity; using failsafe adapter cutoff"
                    .to_string(),
            );
            false
        }
        None => {
            platform::apply_firewall_isolation()?;
            true
        }
    };

    if !firewall_ok {
        if let Err(err) = platform::disable_active_adapters(&network_snapshot) {
            let _ = platform::restore_firewall(&firewall_snapshot);
            return Err(err);
        }
    }

    state.firewall_snapshot = Some(firewall_snapshot);
    state.network_snapshot = Some(network_snapshot);
    state.isolated = true;
    state.isolation_started_unix = Some(now);
    state.isolation_expires_unix = Some(now.saturating_add(timeout_secs));
    save_state(&state)?;

    match crate::config::Config::load() {
        Ok(cfg) => {
            if let Err(err) = crate::break_glass::arm_watchdog(&cfg) {
                warnings.push(format!("watchdog arm failed: {err}"));
            }
        }
        Err(err) => warnings.push(format!("watchdog configuration load failed: {err}")),
    }

    audit::record(
        "isolate_machine",
        if warnings.is_empty() { "success" } else { "partial" },
        json!({
            "warnings": warnings,
            "timeout_secs": timeout_secs,
            "mode": if firewall_ok { "firewall" } else { "firewall+adapter_cutoff" }
        }),
    );

    if warnings.is_empty() {
        if firewall_ok {
            Ok(format!(
                "Network isolation enabled (failsafe recovery armed: {} minute{} stale-heartbeat timeout)",
                timeout_secs / 60,
                if timeout_secs / 60 == 1 { "" } else { "s" }
            ))
        } else {
            Ok(format!(
                "Network isolation enabled via emergency adapter cutoff (failsafe recovery armed: {} minute{} stale-heartbeat timeout)",
                timeout_secs / 60,
                if timeout_secs / 60 == 1 { "" } else { "s" }
            ))
        }
    } else if firewall_ok {
        Ok(format!(
            "Network isolation enabled with warnings: {} (failsafe recovery armed: {} minute{} stale-heartbeat timeout)",
            warnings.join("; "),
            timeout_secs / 60,
            if timeout_secs / 60 == 1 { "" } else { "s" }
        ))
    } else {
        Ok(format!(
            "Network isolation enabled via emergency adapter cutoff with warnings: {} (failsafe recovery armed: {} minute{} stale-heartbeat timeout)",
            warnings.join("; ")
            , timeout_secs / 60
            , if timeout_secs / 60 == 1 { "" } else { "s" }
        ))
    }
}
pub fn restore_machine() -> Result<String, String> {
    ensure_isolation_modifiable()?;
    let (mut state, state_load_warning) = match load_state() {
        Ok(state) => (state, None),
        Err(err) => {
            note_state_load_error_once("restore_machine", &err);
            let state = State {
                isolated: true,
                ..State::default()
            };
            // Restore is the safety path. If the protected state is unreadable,
            // still attempt legacy rule cleanup plus adapter re-enable instead
            // of leaving the host isolated until manual intervention.
            (state, Some(err))
        }
    };
    let had_isolation_intent = state_load_warning.is_some()
        || state.isolated
        || state.firewall_snapshot.is_some()
        || state.network_snapshot.is_some();
    let firewall_snapshot = state.firewall_snapshot.clone();
    let network_snapshot = state.network_snapshot.clone();
    let mut warnings = Vec::new();
    if let Some(err) = state_load_warning {
        warnings.push(format!(
            "protected isolation state could not be loaded; continuing with emergency restore path: {err}"
        ));
    }
    let mut critical_failure = false;
    let in_deleted = platform::delete_rule(ISOLATE_RULE_IN).is_ok();
    let out_deleted = platform::delete_rule(ISOLATE_RULE_OUT).is_ok();
    if !(in_deleted || out_deleted) {
        if let Some(snapshot) = firewall_snapshot.as_ref() {
            if let Err(err) = platform::restore_firewall(snapshot) {
                warnings.push(format!("firewall restore failed: {err}"));
                critical_failure = true;
            }
        }
    }
    if let Some(snapshot) = network_snapshot.as_ref() {
        if let Err(err) = platform::enable_active_adapters(snapshot) {
            warnings.push(format!("adapter restore failed: {err}; trying broad adapter re-enable"));
            match platform::enable_all_network_adapters() {
                Ok(enabled) if enabled > 0 => warnings.push(format!(
                    "broad adapter re-enable restored {enabled} adapter(s)"
                )),
                Ok(_) => {
                    warnings.push("broad adapter re-enable did not find any adapters to restore".into())
                }
                Err(fallback_err) => {
                    warnings.push(format!("broad adapter re-enable failed: {fallback_err}"));
                    critical_failure = true;
                }
            }
        }
    } else if state_load_warning.is_some() {
        match platform::enable_all_network_adapters() {
            Ok(enabled) if enabled > 0 => warnings.push(format!(
                "broad adapter re-enable restored {enabled} adapter(s) after state-load failure"
            )),
            Ok(_) => warnings.push(
                "broad adapter re-enable did not find any adapters after state-load failure"
                    .into(),
            ),
            Err(err) => {
                warnings.push(format!(
                    "broad adapter re-enable failed after state-load failure: {err}"
                ));
                critical_failure = true;
            }
        }
    }
    match crate::config::Config::load() {
        Ok(cfg) => {
            if let Err(err) = crate::break_glass::disarm_watchdog(&cfg) {
                warnings.push(format!("watchdog disarm failed: {err}"));
            }
        }
        Err(err) => warnings.push(format!("watchdog configuration load failed: {err}")),
    }
    let _ = platform::delete_rule(ISOLATE_RULE_IN);
    let _ = platform::delete_rule(ISOLATE_RULE_OUT);
    state.isolated = false;
    state.firewall_snapshot = None;
    state.network_snapshot = None;
    state.isolation_started_unix = None;
    state.isolation_expires_unix = None;
    if let Err(err) = save_state(&state) {
        warnings.push(format!("state save failed: {err}"));
    }
    audit::record(
        "restore_machine",
        if critical_failure {
            "error"
        } else if warnings.is_empty() {
            "success"
        } else {
            "partial"
        },
        json!({ "warnings": warnings }),
    );
    if critical_failure {
        return Err(if warnings.is_empty() {
            "Failed to restore networking after isolation; manual intervention is required.".into()
        } else {
            format!(
                "Failed to fully restore networking after isolation: {}",
                warnings.join("; ")
            )
        });
    }
    if !had_isolation_intent {
        return Ok("No network isolation state was present; no restore steps were needed.".into());
    }
    if warnings.is_empty() {
        Ok("Network isolation disabled and prior connectivity controls restored.".into())
    } else {
        Ok(format!(
            "Network isolation disabled with warnings: {}",
            warnings.join("; ")
        ))
    }
}
fn ensure_modifiable() -> Result<(), String> {
    if !platform::is_supported() {
        return Err("Active response is only implemented on supported operating systems.".into());
    }
    if !platform::is_elevated() {
        return Err("Active response requires administrator privileges. Relaunch Vigil as an administrator and try again.".into());
    }
    Ok(())
}
fn ensure_isolation_modifiable() -> Result<(), String> {
    if !platform::supports_isolation() {
        return Err(
            "Network isolation is not currently implemented on this operating system.".into(),
        );
    }
    if !platform::is_elevated() {
        return Err("Network isolation requires administrator privileges. Relaunch Vigil as an administrator and try again.".into());
    }
    Ok(())
}
fn rule_name_for_target(target: &str) -> String {
    let suffix = target
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    format!("{BLOCK_RULE_PREFIX} {suffix}")
}
fn rule_suffix_for_process(path: &str) -> String {
    path.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
}
fn normalise_target(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Target cannot be empty.".into());
    }
    Ok(trimmed.to_string())
}
fn normalise_domain(domain: &str) -> Result<String, String> {
    let mut domain = domain.trim().trim_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err("Domain cannot be empty.".into());
    }
    if domain.chars().any(|c| {
        !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.')) || c.is_ascii_whitespace()
    }) {
        return Err("Domain contains unsupported characters.".into());
    }
    if !domain.contains('.') {
        return Err("Domain must include a dot-separated host name.".into());
    }
    while domain.contains("..") {
        domain = domain.replace("..", ".");
    }
    Ok(domain)
}
fn domain_marker(domain: &str) -> String {
    format!("{DOMAIN_MARKER_PREFIX} {domain}")
}
fn process_block_matches(rule: &BlockedProcess, path: &str) -> bool {
    rule.path.eq_ignore_ascii_case(path)
}
fn suspended_process_matches(entry: &SuspendedProcess, pid: u32, path: &str) -> bool {
    entry.pid == pid && (path.is_empty() || entry.path.eq_ignore_ascii_case(path))
}
fn reconcile_state<F>(state: &mut State, now: u64, mut delete_rule: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    let before_blocked = state.blocked.len();
    state.blocked.retain(|rule| {
        let expired = rule.expires_at_unix.is_some_and(|deadline| deadline <= now);
        if expired {
            !delete_rule(&rule.rule_name)
        } else {
            true
        }
    });
    let before_processes = state.blocked_processes.len();
    state.blocked_processes.retain(|rule| {
        let expired = rule.expires_at_unix.is_some_and(|deadline| deadline <= now);
        if expired {
            let in_removed = delete_rule(&rule.inbound_rule_name);
            let out_removed = delete_rule(&rule.outbound_rule_name);
            !(in_removed && out_removed)
        } else {
            true
        }
    });
    before_blocked != state.blocked.len() || before_processes != state.blocked_processes.len()
}
fn socket_kill_target(conn: &ConnInfo) -> Result<SocketKillTarget, SocketKillError> {
    if !conn.status.eq_ignore_ascii_case("ESTABLISHED") {
        return Err(SocketKillError::UnsupportedStatus(conn.status.clone()));
    }
    let local = conn
        .local_addr
        .parse::<SocketAddr>()
        .map_err(|_| SocketKillError::InvalidLocalAddr(conn.local_addr.clone()))?;
    let remote = conn
        .remote_addr
        .parse::<SocketAddr>()
        .map_err(|_| SocketKillError::InvalidRemoteAddr(conn.remote_addr.clone()))?;
    if !matches!((local.ip(), remote.ip()), (IpAddr::V4(_), IpAddr::V4(_))) {
        return Err(SocketKillError::UnsupportedAddressFamily);
    }
    Ok(SocketKillTarget { local, remote })
}
fn extract_remote_target(remote_addr: &str) -> Option<String> {
    remote_addr
        .parse::<SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .or_else(|_| {
            // Support IPv6 without brackets but with trailing :port by splitting at the final colon.
            remote_addr
                .rsplit_once(':')
                .and_then(|(host, _)| host.parse::<IpAddr>().ok().map(|ip| ip.to_string()))
        })
        .ok()
}
fn extract_domain_target(conn: &ConnInfo) -> Option<String> {
    conn.hostname.clone().filter(|host| extract_domain_from_hostname(host).is_some())
}
fn extract_domain_from_hostname(hostname: &str) -> Option<String> {
    let trimmed = hostname.trim().trim_matches('.');
    if trimmed.is_empty() || trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}
fn outbound_probe_reachable() -> bool {
    let endpoints = ["1.1.1.1:53", "8.8.8.8:53"];
    endpoints.iter().any(|endpoint| {
        endpoint
            .parse::<SocketAddr>()
            .ok()
            .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok())
            .is_some()
    })
}
fn isolation_effective_now(state: &State, now: u64) -> bool {
    if state
        .isolation_expires_unix
        .is_some_and(|expires_at| now >= expires_at)
    {
        return false;
    }
    if state.isolated {
        return true;
    }
    isolation_controls_active_best_effort(state, false)
}
fn isolation_controls_active_best_effort(state: &State, probe_reachable: bool) -> bool {
    if platform::isolation_controls_active(state).unwrap_or(false) {
        return true;
    }
    state.network_snapshot.is_some() && !probe_reachable
}
fn state_cache() -> &'static RwLock<Option<State>> {
    static CACHE: OnceLock<RwLock<Option<State>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(None))
}
fn state_load_error_notes() -> &'static Mutex<Vec<(String, String)>> {
    static NOTES: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();
    NOTES.get_or_init(|| Mutex::new(Vec::new()))
}
fn note_state_load_error_once(context: &str, err: &str) {
    let mut notes = state_load_error_notes().lock().unwrap();
    if notes.iter().any(|(ctx, msg)| ctx == context && msg == err) {
        return;
    }
    notes.push((context.to_string(), err.to_string()));
    tracing::error!(context, error = err, "protected active-response state load failed")
}
fn state_path() -> PathBuf {
    crate::config::data_dir().join(STATE_FILE)
}
fn load_state() -> Result<State, String> {
    if let Some(state) = state_cache().read().unwrap().clone() {
        return Ok(state);
    }

    let path = state_path();
    let state = load_state_from_path(&path)?;
    *state_cache().write().unwrap() = Some(state.clone());
    Ok(state)
}
fn save_state(state: &State) -> Result<(), String> {
    let path = state_path();
    save_state_to_path(&path, state)?;
    *state_cache().write().unwrap() = Some(state.clone());
    Ok(())
}

fn load_state_from_path(path: &std::path::Path) -> Result<State, String> {
    if !path.exists() {
        return Ok(State::default());
    }
    crate::security::policy::load_struct_with_integrity(path)
        .map_err(|e| {
            format!(
                "failed to load active-response state {}: {e}",
                path.display()
            )
        })?
        .ok_or_else(|| {
            format!(
                "protected active-response state {} could not be verified or restored",
                path.display()
            )
        })
}

fn save_state_to_path(path: &std::path::Path, state: &State) -> Result<(), String> {
    crate::security::policy::save_struct_with_integrity(path, state).map_err(|e| {
        format!(
            "failed to save active-response state {}: {e}",
            path.display()
        )
    })
}

fn load_state_for_query(context: &str) -> Option<State> {
    match load_state() {
        Ok(state) => Some(state),
        Err(err) => {
            note_state_load_error_once(context, &err);
            None
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::net::Ipv4Addr;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::ptr::{null, null_mut};
    use windows::core::{Interface, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, SetTcpEntry, MIB_TCPROW2, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, ResumeThread, SuspendThread,
        PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME,
    };
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    pub fn is_supported() -> bool {
        true
    }
    pub fn supports_isolation() -> bool {
        true
    }
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token = HANDLE::default();
            if !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).as_bool() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            )
            .as_bool();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }
    pub fn add_block_rule(rule_name: &str, target: &str) -> Result<(), String> {
        command_status(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                "dir=out",
                "action=block",
                &format!("remoteip={target}"),
            ],
        )
    }
    pub fn add_block_program_rule(
        rule_name: &str,
        _pid: u32,
        path: &str,
        dir: &str,
    ) -> Result<(), String> {
        command_status(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                &format!("dir={dir}"),
                "action=block",
                &format!("program={path}"),
                "enable=yes",
            ],
        )
    }
    pub fn delete_rule(rule_name: &str) -> Result<(), String> {
        command_status(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={rule_name}"),
            ],
        )
    }
    pub fn suspend_process(pid: u32) -> Result<(), String> {
        unsafe {
            let process = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, false, pid)
                .map_err(|_| format!("could not open PID {pid}"))?;
            let result = SuspendThread(process);
            let _ = CloseHandle(process);
            if result == u32::MAX {
                Err(format!("failed to suspend PID {pid}"))
            } else {
                Ok(())
            }
        }
    }
    pub fn resume_process(pid: u32) -> Result<(), String> {
        unsafe {
            let process = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, false, pid)
                .map_err(|_| format!("could not open PID {pid}"))?;
            let result = ResumeThread(process);
            let _ = CloseHandle(process);
            if result == u32::MAX {
                Err(format!("failed to resume PID {pid}"))
            } else {
                Ok(())
            }
        }
    }
    pub fn kill_tcp_connection(target: &SocketKillTarget) -> Result<(), SocketKillError> {
        let (IpAddr::V4(local_ip), IpAddr::V4(remote_ip)) = (target.local.ip(), target.remote.ip()) else {
            return Err(SocketKillError::UnsupportedAddressFamily);
        };
        let row = MIB_TCPROW2 {
            dwState: 12,
            dwLocalAddr: u32::from_be_bytes(local_ip.octets()),
            dwLocalPort: u32::from((target.local.port() as u16).to_be()),
            dwRemoteAddr: u32::from_be_bytes(remote_ip.octets()),
            dwRemotePort: u32::from((target.remote.port() as u16).to_be()),
            dwOwningPid: 0,
            dwOffloadState: Default::default(),
        };
        unsafe {
            let result = SetTcpEntry((&row as *const MIB_TCPROW2).cast());
            if result == 0 {
                Ok(())
            } else {
                Err(SocketKillError::OsError(format!(
                    "SetTcpEntry failed with code {result}"
                )))
            }
        }
    }
    pub fn snapshot_autoruns() -> Result<AutorunSnapshot, String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run = hkcu
            .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ)
            .map_err(|e| format!("failed to open HKCU Run key: {e}"))?;
        let mut entries = Vec::new();
        for item in run.enum_values() {
            let (name, value) = item.map_err(|e| format!("failed to enumerate Run values: {e}"))?;
            let data = String::from_utf8_lossy(&value.bytes).trim_end_matches('\0').to_string();
            entries.push(AutorunEntry {
                hive: "HKCU".into(),
                key_path: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
                value_name: name,
                value_data: data,
            });
        }
        Ok(AutorunSnapshot {
            captured_at_unix: super::unix_now(),
            entries,
        })
    }
    pub fn revert_autorun_changes(entries: &[AutorunEntry]) -> Result<RevertAutorunResult, String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (run, _) = hkcu
            .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
            .map_err(|e| format!("failed to open HKCU Run key: {e}"))?;
        let expected: std::collections::HashMap<_, _> = entries
            .iter()
            .filter(|entry| entry.hive.eq_ignore_ascii_case("HKCU"))
            .map(|entry| (entry.value_name.clone(), entry.value_data.clone()))
            .collect();
        let current_names = run
            .enum_values()
            .filter_map(|item| item.ok().map(|(name, _)| name))
            .collect::<Vec<_>>();
        let mut removed_additions = 0usize;
        for name in current_names {
            if !expected.contains_key(&name) {
                let _ = run.delete_value(&name);
                removed_additions += 1;
            }
        }
        let mut restored_entries = 0usize;
        for (name, data) in expected {
            run.set_value(&name, &data)
                .map_err(|e| format!("failed to restore Run value {name}: {e}"))?;
            restored_entries += 1;
        }
        Ok(RevertAutorunResult {
            removed_additions,
            restored_entries,
        })
    }
    pub fn add_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        let hosts_path = hosts_path();
        let content = std::fs::read_to_string(&hosts_path)
            .unwrap_or_else(|_| String::from_utf8_lossy(include_bytes!("../../assets/hosts.base")).to_string());
        if content.contains(marker) {
            return Ok(());
        }
        let mut updated = content;
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(&format!("{marker}\r\n127.0.0.1 {domain}\r\n::1 {domain}\r\n"));
        std::fs::write(&hosts_path, updated)
            .map_err(|e| format!("failed to update hosts file {}: {e}", hosts_path.display()))?;
        Ok(())
    }
    pub fn remove_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        let hosts_path = hosts_path();
        let content = std::fs::read_to_string(&hosts_path)
            .map_err(|e| format!("failed to read hosts file {}: {e}", hosts_path.display()))?;
        let filtered = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed != marker && !trimmed.ends_with(&format!(" {domain}"))
            })
            .collect::<Vec<_>>()
            .join("\r\n");
        std::fs::write(&hosts_path, format!("{filtered}\r\n"))
            .map_err(|e| format!("failed to write hosts file {}: {e}", hosts_path.display()))
    }
    pub fn snapshot_firewall() -> Result<FirewallSnapshot, String> {
        let output = command_stdout(
            "netsh",
            &[
                "advfirewall",
                "show",
                "allprofiles",
            ],
        )?;
        let mut profiles = Vec::new();
        let mut current_name = String::new();
        let mut enabled = false;
        let mut inbound = String::new();
        let mut outbound = String::new();
        for line in output.lines() {
            let line = line.trim();
            if line.ends_with("Profile Settings:") {
                if !current_name.is_empty() {
                    profiles.push(FirewallProfileState {
                        name: current_name.clone(),
                        enabled,
                        inbound_action: inbound.clone(),
                        outbound_action: outbound.clone(),
                    });
                }
                current_name = line.trim_end_matches(" Profile Settings:").to_string();
                enabled = false;
                inbound.clear();
                outbound.clear();
            } else if let Some(value) = line.strip_prefix("State") {
                enabled = value.contains("ON");
            } else if let Some(value) = line.strip_prefix("Firewall Policy") {
                let value = value.split_whitespace().collect::<Vec<_>>();
                if value.len() >= 2 {
                    inbound = value[0].trim_matches(',').to_string();
                    outbound = value[1].to_string();
                }
            }
        }
        if !current_name.is_empty() {
            profiles.push(FirewallProfileState {
                name: current_name,
                enabled,
                inbound_action: inbound,
                outbound_action: outbound,
            });
        }
        Ok(FirewallSnapshot { profiles })
    }
    pub fn restore_firewall(snapshot: &FirewallSnapshot) -> Result<(), String> {
        for profile in &snapshot.profiles {
            let profile_name = profile.name.to_ascii_lowercase();
            command_status(
                "netsh",
                &[
                    "advfirewall",
                    "set",
                    &format!("{profile_name}profile"),
                    &format!("state={}", if profile.enabled { "on" } else { "off" }),
                ],
            )?;
            if !profile.inbound_action.is_empty() && !profile.outbound_action.is_empty() {
                command_status(
                    "netsh",
                    &[
                        "advfirewall",
                        "set",
                        &format!("{profile_name}profile"),
                        &format!(
                            "firewallpolicy={},{}",
                            profile.inbound_action, profile.outbound_action
                        ),
                    ],
                )?;
            }
        }
        Ok(())
    }
    pub fn apply_firewall_isolation() -> Result<(), String> {
        command_status(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={ISOLATE_RULE_OUT}"),
                "dir=out",
                "action=block",
                "remoteip=any",
            ],
        )?;
        command_status(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={ISOLATE_RULE_IN}"),
                "dir=in",
                "action=block",
                "remoteip=any",
            ],
        )
    }
    pub fn isolation_controls_active(state: &State) -> Result<bool, String> {
        if state.firewall_snapshot.is_some() {
            let output = command_stdout(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "show",
                    "rule",
                    &format!("name={ISOLATE_RULE_OUT}"),
                ],
            )?;
            if output.contains(ISOLATE_RULE_OUT) {
                return Ok(true);
            }
            let output = command_stdout(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "show",
                    "rule",
                    &format!("name={ISOLATE_RULE_IN}"),
                ],
            )?;
            if output.contains(ISOLATE_RULE_IN) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn isolation_works_via_firewall_only() -> Option<bool> {
        let _ = command_status(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={ISOLATE_RULE_OUT}"),
                "dir=out",
                "action=block",
                "remoteip=any",
            ],
        );
        let _ = command_status(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={ISOLATE_RULE_IN}"),
                "dir=in",
                "action=block",
                "remoteip=any",
            ],
        );
        let reachable = super::outbound_probe_reachable();
        let _ = delete_rule(ISOLATE_RULE_OUT);
        let _ = delete_rule(ISOLATE_RULE_IN);
        Some(!reachable)
    }
    pub fn snapshot_active_adapters() -> Result<NetworkSnapshot, String> {
        let output = command_stdout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name",
            ],
        )?;
        let adapters = output
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| NetworkAdapterState {
                name: name.to_string(),
                is_wireless: false,
                wifi_profile: None,
            })
            .collect();
        Ok(NetworkSnapshot { adapters })
    }
    pub fn disable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        for adapter in &snapshot.adapters {
            command_status(
                "powershell",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!("Disable-NetAdapter -Name '{}' -Confirm:$false", adapter.name),
                ],
            )?;
        }
        Ok(())
    }
    pub fn enable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        for adapter in &snapshot.adapters {
            command_status(
                "powershell",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!("Enable-NetAdapter -Name '{}' -Confirm:$false", adapter.name),
                ],
            )?;
        }
        Ok(())
    }
    pub fn enable_all_network_adapters() -> Result<usize, String> {
        let output = command_stdout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Select-Object -ExpandProperty Name",
            ],
        )?;
        let mut enabled = 0usize;
        for name in output.lines().map(str::trim).filter(|name| !name.is_empty()) {
            if command_status(
                "powershell",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!("Enable-NetAdapter -Name '{}' -Confirm:$false", name),
                ],
            )
            .is_ok()
            {
                enabled += 1;
            }
        }
        Ok(enabled)
    }
    fn hosts_path() -> PathBuf {
        windows_directory()
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    }
    fn windows_directory() -> Option<PathBuf> {
        unsafe {
            let mut buffer = vec![0u16; 260];
            let len = windows::Win32::System::SystemInformation::GetWindowsDirectoryW(Some(&mut buffer));
            if len == 0 {
                return None;
            }
            Some(PathBuf::from(String::from_utf16_lossy(
                &buffer[..len as usize],
            )))
        }
    }
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
        let mut cmd = Command::new(program);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.args(args);
        Ok(cmd)
    }
    struct RevertAutorunResult {
        removed_additions: usize,
        restored_entries: usize,
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    const IPTABLES_COMMENT_PREFIX: &str = "vigil:";

    pub fn is_supported() -> bool {
        true
    }
    pub fn supports_isolation() -> bool {
        true
    }
    pub fn is_elevated() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    // ── Minimal placeholder implementations for Linux to compile and run ──

    pub fn snapshot_autoruns() -> Result<AutorunSnapshot, String> {
        Ok(AutorunSnapshot {
            captured_at_unix: super::unix_now(),
            entries: Vec::new(),
        })
    }
    pub fn revert_autorun_changes(_entries: &[AutorunEntry]) -> Result<RevertAutorunResult, String> {
        Ok(RevertAutorunResult {
            removed_additions: 0,
            restored_entries: 0,
        })
    }
    pub fn snapshot_firewall() -> Result<FirewallSnapshot, String> {
        Ok(FirewallSnapshot {
            profiles: vec![FirewallProfileState {
                name: "all".into(),
                enabled: true,
                inbound_action: "allow".into(),
                outbound_action: "allow".into(),
            }],
        })
    }
    pub fn restore_firewall(_snapshot: &FirewallSnapshot) -> Result<(), String> {
        // Cleanup our temporary isolation rules; no global policy mutation on Linux.
        let _ = delete_rule(ISOLATE_RULE_IN);
        let _ = delete_rule(ISOLATE_RULE_OUT);
        Ok(())
    }
    pub fn apply_firewall_isolation() -> Result<(), String> {
        add_block_rule(ISOLATE_RULE_OUT, "0.0.0.0/0")?;
        add_block_rule(ISOLATE_RULE_IN, "0.0.0.0/0")
    }
    pub fn isolation_controls_active(state: &State) -> Result<bool, String> {
        if state.firewall_snapshot.is_some() {
            if delete_rule(ISOLATE_RULE_OUT).is_err() && delete_rule(ISOLATE_RULE_IN).is_err() {
                return Ok(false);
            }
        }
        Ok(state.firewall_snapshot.is_some())
    }
    pub fn isolation_works_via_firewall_only() -> Option<bool> {
        None
    }

    // ── Firewall blocking (Linux: iptables owner match / cidr) ────────────

    pub fn add_block_rule(rule_name: &str, target: &str) -> Result<(), String> {
        let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
        command_status(
            "iptables",
            &[
                "-I",
                "OUTPUT",
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
    pub fn add_block_program_rule(
        rule_name: &str,
        pid: u32,
        _path: &str,
        dir: &str,
    ) -> Result<(), String> {
        let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
        match dir {
            "out" => {
                let uid = process_effective_uid(pid)?;
                let uid_string = uid.to_string();
                let mut args = vec!["-I", "OUTPUT", "-m", "owner", "--uid-owner"];
                args.push(uid_string.as_str());
                args.extend_from_slice(&["-m", "comment", "--comment", &comment, "-j", "DROP"]);
                command_status("iptables", &args)
            }
            "in" => {
                let uid = process_effective_uid(pid)?;
                let uid_string = uid.to_string();
                let mut args = vec!["-I", "INPUT", "-m", "owner", "--uid-owner"];
                args.push(uid_string.as_str());
                args.extend_from_slice(&["-m", "comment", "--comment", &comment, "-j", "DROP"]);
                return command_status("iptables", &args);
            }
            _ => {
                let _ = (rule_name, _path, dir);
                Err("Active response is not implemented on this platform.".into())
            }
        }
    }
    pub fn delete_rule(rule_name: &str) -> Result<(), String> {
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

    // ── Process control (Linux: SIGSTOP / SIGCONT) ─────────────────────────

    pub fn suspend_process(pid: u32) -> Result<(), String> {
        command_status("kill", &["-STOP", &pid.to_string()])
    }
    pub fn resume_process(pid: u32) -> Result<(), String> {
        command_status("kill", &["-CONT", &pid.to_string()])
    }

    // ── TCP connection kill (Linux: ss -K) ─────────────────────────────────

    pub fn kill_tcp_connection(target: &SocketKillTarget) -> Result<(), SocketKillError> {
        let local_ip = target.local.ip().to_string();
        let local_port = target.local.port().to_string();
        let remote_ip = target.remote.ip().to_string();
        let remote_port = target.remote.port().to_string();
        let status = command_base(
            "ss",
            &[
                "-K",
                "dst",
                &remote_ip,
                "dport",
                "=",
                &remote_port,
                "src",
                &local_ip,
                "sport",
                "=",
                &local_port,
            ],
        )
        .map_err(SocketKillError::OsError)?
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
    pub fn terminate_active_tcp_connections() -> Result<usize, String> {
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
            let status = command_base(
                "ss",
                &[
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
                ],
            )?
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
            if status.map(|s| s.success()).unwrap_or(false) {
                count += 1;
            }
        }
        Ok(count)
    }
    /// Parse "AABBCCDD:PPPP" hex format from /proc/net/tcp into (ip_string, port).
    /// The IP is little-endian hex (e.g. "0100007F" = 127.0.0.1).
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
        let entry = format!("\n{marker}\n127.0.0.1 {domain}\n::1 {domain}\n");
        std::fs::OpenOptions::new()
            .append(true)
            .open("/etc/hosts")
            .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()))
            .map_err(|e| format!("failed to update /etc/hosts: {e}"))?;
        flush_dns();
        Ok(())
    }
    pub fn remove_domain_block(domain: &str, marker: &str) -> Result<(), String> {
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
    fn flush_dns() {
        // Try systemd-resolve first (older Ubuntu), then resolvectl.
        let _ = command_status("resolvectl", &["flush-caches"]);
        let _ = command_status("systemd-resolve", &["--flush-caches"]);
    }

    // ── Network adapter management ─────────────────────────────────────────

    pub fn snapshot_active_adapters() -> Result<NetworkSnapshot, String> {
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
        Ok(NetworkSnapshot { adapters })
    }
    pub fn disable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        for adapter in &snapshot.adapters {
            command_status("ip", &["link", "set", "dev", &adapter.name, "down"])?;
        }
        Ok(())
    }
    pub fn enable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        for adapter in &snapshot.adapters {
            command_status("ip", &["link", "set", "dev", &adapter.name, "up"])?;
        }
        Ok(())
    }
    pub fn enable_all_network_adapters() -> Result<usize, String> {
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
        Ok(enabled)
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
        let resolved = command_paths::resolve(program)?;
        let mut cmd = Command::new(resolved);
        cmd.args(args);
        Ok(cmd)
    }

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

    struct RevertAutorunResult {
        removed_additions: usize,
        restored_entries: usize,
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    use super::*;

    pub fn is_supported() -> bool {
        true
    }
    pub fn supports_isolation() -> bool {
        true
    }
    pub fn is_elevated() -> bool {
        false
    }
    pub fn add_block_rule(_rule_name: &str, _target: &str) -> Result<(), String> {
        Err("Active response is not implemented on this platform.".into())
    }
    pub fn add_block_program_rule(
        _rule_name: &str,
        _pid: u32,
        _path: &str,
        _dir: &str,
    ) -> Result<(), String> {
        Err("Active response is not implemented on this platform.".into())
    }
    pub fn delete_rule(_rule_name: &str) -> Result<(), String> {
        Ok(())
    }
    pub fn suspend_process(_pid: u32) -> Result<(), String> {
        Err("Process suspension is not implemented on this platform.".into())
    }
    pub fn resume_process(_pid: u32) -> Result<(), String> {
        Err("Process resume is not implemented on this platform.".into())
    }
    pub fn kill_tcp_connection(_target: &SocketKillTarget) -> Result<(), SocketKillError> {
        Err(SocketKillError::PlatformUnsupported)
    }
    pub fn terminate_active_tcp_connections() -> Result<usize, String> {
        Err("TCP termination is not implemented on this platform.".into())
    }
    pub fn snapshot_autoruns() -> Result<AutorunSnapshot, String> {
        Ok(AutorunSnapshot {
            captured_at_unix: super::unix_now(),
            entries: Vec::new(),
        })
    }
    pub fn revert_autorun_changes(_entries: &[AutorunEntry]) -> Result<RevertAutorunResult, String> {
        Ok(RevertAutorunResult {
            removed_additions: 0,
            restored_entries: 0,
        })
    }
    pub fn add_domain_block(_domain: &str, _marker: &str) -> Result<(), String> {
        Err("Domain blocking is not implemented on this platform.".into())
    }
    pub fn remove_domain_block(_domain: &str, _marker: &str) -> Result<(), String> {
        Err("Domain blocking is not implemented on this platform.".into())
    }
    pub fn snapshot_firewall() -> Result<FirewallSnapshot, String> {
        Ok(FirewallSnapshot { profiles: Vec::new() })
    }
    pub fn restore_firewall(_snapshot: &FirewallSnapshot) -> Result<(), String> {
        Ok(())
    }
    pub fn apply_firewall_isolation() -> Result<(), String> {
        Err("Network isolation is not implemented on this platform.".into())
    }
    pub fn isolation_controls_active(_state: &State) -> Result<bool, String> {
        Ok(false)
    }
    pub fn isolation_works_via_firewall_only() -> Option<bool> {
        Some(false)
    }
    pub fn snapshot_active_adapters() -> Result<NetworkSnapshot, String> {
        Ok(NetworkSnapshot { adapters: Vec::new() })
    }
    pub fn disable_active_adapters(_snapshot: &NetworkSnapshot) -> Result<(), String> {
        Err("Network adapter isolation is not implemented on this platform.".into())
    }
    pub fn enable_active_adapters(_snapshot: &NetworkSnapshot) -> Result<(), String> {
        Err("Network adapter restoration is not implemented on this platform.".into())
    }
    pub fn enable_all_network_adapters() -> Result<usize, String> {
        Ok(0)
    }

    struct RevertAutorunResult {
        removed_additions: usize,
        restored_entries: usize,
    }
}

#[cfg(windows)]
use platform::RevertAutorunResult;
#[cfg(target_os = "linux")]
use platform::RevertAutorunResult;
#[cfg(not(any(windows, target_os = "linux")))]
use platform::RevertAutorunResult;
