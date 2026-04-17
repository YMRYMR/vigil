//! Active response: reversible, auditable intervention actions.
//!
//! Phase 11 starts with practical controls for blocking traffic, killing a
//! live socket, suspending a suspicious process, and isolating the machine.
//! The module persists a tiny state file so rules can be reconciled and the UI
//! can reflect the current status after restarts.

use crate::{audit, types::ConnInfo};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STATE_FILE: &str = "vigil-active-response.json";
const BLOCK_RULE_PREFIX: &str = "Vigil Block";
const PROCESS_BLOCK_RULE_PREFIX: &str = "Vigil Proc Block";
const ISOLATE_RULE_IN: &str = "Vigil Isolate In";
const ISOLATE_RULE_OUT: &str = "Vigil Isolate Out";

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Status {
    pub blocked_rules: usize,
    pub blocked_processes: usize,
    pub suspended_processes: usize,
    pub isolated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct State {
    blocked: Vec<BlockedTarget>,
    #[serde(default)]
    blocked_processes: Vec<BlockedProcess>,
    #[serde(default)]
    suspended_processes: Vec<SuspendedProcess>,
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
struct SuspendedProcess {
    pid: u32,
    path: String,
    proc_name: String,
    suspended_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketKillError {
    UnsupportedStatus(String),
    InvalidLocalAddr(String),
    InvalidRemoteAddr(String),
    UnsupportedAddressFamily,
    UnsupportedProtocol,
    PlatformUnsupported,
    PermissionDenied,
    OsError(u32),
}

impl std::fmt::Display for SocketKillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedStatus(status) => {
                write!(f, "cannot kill a socket in {status} state")
            }
            Self::InvalidLocalAddr(addr) => write!(f, "invalid local address: {addr}"),
            Self::InvalidRemoteAddr(addr) => write!(f, "invalid remote address: {addr}"),
            Self::UnsupportedAddressFamily => {
                write!(f, "live socket kill currently supports IPv4 TCP only on Windows")
            }
            Self::UnsupportedProtocol => {
                write!(f, "socket kill currently supports TCP connections only")
            }
            Self::PlatformUnsupported => {
                write!(f, "socket kill is currently only implemented on Windows")
            }
            Self::PermissionDenied => {
                write!(f, "administrator privileges are required to kill a TCP connection")
            }
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
    Status {
        blocked_rules: state.blocked.len() + state.blocked_processes.len(),
        blocked_processes: state.blocked_processes.len(),
        suspended_processes: state.suspended_processes.len(),
        isolated: state.isolated,
    }
}

pub fn can_modify_firewall() -> bool {
    platform::is_supported() && platform::is_elevated()
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

pub fn kill_connection(conn: &ConnInfo) -> Result<String, SocketKillError> {
    if !platform::is_supported() {
        return Err(SocketKillError::PlatformUnsupported);
    }
    if !platform::is_elevated() {
        return Err(SocketKillError::PermissionDenied);
    }
    let target = socket_kill_target(conn)?;
    platform::kill_tcp_connection(&target)?;
    let message = format!("Killed TCP connection {} -> {}.", target.local, target.remote);
    audit::record(
        "kill_connection",
        "success",
        json!({
            "local_addr": target.local.to_string(),
            "remote_addr": target.remote.to_string(),
            "pid": conn.pid,
            "proc_name": conn.proc_name,
        }),
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
        json!({
            "pid": pid,
            "path": path,
            "proc_name": proc_name,
        }),
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
        json!({
            "pid": pid,
            "path": path,
            "removed_entries": removed,
        }),
    );
    Ok(message)
}

pub fn reconcile() {
    if !platform::is_supported() || !platform::is_elevated() {
        return;
    }

    let Ok(mut state) = load_state() else {
        return;
    };

    let now = unix_now();
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
        json!({
            "target": target,
            "duration": format!("{:?}", preset),
            "rule_name": rule_name,
        }),
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
        return Err(format!(
            "Could not remove the firewall rule for {target}; it was kept in state so Vigil can retry."
        ));
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
    platform::add_block_program_rule(&outbound_rule_name, &path, "out")?;
    if let Err(err) = platform::add_block_program_rule(&inbound_rule_name, &path, "in") {
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
        json!({
            "pid": pid,
            "path": path,
            "duration": format!("{:?}", preset),
            "inbound_rule_name": inbound_rule_name,
            "outbound_rule_name": outbound_rule_name,
        }),
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
        return Err(format!(
            "Could not remove the firewall rules for PID {pid} ({path}); they were kept in state so Vigil can retry."
        ));
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
    ensure_modifiable()?;
    let _ = platform::delete_rule(ISOLATE_RULE_IN);
    let _ = platform::delete_rule(ISOLATE_RULE_OUT);
    platform::add_block_all_rule(ISOLATE_RULE_IN, "in")?;
    platform::add_block_all_rule(ISOLATE_RULE_OUT, "out")?;

    let mut state = load_state().unwrap_or_default();
    state.isolated = true;
    save_state(&state)?;

    audit::record(
        "isolate_machine",
        "success",
        json!({ "inbound_rule_name": ISOLATE_RULE_IN, "outbound_rule_name": ISOLATE_RULE_OUT }),
    );
    Ok("Network isolation enabled.".into())
}

pub fn restore_machine() -> Result<String, String> {
    ensure_modifiable()?;
    let in_deleted = platform::delete_rule(ISOLATE_RULE_IN).is_ok();
    let out_deleted = platform::delete_rule(ISOLATE_RULE_OUT).is_ok();
    if !(in_deleted && out_deleted) {
        return Err(
            "Could not remove all isolation firewall rules; the state was kept for retry.".into(),
        );
    }

    let mut state = load_state().unwrap_or_default();
    state.isolated = false;
    save_state(&state)?;

    audit::record("restore_machine", "success", json!({}));
    Ok("Network isolation removed.".into())
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

fn ensure_modifiable() -> Result<(), String> {
    if !platform::is_supported() {
        return Err("Active response is currently only implemented on Windows.".into());
    }
    if !platform::is_elevated() {
        return Err("Administrator privileges are required for active response.".into());
    }
    Ok(())
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
        return Err("Target cannot be empty.".into());
    }
    Ok(target.to_string())
}

fn process_block_matches(rule: &BlockedProcess, path: &str) -> bool {
    rule.path == path
}

fn suspended_process_matches(entry: &SuspendedProcess, pid: u32, path: &str) -> bool {
    entry.pid == pid && (path.is_empty() || entry.path == path)
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
    let path = state_path();
    if !path.exists() {
        return Ok(State::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

fn save_state(state: &State) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("failed to serialise active-response state: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("failed to write {}: {e}", path.display()))
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
    use windows::Win32::Foundation::{CloseHandle, HANDLE, ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        SetTcpEntry, MIB_TCP_STATE_DELETE_TCB, MIB_TCPROW,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, ResumeThread, SuspendThread,
        PROCESS_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    pub fn is_supported() -> bool {
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
        let first = unsafe { Thread32First(snapshot, &mut entry).as_bool() };
        if first {
            loop {
                if entry.th32OwnerProcessID == pid {
                    unsafe {
                        if let Ok(thread) = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) {
                            let result = SuspendThread(thread);
                            let _ = CloseHandle(thread);
                            if result != u32::MAX {
                                success_count += 1;
                            }
                        }
                    }
                }
                if !unsafe { Thread32Next(snapshot, &mut entry).as_bool() } {
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
        let first = unsafe { Thread32First(snapshot, &mut entry).as_bool() };
        if first {
            loop {
                if entry.th32OwnerProcessID == pid {
                    unsafe {
                        if let Ok(thread) = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) {
                            let result = ResumeThread(thread);
                            let _ = CloseHandle(thread);
                            if result != u32::MAX {
                                success_count += 1;
                            }
                        }
                    }
                }
                if !unsafe { Thread32Next(snapshot, &mut entry).as_bool() } {
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

    pub fn kill_tcp_connection(target: &SocketKillTarget) -> Result<(), SocketKillError> {
        let local = match target.local {
            SocketAddr::V4(local) => local,
            SocketAddr::V6(_) => return Err(SocketKillError::UnsupportedAddressFamily),
        };
        let remote = match target.remote {
            SocketAddr::V4(remote) => remote,
            SocketAddr::V6(_) => return Err(SocketKillError::UnsupportedAddressFamily),
        };

        let row = MIB_TCPROW {
            dwState: MIB_TCP_STATE_DELETE_TCB,
            dwLocalAddr: u32::from_be_bytes(local.ip().octets()),
            dwLocalPort: u32::from(local.port().to_be()),
            dwRemoteAddr: u32::from_be_bytes(remote.ip().octets()),
            dwRemotePort: u32::from(remote.port().to_be()),
        };

        let status = unsafe { SetTcpEntry(&row) };
        if status == NO_ERROR {
            Ok(())
        } else if status == ERROR_ACCESS_DENIED.0 {
            Err(SocketKillError::PermissionDenied)
        } else {
            Err(SocketKillError::OsError(status))
        }
    }

    pub fn add_block_rule(rule_name: &str, target: &str) -> Result<(), String> {
        let status = Command::new("netsh")
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
        let status = Command::new("netsh")
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

    pub fn add_block_program_rule(rule_name: &str, path: &str, dir: &str) -> Result<(), String> {
        let status = Command::new("netsh")
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
        let status = Command::new("netsh")
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
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub fn is_supported() -> bool {
        false
    }

    pub fn is_elevated() -> bool {
        false
    }

    pub fn process_exists(_pid: u32) -> bool {
        false
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

    pub fn add_block_rule(_rule_name: &str, _target: &str) -> Result<(), String> {
        Err("Active response is not implemented on this platform.".into())
    }

    pub fn add_block_all_rule(_rule_name: &str, _dir: &str) -> Result<(), String> {
        Err("Active response is not implemented on this platform.".into())
    }

    pub fn add_block_program_rule(
        _rule_name: &str,
        _path: &str,
        _dir: &str,
    ) -> Result<(), String> {
        Err("Active response is not implemented on this platform.".into())
    }

    pub fn delete_rule(_rule_name: &str) -> Result<(), String> {
        Ok(())
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
            service_name: String::new(),
            publisher: String::new(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            status: status.into(),
            score: 9,
            reasons: vec!["test".into()],
            ancestor_chain: vec![("cmd.exe".into(), 123)],
            pre_login: false,
            hostname: None,
            country: None,
            asn: None,
            asn_org: None,
            reputation_hit: None,
            recently_dropped: false,
            long_lived: false,
            dga_like: false,
        }
    }

    #[test]
    fn reconcile_keeps_expired_entries_when_deletion_fails() {
        let mut state = State {
            blocked: vec![blocked_target("10.0.0.1", Some(10))],
            blocked_processes: vec![blocked_process("C:/app.exe", Some(10))],
            suspended_processes: vec![suspended_process(1234, "C:/app.exe")],
            isolated: false,
        };

        let changed = reconcile_state(&mut state, 100, |_| false);

        assert!(!changed);
        assert_eq!(state.blocked.len(), 1);
        assert_eq!(state.blocked_processes.len(), 1);
    }

    #[test]
    fn reconcile_removes_expired_entries_after_successful_deletion() {
        let mut deleted = Vec::new();
        let mut state = State {
            blocked: vec![blocked_target("10.0.0.1", Some(10))],
            blocked_processes: vec![blocked_process("C:/app.exe", Some(10))],
            suspended_processes: vec![],
            isolated: false,
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
                "out-C:/app.exe".to_string(),
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
        let parsed = socket_kill_target(&conn(
            "192.168.1.10:50000",
            "8.8.8.8:443",
            "ESTABLISHED",
        ))
        .unwrap();
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
        let err =
            socket_kill_target(&conn("192.168.1.10:50000", "not-an-endpoint", "ESTABLISHED"))
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
        assert_eq!(extract_remote_target("8.8.8.8:443").as_deref(), Some("8.8.8.8"));
        assert_eq!(
            extract_remote_target("[2606:4700:4700::1111]:443").as_deref(),
            Some("2606:4700:4700::1111")
        );
        assert_eq!(
            extract_remote_target("2606:4700:4700::1111:443").as_deref(),
            Some("2606:4700:4700::1111")
        );
    }
}
