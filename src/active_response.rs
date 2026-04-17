//! Active response: reversible, auditable intervention actions.
//!
//! Phase 11 starts with three practical controls:
//! - block a remote IP or CIDR with a temporary Windows firewall rule
//! - block all traffic for a process by executable path
//! - isolate / restore the machine with paired firewall rules
//!
//! The module persists a tiny state file so rules can be reconciled and
//! expired later, and so the UI can reflect the current status after restarts.

use crate::types::ConnInfo;
use serde::{Deserialize, Serialize};
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
    pub isolated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct State {
    blocked: Vec<BlockedTarget>,
    #[serde(default)]
    blocked_processes: Vec<BlockedProcess>,
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
                write!(f, "socket kill currently supports IPv4 TCP only")
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

pub fn kill_connection(conn: &ConnInfo) -> Result<String, SocketKillError> {
    if !platform::is_supported() {
        return Err(SocketKillError::PlatformUnsupported);
    }
    if !platform::is_elevated() {
        return Err(SocketKillError::PermissionDenied);
    }
    let target = socket_kill_target(conn)?;
    platform::kill_tcp_connection(&target)?;
    Ok(format!(
        "Killed TCP connection {} -> {}.",
        target.local, target.remote
    ))
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

    Ok(match preset {
        DurationPreset::OneHour => format!("Blocked {target} for 1 hour."),
        DurationPreset::OneDay => format!("Blocked {target} for 24 hours."),
        DurationPreset::Permanent => format!("Blocked {target} until removed."),
    })
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
    if removed > 0 {
        save_state(&state)?;
        Ok(format!("Removed {removed} block rule(s) for {target}."))
    } else {
        Ok(format!("No active block rule found for {target}."))
    }
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
        inbound_rule_name,
        outbound_rule_name,
        expires_at_unix,
    });
    save_state(&state)?;

    Ok(match preset {
        DurationPreset::OneHour => format!("Blocked {path} for 1 hour."),
        DurationPreset::OneDay => format!("Blocked {path} for 24 hours."),
        DurationPreset::Permanent => format!("Blocked {path} until removed."),
    })
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
    if removed > 0 {
        save_state(&state)?;
        Ok(format!(
            "Removed {removed} process block(s) for PID {pid} ({path})."
        ))
    } else {
        Ok(format!(
            "No active process block found for PID {pid} ({path})."
        ))
    }
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

pub fn extract_remote_target(remote_addr: &str) -> Option<String> {
    let (host, port) = remote_addr.rsplit_once(':')?;
    if host.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(host.to_string())
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

    let local = conn
        .local_addr
        .parse::<SocketAddr>()
        .map_err(|_| SocketKillError::InvalidLocalAddr(conn.local_addr.clone()))?;
    let remote = conn
        .remote_addr
        .parse::<SocketAddr>()
        .map_err(|_| SocketKillError::InvalidRemoteAddr(conn.remote_addr.clone()))?;

    match (local.ip(), remote.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Ok(SocketKillTarget { local, remote }),
        _ => Err(SocketKillError::UnsupportedAddressFamily),
    }
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
    crate::config::config_path()
        .parent()
        .map(|dir| dir.join(STATE_FILE))
        .unwrap_or_else(|| PathBuf::from(STATE_FILE))
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
    use windows::Win32::Foundation::{CloseHandle, HANDLE, ERROR_ACCESS_DENIED, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        SetTcpEntry, MIB_TCP_STATE_DELETE_TCB, MIB_TCPROW,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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

    pub fn kill_tcp_connection(_target: &SocketKillTarget) -> Result<(), SocketKillError> {
        Err(SocketKillError::PlatformUnsupported)
    }

    pub fn add_block_rule(_rule_name: &str, _target: &str) -> Result<(), String> {
        Err("Active response is not implemented on this platform.".into())
    }

    pub fn add_block_all_rule(_rule_name: &str, _dir: &str) -> Result<(), String> {
        Err("Active response is not implemented on this platform.".into())
    }

    pub fn add_block_program_rule(_rule_name: &str, _path: &str, _dir: &str) -> Result<(), String> {
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
        let err = socket_kill_target(&conn(
            "0.0.0.0:80",
            "0.0.0.0:0",
            "LISTEN",
        ))
        .unwrap_err();
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
}
