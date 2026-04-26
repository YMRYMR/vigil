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
use std::path::PathBuf;
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
const PROCESS_RULE_PREFIX_LEN: usize = 48;
const PROCESS_RULE_FINGERPRINT_LEN: usize = 16;

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
