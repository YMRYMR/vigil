//! Core data types shared across all modules.

use serde::{Deserialize, Serialize};

// ── Connection info ───────────────────────────────────────────────────────────

/// Everything captured about a single active connection event.
/// Built by the monitor, consumed by the scorer, stored in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnInfo {
    /// Wall-clock time the connection was first seen. "HH:MM:SS"
    pub timestamp: String,

    // ── Process ──────────────────────────────────────────────────────────────
    pub proc_name:    String,   // e.g. "chrome.exe"
    pub pid:          u32,
    pub proc_path:    String,   // empty if unavailable
    pub proc_user:    String,   // empty if unavailable
    pub parent_name:  String,
    pub parent_pid:   u32,
    pub service_name: String,   // Windows service name, if any
    pub publisher:    String,   // PE CompanyName, Windows only

    // ── Network ──────────────────────────────────────────────────────────────
    pub local_addr:  String,    // "ip:port"
    pub remote_addr: String,    // "ip:port" or "LISTEN"
    pub status:      String,    // ESTABLISHED | LISTEN | SYN_SENT | …

    // ── Score ─────────────────────────────────────────────────────────────────
    pub score:   u8,
    pub reasons: Vec<String>,

    // ── Ancestry ─────────────────────────────────────────────────────────────
    /// Full ancestor chain: [(name, pid), …] from immediate parent to root.
    /// Empty when the process has no parent or the chain cannot be walked.
    pub ancestor_chain: Vec<(String, u32)>,

    // ── Session ──────────────────────────────────────────────────────────────
    /// `true` when this connection was observed while **no interactive user
    /// session** was active — i.e. Vigil is running as a boot-time service
    /// and nobody has logged in yet.  Boot-time persistence callbacks are a
    /// classic rootkit / dropper signal, so this flag adds `+2` to the score
    /// and the UI tags the row with a "PRE-LOGIN" badge.
    #[serde(default)]
    pub pre_login: bool,
}

// ── Events sent monitor → UI ──────────────────────────────────────────────────

/// Sent over the broadcast channel each time the monitor sees something new.
#[derive(Debug, Clone)]
pub enum ConnEvent {
    /// score < alert_threshold (or log_all_connections is true and score == 0)
    New(ConnInfo),
    /// score >= alert_threshold
    Alert(ConnInfo),
    /// A previously-known connection has disappeared.
    Closed {
        pid:    u32,
        local:  String,
        remote: String,
    },
}

// ── Tray state ────────────────────────────────────────────────────────────────

/// Drives the tray icon colour and tooltip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrayState {
    #[default]
    Ok,       // green  — monitoring, no unseen alerts
    Alert,    // amber  — unseen alerts present
    Stopped,  // grey   — monitoring paused
}

// ── Control messages UI → monitor ─────────────────────────────────────────────

/// Sent from the UI (or tray) to the monitor's control channel.
#[derive(Debug)]
pub enum MonitorCmd {
    Stop,
    Resume,
    UpdateConfig(Box<crate::config::Config>),
}
