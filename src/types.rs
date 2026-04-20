//! Core data types shared across all modules.

use serde::{Deserialize, Serialize};

/// Everything captured about a single active connection event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnInfo {
    pub timestamp: String,

    pub proc_name: String,
    pub pid: u32,
    pub proc_path: String,
    pub proc_user: String,
    #[serde(default)]
    pub parent_user: String,
    pub parent_name: String,
    pub parent_pid: u32,
    pub service_name: String,
    pub publisher: String,
    #[serde(default)]
    pub command_line: String,

    pub local_addr: String,
    pub remote_addr: String,
    pub status: String,

    pub score: u8,
    pub reasons: Vec<String>,
    #[serde(default)]
    pub attack_tags: Vec<String>,

    pub ancestor_chain: Vec<(String, u32)>,

    #[serde(default)]
    pub pre_login: bool,

    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub asn_org: Option<String>,
    #[serde(default)]
    pub reputation_hit: Option<String>,
    #[serde(default)]
    pub recently_dropped: bool,
    #[serde(default)]
    pub long_lived: bool,
    #[serde(default)]
    pub dga_like: bool,
    #[serde(default)]
    pub baseline_deviation: bool,
    #[serde(default)]
    pub script_host_suspicious: bool,
    #[serde(default)]
    pub tls_sni: Option<String>,
    #[serde(default)]
    pub tls_ja3: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ConnEvent {
    New(ConnInfo),
    Alert(ConnInfo),
    Closed {
        pid: u32,
        local: String,
        remote: String,
    },
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrayState {
    #[default]
    Ok,
    Alert,
    Stopped,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum MonitorCmd {
    Stop,
    Resume,
    UpdateConfig(Box<crate::config::Config>),
}

/// Per-connection enrichment pipeline timing breakdown.
/// Each field is in microseconds. Used for profiling and diagnostics.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct PipelineTimings {
    pub process_collect_us: u64,
    pub geoip_us: u64,
    pub blocklist_us: u64,
    pub revdns_us: u64,
    pub fswatch_us: u64,
    pub baseline_us: u64,
    pub tls_lookup_us: u64,
    pub scoring_us: u64,
    pub tamper_us: u64,
    pub total_us: u64,
}
