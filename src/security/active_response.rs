#[path = "active_response_impl.rs"]
mod imp;

const ISOLATE_RULE_IN: &str = "Vigil Isolate In";
const ISOLATE_RULE_OUT: &str = "Vigil Isolate Out";

pub use imp::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockdownSchedule {
    pub start_hour: u8,
    pub start_minute: u8,
    pub end_hour: u8,
    pub end_minute: u8,
}

pub fn schedule_contains(schedule: &LockdownSchedule, hour: u8, minute: u8) -> bool {
    let current = hour.min(23) as u16 * 60 + minute.min(59) as u16;
    let start = schedule.start_hour.min(23) as u16 * 60 + schedule.start_minute.min(59) as u16;
    let end = schedule.end_hour.min(23) as u16 * 60 + schedule.end_minute.min(59) as u16;
    if start <= end {
        current >= start && current < end
    } else {
        current >= start || current < end
    }
}

pub fn restore_network() -> Result<String, String> {
    imp::restore_machine()
}

pub fn revert_autoruns() -> Result<String, String> {
    imp::revert_frozen_autoruns()
}

pub fn quarantine_profile(pid: u32, path: &str, proc_name: &str) -> Result<String, String> {
    imp::apply_quarantine_profile(pid, path, proc_name)
}

pub fn clear_quarantine_profile(pid: u32, path: &str) -> Result<String, String> {
    imp::clear_quarantine_profile(pid, path)
}

pub fn suspend_process(pid: u32, path: &str) -> Result<String, String> {
    imp::suspend_process(pid, path, "")
}

pub fn duration_preset_label(preset: DurationPreset) -> &'static str {
    preset.label()
}

pub fn snapshot_target(
    pid: u32,
    selected_connection: Option<&crate::types::ConnInfo>,
    path: Option<&str>,
) -> InspectorSnapshot {
    imp::inspector_snapshot(pid, path.unwrap_or_default(), selected_connection)
}

pub fn kill_connection_by_tuple(
    pid: u32,
    proc_name: &str,
    local_addr: &str,
    remote_addr: &str,
) -> Result<String, String> {
    let conn = crate::types::ConnInfo {
        timestamp: String::new(),
        proc_name: proc_name.to_string(),
        pid,
        proc_path: String::new(),
        proc_user: String::new(),
        parent_user: String::new(),
        parent_name: String::new(),
        parent_pid: 0,
        service_name: String::new(),
        publisher: String::new(),
        command_line: String::new(),
        local_addr: local_addr.to_string(),
        remote_addr: remote_addr.to_string(),
        status: "ESTABLISHED".to_string(),
        protocol: crate::types::TransportProtocol::Tcp,
        first_seen_unix: 0,
        closed_unix: None,
        duration_secs: None,
        score: 0,
        reasons: Vec::new(),
        attack_tags: Vec::new(),
        ancestor_chain: Vec::new(),
        pre_login: false,
        hostname: None,
        country: None,
        asn: None,
        asn_org: None,
        reputation_hit: None,
        recently_dropped: false,
        long_lived: false,
        dga_like: false,
        baseline_deviation: false,
        script_host_suspicious: false,
        tls_sni: None,
        tls_ja3: None,
    };
    imp::kill_connection(&conn).map_err(|err| err.to_string())
}
