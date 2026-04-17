//! Configuration: load, save, and mutate `vigil.json`.
//!
//! On first run, Vigil seeds `vigil.json` with the compiled-in defaults.
//! After that, the file is treated as authoritative so user edits persist
//! exactly as saved.
//!
//! The config file lives in the per-user app-data directory.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Config struct ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub poll_interval_secs: u64,
    pub alert_threshold: u8,
    pub log_all_connections: bool,
    pub autostart: bool,
    pub first_run_done: bool,
    pub trusted_processes: Vec<String>,
    pub common_ports: Vec<u16>,
    pub malware_ports: Vec<u16>,
    pub suspicious_path_fragments: Vec<String>,
    pub lolbins: Vec<String>,

    // ── Phase 10: Reputation & Telemetry ─────────────────────────────────────
    #[serde(default)]
    pub geoip_city_db: String,
    #[serde(default)]
    pub geoip_asn_db: String,
    #[serde(default)]
    pub allowed_countries: Vec<String>,
    #[serde(default)]
    pub blocklist_paths: Vec<String>,
    #[serde(default = "default_true")]
    pub fswatch_enabled: bool,
    #[serde(default = "default_fswatch_window")]
    pub fswatch_window_secs: u64,
    #[serde(default = "default_long_lived_threshold")]
    pub long_lived_secs: u64,
    #[serde(default)]
    pub reverse_dns_enabled: bool,
    #[serde(default = "default_dga_threshold")]
    pub dga_entropy_threshold: f32,

    // ── Phase 12: Optional auto response ─────────────────────────────────────
    #[serde(default)]
    pub auto_response_enabled: bool,
    #[serde(default)]
    pub auto_response_dry_run: bool,
    #[serde(default)]
    pub auto_kill_connection: bool,
    #[serde(default)]
    pub auto_block_remote: bool,
    #[serde(default)]
    pub auto_block_process: bool,
    #[serde(default)]
    pub auto_isolate_machine: bool,
    #[serde(default = "default_auto_response_min_score")]
    pub auto_response_min_score: u8,
    #[serde(default = "default_auto_response_cooldown_secs")]
    pub auto_response_cooldown_secs: u64,

    // ── Phase 11: Scheduled lockdown ─────────────────────────────────────────
    #[serde(default)]
    pub scheduled_lockdown_enabled: bool,
    #[serde(default = "default_scheduled_lockdown_start_hour")]
    pub scheduled_lockdown_start_hour: u8,
    #[serde(default = "default_scheduled_lockdown_start_minute")]
    pub scheduled_lockdown_start_minute: u8,
    #[serde(default = "default_scheduled_lockdown_end_hour")]
    pub scheduled_lockdown_end_hour: u8,
    #[serde(default = "default_scheduled_lockdown_end_minute")]
    pub scheduled_lockdown_end_minute: u8,

    // ── Phase 11: Forensics on alert ─────────────────────────────────────────
    #[serde(default)]
    pub process_dump_on_alert: bool,
    #[serde(default = "default_process_dump_min_score")]
    pub process_dump_min_score: u8,
    #[serde(default = "default_process_dump_cooldown_secs")]
    pub process_dump_cooldown_secs: u64,
    #[serde(default)]
    pub process_dump_dir: String,
}

fn default_true() -> bool { true }
fn default_fswatch_window() -> u64 { 600 }
fn default_long_lived_threshold() -> u64 { 3600 }
fn default_dga_threshold() -> f32 { 3.2 }
fn default_auto_response_min_score() -> u8 { 10 }
fn default_auto_response_cooldown_secs() -> u64 { 300 }
fn default_scheduled_lockdown_start_hour() -> u8 { 23 }
fn default_scheduled_lockdown_start_minute() -> u8 { 0 }
fn default_scheduled_lockdown_end_hour() -> u8 { 6 }
fn default_scheduled_lockdown_end_minute() -> u8 { 0 }
fn default_process_dump_min_score() -> u8 { 12 }
fn default_process_dump_cooldown_secs() -> u64 { 600 }

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_interval_secs: 5,
            alert_threshold: 3,
            log_all_connections: false,
            autostart: false,
            first_run_done: false,
            trusted_processes: vec![
                "svchost","lsass","services","system","smss","csrss","wininit","winlogon","explorer","runtimebroker","searchhost","startmenuexperiencehost","shellhost","sihost","ctfmon","textinputhost","shellexperiencehost","widgetservice","widgetboard","crossdeviceservice","crossdeviceresume","phoneexperiencehost","castsrv",
                "chrome","msedge","firefox","opera","brave","vivaldi","msedgewebview2","cefsharp.browsersubprocess",
                "onedrive","systemsettings","microsoftstartfeedprovider",
                "avgsvc","avgui","avgbidsagent","avgdriverupdsvc","avgtuneupssvc","vpnsvc","tuneupssvc","avgwscreporter","avgantitrack","antitrackSvc","securevpn","su_worker","avgtoolssvc","wa_3rd_party_host_64","avlaunch",
                "claude","node","python","python3",
                "spotify","steam","epicgameslauncher","ealauncher","eadesktop","eabackgroundservice",
                "whatsapp","whatsapp.root","zoom","slack","discord","telegram",
                "ollama","ollama_llama_server",
                "nvdisplay.containerlocalsystem","nvbroadcast.containerlocalsystem",
                "rtkaudiouniversalservice","intelgraphicssoftwareservice","waasmedicsvc","wsaifabricsvc",
            ].iter().map(|s| s.to_string()).collect(),
            common_ports: vec![80, 443, 8080, 8443, 53, 853, 22, 21, 25, 587, 465, 993, 995, 110, 143, 5222, 5228, 3478, 3479, 7500, 27275],
            malware_ports: vec![4444, 1337, 31337, 6666, 6667, 6668, 6669, 9999, 1234, 54321, 12345, 23, 5900, 5901, 4899, 8888],
            suspicious_path_fragments: [r"\Temp\", r"\AppData\Local\Temp\", r"\AppData\Roaming\", r"\Downloads\", r"\Public\", "/tmp/", "/var/tmp/"].into_iter().map(|s| s.to_string()).collect(),
            lolbins: vec!["cmd","powershell","pwsh","wscript","cscript","mshta","regsvr32","rundll32","certutil","bitsadmin","wmic","msiexec","installutil","regasm","regsvcs","forfiles"].iter().map(|s| s.to_string()).collect(),
            geoip_city_db: String::new(),
            geoip_asn_db: String::new(),
            allowed_countries: Vec::new(),
            blocklist_paths: Vec::new(),
            fswatch_enabled: true,
            fswatch_window_secs: 600,
            long_lived_secs: 3600,
            reverse_dns_enabled: false,
            dga_entropy_threshold: 3.2,
            auto_response_enabled: false,
            auto_response_dry_run: true,
            auto_kill_connection: false,
            auto_block_remote: false,
            auto_block_process: false,
            auto_isolate_machine: false,
            auto_response_min_score: 10,
            auto_response_cooldown_secs: 300,
            scheduled_lockdown_enabled: false,
            scheduled_lockdown_start_hour: 23,
            scheduled_lockdown_start_minute: 0,
            scheduled_lockdown_end_hour: 6,
            scheduled_lockdown_end_minute: 0,
            process_dump_on_alert: false,
            process_dump_min_score: 12,
            process_dump_cooldown_secs: 600,
            process_dump_dir: String::new(),
        }
    }
}

pub fn data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA") { return PathBuf::from(dir).join("Vigil"); }
        if let Some(dir) = std::env::var_os("APPDATA") { return PathBuf::from(dir).join("Vigil"); }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") { return PathBuf::from(home).join("Library").join("Application Support").join("Vigil"); }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") { return PathBuf::from(xdg).join("vigil"); }
        if let Some(home) = std::env::var_os("HOME") { return PathBuf::from(home).join(".config").join("vigil"); }
    }
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("vigil-data"))).unwrap_or_else(|| PathBuf::from("vigil-data"))
}

pub fn config_path() -> PathBuf { data_dir().join("vigil.json") }

impl Config {
    pub fn load() -> Self {
        let path = config_path();
        if !path.exists() { return Self::default(); }
        std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str::<Config>(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self) {
        let path = config_path();
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!("failed to create config directory: {e}");
                return;
            }
        }
        match serde_json::to_string_pretty(self) {
            Ok(json) => { if let Err(e) = std::fs::write(&path, json) { tracing::warn!("failed to save config: {e}"); } }
            Err(e) => tracing::warn!("failed to serialise config: {e}"),
        }
    }

    #[allow(dead_code)]
    pub fn get_trusted(&self) -> &[String] { &self.trusted_processes }

    pub fn add_trusted(&mut self, name: &str) -> bool {
        let key = normalise_name(name);
        if key.is_empty() { return false; }
        if self.trusted_processes.iter().any(|t| t.eq_ignore_ascii_case(&key)) { return false; }
        self.trusted_processes.push(key);
        true
    }

    #[allow(dead_code)]
    pub fn remove_trusted(&mut self, name: &str) -> bool {
        let before = self.trusted_processes.len();
        self.trusted_processes.retain(|t| !t.eq_ignore_ascii_case(name));
        self.trusted_processes.len() < before
    }
}

pub fn normalise_name(name: &str) -> String { name.trim().to_lowercase().trim_end_matches(".exe").to_string() }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn default_has_chrome_trusted() { let cfg = Config::default(); assert!(cfg.trusted_processes.contains(&"chrome".to_string())); }
    #[test] fn add_trusted_normalises_name() { let mut cfg = Config::default(); assert!(cfg.add_trusted("MyApp.exe")); assert!(cfg.trusted_processes.contains(&"myapp".to_string())); }
    #[test] fn add_trusted_no_duplicate() { let mut cfg = Config::default(); cfg.add_trusted("testapp"); assert!(!cfg.add_trusted("testapp")); assert_eq!(cfg.trusted_processes.iter().filter(|t| *t == "testapp").count(), 1); }
    #[test] fn remove_trusted_works() { let mut cfg = Config::default(); cfg.add_trusted("removeme"); assert!(cfg.remove_trusted("removeme")); assert!(!cfg.trusted_processes.contains(&"removeme".to_string())); }
    #[test] fn load_uses_stored_values_exactly() { let stored = Config { alert_threshold: 7, poll_interval_secs: 10, trusted_processes: vec!["b".into(), "c".into()], ..Config::default() }; let json = serde_json::to_string(&stored).unwrap(); let loaded: Config = serde_json::from_str(&json).unwrap(); assert_eq!(loaded.alert_threshold, 7); assert_eq!(loaded.poll_interval_secs, 10); assert_eq!(loaded.trusted_processes, vec!["b".to_string(), "c".to_string()]); }
    #[test] fn auto_response_defaults_are_safe() { let cfg = Config::default(); assert!(!cfg.auto_response_enabled); assert!(cfg.auto_response_dry_run); assert!(!cfg.auto_kill_connection); assert!(!cfg.auto_block_remote); assert!(!cfg.auto_block_process); assert!(!cfg.auto_isolate_machine); assert_eq!(cfg.auto_response_min_score, 10); assert_eq!(cfg.auto_response_cooldown_secs, 300); }
    #[test] fn scheduled_lockdown_defaults_are_safe() { let cfg = Config::default(); assert!(!cfg.scheduled_lockdown_enabled); assert_eq!(cfg.scheduled_lockdown_start_hour, 23); assert_eq!(cfg.scheduled_lockdown_start_minute, 0); assert_eq!(cfg.scheduled_lockdown_end_hour, 6); assert_eq!(cfg.scheduled_lockdown_end_minute, 0); }
    #[test] fn process_dump_defaults_are_safe() { let cfg = Config::default(); assert!(!cfg.process_dump_on_alert); assert_eq!(cfg.process_dump_min_score, 12); assert_eq!(cfg.process_dump_cooldown_secs, 600); assert!(cfg.process_dump_dir.is_empty()); }
}
