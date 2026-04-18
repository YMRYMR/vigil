//! Configuration: load, save, and mutate `vigil.json`.
//!
//! On first run, Vigil seeds `vigil.json` with the compiled-in defaults.
//! After that, the file is treated as authoritative so user edits persist
//! exactly as saved.
//!
//! The config file lives in the per-user app-data directory.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

    #[serde(default)]
    pub allowlist_mode_enabled: bool,
    #[serde(default)]
    pub allowlist_mode_dry_run: bool,
    #[serde(default)]
    pub allowlist_processes: Vec<String>,

    #[serde(default)]
    pub response_rules_enabled: bool,
    #[serde(default = "default_true")]
    pub response_rules_dry_run: bool,
    #[serde(default)]
    pub response_rules_path: String,

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

    #[serde(default)]
    pub process_dump_on_alert: bool,
    #[serde(default = "default_process_dump_min_score")]
    pub process_dump_min_score: u8,
    #[serde(default = "default_process_dump_cooldown_secs")]
    pub process_dump_cooldown_secs: u64,
    #[serde(default)]
    pub process_dump_dir: String,

    #[serde(default)]
    pub pcap_on_alert: bool,
    #[serde(default = "default_pcap_min_score")]
    pub pcap_min_score: u8,
    #[serde(default = "default_pcap_duration_secs")]
    pub pcap_duration_secs: u64,
    #[serde(default = "default_pcap_cooldown_secs")]
    pub pcap_cooldown_secs: u64,
    #[serde(default = "default_pcap_packet_size_bytes")]
    pub pcap_packet_size_bytes: u32,
    #[serde(default)]
    pub pcap_dir: String,

    #[serde(default)]
    pub honeypot_decoys_enabled: bool,
    #[serde(default)]
    pub honeypot_auto_isolate: bool,
    #[serde(default = "default_honeypot_poll_secs")]
    pub honeypot_poll_secs: u64,
    #[serde(default)]
    pub honeypot_decoy_names: Vec<String>,

    #[serde(default = "default_true")]
    pub break_glass_enabled: bool,
    #[serde(default = "default_break_glass_timeout_mins")]
    pub break_glass_timeout_mins: u64,
    #[serde(default = "default_break_glass_heartbeat_secs")]
    pub break_glass_heartbeat_secs: u64,
}

fn default_true() -> bool {
    true
}
fn default_fswatch_window() -> u64 {
    600
}
fn default_long_lived_threshold() -> u64 {
    3600
}
fn default_dga_threshold() -> f32 {
    3.2
}
fn default_auto_response_min_score() -> u8 {
    10
}
fn default_auto_response_cooldown_secs() -> u64 {
    300
}
fn default_scheduled_lockdown_start_hour() -> u8 {
    23
}
fn default_scheduled_lockdown_start_minute() -> u8 {
    0
}
fn default_scheduled_lockdown_end_hour() -> u8 {
    6
}
fn default_scheduled_lockdown_end_minute() -> u8 {
    0
}
fn default_process_dump_min_score() -> u8 {
    12
}
fn default_process_dump_cooldown_secs() -> u64 {
    600
}
fn default_pcap_min_score() -> u8 {
    12
}
fn default_pcap_duration_secs() -> u64 {
    15
}
fn default_pcap_cooldown_secs() -> u64 {
    300
}
fn default_pcap_packet_size_bytes() -> u32 {
    0
}
fn default_honeypot_poll_secs() -> u64 {
    10
}
fn default_break_glass_timeout_mins() -> u64 {
    10
}
fn default_break_glass_heartbeat_secs() -> u64 {
    30
}

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_interval_secs: 5,
            alert_threshold: 3,
            log_all_connections: false,
            autostart: false,
            first_run_done: false,
            trusted_processes: vec![
                "svchost",
                "lsass",
                "services",
                "system",
                "smss",
                "csrss",
                "wininit",
                "winlogon",
                "explorer",
                "runtimebroker",
                "searchhost",
                "startmenuexperiencehost",
                "shellhost",
                "sihost",
                "ctfmon",
                "textinputhost",
                "shellexperiencehost",
                "widgetservice",
                "widgetboard",
                "crossdeviceservice",
                "crossdeviceresume",
                "phoneexperiencehost",
                "castsrv",
                "chrome",
                "msedge",
                "firefox",
                "opera",
                "brave",
                "vivaldi",
                "msedgewebview2",
                "cefsharp.browsersubprocess",
                "onedrive",
                "systemsettings",
                "microsoftstartfeedprovider",
                "avgsvc",
                "avgui",
                "avgbidsagent",
                "avgdriverupdsvc",
                "avgtuneupssvc",
                "vpnsvc",
                "tuneupssvc",
                "avgwscreporter",
                "avgantitrack",
                "antitrackSvc",
                "securevpn",
                "su_worker",
                "avgtoolssvc",
                "wa_3rd_party_host_64",
                "avlaunch",
                "claude",
                "node",
                "python",
                "python3",
                "spotify",
                "steam",
                "epicgameslauncher",
                "ealauncher",
                "eadesktop",
                "eabackgroundservice",
                "whatsapp",
                "whatsapp.root",
                "zoom",
                "slack",
                "discord",
                "telegram",
                "ollama",
                "ollama_llama_server",
                "nvdisplay.containerlocalsystem",
                "nvbroadcast.containerlocalsystem",
                "rtkaudiouniversalservice",
                "intelgraphicssoftwareservice",
                "waasmedicsvc",
                "wsaifabricsvc",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            common_ports: vec![
                80, 443, 8080, 8443, 53, 853, 22, 21, 25, 587, 465, 993, 995, 110, 143, 5222, 5228,
                3478, 3479, 7500, 27275,
            ],
            malware_ports: vec![
                4444, 1337, 31337, 6666, 6667, 6668, 6669, 9999, 1234, 54321, 12345, 23, 5900,
                5901, 4899, 8888,
            ],
            suspicious_path_fragments: [
                r"\Temp\",
                r"\AppData\Local\Temp\",
                r"\AppData\Roaming\",
                r"\Downloads\",
                r"\Public\",
                "/tmp/",
                "/var/tmp/",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            lolbins: vec![
                "cmd",
                "powershell",
                "pwsh",
                "wscript",
                "cscript",
                "mshta",
                "regsvr32",
                "rundll32",
                "certutil",
                "bitsadmin",
                "wmic",
                "msiexec",
                "installutil",
                "regasm",
                "regsvcs",
                "forfiles",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
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
            allowlist_mode_enabled: false,
            allowlist_mode_dry_run: true,
            allowlist_processes: Vec::new(),
            response_rules_enabled: false,
            response_rules_dry_run: true,
            response_rules_path: String::new(),
            scheduled_lockdown_enabled: false,
            scheduled_lockdown_start_hour: 23,
            scheduled_lockdown_start_minute: 0,
            scheduled_lockdown_end_hour: 6,
            scheduled_lockdown_end_minute: 0,
            process_dump_on_alert: false,
            process_dump_min_score: 12,
            process_dump_cooldown_secs: 600,
            process_dump_dir: String::new(),
            pcap_on_alert: false,
            pcap_min_score: 12,
            pcap_duration_secs: 15,
            pcap_cooldown_secs: 300,
            pcap_packet_size_bytes: 0,
            pcap_dir: String::new(),
            honeypot_decoys_enabled: false,
            honeypot_auto_isolate: false,
            honeypot_poll_secs: 10,
            honeypot_decoy_names: vec![
                "Quarterly Payroll 2026.xlsx".into(),
                "Passwords-Do-Not-Open.txt".into(),
                "AWS-Root-Keys.txt".into(),
            ],
            break_glass_enabled: true,
            break_glass_timeout_mins: 10,
            break_glass_heartbeat_secs: 30,
        }
    }
}

pub fn data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(dir).join("Vigil");
        }
        if let Some(dir) = std::env::var_os("APPDATA") {
            return PathBuf::from(dir).join("Vigil");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Vigil");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("vigil");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".config").join("vigil");
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("vigil-data")))
        .unwrap_or_else(|| PathBuf::from("vigil-data"))
}

pub fn config_path() -> PathBuf {
    data_dir().join("vigil.json")
}

impl Config {
    pub fn load() -> Self {
        let path = config_path();
        if !path.exists() {
            return Self::default();
        }
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Config>(&s).ok())
            .unwrap_or_default()
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
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("failed to save config: {e}");
                }
            }
            Err(e) => tracing::warn!("failed to serialise config: {e}"),
        }
    }
    #[allow(dead_code)]
    pub fn get_trusted(&self) -> &[String] {
        &self.trusted_processes
    }
    pub fn add_trusted(&mut self, name: &str) -> bool {
        let key = normalise_name(name);
        if key.is_empty() {
            return false;
        }
        if self
            .trusted_processes
            .iter()
            .any(|t| t.eq_ignore_ascii_case(&key))
        {
            return false;
        }
        self.trusted_processes.push(key);
        true
    }
    #[allow(dead_code)]
    pub fn remove_trusted(&mut self, name: &str) -> bool {
        let before = self.trusted_processes.len();
        self.trusted_processes
            .retain(|t| !t.eq_ignore_ascii_case(name));
        self.trusted_processes.len() < before
    }
}

pub fn normalise_name(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .trim_end_matches(".exe")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_has_chrome_trusted() {
        let cfg = Config::default();
        assert!(cfg.trusted_processes.contains(&"chrome".to_string()));
    }
    #[test]
    fn add_trusted_normalises_name() {
        let mut cfg = Config::default();
        assert!(cfg.add_trusted("MyApp.exe"));
        assert!(cfg.trusted_processes.contains(&"myapp".to_string()));
    }
    #[test]
    fn add_trusted_no_duplicate() {
        let mut cfg = Config::default();
        cfg.add_trusted("testapp");
        assert!(!cfg.add_trusted("testapp"));
        assert_eq!(
            cfg.trusted_processes
                .iter()
                .filter(|t| *t == "testapp")
                .count(),
            1
        );
    }
    #[test]
    fn remove_trusted_works() {
        let mut cfg = Config::default();
        cfg.add_trusted("removeme");
        assert!(cfg.remove_trusted("removeme"));
        assert!(!cfg.trusted_processes.contains(&"removeme".to_string()));
    }
    #[test]
    fn defaults_cover_phase_eleven_backlog() {
        let cfg = Config::default();
        assert!(!cfg.allowlist_mode_enabled);
        assert!(cfg.allowlist_mode_dry_run);
        assert!(!cfg.response_rules_enabled);
        assert!(cfg.response_rules_dry_run);
        assert!(!cfg.honeypot_decoys_enabled);
        assert!(!cfg.honeypot_auto_isolate);
        assert_eq!(cfg.honeypot_poll_secs, 10);
        assert!(cfg.break_glass_enabled);
    }
}
