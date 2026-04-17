//! Configuration: load, save, and mutate `vigil.json`.
//!
//! On first run, Vigil seeds `vigil.json` with the compiled-in defaults.
//! After that, the file is treated as authoritative so user edits persist
//! exactly as saved.
//!
//! The config file lives next to the binary:  `<exe_dir>/vigil.json`

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
    //
    // All fields below are optional / defaulted — the `#[serde(default)]`
    // attributes keep the config file backwards-compatible with older Vigil
    // releases.
    /// Path to a MaxMind GeoLite2-City `.mmdb` file. When empty, geolocation is
    /// disabled and country scoring is a no-op.
    #[serde(default)]
    pub geoip_city_db: String,

    /// Path to a MaxMind GeoLite2-ASN `.mmdb` file. Same rules as City.
    #[serde(default)]
    pub geoip_asn_db: String,

    /// Two-letter ISO country codes (uppercase) considered normal. Connections
    /// to countries **not** on the list score +2 "unusual country". Empty list
    /// disables the rule.
    #[serde(default)]
    pub allowed_countries: Vec<String>,

    /// Paths to plain-text IP blocklists (one IP or CIDR per line; `#` starts
    /// a comment). Connections to blocked IPs score +3 with a "reputation hit"
    /// reason naming the list file.
    #[serde(default)]
    pub blocklist_paths: Vec<String>,

    /// Enable the file-system watcher for `Temp`, `AppData`, and `Downloads`.
    /// When a connection's executable matches a file that was dropped there
    /// within `fswatch_window_secs`, the score gets +3.
    #[serde(default = "default_true")]
    pub fswatch_enabled: bool,

    /// Correlation window, in seconds, between a new executable appearing and
    /// a connection originating from it.
    #[serde(default = "default_fswatch_window")]
    pub fswatch_window_secs: u64,

    /// Threshold, in seconds, after which a still-open outbound connection
    /// from an untrusted process earns the "long-lived connection" +2 bonus.
    #[serde(default = "default_long_lived_threshold")]
    pub long_lived_secs: u64,

    /// Enable reverse-DNS lookups on remote IPs. Disabled by default because
    /// the OS resolver can leak the fact that Vigil is watching.
    #[serde(default)]
    pub reverse_dns_enabled: bool,

    /// Minimum Shannon entropy (bits per character) of a resolved hostname's
    /// leftmost label to flag as DGA-like. Typical human-readable domains
    /// score under 3.5; random-looking DGA output scores 4.0+.
    #[serde(default = "default_dga_threshold")]
    pub dga_entropy_threshold: f32,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_interval_secs: 5,
            alert_threshold: 3,
            log_all_connections: false,
            autostart: false,
            first_run_done: false,

            trusted_processes: vec![
                // Windows core
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
                // Browsers
                "chrome",
                "msedge",
                "firefox",
                "opera",
                "brave",
                "vivaldi",
                "msedgewebview2",
                "cefsharp.browsersubprocess",
                // Microsoft cloud / update
                "onedrive",
                "systemsettings",
                "microsoftstartfeedprovider",
                // AVG / antivirus suite
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
                // Dev tools
                "claude",
                "node",
                "python",
                "python3",
                // Gaming / media
                "spotify",
                "steam",
                "epicgameslauncher",
                "ealauncher",
                "eadesktop",
                "eabackgroundservice",
                // Comms
                "whatsapp",
                "whatsapp.root",
                "zoom",
                "slack",
                "discord",
                "telegram",
                // Local AI
                "ollama",
                "ollama_llama_server",
                // NVIDIA
                "nvdisplay.containerlocalsystem",
                "nvbroadcast.containerlocalsystem",
                // Misc hardware / OS
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

            // Phase 10 defaults
            geoip_city_db: String::new(),
            geoip_asn_db: String::new(),
            allowed_countries: Vec::new(),
            blocklist_paths: Vec::new(),
            fswatch_enabled: true,
            fswatch_window_secs: 600,
            long_lived_secs: 3600,
            reverse_dns_enabled: false,
            dga_entropy_threshold: 3.2,
        }
    }
}

// ── Persistence ───────────────────────────────────────────────────────────────

/// Returns the path to `vigil.json` next to the running binary.
pub fn config_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("vigil.json")))
        .unwrap_or_else(|| PathBuf::from("vigil.json"))
}

impl Config {
    /// Load config from disk.
    /// If the file doesn't exist or is corrupt, returns pure defaults.
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

    /// Save to disk. Logs a warning on failure but never panics.
    pub fn save(&self) {
        let path = config_path();
        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("failed to save config: {e}");
                }
            }
            Err(e) => tracing::warn!("failed to serialise config: {e}"),
        }
    }

    // ── Trusted process helpers ───────────────────────────────────────────────

    #[allow(dead_code)]
    pub fn get_trusted(&self) -> &[String] {
        &self.trusted_processes
    }

    /// Add a process name to the trusted list (normalised: lowercase, no .exe).
    /// Returns `true` if it was newly added.
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

    /// Remove a process name from the trusted list.
    /// Returns `true` if it was present.
    #[allow(dead_code)]
    pub fn remove_trusted(&mut self, name: &str) -> bool {
        let before = self.trusted_processes.len();
        self.trusted_processes
            .retain(|t| !t.eq_ignore_ascii_case(name));
        self.trusted_processes.len() < before
    }
}

/// Normalise a process name for storage: lowercase, strip `.exe`.
pub fn normalise_name(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .trim_end_matches(".exe")
        .to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
        assert!(!cfg.add_trusted("testapp")); // second add returns false
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
    fn load_uses_stored_values_exactly() {
        let stored = Config {
            alert_threshold: 7,
            poll_interval_secs: 10,
            trusted_processes: vec!["b".into(), "c".into()],
            ..Config::default()
        };

        let json = serde_json::to_string(&stored).unwrap();
        let loaded: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.alert_threshold, 7);
        assert_eq!(loaded.poll_interval_secs, 10);
        assert_eq!(
            loaded.trusted_processes,
            vec!["b".to_string(), "c".to_string()]
        );
    }
}
