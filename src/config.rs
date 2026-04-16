//! Configuration: load, save, merge, and mutate `vigil.json`.
//!
//! On load, stored values are *merged* with compiled-in defaults:
//! - Lists are unioned (user additions are kept; defaults are always present)
//! - Scalars use the stored value if present, else the default
//!
//! The config file lives next to the binary:  `<exe_dir>/vigil.json`

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

// ── Config struct ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub poll_interval_secs:    u64,
    pub alert_threshold:       u8,
    pub log_all_connections:   bool,
    pub autostart:             bool,
    pub first_run_done:        bool,
    pub trusted_processes:     Vec<String>,
    pub common_ports:          Vec<u16>,
    pub malware_ports:         Vec<u16>,
    pub suspicious_path_fragments: Vec<String>,
    pub lolbins:               Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_interval_secs:  5,
            alert_threshold:     3,
            log_all_connections: false,
            autostart:           false,
            first_run_done:      false,

            trusted_processes: vec![
                // Windows core
                "svchost", "lsass", "services", "system", "smss", "csrss",
                "wininit", "winlogon", "explorer", "runtimebroker", "searchhost",
                "startmenuexperiencehost", "shellhost", "sihost", "ctfmon",
                "textinputhost", "shellexperiencehost", "widgetservice", "widgetboard",
                "crossdeviceservice", "crossdeviceresume", "phoneexperiencehost",
                "castsrv",
                // Browsers
                "chrome", "msedge", "firefox", "opera", "brave", "vivaldi",
                "msedgewebview2", "cefsharp.browsersubprocess",
                // Microsoft cloud / update
                "onedrive", "systemsettings", "microsoftstartfeedprovider",
                // AVG / antivirus suite
                "avgsvc", "avgui", "avgbidsagent", "avgdriverupdsvc",
                "avgtuneupssvc", "vpnsvc", "tuneupssvc", "avgwscreporter",
                "avgantitrack", "antitrackSvc", "securevpn",
                "su_worker", "avgtoolssvc", "wa_3rd_party_host_64", "avlaunch",
                // Dev tools
                "claude", "node", "python", "python3",
                // Gaming / media
                "spotify", "steam", "epicgameslauncher", "ealauncher",
                "eadesktop", "eabackgroundservice",
                // Comms
                "whatsapp", "whatsapp.root", "zoom", "slack", "discord", "telegram",
                // Local AI
                "ollama", "ollama_llama_server",
                // NVIDIA
                "nvdisplay.containerlocalsystem", "nvbroadcast.containerlocalsystem",
                // Misc hardware / OS
                "rtkaudiouniversalservice", "intelgraphicssoftwareservice",
                "waasmedicsvc", "wsaifabricsvc",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),

            common_ports: vec![
                80, 443, 8080, 8443,
                53, 853,
                22, 21,
                25, 587, 465, 993, 995, 110, 143,
                5222, 5228,
                3478, 3479,
                7500, 27275,
            ],

            malware_ports: vec![
                4444, 1337, 31337,
                6666, 6667, 6668, 6669,
                9999, 1234, 54321, 12345,
                23, 5900, 5901, 4899, 8888,
            ],

            suspicious_path_fragments: vec![
                r"\Temp\",
                r"\AppData\Local\Temp\",
                r"\AppData\Roaming\",
                r"\Downloads\",
                r"\Public\",
                "/tmp/",
                "/var/tmp/",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),

            lolbins: vec![
                "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta",
                "regsvr32", "rundll32", "certutil", "bitsadmin", "wmic",
                "msiexec", "installutil", "regasm", "regsvcs", "forfiles",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
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
    /// Load config from disk and merge with compiled-in defaults.
    /// If the file doesn't exist or is corrupt, returns pure defaults.
    pub fn load() -> Self {
        let path = config_path();
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Config>(&s).ok())
        {
            Some(stored) => Self::merge(Self::default(), stored),
            None => Self::default(),
        }
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

    /// Merge `stored` onto `base`:
    /// - Lists: union of base + stored (no duplicates, order preserved)
    /// - Scalars: stored wins
    fn merge(base: Config, stored: Config) -> Config {
        Config {
            // Scalars — stored wins
            poll_interval_secs:  stored.poll_interval_secs,
            alert_threshold:     stored.alert_threshold,
            log_all_connections: stored.log_all_connections,
            autostart:           stored.autostart,
            first_run_done:      stored.first_run_done,

            // String lists — case-insensitive union
            trusted_processes:         union_str(base.trusted_processes,         stored.trusted_processes),
            suspicious_path_fragments: union_str(base.suspicious_path_fragments, stored.suspicious_path_fragments),
            lolbins:                   union_str(base.lolbins,                   stored.lolbins),

            // Numeric lists — exact-equality union
            common_ports:  union_eq(base.common_ports,  stored.common_ports),
            malware_ports: union_eq(base.malware_ports, stored.malware_ports),
        }
    }

    // ── Trusted process helpers ───────────────────────────────────────────────

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
        if self.trusted_processes.iter().any(|t| t.eq_ignore_ascii_case(&key)) {
            return false;
        }
        self.trusted_processes.push(key);
        true
    }

    /// Remove a process name from the trusted list.
    /// Returns `true` if it was present.
    pub fn remove_trusted(&mut self, name: &str) -> bool {
        let before = self.trusted_processes.len();
        self.trusted_processes
            .retain(|t| !t.eq_ignore_ascii_case(name));
        self.trusted_processes.len() < before
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Union two String vecs, case-insensitive dedup, order preserved.
fn union_str(mut base: Vec<String>, extra: Vec<String>) -> Vec<String> {
    let seen: HashSet<String> = base.iter().map(|s| s.to_lowercase()).collect();
    for item in extra {
        if !seen.contains(&item.to_lowercase()) {
            base.push(item);
        }
    }
    base
}

/// Union two u16 vecs, exact dedup, order preserved.
fn union_eq(mut base: Vec<u16>, extra: Vec<u16>) -> Vec<u16> {
    let seen: HashSet<u16> = base.iter().copied().collect();
    for item in extra {
        if !seen.contains(&item) {
            base.push(item);
        }
    }
    base
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
        assert!(!cfg.add_trusted("testapp"));   // second add returns false
        assert_eq!(
            cfg.trusted_processes.iter().filter(|t| *t == "testapp").count(),
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
    fn merge_unions_lists() {
        let mut base = Config::default();
        base.trusted_processes = vec!["a".into(), "b".into()];
        let mut stored = Config::default();
        stored.trusted_processes = vec!["b".into(), "c".into()];
        let merged = Config::merge(base, stored);
        assert!(merged.trusted_processes.contains(&"a".to_string()));
        assert!(merged.trusted_processes.contains(&"b".to_string()));
        assert!(merged.trusted_processes.contains(&"c".to_string()));
        assert_eq!(
            merged.trusted_processes.iter().filter(|t| *t == "b").count(),
            1
        );
    }

    #[test]
    fn merge_scalars_prefer_stored() {
        let base = Config::default();
        let mut stored = Config::default();
        stored.alert_threshold = 7;
        stored.poll_interval_secs = 10;
        let merged = Config::merge(base, stored);
        assert_eq!(merged.alert_threshold, 7);
        assert_eq!(merged.poll_interval_secs, 10);
    }
}
