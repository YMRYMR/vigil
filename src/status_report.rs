//! Conservative local protection-status report used by CLI surfaces.
//!
//! This first slice reports only facts that a local process can check without
//! attaching to the live GUI/service runtime. Runtime-only protection facts stay
//! `unknown` until the running monitor publishes live health.

#[path = "security/policy.rs"]
mod policy;

use serde::Serialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    DisabledByPolicy,
    NeedsElevation,
    FailedOpen,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubsystemStatus {
    pub name: &'static str,
    pub state: HealthState,
    pub summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionStatusReport {
    pub schema_version: u32,
    pub generated_unix: u64,
    pub app_version: &'static str,
    pub target_os: &'static str,
    pub target_arch: &'static str,
    pub data_dir: String,
    pub overall_state: HealthState,
    pub overall_summary: String,
    pub subsystems: Vec<SubsystemStatus>,
}

#[derive(Debug, Clone)]
enum ConfigProbe {
    Missing,
    Loaded(Value),
    Degraded {
        summary: String,
        details: Vec<String>,
    },
}

impl ConfigProbe {
    fn json(&self) -> Option<&Value> {
        match self {
            Self::Loaded(value) => Some(value),
            Self::Missing | Self::Degraded { .. } => None,
        }
    }
}

pub fn print_json_or_exit() {
    let report = build_report();
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("failed to serialize protection status: {err}");
            std::process::exit(1);
        }
    }
}

pub fn build_report() -> ProtectionStatusReport {
    let data_dir = data_dir();
    let config_path = data_dir.join("vigil.json");
    let config = probe_config(&config_path);

    let mut subsystems = vec![
        config_status(&config_path, &config),
        runtime_monitor_status(),
        firewall_status(),
        response_policy_status(config.json(), &data_dir),
        active_response_status(&data_dir),
        storage_status(&data_dir),
        yara_status(&data_dir),
        advisory_status(&data_dir),
        update_trust_status(),
    ];

    let overall_state = summarize_overall_state(&subsystems);
    let overall_summary = match overall_state {
        HealthState::Healthy => "checked subsystems are healthy; runtime-only protection still needs live service reporting",
        HealthState::Degraded => "one or more checked subsystems are degraded",
        HealthState::FailedOpen => "one or more subsystems failed open to preserve host availability",
        HealthState::NeedsElevation => "one or more checks need elevated privileges",
        HealthState::Unknown => "runtime protection state is not fully observable from this standalone command yet",
        HealthState::DisabledByPolicy => "protection is disabled by local policy",
    }
    .to_string();

    subsystems.sort_by_key(|status| status.name);

    ProtectionStatusReport {
        schema_version: SCHEMA_VERSION,
        generated_unix: unix_now(),
        app_version: env!("CARGO_PKG_VERSION"),
        target_os: env::consts::OS,
        target_arch: env::consts::ARCH,
        data_dir: data_dir.display().to_string(),
        overall_state,
        overall_summary,
        subsystems,
    }
}

fn probe_config(path: &Path) -> ConfigProbe {
    if !path.exists() {
        return ConfigProbe::Missing;
    }

    match policy::load_json_with_integrity(path) {
        Ok(Some(bytes)) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) => ConfigProbe::Loaded(value),
            Err(err) => ConfigProbe::Degraded {
                summary: "configuration file passed integrity checks but could not be parsed as JSON"
                    .into(),
                details: vec![format!("path={}", path.display()), format!("parse: {err}")],
            },
        },
        Ok(None) => ConfigProbe::Degraded {
            summary: "configuration file failed integrity verification and no restorable backup was available"
                .into(),
            details: vec![format!("path={}", path.display())],
        },
        Err(err) => ConfigProbe::Degraded {
            summary: "configuration file could not be loaded through the protected policy store".into(),
            details: vec![format!("path={}", path.display()), err],
        },
    }
}

fn config_status(path: &Path, config: &ConfigProbe) -> SubsystemStatus {
    match config {
        ConfigProbe::Loaded(_) => SubsystemStatus {
            name: "configuration",
            state: HealthState::Healthy,
            summary: "configuration file passed integrity verification and JSON parsing".into(),
            details: vec![format!("path={}", path.display())],
        },
        ConfigProbe::Degraded { summary, details } => SubsystemStatus {
            name: "configuration",
            state: HealthState::Degraded,
            summary: summary.clone(),
            details: details.clone(),
        },
        ConfigProbe::Missing => SubsystemStatus {
            name: "configuration",
            state: HealthState::Healthy,
            summary:
                "configuration file is absent; Vigil will use compiled defaults on first launch"
                    .into(),
            details: vec![format!("path={}", path.display())],
        },
    }
}

fn runtime_monitor_status() -> SubsystemStatus {
    SubsystemStatus {
        name: "runtime_monitor",
        state: HealthState::Unknown,
        summary: "standalone status does not yet attach to the GUI/service monitor".into(),
        details: vec![
            "future live health should report ETW/eBPF/polling backend, event lag, and last event time".into(),
        ],
    }
}

fn firewall_status() -> SubsystemStatus {
    let mut details = Vec::new();
    #[cfg(target_os = "linux")]
    {
        let nft = command_exists("nft");
        let iptables = command_exists("iptables");
        details.push(format!("nft_available={nft}"));
        details.push(format!("iptables_available={iptables}"));
        if nft || iptables {
            return SubsystemStatus {
                name: "firewall_backend",
                state: HealthState::Unknown,
                summary: "firewall tooling is present, but live backend health requires Vigil runtime checks"
                    .into(),
                details,
            };
        }
        return SubsystemStatus {
            name: "firewall_backend",
            state: HealthState::Degraded,
            summary: "no supported Linux firewall command was found in PATH".into(),
            details,
        };
    }

    #[cfg(windows)]
    {
        details.push("wfp_health=runtime_check_required".into());
        return SubsystemStatus {
            name: "firewall_backend",
            state: HealthState::Unknown,
            summary: "Windows WFP/backend health requires live Vigil runtime checks".into(),
            details,
        };
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        SubsystemStatus {
            name: "firewall_backend",
            state: HealthState::Degraded,
            summary: "this platform is outside Vigil's active Windows/Linux support scope".into(),
            details,
        }
    }
}

fn response_policy_status(config: Option<&Value>, data_dir: &Path) -> SubsystemStatus {
    let Some(config) = config else {
        return SubsystemStatus {
            name: "response_policy",
            state: HealthState::DisabledByPolicy,
            summary: "no readable protected config; disruptive response features default to off or dry-run"
                .into(),
            details: Vec::new(),
        };
    };

    let response_rules_enabled = bool_field(config, "response_rules_enabled");
    let response_rules_dry_run = bool_field(config, "response_rules_dry_run").unwrap_or(true);
    let auto_response_enabled = bool_field(config, "auto_response_enabled").unwrap_or(false);
    let auto_response_dry_run = bool_field(config, "auto_response_dry_run").unwrap_or(true);
    let allowlist_mode_enabled = bool_field(config, "allowlist_mode_enabled").unwrap_or(false);
    let allowlist_mode_dry_run = bool_field(config, "allowlist_mode_dry_run").unwrap_or(true);
    let scheduled_lockdown_enabled =
        bool_field(config, "scheduled_lockdown_enabled").unwrap_or(false);
    let response_rules_path = string_field(config, "response_rules_path").unwrap_or_default();

    let mut details = vec![
        format!("auto_response_enabled={auto_response_enabled}"),
        format!("auto_response_dry_run={auto_response_dry_run}"),
        format!("allowlist_mode_enabled={allowlist_mode_enabled}"),
        format!("allowlist_mode_dry_run={allowlist_mode_dry_run}"),
        format!(
            "response_rules_enabled={}",
            response_rules_enabled.unwrap_or(false)
        ),
        format!("response_rules_dry_run={response_rules_dry_run}"),
        format!("scheduled_lockdown_enabled={scheduled_lockdown_enabled}"),
    ];

    if response_rules_enabled.unwrap_or(false) {
        if response_rules_path.trim().is_empty() {
            return SubsystemStatus {
                name: "response_policy",
                state: HealthState::Degraded,
                summary: "response rules are enabled but no response_rules_path is configured"
                    .into(),
                details,
            };
        }
        let path = expand_data_relative(data_dir, &response_rules_path);
        details.push(format!("response_rules_path={}", path.display()));
        if !path.exists() {
            return SubsystemStatus {
                name: "response_policy",
                state: HealthState::Degraded,
                summary: "response rules are enabled but the configured file does not exist".into(),
                details,
            };
        }
    }

    let disruptive_enabled =
        auto_response_enabled || allowlist_mode_enabled || scheduled_lockdown_enabled;
    if !disruptive_enabled && !response_rules_enabled.unwrap_or(false) {
        return SubsystemStatus {
            name: "response_policy",
            state: HealthState::DisabledByPolicy,
            summary: "automatic response, allowlist mode, scheduled lockdown, and response rules are disabled"
                .into(),
            details,
        };
    }

    if auto_response_enabled && auto_response_dry_run
        || allowlist_mode_enabled && allowlist_mode_dry_run
        || response_rules_enabled.unwrap_or(false) && response_rules_dry_run
    {
        return SubsystemStatus {
            name: "response_policy",
            state: HealthState::DisabledByPolicy,
            summary: "one or more response features are enabled in dry-run mode only".into(),
            details,
        };
    }

    SubsystemStatus {
        name: "response_policy",
        state: HealthState::Healthy,
        summary: "one or more response features are enabled by policy".into(),
        details,
    }
}

fn active_response_status(data_dir: &Path) -> SubsystemStatus {
    let path = data_dir.join("vigil-active-response.json");
    if path.exists() {
        SubsystemStatus {
            name: "active_response_state",
            state: HealthState::Unknown,
            summary: "active-response state file exists; live reconciliation status requires Vigil runtime checks"
                .into(),
            details: vec![format!("path={}", path.display())],
        }
    } else {
        SubsystemStatus {
            name: "active_response_state",
            state: HealthState::Healthy,
            summary: "no persisted active-response state file is present".into(),
            details: vec![format!("path={}", path.display())],
        }
    }
}

fn storage_status(data_dir: &Path) -> SubsystemStatus {
    let db = data_dir.join("vigil-state.db");
    let manifest = data_dir.join("vigil-state.manifest.json");
    match (db.exists(), manifest.exists()) {
        (true, true) => SubsystemStatus {
            name: "protected_storage",
            state: HealthState::Unknown,
            summary:
                "state database and manifest exist; digest verification requires Vigil storage code"
                    .into(),
            details: vec![
                format!("db={}", db.display()),
                format!("manifest={}", manifest.display()),
            ],
        },
        (true, false) => SubsystemStatus {
            name: "protected_storage",
            state: HealthState::Degraded,
            summary: "state database exists but its integrity manifest is missing".into(),
            details: vec![
                format!("db={}", db.display()),
                format!("manifest={}", manifest.display()),
            ],
        },
        (false, true) => SubsystemStatus {
            name: "protected_storage",
            state: HealthState::Degraded,
            summary: "state manifest exists but the state database is missing".into(),
            details: vec![
                format!("db={}", db.display()),
                format!("manifest={}", manifest.display()),
            ],
        },
        (false, false) => SubsystemStatus {
            name: "protected_storage",
            state: HealthState::Healthy,
            summary: "state database is not initialized yet".into(),
            details: vec![
                format!("db={}", db.display()),
                format!("manifest={}", manifest.display()),
            ],
        },
    }
}

fn yara_status(data_dir: &Path) -> SubsystemStatus {
    let local_rules = data_dir.join("yara-rules");
    let mut details = vec![format!("local_rules_dir={}", local_rules.display())];
    if local_rules.exists() {
        let sidecar_count = count_extension(&local_rules, "sha256");
        details.push(format!("sha256_sidecars={sidecar_count}"));
        SubsystemStatus {
            name: "yara_rules",
            state: HealthState::Unknown,
            summary: "local YARA rule directory exists; run vigil --yara-rule-status for integrity details"
                .into(),
            details,
        }
    } else {
        SubsystemStatus {
            name: "yara_rules",
            state: HealthState::Unknown,
            summary: "local YARA rule directory is absent; bundled-rule health requires Vigil runtime validation"
                .into(),
            details,
        }
    }
}

fn advisory_status(data_dir: &Path) -> SubsystemStatus {
    let db = data_dir.join("vigil-state.db");
    if db.exists() {
        SubsystemStatus {
            name: "advisory_cache",
            state: HealthState::Unknown,
            summary: "state database exists; advisory source freshness requires storage-backed cache inspection"
                .into(),
            details: vec![format!("db={}", db.display())],
        }
    } else {
        SubsystemStatus {
            name: "advisory_cache",
            state: HealthState::Unknown,
            summary: "state database is not initialized; advisory cache may be empty until first import or sync"
                .into(),
            details: vec![format!("db={}", db.display())],
        }
    }
}

fn update_trust_status() -> SubsystemStatus {
    SubsystemStatus {
        name: "update_trust",
        state: HealthState::Unknown,
        summary: "release-manifest verification is available, but periodic signed threat-data updates are not implemented yet"
            .into(),
        details: vec![
            "use --verify-update-manifest MANIFEST.json MANIFEST.json.sig for offline release manifest checks"
                .into(),
        ],
    }
}

fn summarize_overall_state(subsystems: &[SubsystemStatus]) -> HealthState {
    if subsystems
        .iter()
        .any(|status| matches!(status.state, HealthState::FailedOpen))
    {
        return HealthState::FailedOpen;
    }
    if subsystems
        .iter()
        .any(|status| matches!(status.state, HealthState::Degraded))
    {
        return HealthState::Degraded;
    }
    if subsystems.iter().any(|status| {
        matches!(
            status.state,
            HealthState::NeedsElevation | HealthState::Unknown
        )
    }) {
        return HealthState::Unknown;
    }
    if subsystems
        .iter()
        .any(|status| matches!(status.state, HealthState::DisabledByPolicy))
    {
        return HealthState::DisabledByPolicy;
    }
    HealthState::Healthy
}

fn data_dir() -> PathBuf {
    if let Some(dir) = env::var_os("VIGIL_DATA_DIR") {
        return PathBuf::from(dir);
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = env::var_os("LOCALAPPDATA") {
            return PathBuf::from(dir).join("Vigil");
        }
        if let Some(dir) = env::var_os("APPDATA") {
            return PathBuf::from(dir).join("Vigil");
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("vigil");
        }
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(".config").join("vigil");
        }
    }

    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("vigil-data")))
        .unwrap_or_else(|| PathBuf::from("vigil-data"))
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn expand_data_relative(data_dir: &Path, configured: &str) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        path
    } else {
        data_dir.join(path)
    }
}

fn count_extension(dir: &Path, extension: &str) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case(extension))
                .unwrap_or(false)
        })
        .count()
}

#[cfg(target_os = "linux")]
fn command_exists(name: &str) -> bool {
    let Some(path_var) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path_var).any(|dir| dir.join(name).is_file())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn degraded_subsystem_makes_overall_degraded() {
        let subsystems = vec![SubsystemStatus {
            name: "test",
            state: HealthState::Degraded,
            summary: "bad".into(),
            details: Vec::new(),
        }];
        assert_eq!(summarize_overall_state(&subsystems), HealthState::Degraded);
    }

    #[test]
    fn unknown_subsystem_keeps_overall_honest() {
        let subsystems = vec![SubsystemStatus {
            name: "runtime_monitor",
            state: HealthState::Unknown,
            summary: "not attached".into(),
            details: Vec::new(),
        }];
        assert_eq!(summarize_overall_state(&subsystems), HealthState::Unknown);
    }

    #[test]
    fn disabled_subsystem_makes_overall_disabled_by_policy() {
        let subsystems = vec![SubsystemStatus {
            name: "response_policy",
            state: HealthState::DisabledByPolicy,
            summary: "dry-run only".into(),
            details: Vec::new(),
        }];
        assert_eq!(
            summarize_overall_state(&subsystems),
            HealthState::DisabledByPolicy
        );
    }

    #[test]
    fn unsigned_existing_config_is_reported_degraded() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vigil.json");
        fs::write(&path, br#"{"auto_response_enabled":true}"#).unwrap();

        let probe = probe_config(&path);
        let status = config_status(&path, &probe);

        assert_eq!(status.state, HealthState::Degraded);
        assert!(status.summary.contains("protected policy store"));
    }

    #[test]
    fn signed_existing_config_is_reported_healthy() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vigil.json");
        policy::save_json_with_integrity(&path, br#"{"auto_response_enabled":true}"#).unwrap();

        let probe = probe_config(&path);
        let status = config_status(&path, &probe);

        assert_eq!(status.state, HealthState::Healthy);
    }

    #[test]
    fn relative_policy_path_is_data_dir_relative() {
        assert_eq!(
            expand_data_relative(Path::new("/tmp/vigil"), "rules.yaml"),
            PathBuf::from("/tmp/vigil/rules.yaml")
        );
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-status-report-{nanos}"))
    }
}
