//! Standalone Vigil protection-status report.
//!
//! This first slice is intentionally conservative: it reports only facts that a
//! CLI process can check without attaching to the live GUI/service runtime. Live
//! runtime health will be layered on top of the same JSON contract later.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HealthState {
    Healthy,
    Degraded,
    DisabledByPolicy,
    NeedsElevation,
    FailedOpen,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
struct SubsystemStatus {
    name: &'static str,
    state: HealthState,
    summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ProtectionStatusReport {
    schema_version: u32,
    generated_unix: u64,
    app_version: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
    data_dir: String,
    overall_state: HealthState,
    overall_summary: String,
    subsystems: Vec<SubsystemStatus>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "vigil_status v{}\n\nUsage: vigil_status [--json]\n\nPrints a conservative JSON health report for local Vigil state. Runtime-only\nfacts remain unknown until the GUI/service publishes live health.",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    let report = build_report();
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("failed to serialize protection status: {err}");
            std::process::exit(1);
        }
    }
}

fn build_report() -> ProtectionStatusReport {
    let data_dir = data_dir();
    let config_path = data_dir.join("vigil.json");
    let config_json = read_json_file(&config_path);

    let mut subsystems = vec![
        config_status(&config_path, config_json.as_ref()),
        runtime_monitor_status(),
        firewall_status(),
        response_policy_status(config_json.as_ref(), &data_dir),
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

fn config_status(path: &Path, json: Option<&Result<Value, String>>) -> SubsystemStatus {
    match json {
        Some(Ok(_)) => SubsystemStatus {
            name: "configuration",
            state: HealthState::Healthy,
            summary: "configuration file is present and valid JSON".into(),
            details: vec![format!("path={}", path.display())],
        },
        Some(Err(err)) => SubsystemStatus {
            name: "configuration",
            state: HealthState::Degraded,
            summary: "configuration file could not be parsed as JSON".into(),
            details: vec![format!("path={}", path.display()), err.clone()],
        },
        None => SubsystemStatus {
            name: "configuration",
            state: HealthState::Healthy,
            summary: "configuration file is absent; Vigil will use compiled defaults on first launch".into(),
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
                summary: "firewall tooling is present, but live backend health requires Vigil runtime checks".into(),
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

fn response_policy_status(json: Option<&Result<Value, String>>, data_dir: &Path) -> SubsystemStatus {
    let Some(Ok(config)) = json else {
        return SubsystemStatus {
            name: "response_policy",
            state: HealthState::DisabledByPolicy,
            summary: "no readable config; disruptive response features default to off or dry-run".into(),
            details: Vec::new(),
        };
    };

    let response_rules_enabled = bool_field(config, "response_rules_enabled");
    let response_rules_dry_run = bool_field(config, "response_rules_dry_run").unwrap_or(true);
    let auto_response_enabled = bool_field(config, "auto_response_enabled").unwrap_or(false);
    let auto_response_dry_run = bool_field(config, "auto_response_dry_run").unwrap_or(true);
    let allowlist_mode_enabled = bool_field(config, "allowlist_mode_enabled").unwrap_or(false);
    let allowlist_mode_dry_run = bool_field(config, "allowlist_mode_dry_run").unwrap_or(true);
    let scheduled_lockdown_enabled = bool_field(config, "scheduled_lockdown_enabled").unwrap_or(false);
    let response_rules_path = string_field(config, "response_rules_path").unwrap_or_default();

    let mut details = vec![
        format!("auto_response_enabled={auto_response_enabled}"),
        format!("auto_response_dry_run={auto_response_dry_run}"),
        format!("allowlist_mode_enabled={allowlist_mode_enabled}"),
        format!("allowlist_mode_dry_run={allowlist_mode_dry_run}"),
        format!("response_rules_enabled={}", response_rules_enabled.unwrap_or(false)),
        format!("response_rules_dry_run={response_rules_dry_run}"),
        format!("scheduled_lockdown_enabled={scheduled_lockdown_enabled}"),
    ];

    if response_rules_enabled.unwrap_or(false) {
        if response_rules_path.trim().is_empty() {
            return SubsystemStatus {
                name: "response_policy",
                state: HealthState::Degraded,
                summary: "response rules are enabled but no response_rules_path is configured".into(),
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

    let disruptive_enabled = auto_response_enabled || allowlist_mode_enabled || scheduled_lockdown_enabled;
    if !disruptive_enabled && !response_rules_enabled.unwrap_or(false) {
        return SubsystemStatus {
            name: "response_policy",
            state: HealthState::DisabledByPolicy,
            summary: "automatic response, allowlist mode, scheduled lockdown, and response rules are disabled".into(),
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
            summary: "active-response state file exists; live reconciliation status requires Vigil runtime checks".into(),
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
            summary: "state database and manifest exist; digest verification requires Vigil storage code".into(),
            details: vec![format!("db={}", db.display()), format!("manifest={}", manifest.display())],
        },
        (true, false) => SubsystemStatus {
            name: "protected_storage",
            state: HealthState::Degraded,
            summary: "state database exists but its integrity manifest is missing".into(),
            details: vec![format!("db={}", db.display()), format!("manifest={}", manifest.display())],
        },
        (false, true) => SubsystemStatus {
            name: "protected_storage",
            state: HealthState::Degraded,
            summary: "state manifest exists but the state database is missing".into(),
            details: vec![format!("db={}", db.display()), format!("manifest={}", manifest.display())],
        },
        (false, false) => SubsystemStatus {
            name: "protected_storage",
            state: HealthState::Healthy,
            summary: "state database is not initialized yet".into(),
            details: vec![format!("db={}", db.display()), format!("manifest={}", manifest.display())],
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
            summary: "local YARA rule directory exists; run vigil --yara-rule-status for integrity details".into(),
            details,
        }
    } else {
        SubsystemStatus {
            name: "yara_rules",
            state: HealthState::Unknown,
            summary: "local YARA rule directory is absent; bundled-rule health requires Vigil runtime validation".into(),
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
            summary: "state database exists; advisory source freshness requires storage-backed cache inspection".into(),
            details: vec![format!("db={}", db.display())],
        }
    } else {
        SubsystemStatus {
            name: "advisory_cache",
            state: HealthState::Unknown,
            summary: "state database is not initialized; advisory cache may be empty until first import or sync".into(),
            details: vec![format!("db={}", db.display())],
        }
    }
}

fn update_trust_status() -> SubsystemStatus {
    SubsystemStatus {
        name: "update_trust",
        state: HealthState::Unknown,
        summary: "release-manifest verification is available, but periodic signed threat-data updates are not implemented yet".into(),
        details: vec!["use --verify-update-manifest MANIFEST.json MANIFEST.json.sig for offline release manifest checks".into()],
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
    if subsystems
        .iter()
        .any(|status| matches!(status.state, HealthState::NeedsElevation | HealthState::Unknown))
    {
        return HealthState::Unknown;
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

fn read_json_file(path: &Path) -> Option<Result<Value, String>> {
    if !path.exists() {
        return None;
    }
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => return Some(Err(format!("read: {err}"))),
    };
    Some(serde_json::from_str::<Value>(&content).map_err(|err| format!("parse: {err}")))
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
    fn relative_policy_path_is_data_dir_relative() {
        assert_eq!(
            expand_data_relative(Path::new("/tmp/vigil"), "rules.yaml"),
            PathBuf::from("/tmp/vigil/rules.yaml")
        );
    }
}
