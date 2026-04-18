//! Behavioural baselines for per-process network activity.
//!
//! The goal is not to build a full ML model. We keep a compact, auditable set of
//! previously-seen remotes, ports, and countries for each stable process profile
//! and surface mature novelty as an additional signal during scoring.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const STATE_FILE: &str = "vigil-behaviour-baselines.json";
const MATURITY_THRESHOLD: u64 = 8;
const MAX_REMOTES: usize = 64;
const MAX_PORTS: usize = 32;
const MAX_COUNTRIES: usize = 16;
const SAVE_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, Default)]
pub struct BaselineSignal {
    pub mature: bool,
    pub new_remote: bool,
    pub new_port: bool,
    pub new_country: bool,
    pub observations: u64,
}

#[derive(Debug, Default)]
struct RuntimeState {
    state: BaselineState,
    last_save_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BaselineState {
    entries: BTreeMap<String, BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BaselineEntry {
    observations: u64,
    first_seen_unix: u64,
    last_seen_unix: u64,
    remotes: Vec<String>,
    ports: Vec<u16>,
    countries: Vec<String>,
}

pub fn observe(
    process_name: &str,
    publisher: &str,
    proc_path: &str,
    remote_ip: &str,
    remote_port: u16,
    country: Option<&str>,
) -> BaselineSignal {
    if remote_ip.is_empty() || matches!(remote_ip, "127.0.0.1" | "::1" | "0.0.0.0") {
        return BaselineSignal::default();
    }

    let key = profile_key(process_name, publisher, proc_path);
    if key.is_empty() {
        return BaselineSignal::default();
    }

    let now = unix_now();
    let manager = manager();
    let mut runtime = manager.lock().unwrap();
    let entry = runtime.state.entries.entry(key).or_default();

    if entry.first_seen_unix == 0 {
        entry.first_seen_unix = now;
    }
    entry.last_seen_unix = now;

    let mature_before = entry.observations >= MATURITY_THRESHOLD;
    let new_remote = remember_string(&mut entry.remotes, remote_ip, MAX_REMOTES);
    let new_port = remember_port(&mut entry.ports, remote_port, MAX_PORTS);
    let new_country = country
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| remember_string(&mut entry.countries, c, MAX_COUNTRIES))
        .unwrap_or(false);

    entry.observations = entry.observations.saturating_add(1);

    let should_save = (new_remote || new_port || new_country)
        || now.saturating_sub(runtime.last_save_unix) >= SAVE_INTERVAL_SECS
        || entry.observations % 16 == 0;
    if should_save {
        if save_state(&runtime.state).is_ok() {
            runtime.last_save_unix = now;
        }
    }

    BaselineSignal {
        mature: mature_before,
        new_remote,
        new_port,
        new_country,
        observations: entry.observations,
    }
}

fn manager() -> &'static Mutex<RuntimeState> {
    static MANAGER: OnceLock<Mutex<RuntimeState>> = OnceLock::new();
    MANAGER.get_or_init(|| {
        let state = load_state().unwrap_or_default();
        Mutex::new(RuntimeState {
            state,
            last_save_unix: unix_now(),
        })
    })
}

fn remember_string(values: &mut Vec<String>, value: &str, cap: usize) -> bool {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() || values.iter().any(|existing| existing.eq_ignore_ascii_case(&value)) {
        return false;
    }
    if values.len() >= cap {
        let _ = values.remove(0);
    }
    values.push(value);
    true
}

fn remember_port(values: &mut Vec<u16>, value: u16, cap: usize) -> bool {
    if value == 0 || values.contains(&value) {
        return false;
    }
    if values.len() >= cap {
        let _ = values.remove(0);
    }
    values.push(value);
    true
}

fn profile_key(process_name: &str, publisher: &str, proc_path: &str) -> String {
    let name = crate::config::normalise_name(process_name);
    let publisher = publisher.trim().to_ascii_lowercase();
    let stem = std::path::Path::new(proc_path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(crate::config::normalise_name)
        .unwrap_or_default();
    let parts = [name, publisher, stem]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts.join("|")
}

fn state_path() -> PathBuf {
    crate::config::data_dir().join(STATE_FILE)
}

fn load_state() -> Result<BaselineState, String> {
    let path = state_path();
    if !path.exists() {
        return Ok(BaselineState::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

fn save_state(state: &BaselineState) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(state)
        .map_err(|e| format!("failed to serialise behavioural baselines: {e}"))?;
    std::fs::write(&path, text).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_key_uses_normalised_components() {
        let key = profile_key("PowerShell.EXE", "Microsoft Corporation", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        assert!(key.contains("powershell"));
        assert!(key.contains("microsoft corporation"));
    }

    #[test]
    fn remember_string_tracks_novel_values() {
        let mut values = vec!["known.example".to_string()];
        assert!(!remember_string(&mut values, "KNOWN.example", 4));
        assert!(remember_string(&mut values, "new.example", 4));
        assert_eq!(values.len(), 2);
    }
}
