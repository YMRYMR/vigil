//! Break-glass recovery for machine isolation.
//!
//! When network isolation is active, Vigil can arm a recurring scheduled task
//! that runs `vigil --break-glass-recover` every minute. The live process keeps
//! touching a heartbeat file. If the watchdog sees stale or missing heartbeats
//! after the configured timeout, it restores connectivity automatically.

use crate::{active_response, audit, config::Config};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

const TASK_NAME: &str = "Vigil Break Glass Recovery";
const STATE_FILE: &str = "vigil-break-glass.json";
const HEARTBEAT_FILE: &str = "vigil-break-glass-heartbeat";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryState {
    armed_at_unix: u64,
    deadline_unix: u64,
    heartbeat_max_age_secs: u64,
    task_name: String,
}

pub fn start_heartbeat_loop(cfg: Arc<RwLock<Config>>) {
    std::thread::Builder::new()
        .name("vigil-break-glass-heartbeat".into())
        .spawn(move || loop {
            let snapshot = cfg.read().map(|c| c.clone()).unwrap_or_default();
            sync_watchdog(&snapshot);
            if snapshot.break_glass_enabled && active_response::status().isolated {
                let _ = touch_heartbeat();
            }
            std::thread::sleep(std::time::Duration::from_secs(snapshot.break_glass_heartbeat_secs.clamp(5, 300)));
        })
        .ok();
}

pub fn sync_watchdog(cfg: &Config) {
    if !cfg.break_glass_enabled {
        let _ = disarm();
        return;
    }
    if active_response::status().isolated {
        let _ = arm(cfg);
    } else {
        let _ = disarm();
    }
}

pub fn recover_if_stale() -> i32 {
    let cfg = crate::config::Config::load();
    if !cfg.break_glass_enabled {
        return 0;
    }
    let Some(state) = load_state().ok().flatten() else { return 0; };
    if !active_response::status().isolated {
        let _ = disarm();
        return 0;
    }
    let now = unix_now();
    if now < state.deadline_unix {
        return 0;
    }
    let heartbeat_age = heartbeat_age_secs();
    if heartbeat_age.is_some_and(|age| age <= state.heartbeat_max_age_secs) {
        return 0;
    }
    match active_response::restore_machine() {
        Ok(message) => {
            audit::record("break_glass_recovery", "success", json!({
                "message": message,
                "heartbeat_age_secs": heartbeat_age,
                "deadline_unix": state.deadline_unix,
            }));
            let _ = disarm();
            0
        }
        Err(err) => {
            audit::record("break_glass_recovery", "error", json!({
                "error": err,
                "heartbeat_age_secs": heartbeat_age,
                "deadline_unix": state.deadline_unix,
            }));
            1
        }
    }
}

fn arm(cfg: &Config) -> Result<(), String> {
    let now = unix_now();
    if let Some(existing) = load_state()? {
        if existing.deadline_unix >= now && platform::task_exists(TASK_NAME) {
            return Ok(());
        }
    }
    platform::create_recovery_task(TASK_NAME)?;
    let deadline_unix = now.saturating_add(cfg.break_glass_timeout_mins.clamp(1, 240) * 60);
    save_state(&RecoveryState {
        armed_at_unix: now,
        deadline_unix,
        heartbeat_max_age_secs: cfg.break_glass_heartbeat_secs.clamp(5, 300) * 2,
        task_name: TASK_NAME.to_string(),
    })?;
    touch_heartbeat()?;
    audit::record("break_glass_arm", "success", json!({
        "deadline_unix": deadline_unix,
        "heartbeat_secs": cfg.break_glass_heartbeat_secs,
        "task_name": TASK_NAME,
    }));
    Ok(())
}

pub fn disarm() -> Result<(), String> {
    let _ = platform::delete_recovery_task(TASK_NAME);
    let _ = std::fs::remove_file(state_path());
    let _ = std::fs::remove_file(heartbeat_path());
    Ok(())
}

fn touch_heartbeat() -> Result<(), String> {
    let path = heartbeat_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, unix_now().to_string()).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

fn heartbeat_age_secs() -> Option<u64> {
    let path = heartbeat_path();
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = std::time::SystemTime::now().duration_since(modified).ok()?;
    Some(age.as_secs())
}

fn state_path() -> PathBuf { crate::config::data_dir().join(STATE_FILE) }
fn heartbeat_path() -> PathBuf { crate::config::data_dir().join(HEARTBEAT_FILE) }
fn unix_now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

fn load_state() -> Result<Option<RecoveryState>, String> {
    let path = state_path();
    if !path.exists() { return Ok(None); }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map(Some).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}
fn save_state(state: &RecoveryState) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|e| format!("failed to create {}: {e}", parent.display()))?; }
    let json = serde_json::to_string_pretty(state).map_err(|e| format!("failed to serialise break-glass state: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

#[cfg(windows)]
mod platform {
    use super::*;
    use chrono::{Duration as ChronoDuration, Local};
    use std::path::PathBuf;
    use std::process::Command;
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    pub fn task_exists(name: &str) -> bool {
        schtasks().arg("/Query").arg("/TN").arg(name).status().map(|s| s.success()).unwrap_or(false)
    }
    pub fn create_recovery_task(name: &str) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| format!("failed to resolve current exe: {e}"))?;
        let command = format!("\"{}\" --break-glass-recover", exe.display());
        let start = (Local::now() + ChronoDuration::minutes(1)).format("%H:%M").to_string();
        let status = schtasks()
            .args(["/Create", "/F", "/SC", "MINUTE", "/MO", "1", "/TN", name, "/TR", &command, "/ST", &start, "/RU", "SYSTEM", "/RL", "HIGHEST"])
            .status()
            .map_err(|e| format!("failed to spawn schtasks.exe: {e}"))?;
        if status.success() { Ok(()) } else { Err(format!("schtasks /Create failed with status {status}")) }
    }
    pub fn delete_recovery_task(name: &str) -> Result<(), String> {
        let status = schtasks().args(["/Delete", "/F", "/TN", name]).status().map_err(|e| format!("failed to spawn schtasks.exe: {e}"))?;
        if status.success() { Ok(()) } else { Err(format!("schtasks /Delete failed with status {status}")) }
    }
    fn schtasks() -> Command {
        let path = windows_directory().unwrap_or_else(|| PathBuf::from(r"C:\Windows")).join("System32").join("schtasks.exe");
        Command::new(path)
    }
    fn windows_directory() -> Option<PathBuf> {
        let mut buffer = vec![0u16; 260];
        unsafe {
            let len = GetSystemWindowsDirectoryW(Some(&mut buffer));
            if len == 0 { return None; }
            let len = len as usize;
            if len >= buffer.len() {
                buffer.resize(len + 1, 0);
                let retry_len = GetSystemWindowsDirectoryW(Some(&mut buffer));
                if retry_len == 0 { return None; }
                return Some(PathBuf::from(String::from_utf16_lossy(&buffer[..retry_len as usize])));
            }
            Some(PathBuf::from(String::from_utf16_lossy(&buffer[..len])))
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn task_exists(_name: &str) -> bool { false }
    pub fn create_recovery_task(_name: &str) -> Result<(), String> { Err("break-glass recovery is not implemented on this platform".into()) }
    pub fn delete_recovery_task(_name: &str) -> Result<(), String> { Ok(()) }
}
