#![allow(dead_code)]
//! Extended quarantine helpers.
//!
//! Current Windows implementation complements the existing network / process
//! containment with optional USB storage disablement and scheduled-task pause /
//! restore so the quarantine preset is closer to a real host-containment flow.

use crate::audit;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;

const STATE_FILE: &str = "vigil-quarantine-state.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct State {
    usb_disabled: bool,
    paused_tasks: Vec<String>,
}

pub fn apply() -> (Vec<String>, Vec<String>) {
    #[cfg(windows)]
    {
        let mut state = load_state().unwrap_or_default();
        let mut applied = Vec::new();
        let mut warnings = Vec::new();
        match platform::disable_usb_storage() {
            Ok(changed) => {
                if changed {
                    state.usb_disabled = true;
                    applied.push("USB storage disabled".into());
                }
            }
            Err(err) => warnings.push(format!("USB disable failed: {err}")),
        }
        match platform::pause_scheduled_tasks() {
            Ok(tasks) => {
                if !tasks.is_empty() {
                    state.paused_tasks = tasks.clone();
                    applied.push(format!("{} scheduled task(s) paused", tasks.len()));
                }
            }
            Err(err) => warnings.push(format!("scheduled-task pause failed: {err}")),
        }
        let _ = save_state(&state);
        audit::record(
            "quarantine_extended_apply",
            if warnings.is_empty() {
                "success"
            } else {
                "partial"
            },
            json!({"applied": applied, "warnings": warnings, "paused_tasks": state.paused_tasks}),
        );
        (applied, warnings)
    }
    #[cfg(not(windows))]
    {
        (
            Vec::new(),
            vec!["extended quarantine is not implemented on this platform".into()],
        )
    }
}

pub fn clear() -> (Vec<String>, Vec<String>) {
    #[cfg(windows)]
    {
        let state = load_state().unwrap_or_default();
        let mut cleared = Vec::new();
        let mut warnings = Vec::new();
        if state.usb_disabled {
            match platform::restore_usb_storage() {
                Ok(()) => cleared.push("USB storage restored".into()),
                Err(err) => warnings.push(format!("USB restore failed: {err}")),
            }
        }
        if !state.paused_tasks.is_empty() {
            match platform::resume_scheduled_tasks(&state.paused_tasks) {
                Ok(restored) => {
                    if restored > 0 {
                        cleared.push(format!("{} scheduled task(s) resumed", restored));
                    }
                }
                Err(err) => warnings.push(format!("scheduled-task resume failed: {err}")),
            }
        }
        let _ = std::fs::remove_file(state_path());
        audit::record(
            "quarantine_extended_clear",
            if warnings.is_empty() {
                "success"
            } else {
                "partial"
            },
            json!({"cleared": cleared, "warnings": warnings }),
        );
        (cleared, warnings)
    }
    #[cfg(not(windows))]
    {
        (
            Vec::new(),
            vec!["extended quarantine clear is not implemented on this platform".into()],
        )
    }
}

fn state_path() -> PathBuf {
    crate::config::data_dir().join(STATE_FILE)
}
fn load_state() -> Result<State, String> {
    let path = state_path();
    if !path.exists() {
        return Ok(State::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}
fn save_state(state: &State) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(state)
        .map_err(|e| format!("failed to serialise quarantine state: {e}"))?;
    std::fs::write(&path, text).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

#[cfg(windows)]
mod platform {
    use std::path::PathBuf;
    use std::process::Command;
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    pub fn disable_usb_storage() -> Result<bool, String> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let (key, _) = hklm
            .create_subkey(r"SYSTEM\CurrentControlSet\Services\USBSTOR")
            .map_err(|e| format!("failed to open USBSTOR key: {e}"))?;
        let current = key.get_value::<u32, _>("Start").unwrap_or(3);
        if current == 4 {
            return Ok(false);
        }
        key.set_value("Start", &4u32)
            .map_err(|e| format!("failed to set USBSTOR Start=4: {e}"))?;
        Ok(true)
    }
    pub fn restore_usb_storage() -> Result<(), String> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let (key, _) = hklm
            .create_subkey(r"SYSTEM\CurrentControlSet\Services\USBSTOR")
            .map_err(|e| format!("failed to open USBSTOR key: {e}"))?;
        key.set_value("Start", &3u32)
            .map_err(|e| format!("failed to set USBSTOR Start=3: {e}"))
    }
    pub fn pause_scheduled_tasks() -> Result<Vec<String>, String> {
        let output = schtasks()
            .args(["/Query", "/FO", "CSV", "/NH"])
            .output()
            .map_err(|e| format!("failed to run schtasks /Query: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "schtasks /Query failed with status {}",
                output.status
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut paused = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut cols = line.split("\",\"").map(|s| s.trim_matches('"'));
            let Some(task_name) = cols.next() else {
                continue;
            };
            if task_name.starts_with("\\Microsoft\\") || task_name.eq_ignore_ascii_case("TaskName")
            {
                continue;
            }
            let status = schtasks()
                .args(["/Change", "/TN", task_name, "/Disable"])
                .status()
                .map_err(|e| format!("failed to disable {task_name}: {e}"))?;
            if status.success() {
                paused.push(task_name.to_string());
            }
        }
        Ok(paused)
    }
    pub fn resume_scheduled_tasks(tasks: &[String]) -> Result<usize, String> {
        let mut restored = 0usize;
        for task in tasks {
            let status = schtasks()
                .args(["/Change", "/TN", task, "/Enable"])
                .status()
                .map_err(|e| format!("failed to enable {task}: {e}"))?;
            if status.success() {
                restored += 1;
            }
        }
        Ok(restored)
    }
    fn schtasks() -> Command {
        let path = windows_directory()
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join("schtasks.exe");
        Command::new(path)
    }
    fn windows_directory() -> Option<PathBuf> {
        let mut buffer = vec![0u16; 260];
        unsafe {
            let len = GetSystemWindowsDirectoryW(Some(&mut buffer));
            if len == 0 {
                return None;
            }
            Some(PathBuf::from(String::from_utf16_lossy(
                &buffer[..len as usize],
            )))
        }
    }
}
