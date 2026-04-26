#![allow(dead_code)]
//! Extended quarantine helpers.
//!
//! Current Windows implementation complements the existing network / process
//! containment with optional USB storage disablement and scheduled-task pause /
//! restore so the quarantine preset is closer to a real host-containment flow.

use serde::{Deserialize, Serialize};
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
        use crate::audit;
        use serde_json::json;

        let (mut state, mut warnings) = state_for_apply(load_state());
        let mut applied = Vec::new();
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
        if let Err(err) = save_state(&state) {
            warnings.push(format!("quarantine state save failed: {err}"));
        }
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
        use crate::audit;
        use serde_json::json;

        let state = match load_state() {
            Ok(state) => state,
            Err(err) => {
                audit::record(
                    "quarantine_extended_clear",
                    "error",
                    json!({ "error": err }),
                );
                return (
                    Vec::new(),
                    vec![format!("quarantine state load failed: {err}")],
                );
            }
        };
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
        let _ = crate::security::policy::remove_json_with_integrity(&state_path());
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
    load_state_from_path(&path)
}
fn save_state(state: &State) -> Result<(), String> {
    let path = state_path();
    save_state_to_path(&path, state)
        .map_err(|e| format!("failed to save quarantine state {}: {e}", path.display()))
}

fn state_for_apply(load_result: Result<State, String>) -> (State, Vec<String>) {
    match load_result {
        Ok(state) => (state, Vec::new()),
        Err(err) => (
            State::default(),
            vec![format!("quarantine state load failed: {err}")],
        ),
    }
}

fn load_state_from_path(path: &std::path::Path) -> Result<State, String> {
    if !path.exists() {
        return Ok(State::default());
    }
    crate::security::policy::load_struct_with_integrity(path)
        .map_err(|e| format!("failed to load quarantine state {}: {e}", path.display()))?
        .ok_or_else(|| {
            format!(
                "protected quarantine state {} could not be verified or restored",
                path.display()
            )
        })
}

fn save_state_to_path(path: &std::path::Path, state: &State) -> Result<(), String> {
    crate::security::policy::save_struct_with_integrity(path, state)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn protected_quarantine_state_load_fails_when_existing_state_cannot_be_restored() {
        let base = unique_temp_dir();
        fs::create_dir_all(&base).unwrap();
        let path = base.join("vigil-quarantine-state.json");
        let state = State {
            usb_disabled: true,
            paused_tasks: vec!["TaskA".into(), "TaskB".into()],
        };
        save_state_to_path(&path, &state).unwrap();
        fs::write(&path, br#"{"tampered":true}"#).unwrap();
        let _ = fs::remove_file(path.with_extension("json.sig"));
        let _ = fs::remove_file(path.with_extension("json.bak"));
        let _ = fs::remove_file(path.with_extension("json.bak.sig"));

        let err = load_state_from_path(&path).unwrap_err();
        assert!(err.contains("could not be verified or restored"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn apply_continues_with_empty_state_when_prior_state_load_fails() {
        let (state, warnings) = state_for_apply(Err("tampered state".into()));
        assert!(!state.usb_disabled);
        assert!(state.paused_tasks.is_empty());
        assert_eq!(
            warnings,
            vec!["quarantine state load failed: tampered state"]
        );
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-quarantine-test-{nanos}"))
    }
}
