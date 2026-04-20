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
            let _ = sync_watchdog(&snapshot);
            if active_response::status().isolated {
                let _ = touch_heartbeat();
            }
            std::thread::sleep(std::time::Duration::from_secs(
                snapshot.break_glass_heartbeat_secs.clamp(5, 300),
            ));
        })
        .ok();
}

pub fn sync_watchdog(cfg: &Config) -> Result<(), String> {
    if active_response::status().isolated {
        arm(cfg)
    } else {
        disarm()
    }
}

pub fn recover_if_stale() -> i32 {
    let Some(state) = load_state().ok().flatten() else {
        return 0;
    };
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
            audit::record(
                "break_glass_recovery",
                "success",
                json!({
                    "message": message,
                    "heartbeat_age_secs": heartbeat_age,
                    "deadline_unix": state.deadline_unix,
                }),
            );
            let _ = disarm();
            0
        }
        Err(err) => {
            audit::record(
                "break_glass_recovery",
                "error",
                json!({
                    "error": err,
                    "heartbeat_age_secs": heartbeat_age,
                    "deadline_unix": state.deadline_unix,
                }),
            );
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
    let state = RecoveryState {
        armed_at_unix: now,
        deadline_unix,
        heartbeat_max_age_secs: cfg.break_glass_heartbeat_secs.clamp(5, 300) * 2,
        task_name: TASK_NAME.to_string(),
    };
    if let Err(err) = save_state(&state) {
        let _ = platform::delete_recovery_task(TASK_NAME);
        return Err(err);
    }
    if let Err(err) = touch_heartbeat() {
        let _ = platform::delete_recovery_task(TASK_NAME);
        let _ = std::fs::remove_file(state_path());
        return Err(err);
    }
    audit::record(
        "break_glass_arm",
        "success",
        json!({
            "deadline_unix": deadline_unix,
            "heartbeat_secs": cfg.break_glass_heartbeat_secs,
            "task_name": TASK_NAME,
        }),
    );
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
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, unix_now().to_string())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

fn heartbeat_age_secs() -> Option<u64> {
    let path = heartbeat_path();
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = std::time::SystemTime::now().duration_since(modified).ok()?;
    Some(age.as_secs())
}

fn state_path() -> PathBuf {
    crate::config::data_dir().join(STATE_FILE)
}
fn heartbeat_path() -> PathBuf {
    crate::config::data_dir().join(HEARTBEAT_FILE)
}
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_state() -> Result<Option<RecoveryState>, String> {
    let path = state_path();
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}
fn save_state(state: &RecoveryState) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("failed to serialise break-glass state: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

#[cfg(windows)]
mod platform {
    use chrono::{Duration as ChronoDuration, Local};
    use std::ffi::OsStr;
    use std::fs;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    pub fn task_exists(name: &str) -> bool {
        schtasks()
            .arg("/Query")
            .arg("/TN")
            .arg(name)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    pub fn create_recovery_task(name: &str) -> Result<(), String> {
        let exe =
            std::env::current_exe().map_err(|e| format!("failed to resolve current exe: {e}"))?;
        let command = format!("\"{}\" --break-glass-recover", exe.display());
        let start = (Local::now() + ChronoDuration::minutes(1))
            .format("%H:%M")
            .to_string();
        if is_trusted_install_path(&exe)? {
            if create_system_task(name, &command, &start).is_ok() {
                return Ok(());
            }
            create_user_task(name, &command, &start).map_err(|err| {
                format!("failed to create recovery task as SYSTEM and as current user: {err}")
            })
        } else {
            Err(format!(
                "refusing recovery task creation for untrusted executable path ({})",
                exe.display()
            ))
        }
    }
    fn create_system_task(name: &str, command: &str, start: &str) -> Result<(), String> {
        let status = schtasks()
            .args([
                "/Create", "/F", "/SC", "MINUTE", "/MO", "1", "/TN", name, "/TR", command, "/ST",
                start, "/RU", "SYSTEM", "/RL", "HIGHEST",
            ])
            .status()
            .map_err(|e| format!("failed to spawn schtasks.exe: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "schtasks /Create (/RU SYSTEM) failed with status {status}"
            ))
        }
    }
    fn create_user_task(name: &str, command: &str, start: &str) -> Result<(), String> {
        let status = schtasks()
            .args([
                "/Create", "/F", "/SC", "MINUTE", "/MO", "1", "/TN", name, "/TR", command, "/ST",
                start, "/RL", "HIGHEST",
            ])
            .status()
            .map_err(|e| format!("failed to spawn schtasks.exe: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "schtasks /Create (current user) failed with status {status}"
            ))
        }
    }
    pub fn delete_recovery_task(name: &str) -> Result<(), String> {
        let status = schtasks()
            .args(["/Delete", "/F", "/TN", name])
            .status()
            .map_err(|e| format!("failed to spawn schtasks.exe: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("schtasks /Delete failed with status {status}"))
        }
    }
    fn schtasks() -> Command {
        let path = windows_directory()
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join("schtasks.exe");
        hidden_command(path)
    }
    fn hidden_command<S: AsRef<OsStr>>(program: S) -> Command {
        let mut cmd = Command::new(program);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }
    fn is_trusted_install_path(exe: &Path) -> Result<bool, String> {
        let exe_norm = canonicalise_for_prefix_compare(exe)?;
        for base in trusted_base_directories() {
            let Ok(base_norm) = canonicalise_for_prefix_compare(&base) else {
                continue;
            };
            if path_starts_with(&exe_norm, &base_norm) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn trusted_base_directories() -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(windows_dir) = windows_directory() {
            dirs.push(windows_dir.join("System32"));
        }
        if let Ok(program_files) = std::env::var("ProgramFiles") {
            dirs.push(PathBuf::from(program_files));
        }
        if let Ok(program_files_x86) = std::env::var("ProgramFiles(x86)") {
            dirs.push(PathBuf::from(program_files_x86));
        }
        if dirs.is_empty() {
            dirs.push(PathBuf::from(r"C:\Windows\System32"));
            dirs.push(PathBuf::from(r"C:\Program Files"));
            dirs.push(PathBuf::from(r"C:\Program Files (x86)"));
        }
        dirs
    }
    fn canonicalise_for_prefix_compare(path: &Path) -> Result<String, String> {
        let canonical = fs::canonicalize(path)
            .map_err(|e| format!("failed to canonicalize {}: {e}", path.display()))?;
        Ok(normalise_for_prefix_compare(&canonical))
    }
    fn normalise_for_prefix_compare(path: &Path) -> String {
        path.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    }
    fn path_starts_with(path: &str, base: &str) -> bool {
        path == base || path.starts_with(&format!("{base}\\"))
    }
    fn windows_directory() -> Option<PathBuf> {
        let mut buffer = vec![0u16; 260];
        unsafe {
            let len = GetSystemWindowsDirectoryW(Some(&mut buffer));
            if len == 0 {
                return None;
            }
            let len = len as usize;
            if len >= buffer.len() {
                buffer.resize(len + 1, 0);
                let retry_len = GetSystemWindowsDirectoryW(Some(&mut buffer));
                if retry_len == 0 {
                    return None;
                }
                return Some(PathBuf::from(String::from_utf16_lossy(
                    &buffer[..retry_len as usize],
                )));
            }
            Some(PathBuf::from(String::from_utf16_lossy(&buffer[..len])))
        }
    }
}

#[cfg(not(windows))]
mod platform {
    #[cfg(target_os = "linux")]
    mod imp {
        use std::io::Write;
        use std::process::{Command, Stdio};
        const CRON_MARKER: &str = "# Vigil Break Glass Recovery";
        pub fn task_exists() -> bool {
            read_crontab()
                .map(|content| content.lines().any(|line| line.contains(CRON_MARKER)))
                .unwrap_or(false)
        }
        pub fn create_recovery_task() -> Result<(), String> {
            let mut lines: Vec<String> = read_crontab()?
                .lines()
                .filter(|line| !line.contains(CRON_MARKER))
                .map(|line| line.to_string())
                .collect();
            lines.push(recovery_cron_line()?);
            write_crontab(&lines.join("\n"))
        }
        pub fn delete_recovery_task() -> Result<(), String> {
            let lines: Vec<String> = read_crontab()?
                .lines()
                .filter(|line| !line.contains(CRON_MARKER))
                .map(|line| line.to_string())
                .collect();
            write_crontab(&lines.join("\n"))
        }
        fn recovery_cron_line() -> Result<String, String> {
            let exe = std::env::current_exe()
                .map_err(|e| format!("failed to resolve current exe: {e}"))?;
            let exe = exe.display().to_string().replace('"', "\\\"");
            Ok(format!(
                "* * * * * \"{exe}\" --break-glass-recover {CRON_MARKER}"
            ))
        }
        fn read_crontab() -> Result<String, String> {
            let output = Command::new("crontab")
                .arg("-l")
                .output()
                .map_err(|e| format!("failed to spawn crontab -l: {e}"))?;
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
                if stderr.contains("no crontab") {
                    Ok(String::new())
                } else {
                    Err(format!("crontab -l failed: {stderr}"))
                }
            }
        }
        fn write_crontab(content: &str) -> Result<(), String> {
            let mut child = Command::new("crontab")
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("failed to spawn crontab -: {e}"))?;
            if let Some(stdin) = child.stdin.as_mut() {
                if !content.trim().is_empty() {
                    stdin
                        .write_all(content.as_bytes())
                        .map_err(|e| format!("failed to write crontab content: {e}"))?;
                }
                stdin
                    .write_all(b"\n")
                    .map_err(|e| format!("failed to finalise crontab content: {e}"))?;
            }
            let output = child
                .wait_with_output()
                .map_err(|e| format!("failed to wait for crontab -: {e}"))?;
            if output.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "crontab - failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
        }
    }
    #[cfg(target_os = "macos")]
    mod imp {
        use std::path::PathBuf;
        use std::process::Command;
        const PLIST_LABEL: &str = "com.vigil.break-glass-recovery";
        pub fn task_exists() -> bool {
            plist_path().exists()
        }
        pub fn create_recovery_task() -> Result<(), String> {
            let exe = std::env::current_exe()
                .map_err(|e| format!("failed to resolve current exe: {e}"))?;
            let plist = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{PLIST_LABEL}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>--break-glass-recover</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>StartInterval</key>\n  <integer>60</integer>\n</dict>\n</plist>\n", xml_escape(&exe.display().to_string()));
            std::fs::write(plist_path(), plist)
                .map_err(|e| format!("failed to write launchd plist: {e}"))?;
            let _ = Command::new("launchctl")
                .args(["bootout", "system", plist_path().to_string_lossy().as_ref()])
                .status();
            let status = Command::new("launchctl")
                .args([
                    "bootstrap",
                    "system",
                    plist_path().to_string_lossy().as_ref(),
                ])
                .status()
                .map_err(|e| format!("failed to spawn launchctl bootstrap: {e}"))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("launchctl bootstrap failed with status {status}"))
            }
        }
        pub fn delete_recovery_task() -> Result<(), String> {
            let _ = Command::new("launchctl")
                .args(["bootout", "system", plist_path().to_string_lossy().as_ref()])
                .status();
            if plist_path().exists() {
                std::fs::remove_file(plist_path())
                    .map_err(|e| format!("failed to remove launchd plist: {e}"))?;
            }
            Ok(())
        }
        fn plist_path() -> PathBuf {
            PathBuf::from(format!("/Library/LaunchDaemons/{PLIST_LABEL}.plist"))
        }
        fn xml_escape(text: &str) -> String {
            text.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&apos;")
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    mod imp {
        pub fn task_exists() -> bool {
            false
        }
        pub fn create_recovery_task() -> Result<(), String> {
            Err("break-glass recovery is not implemented on this platform".into())
        }
        pub fn delete_recovery_task() -> Result<(), String> {
            Ok(())
        }
    }
    pub fn task_exists(_name: &str) -> bool {
        imp::task_exists()
    }
    pub fn create_recovery_task(_name: &str) -> Result<(), String> {
        imp::create_recovery_task()
    }
    pub fn delete_recovery_task(_name: &str) -> Result<(), String> {
        imp::delete_recovery_task()
    }
}
