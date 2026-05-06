//! Cross-platform boot-time service installation.
//!
//! Vigil can run as an OS-managed service/daemon so it starts **before** any
//! user logs in and catches malware that activates during boot (rootkits,
//! dropper callbacks, persistence mechanisms).  This module implements the
//! install / uninstall commands for each supported OS:
//!
//! | OS      | Mechanism                     | Location                                      |
//! | ------- | ----------------------------- | --------------------------------------------- |
//! | Windows | Task Scheduler                | `schtasks /Create ...`                        |
//! | macOS   | launchd system daemon         | `/Library/LaunchDaemons/com.vigil.monitor.plist` |
//! | Linux   | systemd system unit           | `/etc/systemd/system/vigil.service`           |
//!
//! All three require elevation; this module does **not** elevate itself —
//! the user must invoke Vigil from an elevated shell.  On failure we print
//! a helpful, OS-specific hint and return a non-zero exit code to `main`.
//!
//! The installed service runs the **monitor only** — no GUI, no tray
//! (those require a desktop session).  When the user logs in, the normal
//! user-mode Vigil process starts via autostart and reads the same log
//! file, so pre-login events remain visible via the log.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Result of an install / uninstall command.  `Ok(msg)` is printed verbatim
/// to stdout; `Err(msg)` is printed to stderr and the process exits 1.
pub type CmdResult = Result<String, String>;

/// Internal headless entrypoint used by OS services / daemons.
pub const SERVICE_MODE_FLAG: &str = "--service-mode";
pub const DATA_DIR_FLAG: &str = "--data-dir";
const PRELOGIN_GUARD_FILE: &str = "vigil-prelogin-guard.json";
const PRELOGIN_GUARD_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PreLoginGuardState {
    armed: bool,
    last_start_unix: u64,
    last_success_unix: u64,
    failure_streak: u32,
    disabled_boot_start: bool,
}

pub struct PreLoginBootGuard {
    active: bool,
    disarmed: bool,
    handoff_started: bool,
}

impl PreLoginBootGuard {
    pub fn disarm(&mut self) {
        if !self.active || self.disarmed {
            return;
        }
        if crate::session::is_pre_login() {
            if self.handoff_started {
                return;
            }
            if let Err(err) = spawn_deferred_disarm_worker() {
                tracing::warn!(%err, "failed to defer pre-login boot guard disarm until login");
                return;
            }
            self.handoff_started = true;
            return;
        }
        if let Err(err) = disarm_prelogin_guard() {
            tracing::warn!(%err, "failed to disarm pre-login boot guard");
            return;
        }
        self.disarmed = true;
    }
}

impl Drop for PreLoginBootGuard {
    fn drop(&mut self) {
        if !self.active || self.disarmed {
            return;
        }
        if crate::session::is_pre_login() {
            tracing::warn!(
                "pre-login Vigil service exited before boot guard disarm; the next boot will trip the circuit breaker"
            );
            return;
        }
        if let Err(err) = disarm_prelogin_guard() {
            tracing::warn!(%err, "failed to disarm pre-login boot guard during shutdown handoff");
            return;
        }
        self.disarmed = true;
    }
}

fn spawn_deferred_disarm_worker() -> Result<(), String> {
    std::thread::Builder::new()
        .name("vigil-prelogin-guard".into())
        .spawn(|| {
            drive_prelogin_guard_until_login(
                PRELOGIN_GUARD_POLL_INTERVAL,
                crate::session::is_pre_login,
                || {
                    tracing::info!("interactive login detected; disarming pre-login boot guard");
                    if let Err(err) = disarm_prelogin_guard() {
                        tracing::warn!(
                            %err,
                            "failed to disarm pre-login boot guard after login transition"
                        );
                    }
                },
            );
        })
        .map(|_| ())
        .map_err(|err| format!("failed to spawn pre-login guard handoff thread: {err}"))
}

fn drive_prelogin_guard_until_login<FCheck, FDisarm>(
    poll_interval: Duration,
    mut still_pre_login: FCheck,
    mut disarm: FDisarm,
) where
    FCheck: FnMut() -> bool,
    FDisarm: FnMut(),
{
    while still_pre_login() {
        std::thread::sleep(poll_interval);
    }
    disarm();
}

pub fn enter_prelogin_boot_guard() -> Result<PreLoginBootGuard, String> {
    let path = prelogin_guard_path();
    let mut state = load_prelogin_guard_state(&path).map_err(|err| {
        fail_open_disable_boot_start(
            &format!(
                "Vigil could not read its pre-login boot guard state at {}",
                path.display()
            ),
            err,
        )
    })?;
    if state.armed {
        state.failure_streak = next_failure_streak(&state);
        if should_disable_boot_start(&state) {
            disable_boot_start()?;
            state.armed = false;
            state.disabled_boot_start = true;
            save_prelogin_guard_state(&path, &state).map_err(|err| {
                fail_open_disable_boot_start(
                    &format!(
                        "Vigil disabled its boot-time startup after an unclean pre-login run, but could not persist that guard state at {}",
                        path.display()
                    ),
                    err,
                )
            })?;
            return Err(
                "Vigil disabled its boot-time startup after an unclean pre-login run so the operating system can finish booting safely. Re-enable only after reviewing the failure."
                    .into(),
            );
        }
    }

    state.armed = true;
    state.disabled_boot_start = false;
    state.last_start_unix = unix_now();
    save_prelogin_guard_state(&path, &state).map_err(|err| {
        fail_open_disable_boot_start(
            &format!(
                "Vigil could not arm its pre-login boot guard at {}",
                path.display()
            ),
            err,
        )
    })?;
    Ok(PreLoginBootGuard {
        active: true,
        disarmed: false,
        handoff_started: false,
    })
}

fn fail_open_disable_boot_start(context: &str, cause: String) -> String {
    let disable_result = disable_boot_start().err();
    format_fail_open_disable_message(context, &cause, disable_result.as_deref())
}

fn format_fail_open_disable_message(
    context: &str,
    cause: &str,
    disable_err: Option<&str>,
) -> String {
    match disable_err {
        None => format!(
            "{context}: {cause}. Vigil disabled its own boot-time startup so one bad boot cannot repeat on the next restart."
        ),
        Some(disable_err) => format!(
            "{context}: {cause}. Vigil then tried to disable its own boot-time startup but failed: {disable_err}"
        ),
    }
}

fn next_failure_streak(state: &PreLoginGuardState) -> u32 {
    state.failure_streak.saturating_add(1)
}

fn should_disable_boot_start(state: &PreLoginGuardState) -> bool {
    state.failure_streak >= 1
}

fn disarm_prelogin_guard() -> Result<(), String> {
    let path = prelogin_guard_path();
    let mut state = load_prelogin_guard_state(&path)?;
    state.armed = false;
    state.failure_streak = 0;
    state.disabled_boot_start = false;
    state.last_success_unix = unix_now();
    save_prelogin_guard_state(&path, &state)
}

fn prelogin_guard_path() -> PathBuf {
    crate::config::data_dir().join(PRELOGIN_GUARD_FILE)
}

fn load_prelogin_guard_state(path: &std::path::Path) -> Result<PreLoginGuardState, String> {
    if !path.exists() {
        return Ok(PreLoginGuardState::default());
    }
    let loaded = crate::security::policy::load_struct_with_integrity(path)
        .map_err(|e| format!("failed to load pre-login guard {}: {e}", path.display()))?;
    Ok(loaded.unwrap_or_default())
}

fn save_prelogin_guard_state(
    path: &std::path::Path,
    state: &PreLoginGuardState,
) -> Result<(), String> {
    crate::security::policy::save_struct_with_integrity(path, state)
        .map_err(|e| format!("failed to save pre-login guard {}: {e}", path.display()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn install() -> CmdResult {
    let exe =
        std::env::current_exe().map_err(|e| format!("could not resolve current exe path: {e}"))?;
    platform::install(&exe)
}

pub fn uninstall() -> CmdResult {
    platform::uninstall()
}

fn disable_boot_start() -> Result<(), String> {
    platform::disable_boot_start()
}

// ── Windows ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::platform::command_paths;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    const TASK_NAME: &str = "VigilBootMonitor";
    const LEGACY_SERVICE_NAME: &str = "Vigil";

    pub fn install(exe: &Path) -> CmdResult {
        let shared_data_dir = exe
            .parent()
            .map(|d| d.join("vigil-data"))
            .ok_or_else(|| format!("could not determine parent directory for {}", exe.display()))?;
        let task_command = format!(
            r#""{}" {} {} "{}""#,
            exe.display(),
            SERVICE_MODE_FLAG,
            DATA_DIR_FLAG,
            shared_data_dir.display()
        );
        let status = Command::new(command_paths::resolve("schtasks")?)
            .args([
                "/Create",
                "/TN",
                TASK_NAME,
                "/TR",
                &task_command,
                "/SC",
                "ONSTART",
                "/RU",
                "SYSTEM",
                "/RL",
                "HIGHEST",
                "/F",
            ])
            .status()
            .map_err(|e| format!("failed to spawn `schtasks`: {e}"))?;
        if !status.success() {
            return Err(
                "`schtasks /Create` failed.  Open an *elevated* Command Prompt \
                 (Run as Administrator) and re-run `vigil --install-service`."
                    .into(),
            );
        }

        let _ = Command::new(command_paths::resolve("schtasks")?)
            .args(["/Run", "/TN", TASK_NAME])
            .status();
        Ok(format!(
            "Installed Windows boot-time monitor task `{TASK_NAME}` and started it.  \
             It will auto-start before login from now on.\n\
             To remove:  vigil --uninstall-service"
        ))
    }

    pub fn uninstall() -> CmdResult {
        let mut removed_any = false;
        let task_path = task_path();

        let task_query = Command::new(command_paths::resolve("schtasks")?)
            .args(["/Query", "/TN", TASK_NAME])
            .output()
            .map_err(|e| format!("failed to spawn `schtasks`: {e}"))?;
        if task_query.status.success() {
            let _ = Command::new(command_paths::resolve("schtasks")?)
                .args(["/End", "/TN", TASK_NAME])
                .status();
            let delete = Command::new(command_paths::resolve("schtasks")?)
                .args(["/Delete", "/TN", TASK_NAME, "/F"])
                .output()
                .map_err(|e| format!("failed to spawn `schtasks`: {e}"))?;
            if !delete.status.success() {
                return Err(format!(
                    "`schtasks /Delete` failed unexpectedly: {}",
                    command_output_summary(&delete)
                ));
            }
            removed_any = true;
        } else if task_path
            .try_exists()
            .map_err(|e| format!("could not inspect {}: {e}", task_path.display()))?
        {
            return Err(format!(
                "`schtasks /Query /TN {TASK_NAME}` failed unexpectedly: {}",
                command_output_summary(&task_query)
            ));
        }

        let query = Command::new(command_paths::resolve("sc")?)
            .args(["query", LEGACY_SERVICE_NAME])
            .output()
            .map_err(|e| format!("failed to spawn `sc`: {e}"))?;
        if query.status.success() {
            let _ = Command::new(command_paths::resolve("sc")?)
                .args(["stop", LEGACY_SERVICE_NAME])
                .status();
            let status = Command::new(command_paths::resolve("sc")?)
                .args(["delete", LEGACY_SERVICE_NAME])
                .status()
                .map_err(|e| format!("failed to spawn `sc`: {e}"))?;
            if !status.success() {
                return Err("`sc delete` failed.  Re-run from an elevated Command Prompt.".into());
            }
            removed_any = true;
        } else if !service_does_not_exist(&query) {
            return Err(format!(
                "`sc query {LEGACY_SERVICE_NAME}` failed unexpectedly: {}",
                command_output_summary(&query)
            ));
        }

        if removed_any {
            Ok(format!(
                "Removed Windows boot-time monitor task `{TASK_NAME}` and any legacy Windows service `{LEGACY_SERVICE_NAME}`."
            ))
        } else {
            Ok(format!(
                "Windows boot-time monitor task `{TASK_NAME}` was not installed."
            ))
        }
    }

    pub fn disable_boot_start() -> Result<(), String> {
        let output = Command::new(command_paths::resolve("schtasks")?)
            .args(["/Change", "/TN", TASK_NAME, "/DISABLE"])
            .output()
            .map_err(|e| format!("failed to spawn `schtasks`: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "failed to disable Windows boot-time monitor task `{TASK_NAME}`: {}",
                command_output_summary(&output)
            ))
        }
    }

    fn task_path() -> PathBuf {
        let mut path = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        path.push("System32");
        path.push("Tasks");
        path.push(TASK_NAME);
        path
    }

    fn service_does_not_exist(output: &Output) -> bool {
        let text = command_output_text(output).to_ascii_lowercase();
        text.contains("1060")
            || text.contains("does not exist")
            || text.contains("does not exist as an installed service")
    }

    fn command_output_summary(output: &Output) -> String {
        let text = command_output_text(output);
        if text.trim().is_empty() {
            format!("exit status {}", output.status)
        } else {
            format!("exit status {}; {}", output.status, text.trim())
        }
    }

    fn command_output_text(output: &Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("{stdout}{stderr}")
    }
}

// ── macOS ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use crate::platform::command_paths;
    use std::path::Path;
    use std::process::{Command, Output};

    const LABEL: &str = "com.vigil.monitor";

    fn plist_path() -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/Library/LaunchDaemons/{LABEL}.plist"))
    }

    pub fn install(exe: &Path) -> CmdResult {
        if !is_root() {
            return Err("launchd daemons must be installed as root.  Re-run with:\n\
                 \n\
                 \u{00a0}\u{00a0}sudo vigil --install-service"
                .into());
        }

        let shared_data_dir = exe
            .parent()
            .map(|d| d.join("vigil-data"))
            .ok_or_else(|| format!("could not determine parent directory for {}", exe.display()))?;
        let exe = xml_escape(&exe.display().to_string());
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>{LABEL}</string>
    <key>ProgramArguments</key>  <array><string>{exe}</string><string>{service_flag}</string><string>{data_dir_flag}</string><string>{shared_data_dir}</string></array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>/var/log/vigil.log</string>
    <key>StandardErrorPath</key> <string>/var/log/vigil.log</string>
</dict>
</plist>
"#,
            exe = exe,
            service_flag = SERVICE_MODE_FLAG,
            data_dir_flag = DATA_DIR_FLAG,
            shared_data_dir = xml_escape(&shared_data_dir.display().to_string()),
        );
        let path = plist_path();
        std::fs::write(&path, plist.as_bytes())
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        // Permissions: root:wheel 0644
        let _ = Command::new(command_paths::resolve("chown")?)
            .args(["root:wheel", &path.display().to_string()])
            .status();
        let _ = Command::new(command_paths::resolve("chmod")?)
            .args(["644", &path.display().to_string()])
            .status();

        let status = Command::new(command_paths::resolve("launchctl")?)
            .args(["load", "-w", &path.display().to_string()])
            .status()
            .map_err(|e| format!("failed to spawn `launchctl`: {e}"))?;
        if !status.success() {
            return Err("`launchctl load` failed (see /var/log/system.log)".into());
        }
        Ok(format!(
            "Installed launchd daemon `{LABEL}` at {}.\n\
             It will auto-start at boot (even before login).\n\
             To remove:  sudo vigil --uninstall-service",
            path.display()
        ))
    }

    pub fn uninstall() -> CmdResult {
        let path = plist_path();
        if !path.exists() {
            return Ok(format!("launchd daemon `{LABEL}` was not installed."));
        }
        if !is_root() {
            return Err("Re-run with:  sudo vigil --uninstall-service".into());
        }
        let _ = Command::new(command_paths::resolve("launchctl")?)
            .args(["unload", "-w", &path.display().to_string()])
            .status();
        std::fs::remove_file(&path)
            .map_err(|e| format!("could not remove {}: {e}", path.display()))?;
        Ok(format!("Removed launchd daemon `{LABEL}`."))
    }

    pub fn disable_boot_start() -> Result<(), String> {
        let path = plist_path();
        if !path.exists() {
            return Ok(());
        }
        if !is_root() {
            return Err("launchd daemon disable requires root".into());
        }
        let output = Command::new(command_paths::resolve("launchctl")?)
            .args(["unload", "-w", &path.display().to_string()])
            .output()
            .map_err(|e| format!("failed to spawn `launchctl`: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "failed to disable launchd daemon `{LABEL}`: {}",
                command_output_summary(&output)
            ))
        }
    }

    fn is_root() -> bool {
        // Declare getuid() directly to avoid pulling in a `libc` dependency
        // just for a single uid comparison.  It's an infallible C ABI call.
        extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() == 0 }
    }

    fn xml_escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    fn command_output_summary(output: &Output) -> String {
        let text = command_output_text(output);
        if text.trim().is_empty() {
            format!("exit status {}", output.status)
        } else {
            format!("exit status {}; {}", output.status, text.trim())
        }
    }

    fn command_output_text(output: &Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("{stdout}{stderr}")
    }
}

// ── Linux ─────────────────────────────────────────────────────────────────────

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use super::*;
    use crate::platform::command_paths;
    use std::path::Path;
    use std::process::{Command, Output};

    const UNIT_NAME: &str = "vigil.service";

    fn unit_path() -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/etc/systemd/system/{UNIT_NAME}"))
    }

    pub fn install(exe: &Path) -> CmdResult {
        if !is_root() {
            return Err("systemd units must be installed as root.  Re-run with:\n\
                 \n\
                 \u{00a0}\u{00a0}sudo vigil --install-service"
                .into());
        }

        let shared_data_dir = exe
            .parent()
            .map(|d| d.join("vigil-data"))
            .ok_or_else(|| format!("could not determine parent directory for {}", exe.display()))?;
        let exe = systemd_quote(&exe.display().to_string());
        let unit = format!(
            "[Unit]\n\
             Description=Vigil network monitor\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe} {service_flag} {data_dir_flag} {shared_data_dir}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             StandardOutput=journal\n\
             StandardError=journal\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            exe = exe,
            service_flag = SERVICE_MODE_FLAG,
            data_dir_flag = DATA_DIR_FLAG,
            shared_data_dir = systemd_quote(&shared_data_dir.display().to_string()),
        );
        let path = unit_path();
        std::fs::write(&path, unit.as_bytes())
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;

        let _ = Command::new(command_paths::resolve("systemctl")?)
            .args(["daemon-reload"])
            .status();
        let enable = Command::new(command_paths::resolve("systemctl")?)
            .args(["enable", "--now", UNIT_NAME])
            .status()
            .map_err(|e| format!("failed to spawn `systemctl`: {e}"))?;
        if !enable.success() {
            return Err(format!(
                "`systemctl enable --now {UNIT_NAME}` failed.  \
                 Check  systemctl status {UNIT_NAME}  for details."
            ));
        }
        Ok(format!(
            "Installed systemd unit `{UNIT_NAME}` at {}.\n\
             It will auto-start at boot (even before login).\n\
             To remove:  sudo vigil --uninstall-service",
            path.display()
        ))
    }

    pub fn uninstall() -> CmdResult {
        let path = unit_path();
        if !path.exists() {
            return Ok(format!("systemd unit `{UNIT_NAME}` was not installed."));
        }
        if !is_root() {
            return Err("Re-run with:  sudo vigil --uninstall-service".into());
        }
        let _ = Command::new(command_paths::resolve("systemctl")?)
            .args(["disable", "--now", UNIT_NAME])
            .status();
        std::fs::remove_file(&path)
            .map_err(|e| format!("could not remove {}: {e}", path.display()))?;
        let _ = Command::new(command_paths::resolve("systemctl")?)
            .args(["daemon-reload"])
            .status();
        Ok(format!("Removed systemd unit `{UNIT_NAME}`."))
    }

    pub fn disable_boot_start() -> Result<(), String> {
        if !unit_path().exists() {
            return Ok(());
        }
        if !is_root() {
            return Err("systemd unit disable requires root".into());
        }
        let output = Command::new(command_paths::resolve("systemctl")?)
            .args(["disable", "--now", UNIT_NAME])
            .output()
            .map_err(|e| format!("failed to spawn `systemctl`: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "failed to disable systemd unit `{UNIT_NAME}`: {}",
                command_output_summary(&output)
            ));
        }
        let _ = Command::new(command_paths::resolve("systemctl")?)
            .args(["daemon-reload"])
            .status();
        Ok(())
    }

    fn is_root() -> bool {
        extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() == 0 }
    }

    fn systemd_quote(text: &str) -> String {
        format!("\"{}\"", text.replace('"', "\\\""))
    }

    fn command_output_summary(output: &Output) -> String {
        let text = command_output_text(output);
        if text.trim().is_empty() {
            format!("exit status {}", output.status)
        } else {
            format!("exit status {}; {}", output.status, text.trim())
        }
    }

    fn command_output_text(output: &Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("{stdout}{stderr}")
    }
}

// ── Shared pretty-printer used by main.rs ─────────────────────────────────────

pub fn run_cmd(cmd: &str) -> i32 {
    let res = match cmd {
        "install" => install(),
        "uninstall" => uninstall(),
        _ => return 2,
    };
    match res {
        Ok(msg) => {
            println!("{msg}");
            0
        }
        Err(msg) => {
            eprintln!("vigil: {msg}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        drive_prelogin_guard_until_login, format_fail_open_disable_message, next_failure_streak,
        should_disable_boot_start, PreLoginGuardState,
    };
    use std::cell::Cell;
    use std::time::Duration;

    #[test]
    fn next_unclean_prelogin_run_increments_failure_streak() {
        let state = PreLoginGuardState {
            armed: true,
            failure_streak: 0,
            ..Default::default()
        };
        assert_eq!(next_failure_streak(&state), 1);
    }

    #[test]
    fn first_unclean_prelogin_run_disables_boot_start() {
        let state = PreLoginGuardState {
            failure_streak: 1,
            ..Default::default()
        };
        assert!(should_disable_boot_start(&state));
    }

    #[test]
    fn deferred_guard_handoff_waits_for_login_transition() {
        let mut states = vec![true, true, false].into_iter();
        let polls = Cell::new(0);
        let disarmed = Cell::new(false);

        drive_prelogin_guard_until_login(
            Duration::ZERO,
            || {
                polls.set(polls.get() + 1);
                states.next().unwrap_or(false)
            },
            || disarmed.set(true),
        );

        assert!(disarmed.get());
        assert_eq!(polls.get(), 3);
    }

    #[test]
    fn deferred_guard_handoff_disarms_immediately_after_login() {
        let polls = Cell::new(0);
        let disarmed = Cell::new(false);

        drive_prelogin_guard_until_login(
            Duration::ZERO,
            || {
                polls.set(polls.get() + 1);
                false
            },
            || disarmed.set(true),
        );

        assert!(disarmed.get());
        assert_eq!(polls.get(), 1);
    }

    #[test]
    fn fail_open_message_mentions_boot_disable_attempt() {
        let message = format_fail_open_disable_message("guard write failed", "disk full", None);
        assert!(message.contains("guard write failed"));
        assert!(message.contains("disk full"));
        assert!(message.contains("boot-time startup"));
    }
}
