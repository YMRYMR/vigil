//! Cross-platform boot-time service installation.
//!
//! Vigil can run as an OS-managed service/daemon so it starts **before** any
//! user logs in and catches malware that activates during boot (rootkits,
//! dropper callbacks, persistence mechanisms).  This module implements the
//! install / uninstall commands for each supported OS:
//!
//! | OS      | Mechanism                     | Location                                      |
//! | ------- | ----------------------------- | ------------------------------------------------ |
//! | Windows | Service Control Manager (SCM) | `sc create Vigil …`                           |
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

/// Result of an install / uninstall command.  `Ok(msg)` is printed verbatim
/// to stdout; `Err(msg)` is printed to stderr and the process exits 1.
pub type CmdResult = Result<String, String>;
pub const BACKGROUND_MONITOR_FLAG: &str = "--background-monitor";

pub fn install() -> CmdResult {
    let exe =
        std::env::current_exe().map_err(|e| format!("could not resolve current exe path: {e}"))?;
    platform::install(&exe)
}

pub fn uninstall() -> CmdResult {
    platform::uninstall()
}

// ── Windows ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::platform::command_paths;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::{Command, Output};

    const TASK_NAME: &str = "VigilBootMonitor";

    pub fn install(exe: &Path) -> CmdResult {
        let task_command = boot_monitor_command_line(exe);
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
            return Err("`schtasks /Create` failed.  Open an *elevated* Command Prompt \
                 (Run as Administrator) and re-run `vigil --install-service`."
                .into());
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
