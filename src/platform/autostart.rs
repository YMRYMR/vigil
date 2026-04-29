//! Autostart: register or unregister the binary with the OS login items.
//!
//! On Windows, Vigil chooses the best available startup mechanism:
//! - unelevated runs use the normal login-item path
//! - elevated runs use a scheduled task with the highest available privileges
//!
//! On macOS and Linux, the normal login-item abstraction is used.

use auto_launch::AutoLaunchBuilder;

pub(crate) const ELEVATED_RELAUNCH_FLAG: &str = "--elevated-relaunch";
pub(crate) const ELEVATED_LAUNCHER_FLAG: &str = "--elevated-launcher";

/// Enable autostart for the current executable.
/// Returns `true` on success, `false` on any error.
pub fn enable() -> bool {
    platform::enable()
}

/// Disable autostart.
/// Returns `true` on success, `false` on any error.
pub fn disable() -> bool {
    platform::disable()
}

/// Check whether autostart is currently enabled.
#[allow(dead_code)]
pub fn is_enabled() -> bool {
    platform::is_enabled()
}

/// Check whether the current process is running with elevated privileges.
pub fn is_elevated() -> bool {
    platform::is_elevated()
}

/// Re-launch the current executable with elevated privileges.
///
/// On Windows this uses the shell `runas` verb so the user can approve UAC.
#[allow(dead_code)]
pub fn relaunch_as_admin() -> Result<(), String> {
    platform::relaunch_as_admin()
}

/// Linux-only launcher entrypoint used by `pkexec` to spawn the elevated app
/// and then exit only after the elevated child has been started.
pub fn launch_elevated_child() -> Result<(), String> {
    platform::launch_elevated_child()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn with_builder<F: FnOnce(auto_launch::AutoLaunch) -> bool>(f: F) -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    match AutoLaunchBuilder::new()
        .set_app_name("Vigil")
        .set_app_path(&exe)
        .build()
    {
        Ok(al) => f(al),
        Err(_) => false,
    }
}

#[cfg(windows)]
mod platform {
    use crate::service;
    use super::with_builder;
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::process::Command;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    const TASK_NAME: &str = "Vigil";
    const BOOT_TASK_NAME: &str = "VigilBootMonitor";

    pub fn enable() -> bool {
        if is_elevated() {
            let created = create_high_privilege_task();
            let boot_created = create_boot_monitor_task();
            let _ = disable_login_item();
            if created && boot_created {
                true
            } else {
                let _ = delete_high_privilege_task();
                let _ = delete_boot_monitor_task();
                false
            }
        } else {
            let enabled = enable_login_item();
            let _ = delete_high_privilege_task();
            let _ = delete_boot_monitor_task();
            enabled
        }
    }

    pub fn disable() -> bool {
        let login = disable_login_item();
        let task = delete_high_privilege_task();
        let boot_task = delete_boot_monitor_task();
        login || task || boot_task
    }

    pub fn is_enabled() -> bool {
        login_item_enabled() || high_privilege_task_exists() || boot_monitor_task_exists()
    }

    pub fn is_elevated() -> bool {
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION::default();
            let mut bytes = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut bytes,
            )
            .is_ok();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }
