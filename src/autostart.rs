//! Autostart: register or unregister the binary with the OS login items.
//!
//! On Windows, Vigil chooses the best available startup mechanism:
//! - unelevated runs use the normal login-item path
//! - elevated runs use a scheduled task with the highest available privileges
//!
//! On macOS and Linux, the normal login-item abstraction is used.

use auto_launch::AutoLaunchBuilder;

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
    use super::with_builder;
    use std::path::PathBuf;
    use std::process::Command;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const TASK_NAME: &str = "Vigil";

    pub fn enable() -> bool {
        if is_elevated() {
            let created = create_high_privilege_task();
            let _ = disable_login_item();
            created
        } else {
            let enabled = enable_login_item();
            let _ = delete_high_privilege_task();
            enabled
        }
    }

    pub fn disable() -> bool {
        let login = disable_login_item();
        let task = delete_high_privilege_task();
        login || task
    }

    pub fn is_enabled() -> bool {
        login_item_enabled() || high_privilege_task_exists()
    }

    fn enable_login_item() -> bool {
        with_builder(|al| al.enable().is_ok())
    }

    fn disable_login_item() -> bool {
        with_builder(|al| al.disable().is_ok())
    }

    fn login_item_enabled() -> bool {
        with_builder(|al| al.is_enabled().unwrap_or(false))
    }

    fn current_exe() -> Option<PathBuf> {
        std::env::current_exe().ok()
    }

    fn quoted_exe() -> Option<String> {
        current_exe().map(|p| format!("\"{}\"", p.display()))
    }

    fn create_high_privilege_task() -> bool {
        let Some(tr) = quoted_exe() else {
            return false;
        };
        Command::new("schtasks")
            .args([
                "/Create", "/TN", TASK_NAME, "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn delete_high_privilege_task() -> bool {
        Command::new("schtasks")
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn high_privilege_task_exists() -> bool {
        Command::new("schtasks")
            .args(["/Query", "/TN", TASK_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn is_elevated() -> bool {
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
}

#[cfg(not(windows))]
mod platform {
    use super::with_builder;

    pub fn enable() -> bool {
        with_builder(|al| al.enable().is_ok())
    }

    pub fn disable() -> bool {
        with_builder(|al| al.disable().is_ok())
    }

    pub fn is_enabled() -> bool {
        with_builder(|al| al.is_enabled().unwrap_or(false))
    }
}
