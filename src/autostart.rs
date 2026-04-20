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
    use std::ffi::OsStr;
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

    pub fn relaunch_as_admin() -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| format!("failed to locate Vigil: {e}"))?;
        let args = std::env::args_os().skip(1).collect::<Vec<_>>();
        let args = join_args(&args);

        let exe_w = to_wide(exe.as_os_str());
        let args_w = to_wide(OsStr::new(&args));
        let verb = windows::core::w!("runas");

        unsafe {
            let result = ShellExecuteW(
                None,
                verb,
                PCWSTR(exe_w.as_ptr()),
                if args_w.is_empty() {
                    PCWSTR::null()
                } else {
                    PCWSTR(args_w.as_ptr())
                },
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );
            if result.0 as isize > 32 {
                Ok(())
            } else {
                Err("Windows declined the elevation request.".into())
            }
        }
    }

    fn to_wide(text: &OsStr) -> Vec<u16> {
        text.encode_wide().chain(Some(0)).collect()
    }

    fn join_args(args: &[std::ffi::OsString]) -> String {
        args.iter()
            .map(|arg| {
                let s = arg.to_string_lossy();
                if s.contains(' ') || s.contains('\t') || s.contains('"') {
                    format!("\"{}\"", s.replace('"', "\\\""))
                } else {
                    s.into_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
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

    fn schtasks_exe() -> PathBuf {
        PathBuf::from(r"C:\Windows\System32\schtasks.exe")
    }

    fn create_high_privilege_task() -> bool {
        let Some(tr) = quoted_exe() else {
            return false;
        };
        Command::new(schtasks_exe())
            .args([
                "/Create", "/TN", TASK_NAME, "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn delete_high_privilege_task() -> bool {
        Command::new(schtasks_exe())
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn high_privilege_task_exists() -> bool {
        Command::new(schtasks_exe())
            .args(["/Query", "/TN", TASK_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
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

    pub fn is_elevated() -> bool {
        if unsafe { libc::geteuid() == 0 } {
            return true;
        }
        check_capability(12) // CAP_NET_ADMIN
    }

    pub fn relaunch_as_admin() -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            grant_capabilities()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("Elevation is not supported on this platform.".into())
        }
    }

    /// Check whether a specific Linux capability (by bit index) is present in
    /// the effective capability set of the current process.
    #[cfg(target_os = "linux")]
    fn check_capability(bit: u8) -> bool {
        let Ok(data) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        for line in data.lines() {
            let Some(rest) = line.strip_prefix("CapEff:\t") else {
                continue;
            };
            let Ok(val) = u64::from_str_radix(rest.trim(), 16) else {
                return false;
            };
            return val & (1u64 << bit) != 0;
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    fn check_capability(_bit: u8) -> bool {
        false
    }

    /// Use pkexec to grant capabilities via setcap on the current binary.
    #[cfg(target_os = "linux")]
    fn grant_capabilities() -> Result<(), String> {
        let exe = std::env::current_exe()
            .map_err(|e| format!("failed to locate Vigil binary: {e}"))?;
        let exe_str = exe.to_string_lossy();
        let caps = "cap_bpf,cap_net_admin,cap_perfmon,cap_dac_read_search,cap_dac_override+ep";
        let setcap_arg = format!("{caps} {exe_str}");

        // Try pkexec first (graphical polkit prompt).
        let pkexec_result = std::process::Command::new("pkexec")
            .args(["setcap", &setcap_arg])
            .status();

        match pkexec_result {
            Ok(status) if status.success() => Ok(()),
            Ok(_) => {
                // pkexec ran but setcap failed — fall back to showing the command.
                Err(format!(
                    "pkexec setcap failed. Run manually:\n  sudo setcap {caps} {exe_str}"
                ))
            }
            Err(_) => {
                // pkexec not found — show the command.
                Err(format!(
                    "pkexec not found. Run manually:\n  sudo setcap {caps} {exe_str}"
                ))
            }
        }
    }
}
