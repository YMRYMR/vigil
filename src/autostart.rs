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
        let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
        if !args
            .iter()
            .any(|arg| arg == OsStr::new(super::ELEVATED_RELAUNCH_FLAG))
        {
            args.push(OsString::from(super::ELEVATED_RELAUNCH_FLAG));
        }
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

    pub fn launch_elevated_child() -> Result<(), String> {
        Err("Elevation is not supported on this platform.".into())
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
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::Command;

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
            relaunch_with_pkexec()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("Elevation is not supported on this platform.".into())
        }
    }

    pub fn launch_elevated_child() -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            launch_elevated_child_impl()
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

    /// Relaunch Vigil under root privileges via pkexec.
    #[cfg(target_os = "linux")]
    fn relaunch_with_pkexec() -> Result<(), String> {
        let exe =
            std::env::current_exe().map_err(|e| format!("failed to locate Vigil binary: {e}"))?;
        let target = elevation_target_path().unwrap_or(exe);
        let mut cmd = Command::new("pkexec");
        cmd.arg("env");

        // Preserve desktop-session variables so the relaunched GUI can attach
        // to the current display/session instead of failing EGL/GL init.
        for key in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_CURRENT_DESKTOP",
            "XDG_SESSION_TYPE",
        ] {
            if let Some(value) = std::env::var_os(key) {
                let mut kv = OsString::from(key);
                kv.push("=");
                kv.push(value);
                cmd.arg(kv);
            }
        }

        cmd.arg(&target);
        let mut launcher_present = false;
        for arg in std::env::args_os().skip(1) {
            if arg == std::ffi::OsStr::new(ELEVATED_LAUNCHER_FLAG) {
                launcher_present = true;
            }
            if arg != std::ffi::OsStr::new(ELEVATED_RELAUNCH_FLAG) {
                cmd.arg(arg);
            }
        }
        if !launcher_present {
            cmd.arg(ELEVATED_LAUNCHER_FLAG);
        }

        let status = cmd.status().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "pkexec is not available on this system. Install polkit and pkexec, then retry."
                    .to_string()
            } else {
                format!("failed to launch pkexec: {e}")
            }
        })?;
        if status.success() {
            Ok(())
        } else {
            Err("the elevation request was denied or the launcher failed".into())
        }
    }

    #[cfg(target_os = "linux")]
    fn launch_elevated_child_impl() -> Result<(), String> {
        let target =
            elevation_target_path().ok_or_else(|| "could not locate Vigil binary".to_string())?;
        let mut args = Vec::new();
        for arg in std::env::args_os().skip(1) {
            if arg != std::ffi::OsStr::new(ELEVATED_LAUNCHER_FLAG) {
                args.push(arg);
            }
        }
        if !args
            .iter()
            .any(|arg| arg == std::ffi::OsStr::new(ELEVATED_RELAUNCH_FLAG))
        {
            args.push(OsString::from(ELEVATED_RELAUNCH_FLAG));
        }
        Command::new(target)
            .args(args)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("failed to launch elevated Vigil: {e}"))
    }

    #[cfg(target_os = "linux")]
    fn elevation_target_path() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("APPIMAGE")
            .map(PathBuf::from)
            .filter(|path| path.exists())
        {
            return Some(path);
        }

        if let Some(path) = std::env::args_os()
            .next()
            .map(PathBuf::from)
            .filter(|path| path.exists())
        {
            return Some(path);
        }

        let current = std::env::current_exe().ok()?;
        if current.to_string_lossy().contains("/tmp/.mount_") {
            return None;
        }
        Some(current)
    }
}
