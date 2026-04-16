//! Autostart: register or unregister the binary with the OS login items.
//!
//! Uses the `auto-launch` crate which abstracts:
//! - Windows: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
//! - macOS:   Launch Agent plist in `~/Library/LaunchAgents/`
//! - Linux:   XDG autostart `.desktop` file

use auto_launch::AutoLaunchBuilder;

/// Enable autostart for the current executable.
/// Returns `true` on success, `false` on any error.
pub fn enable() -> bool {
    with_builder(|al| al.enable().is_ok())
}

/// Disable autostart.
/// Returns `true` on success, `false` on any error.
pub fn disable() -> bool {
    with_builder(|al| al.disable().is_ok())
}

/// Check whether autostart is currently enabled.
pub fn is_enabled() -> bool {
    with_builder(|al| al.is_enabled().unwrap_or(false))
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
