//! Interactive-user-session detection.
//!
//! `is_pre_login()` returns `true` when the host currently has **no
//! interactive user session** — i.e. Vigil is running as a boot-time
//! service / launchd daemon / systemd unit and no one has logged in yet
//! (or the screen is at the lock / login prompt before any user has
//! authenticated for the first time).
//!
//! Events observed while this is true are tagged with `pre_login: true`
//! on `ConnInfo`, which:
//!   1. adds a `+2` score bump in `score::score()`  (boot-time persistence
//!      is high-value signal for rootkits / dropper callbacks), and
//!   2. renders a small "PRE-LOGIN" badge in the UI so the user can tell
//!      which events were captured before they logged in.
//!
//! The check is cheap (a single syscall / env lookup) and is called
//! per-connection from the monitor.

/// Returns `true` when there is no interactive user session on this host.
pub fn is_pre_login() -> bool {
    platform::is_pre_login()
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    /// On Windows, `WTSGetActiveConsoleSessionId()` returns `0xFFFFFFFF`
    /// when no user is attached to the physical console — i.e. we're at
    /// the pre-login Winlogon desktop (or the machine was just booted
    /// into a service context with nobody signed in yet).
    ///
    /// Session ID 0 is the "Services" session, which hosts all Windows
    /// services and never has an interactive user.  Anything else (1, 2,
    /// …) is a real user session.
    pub fn is_pre_login() -> bool {
        use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
        unsafe {
            let sid = WTSGetActiveConsoleSessionId();
            sid == 0xFFFFFFFF || sid == 0
        }
    }
}

// ── Unix (macOS + Linux) ──────────────────────────────────────────────────────

#[cfg(not(windows))]
mod platform {
    /// On macOS + Linux we approximate by checking the environment Vigil
    /// inherited at launch:
    ///
    /// * A `launchd` daemon launched at boot (before `loginwindow` hands
    ///   off to a user) inherits *no* `USER` / `HOME` / `DISPLAY` /
    ///   `WAYLAND_DISPLAY` — its context is whatever the plist declared.
    /// * A `systemd` system unit has `USER=root` (or the `User=` directive
    ///   value) and never gets `DISPLAY` or `WAYLAND_DISPLAY`.
    /// * An interactive session always has at least one of
    ///   `DISPLAY` / `WAYLAND_DISPLAY` / `XDG_SESSION_TYPE=tty|x11|wayland`
    ///   set, regardless of the specific desktop environment.
    ///
    /// If none of those interactive markers are present we treat the run
    /// as pre-login.  False positives are possible (a cron job on a user
    /// account with no $DISPLAY set) but are benign — they just add `+2`
    /// to the risk score for those particular events.
    pub fn is_pre_login() -> bool {
        let has_display = std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some();
        if has_display {
            return false;
        }

        match std::env::var("XDG_SESSION_TYPE").as_deref() {
            Ok("x11") | Ok("wayland") | Ok("tty") | Ok("mir") => return false,
            _ => {}
        }

        // No desktop indicators — and user is root or unset → pre-login.
        match std::env::var("USER").as_deref() {
            Ok("") | Err(_) => true,
            Ok("root") => true,
            Ok(_) => false,
        }
    }
}
