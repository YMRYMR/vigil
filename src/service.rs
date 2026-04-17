//! Cross-platform boot-time service installation.
//!
//! Vigil can run as an OS-managed service/daemon so it starts **before** any
//! user logs in and catches malware that activates during boot (rootkits,
//! dropper callbacks, persistence mechanisms).  This module implements the
//! install / uninstall commands for each supported OS:
//!
//! | OS      | Mechanism                     | Location                                      |
//! | ------- | ----------------------------- | --------------------------------------------- |
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

pub fn install() -> CmdResult {
    let exe =
        std::env::current_exe().map_err(|e| format!("could not resolve current exe path: {e}"))?;
    platform::install(&exe)
}

pub fn uninstall() -> CmdResult {
    platform::uninstall()
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    const SVC_NAME: &str = "Vigil";

    pub fn install(exe: &Path) -> CmdResult {
        // sc create Vigil binPath= "\"C:\path\to\vigil.exe\"" start= auto
        let bin_path = format!("\"{}\"", exe.display());
        let status = Command::new("sc")
            .args([
                "create",
                SVC_NAME,
                "binPath=",
                &bin_path,
                "start=",
                "auto",
                "DisplayName=",
                "Vigil Network Monitor",
            ])
            .status()
            .map_err(|e| format!("failed to spawn `sc`: {e}"))?;
        if !status.success() {
            return Err("`sc create` failed.  Open an *elevated* Command Prompt \
                 (Run as Administrator) and re-run `vigil --install-service`."
                .into());
        }

        let _ = Command::new("sc").args(["start", SVC_NAME]).status();
        Ok(format!(
            "Installed Windows service `{SVC_NAME}` and started it.  \
             It will auto-start at boot from now on.\n\
             To remove:  vigil --uninstall-service"
        ))
    }

    pub fn uninstall() -> CmdResult {
        let _ = Command::new("sc").args(["stop", SVC_NAME]).status();
        let status = Command::new("sc")
            .args(["delete", SVC_NAME])
            .status()
            .map_err(|e| format!("failed to spawn `sc`: {e}"))?;
        if !status.success() {
            return Err("`sc delete` failed.  Re-run from an elevated Command Prompt.".into());
        }
        Ok(format!("Removed Windows service `{SVC_NAME}`."))
    }
}

// ── macOS ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::path::Path;
    use std::process::Command;

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

        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>{LABEL}</string>
    <key>ProgramArguments</key>  <array><string>{exe}</string></array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>/var/log/vigil.log</string>
    <key>StandardErrorPath</key> <string>/var/log/vigil.log</string>
</dict>
</plist>
"#,
            exe = exe.display(),
        );
        let path = plist_path();
        std::fs::write(&path, plist.as_bytes())
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        // Permissions: root:wheel 0644
        let _ = Command::new("chown")
            .args(["root:wheel", &path.display().to_string()])
            .status();
        let _ = Command::new("chmod")
            .args(["644", &path.display().to_string()])
            .status();

        let status = Command::new("launchctl")
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
        if !is_root() {
            return Err("Re-run with:  sudo vigil --uninstall-service".into());
        }
        let path = plist_path();
        if path.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", "-w", &path.display().to_string()])
                .status();
            std::fs::remove_file(&path)
                .map_err(|e| format!("could not remove {}: {e}", path.display()))?;
        }
        Ok(format!("Removed launchd daemon `{LABEL}`."))
    }

    fn is_root() -> bool {
        // Declare getuid() directly to avoid pulling in a `libc` dependency
        // just for a single uid comparison.  It's an infallible C ABI call.
        extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() == 0 }
    }
}

// ── Linux ─────────────────────────────────────────────────────────────────────

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use super::*;
    use std::path::Path;
    use std::process::Command;

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

        let unit = format!(
            "[Unit]\n\
             Description=Vigil network monitor\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             StandardOutput=journal\n\
             StandardError=journal\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            exe = exe.display(),
        );
        let path = unit_path();
        std::fs::write(&path, unit.as_bytes())
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;

        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        let enable = Command::new("systemctl")
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
        if !is_root() {
            return Err("Re-run with:  sudo vigil --uninstall-service".into());
        }
        let _ = Command::new("systemctl")
            .args(["disable", "--now", UNIT_NAME])
            .status();
        let path = unit_path();
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("could not remove {}: {e}", path.display()))?;
        }
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        Ok(format!("Removed systemd unit `{UNIT_NAME}`."))
    }

    fn is_root() -> bool {
        extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() == 0 }
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
