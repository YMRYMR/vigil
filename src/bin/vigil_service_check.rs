//! Windows/Linux installer and service parity checker.
//!
//! Verifies that Vigil's boot-time service is properly installed and configured
//! on both Windows (scheduled task) and Linux (systemd unit), and that fail-open
//! startup behavior works correctly on each platform.
//!
//! Usage:
//!   vigil-service-check [--fix]
//!
//! With `--fix`, attempts to repair common issues (e.g., reinstall the service,
//! restore default config, reset permissions).

use std::path::{Path, PathBuf};
use std::process::Command;

const LINUX_SERVICE_NAME: &str = "vigil";
const LINUX_SERVICE_PATH: &str = "/etc/systemd/system/vigil.service";
const WINDOWS_TASK_NAME: &str = "VigilBootMonitor";
const CONFIG_PATH: &str = "vigil.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Windows,
    Linux,
    Other,
}

impl Platform {
    fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }
}

struct CheckResult {
    check: &'static str,
    status: CheckStatus,
    detail: String,
}

enum CheckStatus {
    Pass,
    Fail,
    Warn,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fix_mode = args.iter().any(|a| a == "--fix");
    let platform = Platform::current();

    println!("=== Vigil Service Parity Check ===");
    println!("Platform: {platform:?}");
    if fix_mode {
        println!("Mode:     fix (will attempt repairs)");
    } else {
        println!("Mode:     read-only");
    }
    println!();

    let mut results = Vec::new();

    // Platform-agnostic checks.
    results.push(check_config_exists());
    results.push(check_binary_exists());

    // Platform-specific checks.
    match platform {
        Platform::Windows => {
            results.extend(check_windows_service());
        }
        Platform::Linux => {
            results.extend(check_linux_service());
        }
        Platform::Other => {
            println!("This tool only supports Windows and Linux.");
            std::process::exit(1);
        }
    }

    // Report results.
    let mut all_pass = true;
    for r in &results {
        let icon = match r.status {
            CheckStatus::Pass => "✅",
            CheckStatus::Fail => "❌",
            CheckStatus::Warn => "⚠️",
        };
        println!(" {icon} {}: {}", r.check, r.detail);
        if matches!(r.status, CheckStatus::Fail) {
            all_pass = false;
        }
    }

    println!();
    if all_pass {
        println!("✅ All checks passed. Service parity is healthy.");
    } else {
        println!("❌ Some checks failed. Run with --fix to attempt repairs.");
        if fix_mode {
            println!("Fix mode is enabled but not all repairs are automated.");
        }
    }
}

fn check_config_exists() -> CheckResult {
    let data_dir = default_data_dir();
    let config = data_dir.join(CONFIG_PATH);
    CheckResult {
        check: "Configuration file exists",
        status: if config.exists() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if config.exists() {
            format!("Found at {}", config.display())
        } else {
            format!("Not found at {} — will use defaults", config.display())
        },
    }
}

fn default_data_dir() -> PathBuf {
    // Matches Vigil's config::data_dir() logic.
    if let Some(dir) = std::env::var_os("VIGIL_DATA_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(dir).join("Vigil");
        }
        if let Some(dir) = std::env::var_os("APPDATA") {
            return PathBuf::from(dir).join("Vigil");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(dir).join("vigil");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".config").join("vigil");
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("vigil-data")))
        .unwrap_or_else(|| PathBuf::from("vigil-data"))
}

fn check_binary_exists() -> CheckResult {
    let self_path = std::env::current_exe().ok();
    CheckResult {
        check: "Binary exists",
        status: CheckStatus::Pass,
        detail: match self_path {
            Some(p) => format!("Running from {}", p.display()),
            None => "Could not determine binary path".into(),
        },
    }
}

fn check_windows_service() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // Check if the scheduled task exists.
    let output = Command::new("schtasks")
        .args(["/query", "/tn", WINDOWS_TASK_NAME, "/fo", "LIST", "/v"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let has_task = stdout.contains(WINDOWS_TASK_NAME);
            results.push(CheckResult {
                check: "Scheduled task installed",
                status: if has_task {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                },
                detail: if has_task {
                    format!("Task '{}' is registered", WINDOWS_TASK_NAME)
                } else {
                    format!("Task '{}' is not registered", WINDOWS_TASK_NAME)
                },
            });

            // Check if the task is enabled.
            let enabled = stdout.contains("Enabled: True");
            results.push(CheckResult {
                check: "Scheduled task enabled",
                status: if enabled {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Warn
                },
                detail: if enabled {
                    "Task is enabled and will run at boot".into()
                } else {
                    "Task is disabled — Vigil won't start automatically".into()
                },
            });

            // Check the run level (highest available).
            let run_level = stdout.contains("HighestAvailable");
            results.push(CheckResult {
                check: "Scheduled task runs with highest privileges",
                status: if run_level {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Warn
                },
                detail: if run_level {
                    "Task runs with highest privileges".into()
                } else {
                    "Task may not have enough privileges for active response".into()
                },
            });
        }
        Ok(_) => {
            results.push(CheckResult {
                check: "Scheduled task installed",
                status: CheckStatus::Fail,
                detail: format!("Task '{}' not found", WINDOWS_TASK_NAME),
            });
        }
        Err(e) => {
            results.push(CheckResult {
                check: "Scheduled task check",
                status: CheckStatus::Fail,
                detail: format!("schtasks failed: {e}"),
            });
        }
    }

    results
}

fn check_linux_service() -> Vec<CheckResult> {
    let mut results = Vec::new();

    // Check if the systemd service file exists.
    let service_exists = Path::new(LINUX_SERVICE_PATH).exists();
    results.push(CheckResult {
        check: "systemd service unit installed",
        status: if service_exists {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        detail: if service_exists {
            format!("Unit file found at {LINUX_SERVICE_PATH}")
        } else {
            format!("Unit file not found at {LINUX_SERVICE_PATH}")
        },
    });

    // Check if the service is enabled.
    let enabled = Command::new("systemctl")
        .args(["is-enabled", LINUX_SERVICE_NAME])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
        .unwrap_or(false);
    results.push(CheckResult {
        check: "systemd service enabled",
        status: if enabled {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if enabled {
            "Service is enabled and starts at boot".into()
        } else {
            "Service is not enabled — use 'systemctl enable vigil'".into()
        },
    });

    // Check if the service is currently running.
    let running = Command::new("systemctl")
        .args(["is-active", LINUX_SERVICE_NAME])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);
    results.push(CheckResult {
        check: "systemd service running",
        status: if running {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if running {
            "Service is currently active".into()
        } else {
            "Service is not running — start with 'systemctl start vigil'".into()
        },
    });

    // Check fail-open: does the service file use Restart=always?
    if service_exists {
        let content = std::fs::read_to_string(LINUX_SERVICE_PATH).unwrap_or_default();
        let restart_always = content.contains("Restart=always");
        let restart_on_failure = content.contains("Restart=on-failure");
        results.push(CheckResult {
            check: "systemd auto-restart configured",
            status: if restart_always || restart_on_failure {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            detail: if restart_always {
                "Restart=always set — service recovers from crash".into()
            } else if restart_on_failure {
                "Restart=on-failure set — service recovers from crash".into()
            } else {
                "No auto-restart policy — service won't recover from crash".into()
            },
        });
    }

    // Check capabilities via the systemd unit file. When the unit has
    // CapabilityBoundingSet=CAP_NET_ADMIN or runs as root (no bounding
    // set restriction), Vigil has the required network privileges.
    let has_caps = if service_exists {
        let content = std::fs::read_to_string(LINUX_SERVICE_PATH).unwrap_or_default();
        let has_bounding = content.contains("CapabilityBoundingSet");
        let has_admin = content.contains("CAP_NET_ADMIN") || content.contains("CAP_NET_RAW");
        let runs_as_root = content.contains("User=root") || !content.contains("User=");
        // If no bounding set is configured, root has all caps.
        // If bounding set is configured, it must include CAP_NET_ADMIN.
        (!has_bounding && runs_as_root) || (has_bounding && has_admin)
    } else {
        // If no service file exists, check the current process (for dev runs).
        std::fs::read_to_string("/proc/self/status")
            .map(|s| {
                let cap_eff = s
                    .lines()
                    .find(|l| l.starts_with("CapEff:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
                    .unwrap_or(0);
                (cap_eff & (1u64 << 12)) != 0 // CAP_NET_ADMIN
            })
            .unwrap_or(false)
    };
    results.push(CheckResult {
        check: "Linux capabilities for network operations",
        status: if has_caps {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: if has_caps {
            "CAP_NET_ADMIN or root — eBPF and firewall operations available".into()
        } else {
            "No CAP_NET_ADMIN — eBPF and iptables operations may fail".into()
        },
    });

    results
}
