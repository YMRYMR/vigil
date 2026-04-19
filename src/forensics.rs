//! Optional forensic artifact capture.
//!
//! Current Phase 11 implementation focuses on process memory dumps for
//! high-confidence alerts. The feature is opt-in, Windows-only, audited, and
//! rate-limited per PID so a noisy process does not flood disk with dumps.

use crate::{audit, config::Config, types::ConnInfo};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static LAST_DUMP_AT: OnceLock<Mutex<HashMap<u32, u64>>> = OnceLock::new();
static LAST_GLOBAL_DUMP_AT: OnceLock<Mutex<u64>> = OnceLock::new();
const GLOBAL_COOLDOWN_SECS: u64 = 30;

pub fn maybe_capture_process_dump(info: &ConnInfo, cfg: &Config) {
    if !cfg.process_dump_on_alert || info.score < cfg.process_dump_min_score || info.pid == 0 {
        return;
    }
    if info.proc_name.starts_with('<') && info.proc_name.ends_with('>') {
        return;
    }

    let now = unix_now();
    let gate = LAST_DUMP_AT.get_or_init(|| Mutex::new(HashMap::new()));
    let mut last = match gate.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    if let Some(previous) = last.get(&info.pid).copied() {
        if now.saturating_sub(previous) < cfg.process_dump_cooldown_secs {
            return;
        }
    }

    // Global cooldown: only one dump per GLOBAL_COOLDOWN_SECS across all PIDs.
    let global_gate = LAST_GLOBAL_DUMP_AT.get_or_init(|| Mutex::new(0));
    if let Ok(global_last) = global_gate.lock() {
        if now.saturating_sub(*global_last) < GLOBAL_COOLDOWN_SECS {
            return;
        }
    }

    match platform::capture_process_dump(info, cfg) {
        Ok(path) => {
            last.insert(info.pid, now);
            if let Ok(mut global_last) = global_gate.lock() {
                *global_last = now;
            }
            audit::record(
                "process_dump_on_alert",
                "success",
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "path": path.display().to_string(),
                    "score": info.score,
                }),
            );
            tracing::warn!(pid = info.pid, proc = %info.proc_name, dump = %path.display(), "captured process dump on alert");
        }
        Err(err) => {
            audit::record(
                "process_dump_on_alert",
                "error",
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "score": info.score,
                    "error": err,
                }),
            );
            tracing::warn!(pid = info.pid, proc = %info.proc_name, %err, "failed to capture process dump on alert");
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn dump_root(cfg: &Config) -> PathBuf {
    if !cfg.process_dump_dir.trim().is_empty() {
        PathBuf::from(cfg.process_dump_dir.trim())
    } else {
        crate::config::data_dir()
            .join("artifacts")
            .join("process-dumps")
    }
}

fn safe_name(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('_');
    if cleaned.is_empty() {
        "process".to_string()
    } else {
        cleaned.to_string()
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::process::Command;

    pub fn capture_process_dump(info: &ConnInfo, cfg: &Config) -> Result<PathBuf, String> {
        let dir = dump_root(cfg);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("failed to create {}: {e}", dir.display()))?;

        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        let filename = format!(
            "{}-pid{}-score{}-{}.dmp",
            stamp,
            info.pid,
            info.score,
            safe_name(&info.proc_name)
        );
        let out = dir.join(filename);

        let status = Command::new("rundll32.exe")
            .arg("C:\\Windows\\System32\\comsvcs.dll,MiniDump")
            .arg(info.pid.to_string())
            .arg(&out)
            .arg("full")
            .status()
            .map_err(|e| format!("failed to spawn rundll32.exe: {e}"))?;

        if !status.success() {
            return Err(format!("rundll32 MiniDump exited with status {status}"));
        }
        if !out.exists() {
            return Err(format!(
                "expected dump file {} was not created",
                out.display()
            ));
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn capture_process_dump(_info: &ConnInfo, _cfg: &Config) -> Result<PathBuf, String> {
        Err("process dump on alert is not implemented on this platform".into())
    }
}
