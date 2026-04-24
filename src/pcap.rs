//! Optional packet-capture artifact generation.
//!
//! Current Phase 11 implementation uses Windows Packet Monitor (`pktmon`) to
//! capture a short host-wide packet window when a sufficiently severe alert
//! fires. The capture is opt-in, audited, and globally serialized so multiple
//! alerts do not race the capture session.

use crate::{artifact_provenance, audit, config::Config, tls_artifacts, types::ConnInfo};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static LAST_CAPTURE_AT: OnceLock<Mutex<HashMap<u32, u64>>> = OnceLock::new();
static LAST_GLOBAL_CAPTURE_AT: OnceLock<Mutex<u64>> = OnceLock::new();
static CAPTURE_ACTIVE: OnceLock<Mutex<bool>> = OnceLock::new();
const GLOBAL_COOLDOWN_SECS: u64 = 60;

pub fn maybe_capture_pcap(info: &ConnInfo, cfg: &Config) {
    if !cfg.pcap_on_alert || info.score < cfg.pcap_min_score || info.pid == 0 {
        return;
    }
    if info.proc_name.starts_with('<') && info.proc_name.ends_with('>') {
        return;
    }

    let now = unix_now();
    let gate = LAST_CAPTURE_AT.get_or_init(|| Mutex::new(HashMap::new()));
    let mut last = match gate.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    if let Some(previous) = last.get(&info.pid).copied() {
        if now.saturating_sub(previous) < cfg.pcap_cooldown_secs {
            return;
        }
    }

    // Global cooldown: only one capture per GLOBAL_COOLDOWN_SECS across all PIDs.
    let global_gate = LAST_GLOBAL_CAPTURE_AT.get_or_init(|| Mutex::new(0));
    if let Ok(global_last) = global_gate.lock() {
        if now.saturating_sub(*global_last) < GLOBAL_COOLDOWN_SECS {
            return;
        }
    }

    let active = CAPTURE_ACTIVE.get_or_init(|| Mutex::new(false));
    let mut active_guard = match active.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    if *active_guard {
        audit::record(
            "pcap_on_alert",
            "skipped",
            json!({
                "pid": info.pid,
                "proc_name": info.proc_name,
                "reason": "capture already active",
                "score": info.score,
            }),
        );
        return;
    }
    *active_guard = true;
    drop(active_guard);

    last.insert(info.pid, now);
    if let Ok(mut global_last) = global_gate.lock() {
        *global_last = now;
    }
    let info = info.clone();
    let cfg = cfg.clone();
    std::thread::Builder::new()
        .name("vigil-pcap-capture".into())
        .spawn(move || {
            let result = platform::capture_window(&info, &cfg);
            match result {
                Ok(path) => {
                    let tls_sidecar = match tls_artifacts::analyze_capture(&info, &path) {
                        Ok(sidecar) => {
                            if let Some(sidecar_path) = sidecar.as_ref() {
                                audit::record("tls_client_hello_extract", "success", json!({
                                    "pid": info.pid,
                                    "proc_name": info.proc_name,
                                    "pcap_path": path.display().to_string(),
                                    "tls_sidecar": sidecar_path.display().to_string(),
                                }));
                            }
                            sidecar
                        }
                        Err(err) => {
                            audit::record("tls_client_hello_extract", "error", json!({
                                "pid": info.pid,
                                "proc_name": info.proc_name,
                                "pcap_path": path.display().to_string(),
                                "error": err,
                            }));
                            None
                        }
                    };
                    let manifest = match artifact_provenance::write_manifest(
                        &path,
                        "pcap",
                        &info,
                        json!({
                            "seconds": cfg.pcap_duration_secs,
                            "packet_size_bytes": cfg.pcap_packet_size_bytes,
                            "capture_method": "pktmon",
                            "tls_sidecar": tls_sidecar.as_ref().map(|p| p.display().to_string()),
                        }),
                    ) {
                        Ok(manifest) => Some(manifest),
                        Err(err) => {
                            audit::record("artifact_manifest", "error", json!({
                                "artifact_kind": "pcap",
                                "artifact_path": path.display().to_string(),
                                "pid": info.pid,
                                "proc_name": info.proc_name,
                                "error": err,
                            }));
                            None
                        }
                    };
                    if let Some(sidecar_path) = tls_sidecar.as_ref() {
                        if let Err(err) = artifact_provenance::write_manifest(
                            sidecar_path,
                            "tls_sidecar",
                            &info,
                            json!({
                                "source_pcap": path.display().to_string(),
                                "source_pcap_manifest": manifest.as_ref().map(|p| p.display().to_string()),
                            }),
                        ) {
                            audit::record("artifact_manifest", "error", json!({
                                "artifact_kind": "tls_sidecar",
                                "artifact_path": sidecar_path.display().to_string(),
                                "pid": info.pid,
                                "proc_name": info.proc_name,
                                "error": err,
                            }));
                        }
                    }
                    audit::record("pcap_on_alert", "success", json!({
                        "pid": info.pid,
                        "proc_name": info.proc_name,
                        "path": path.display().to_string(),
                        "manifest": manifest.as_ref().map(|p| p.display().to_string()),
                        "tls_sidecar": tls_sidecar.as_ref().map(|p| p.display().to_string()),
                        "score": info.score,
                        "seconds": cfg.pcap_duration_secs,
                    }));
                    tracing::warn!(pid = info.pid, proc = %info.proc_name, pcap = %path.display(), manifest = ?manifest.as_ref().map(|p| p.display().to_string()), tls = ?tls_sidecar.as_ref().map(|p| p.display().to_string()), "captured pcap window on alert");
                }
                Err(err) => {
                    audit::record("pcap_on_alert", "error", json!({
                        "pid": info.pid,
                        "proc_name": info.proc_name,
                        "score": info.score,
                        "error": err,
                    }));
                    tracing::warn!(pid = info.pid, proc = %info.proc_name, %err, "failed to capture pcap window on alert");
                }
            }
            if let Ok(mut guard) = CAPTURE_ACTIVE.get_or_init(|| Mutex::new(false)).lock() {
                *guard = false;
            }
        })
        .ok();
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn capture_root(cfg: &Config) -> PathBuf {
    if !cfg.pcap_dir.trim().is_empty() {
        PathBuf::from(cfg.pcap_dir.trim())
    } else {
        crate::config::data_dir().join("artifacts").join("pcap")
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
    use crate::platform::command_paths;
    use std::process::Command;

    pub fn capture_window(info: &ConnInfo, cfg: &Config) -> Result<PathBuf, String> {
        let dir = capture_root(cfg);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("failed to create {}: {e}", dir.display()))?;

        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        let stem = format!(
            "{}-pid{}-score{}-{}",
            stamp,
            info.pid,
            info.score,
            safe_name(&info.proc_name)
        );
        let etl = dir.join(format!("{stem}.etl"));
        let pcapng = dir.join(format!("{stem}.pcapng"));

        let _ = Command::new(command_paths::resolve("pktmon.exe")?)
            .arg("stop")
            .status();
        let _ = Command::new(command_paths::resolve("pktmon.exe")?)
            .arg("reset")
            .status();

        let start = Command::new(command_paths::resolve("pktmon.exe")?)
            .args(["start", "--capture", "--file-name"])
            .arg(&etl)
            .args(["--pkt-size"])
            .arg(cfg.pcap_packet_size_bytes.to_string())
            .args(["--file-size", "64", "--log-mode", "memory"])
            .status()
            .map_err(|e| format!("failed to spawn pktmon start: {e}"))?;
        if !start.success() {
            return Err(format!("pktmon start exited with status {start}"));
        }

        std::thread::sleep(std::time::Duration::from_secs(
            cfg.pcap_duration_secs.max(1),
        ));

        let stop = Command::new(command_paths::resolve("pktmon.exe")?)
            .arg("stop")
            .status()
            .map_err(|e| format!("failed to spawn pktmon stop: {e}"))?;
        if !stop.success() {
            return Err(format!("pktmon stop exited with status {stop}"));
        }

        let convert = Command::new(command_paths::resolve("pktmon.exe")?)
            .args(["etl2pcap"])
            .arg(&etl)
            .args(["--out"])
            .arg(&pcapng)
            .status()
            .map_err(|e| format!("failed to spawn pktmon etl2pcap: {e}"))?;
        if !convert.success() {
            return Err(format!("pktmon etl2pcap exited with status {convert}"));
        }
        if !pcapng.exists() {
            return Err(format!(
                "expected pcap file {} was not created",
                pcapng.display()
            ));
        }

        let _ = Command::new(command_paths::resolve("pktmon.exe")?)
            .arg("reset")
            .status();
        Ok(pcapng)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn capture_window(_info: &ConnInfo, _cfg: &Config) -> Result<PathBuf, String> {
        Err("pcap on alert is not implemented on this platform".into())
    }
}
