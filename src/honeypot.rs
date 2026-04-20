//! Honeypot decoy files.
//!
//! Vigil can plant a small set of decoy files in common lure directories and
//! poll them for timestamp changes. Any touch triggers a synthetic high-score
//! alert and can optionally auto-isolate the machine.

use crate::{
    active_response, audit,
    config::Config,
    types::{ConnEvent, ConnInfo},
};
use chrono::Local;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

#[derive(Clone)]
struct DecoyEntry {
    path: PathBuf,
    modified_unix: u64,
}

pub fn start(cfg: Arc<RwLock<Config>>, tx: broadcast::Sender<ConnEvent>, threshold: u8) {
    std::thread::Builder::new()
        .name("vigil-honeypot-decoys".into())
        .spawn(move || loop {
            let snapshot = cfg.read().map(|c| c.clone()).unwrap_or_default();
            if !snapshot.honeypot_decoys_enabled {
                std::thread::sleep(std::time::Duration::from_secs(10));
                continue;
            }
            let mut decoys = ensure_decoys(&snapshot);
            let poll = snapshot.honeypot_poll_secs.clamp(5, 300);
            loop {
                let current_cfg = cfg.read().map(|c| c.clone()).unwrap_or_default();
                if !current_cfg.honeypot_decoys_enabled {
                    break;
                }
                for decoy in &mut decoys {
                    let updated = modified_unix(&decoy.path).unwrap_or(decoy.modified_unix);
                    if updated > decoy.modified_unix {
                        decoy.modified_unix = updated;
                        let info = synthetic_alert(&decoy.path, threshold.max(10));
                        let _ = tx.send(ConnEvent::Alert(info.clone()));
                        audit::record(
                            "honeypot_decoy",
                            "success",
                            json!({"path": decoy.path.display().to_string(), "score": info.score}),
                        );
                        if current_cfg.honeypot_auto_isolate {
                            let _ = active_response::isolate_machine();
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(poll));
            }
        })
        .ok();
}

fn synthetic_alert(path: &Path, score: u8) -> ConnInfo {
    ConnInfo {
        timestamp: Local::now().format("%H:%M:%S").to_string(),
        proc_name: "honeypot-decoy".into(),
        pid: 0,
        proc_path: path.display().to_string(),
        proc_user: String::new(),
        parent_name: String::new(),
        parent_pid: 0,
        parent_user: String::new(),
        service_name: String::new(),
        publisher: String::new(),
        local_addr: "file://local".into(),
        remote_addr: path.display().to_string(),
        status: "HONEYPOT_TOUCH".into(),
        score,
        reasons: vec![format!("Honeypot decoy touched: {}", path.display())],
        ancestor_chain: Vec::new(),
        pre_login: false,
        hostname: None,
        country: None,
        asn: None,
        asn_org: None,
        reputation_hit: None,
        recently_dropped: false,
        long_lived: false,
        dga_like: false,
        baseline_deviation: false,
        script_host_suspicious: false,
        command_line: String::new(),
        attack_tags: Vec::new(),
        tls_sni: None,
        tls_ja3: None,
    }
}

fn ensure_decoys(cfg: &Config) -> Vec<DecoyEntry> {
    let mut out = Vec::new();
    for dir in watched_dirs() {
        let _ = std::fs::create_dir_all(&dir);
        for name in &cfg.honeypot_decoy_names {
            let path = dir.join(name);
            if !path.exists() {
                let _ = std::fs::write(&path, decoy_contents(name));
            }
            out.push(DecoyEntry {
                modified_unix: modified_unix(&path).unwrap_or(0),
                path,
            });
        }
    }
    out
}

fn decoy_contents(name: &str) -> String {
    format!("Vigil honeypot decoy: {name}\nThis file is monitored for unauthorized access.\n")
}

fn watched_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
    {
        out.push(home.join("Desktop"));
        out.push(home.join("Documents"));
        out.push(home.join("Downloads"));
    }
    if let Some(public) = std::env::var_os("PUBLIC").map(PathBuf::from) {
        out.push(public.join("Documents"));
    }
    out.retain(|p| p.is_dir());
    out.sort();
    out.dedup();
    out
}

fn modified_unix(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}
