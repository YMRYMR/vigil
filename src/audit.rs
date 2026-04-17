//! Lightweight audit log for active and automatic response actions.
//!
//! Records are appended as JSON Lines to `<exe_dir>/logs/vigil-audit.jsonl` so
//! operators can review what Vigil actually did (or would have done in dry run)
//! without scraping the general tracing log.

use serde::Serialize;
use serde_json::Value;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    timestamp: String,
    action: &'a str,
    outcome: &'a str,
    details: Value,
}

pub fn record(action: &str, outcome: &str, details: Value) {
    let record = AuditRecord {
        timestamp: chrono::Local::now().to_rfc3339(),
        action,
        outcome,
        details,
    };

    let Ok(line) = serde_json::to_string(&record) else {
        tracing::warn!(action, outcome, "failed to serialise audit record");
        return;
    };

    let path = audit_path();
    if let Some(parent) = path.parent() {
        if let Err(err) = create_dir_all(parent) {
            tracing::warn!(%err, path = %path.display(), "failed to create audit log directory");
            return;
        }
    }

    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            if let Err(err) = writeln!(file, "{line}") {
                tracing::warn!(%err, path = %path.display(), "failed to append audit record");
            }
        }
        Err(err) => {
            tracing::warn!(%err, path = %path.display(), "failed to open audit log");
        }
    }
}

fn audit_path() -> PathBuf {
    crate::config::config_path()
        .parent()
        .map(|dir| dir.join("logs").join("vigil-audit.jsonl"))
        .unwrap_or_else(|| PathBuf::from("logs").join("vigil-audit.jsonl"))
}
