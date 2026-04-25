//! Lightweight audit log for active and automatic response actions.
//!
//! Records are appended as JSON Lines to `<exe_dir>/logs/vigil-audit.jsonl` so
//! operators can review what Vigil actually did (or would have done in dry run)
//! without scraping the general tracing log.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    timestamp: String,
    action: &'a str,
    outcome: &'a str,
    details: Value,
    prev_hash: String,
    entry_hash: String,
}

#[derive(Debug, Serialize)]
struct AuditPayload<'a> {
    timestamp: &'a str,
    action: &'a str,
    outcome: &'a str,
    details: &'a Value,
    prev_hash: &'a str,
}

#[derive(Debug, Default)]
struct AuditState {
    last_hash: String,
}

static AUDIT_STATE: OnceLock<Mutex<AuditState>> = OnceLock::new();
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn init() {
    let path = audit_path();
    let (last_hash, verified) = verify_chain_at(&path).unwrap_or_else(|err| {
        tracing::warn!(%err, path = %audit_path().display(), "audit chain verification failed");
        (ZERO_HASH.to_string(), false)
    });
    let mut state = audit_state().lock().unwrap();
    state.last_hash = last_hash;
    if !verified {
        tracing::warn!(
            path = %path.display(),
            "audit chain is not currently verifiable; continuing from last known hash"
        );
    }
}

pub fn record(action: &str, outcome: &str, details: Value) {
    let path = audit_path();
    let mut state = audit_state().lock().unwrap();
    let prev_hash = if state.last_hash.is_empty() {
        ZERO_HASH.to_string()
    } else {
        state.last_hash.clone()
    };
    let Ok(entry_hash) = append_record(&path, action, outcome, details, prev_hash.clone()) else {
        tracing::warn!(action, outcome, "failed to serialise audit record");
        return;
    };

    state.last_hash = entry_hash;
}

fn audit_path() -> PathBuf {
    crate::config::config_path()
        .parent()
        .map(|dir| dir.join("logs").join("vigil-audit.jsonl"))
        .unwrap_or_else(|| PathBuf::from("logs").join("vigil-audit.jsonl"))
}

fn append_record(
    path: &PathBuf,
    action: &str,
    outcome: &str,
    details: Value,
    prev_hash: String,
) -> Result<String, String> {
    let timestamp = chrono::Local::now().to_rfc3339();
    let payload = AuditPayload {
        timestamp: &timestamp,
        action,
        outcome,
        details: &details,
        prev_hash: &prev_hash,
    };
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| format!("failed to serialise audit payload: {e}"))?;
    let entry_hash = hash_hex(&payload_json);
    let record = AuditRecord {
        timestamp,
        action,
        outcome,
        details,
        prev_hash,
        entry_hash: entry_hash.clone(),
    };
    let line = serde_json::to_string(&record)
        .map_err(|e| format!("failed to serialise audit record: {e}"))?;
    if let Some(parent) = path.parent() {
        create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut file) => {
            writeln!(file, "{line}").map_err(|e| format!("failed to append audit record: {e}"))?;
        }
        Err(err) => {
            return Err(format!(
                "failed to open audit log {}: {err}",
                path.display()
            ));
        }
    }
    Ok(entry_hash)
}

fn verify_chain_at(path: &PathBuf) -> Result<(String, bool), String> {
    if !path.exists() {
        return Ok((ZERO_HASH.to_string(), true));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let mut prev_hash = ZERO_HASH.to_string();
    let mut last_hash = ZERO_HASH.to_string();
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecordOwned = serde_json::from_str(line).map_err(|e| {
            format!(
                "failed to parse line {} in {}: {e}",
                idx + 1,
                path.display()
            )
        })?;
        if record.prev_hash != prev_hash {
            return Err(format!(
                "audit chain broke at line {} in {}",
                idx + 1,
                path.display()
            ));
        }
        let payload = AuditPayloadOwned {
            timestamp: record.timestamp.clone(),
            action: record.action.clone(),
            outcome: record.outcome.clone(),
            details: record.details.clone(),
            prev_hash: record.prev_hash.clone(),
        };
        let payload_json = serde_json::to_vec(&payload)
            .map_err(|e| format!("failed to serialise audit payload at line {}: {e}", idx + 1))?;
        let computed_hash = hash_hex(&payload_json);
        if computed_hash != record.entry_hash {
            return Err(format!(
                "audit entry hash mismatch at line {} in {}",
                idx + 1,
                path.display()
            ));
        }
        prev_hash = record.entry_hash;
        last_hash = prev_hash.clone();
    }
    Ok((last_hash, true))
}

fn hash_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn audit_state() -> &'static Mutex<AuditState> {
    AUDIT_STATE.get_or_init(|| Mutex::new(AuditState::default()))
}

#[derive(Debug, Deserialize)]
struct AuditRecordOwned {
    timestamp: String,
    action: String,
    outcome: String,
    details: Value,
    prev_hash: String,
    entry_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditPayloadOwned {
    timestamp: String,
    action: String,
    outcome: String,
    details: Value,
    prev_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn hash_chain_verifies_and_appends() {
        let base = unique_temp_dir();
        let path = base.join("logs").join("vigil-audit.jsonl");
        let first_hash = append_record(
            &path,
            "test",
            "ok",
            serde_json::json!({"n": 1}),
            ZERO_HASH.to_string(),
        )
        .unwrap();
        let second_hash = append_record(
            &path,
            "test",
            "ok",
            serde_json::json!({"n": 2}),
            first_hash.clone(),
        )
        .unwrap();
        let log = std::fs::read_to_string(&path).unwrap();
        let mut lines = log.lines();
        let first: AuditRecordOwned = serde_json::from_str(lines.next().unwrap()).unwrap();
        let second_record: AuditRecordOwned = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(first.prev_hash, ZERO_HASH);
        assert_eq!(second_record.prev_hash, first.entry_hash);
        assert_eq!(second_record.entry_hash, second_hash);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn verify_chain_detects_tamper() {
        let base = unique_temp_dir();
        let log_path = base.join("logs").join("vigil-audit.jsonl");
        let _ = append_record(
            &log_path,
            "test",
            "ok",
            serde_json::json!({"n": 1}),
            ZERO_HASH.to_string(),
        )
        .unwrap();
        let mut line = std::fs::read_to_string(&log_path).unwrap();
        line = line.replace("\"ok\"", "\"bad\"");
        std::fs::write(&log_path, line).unwrap();
        assert!(verify_chain_at(&log_path).is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-audit-test-{nanos}"))
    }
}
