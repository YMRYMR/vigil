//! Provenance tracking for operator-managed input files.
//!
//! Blocklists and response-rule YAML are intentionally edited by operators, so
//! Vigil must not treat every content change as corruption. Instead, this
//! module records first-seen and changed hashes in a protected local registry and
//! emits audit events whenever those files appear, disappear, or change.

use crate::audit;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const REGISTRY_FILE: &str = "operator-file-provenance.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Registry {
    #[serde(default)]
    files: BTreeMap<String, ProvenanceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvenanceEntry {
    kind: String,
    path: String,
    sha256: String,
    size_bytes: u64,
    modified_unix: Option<u64>,
    first_seen_unix: u64,
    last_changed_unix: u64,
    change_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    Unchanged,
    FirstSeen,
    Changed,
    Missing,
    Unreadable,
}

pub fn observe_operator_file(kind: &str, path: &Path) -> Observation {
    match observe_operator_file_inner(kind, path, &registry_path(), true) {
        Ok(observation) => observation,
        Err(err) => {
            audit::record(
                "operator_file_provenance",
                "error",
                json!({
                    "kind": kind,
                    "path": path.display().to_string(),
                    "error": err,
                }),
            );
            Observation::Unreadable
        }
    }
}

fn observe_operator_file_inner(
    kind: &str,
    path: &Path,
    registry_path: &Path,
    audit_events: bool,
) -> Result<Observation, String> {
    let canonical = canonical_key(path);
    if !path.exists() {
        if audit_events {
            audit::record(
                "operator_file_provenance",
                "missing",
                json!({ "kind": kind, "path": path.display().to_string() }),
            );
        }
        return Ok(Observation::Missing);
    }

    let fingerprint = match fingerprint(path) {
        Ok(fingerprint) => fingerprint,
        Err(err) => {
            if audit_events {
                audit::record(
                    "operator_file_provenance",
                    "unreadable",
                    json!({
                        "kind": kind,
                        "path": path.display().to_string(),
                        "error": err,
                    }),
                );
            }
            return Ok(Observation::Unreadable);
        }
    };

    let now = unix_now();
    let mut registry = load_registry(registry_path)?;
    match registry.files.get_mut(&canonical) {
        Some(entry) if entry.sha256 == fingerprint.sha256 && entry.size_bytes == fingerprint.size_bytes => {
            Ok(Observation::Unchanged)
        }
        Some(entry) => {
            let previous_sha256 = entry.sha256.clone();
            let previous_size_bytes = entry.size_bytes;
            entry.kind = kind.to_string();
            entry.path = path.display().to_string();
            entry.sha256 = fingerprint.sha256.clone();
            entry.size_bytes = fingerprint.size_bytes;
            entry.modified_unix = fingerprint.modified_unix;
            entry.last_changed_unix = now;
            entry.change_count = entry.change_count.saturating_add(1);
            save_registry(registry_path, &registry)?;
            if audit_events {
                audit::record(
                    "operator_file_provenance",
                    "changed",
                    json!({
                        "kind": kind,
                        "path": path.display().to_string(),
                        "previous_sha256": previous_sha256,
                        "new_sha256": fingerprint.sha256,
                        "previous_size_bytes": previous_size_bytes,
                        "new_size_bytes": fingerprint.size_bytes,
                    }),
                );
            }
            Ok(Observation::Changed)
        }
        None => {
            registry.files.insert(
                canonical,
                ProvenanceEntry {
                    kind: kind.to_string(),
                    path: path.display().to_string(),
                    sha256: fingerprint.sha256.clone(),
                    size_bytes: fingerprint.size_bytes,
                    modified_unix: fingerprint.modified_unix,
                    first_seen_unix: now,
                    last_changed_unix: now,
                    change_count: 0,
                },
            );
            save_registry(registry_path, &registry)?;
            if audit_events {
                audit::record(
                    "operator_file_provenance",
                    "first_seen",
                    json!({
                        "kind": kind,
                        "path": path.display().to_string(),
                        "sha256": fingerprint.sha256,
                        "size_bytes": fingerprint.size_bytes,
                    }),
                );
            }
            Ok(Observation::FirstSeen)
        }
    }
}

#[derive(Debug, Clone)]
struct Fingerprint {
    sha256: String,
    size_bytes: u64,
    modified_unix: Option<u64>,
}

fn fingerprint(path: &Path) -> Result<Fingerprint, String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(Fingerprint {
        sha256: sha256_file(path)?,
        size_bytes: metadata.len(),
        modified_unix: metadata.modified().ok().and_then(system_time_to_unix),
    })
}

fn load_registry(path: &Path) -> Result<Registry, String> {
    let existed_before_load = path.exists();
    let Some(bytes) = crate::security::policy::load_json_with_integrity(path)? else {
        if existed_before_load {
            return Err(format!(
                "operator provenance registry {} failed integrity verification and could not be recovered",
                path.display()
            ));
        }
        return Ok(Registry::default());
    };
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse operator provenance registry: {e}"))
}

fn save_registry(path: &Path, registry: &Registry) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(registry)
        .map_err(|e| format!("failed to serialize operator provenance registry: {e}"))?;
    crate::security::policy::save_json_with_integrity(path, &data)
}

fn registry_path() -> PathBuf {
    crate::config::data_dir().join(REGISTRY_FILE)
}

fn canonical_key(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn system_time_to_unix(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn records_first_seen_then_unchanged() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rules.yaml");
        let registry = dir.join("registry.json");
        fs::write(&file, b"rules: []\n").unwrap();

        assert_eq!(
            observe_operator_file_inner("response_rules", &file, &registry, false).unwrap(),
            Observation::FirstSeen
        );
        let before = fs::read_to_string(&registry).unwrap();
        assert_eq!(
            observe_operator_file_inner("response_rules", &file, &registry, false).unwrap(),
            Observation::Unchanged
        );
        assert_eq!(fs::read_to_string(&registry).unwrap(), before);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn records_changed_content_without_rejecting_it() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("blocklist.txt");
        let registry = dir.join("registry.json");
        fs::write(&file, b"203.0.113.1\n").unwrap();
        assert_eq!(
            observe_operator_file_inner("blocklist", &file, &registry, false).unwrap(),
            Observation::FirstSeen
        );

        fs::write(&file, b"203.0.113.2\n").unwrap();
        assert_eq!(
            observe_operator_file_inner("blocklist", &file, &registry, false).unwrap(),
            Observation::Changed
        );
        assert_eq!(
            observe_operator_file_inner("blocklist", &file, &registry, false).unwrap(),
            Observation::Unchanged
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reports_missing_file() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("missing.txt");
        let registry = dir.join("registry.json");
        assert_eq!(
            observe_operator_file_inner("blocklist", &file, &registry, false).unwrap(),
            Observation::Missing
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn registry_parse_failure_does_not_reset_provenance() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rules.yaml");
        let registry = dir.join("registry.json");
        fs::write(&file, b"rules: []\n").unwrap();
        fs::write(&registry, b"not-json").unwrap();

        let err = observe_operator_file_inner("response_rules", &file, &registry, false)
            .expect_err("corrupt registry must fail closed");
        assert!(err.contains("failed to parse operator provenance registry"));
        assert_eq!(fs::read_to_string(&registry).unwrap(), "not-json");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unrecoverable_protected_registry_does_not_reset_provenance() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rules.yaml");
        let registry = dir.join("registry.json");
        fs::write(&file, b"rules: []\n").unwrap();
        let original = br#"{"files":{"existing":{"kind":"response_rules","path":"rules.yaml","sha256":"abc","size_bytes":1,"modified_unix":null,"first_seen_unix":1,"last_changed_unix":1,"change_count":0}}}"#;
        crate::security::policy::save_json_with_integrity(&registry, original).unwrap();
        fs::write(&registry, b"tampered-current").unwrap();
        fs::write(registry.with_extension("json.bak"), b"tampered-backup").unwrap();

        let err = observe_operator_file_inner("response_rules", &file, &registry, false)
            .expect_err("unrecoverable protected registry must fail closed");
        assert!(err.contains("failed integrity verification"));
        assert_eq!(fs::read_to_string(&registry).unwrap(), "tampered-current");
        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-operator-provenance-test-{nanos}"))
    }
}
