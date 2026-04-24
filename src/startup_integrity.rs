//! Startup integrity scan for Phase 15.
//!
//! This is intentionally read-only: it surfaces missing or inconsistent
//! integrity metadata without silently changing operator-managed files. Existing
//! load paths still perform their own recovery where recovery is safe.

use crate::{audit, config};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
struct ScanSummary {
    checked: usize,
    ok: usize,
    warnings: usize,
    failures: usize,
}

#[derive(Debug, Deserialize)]
struct ArtifactManifestScan {
    artifact_path: String,
    size_bytes: u64,
    sha256: String,
}

pub fn run() {
    let mut summary = ScanSummary::default();
    scan_policy_sidecars(&mut summary);
    scan_artifact_manifests(&mut summary);

    let outcome = if summary.failures > 0 {
        "error"
    } else if summary.warnings > 0 {
        "warning"
    } else {
        "success"
    };
    audit::record(
        "startup_integrity_scan",
        outcome,
        json!({
            "checked": summary.checked,
            "ok": summary.ok,
            "warnings": summary.warnings,
            "failures": summary.failures,
        }),
    );
    match outcome {
        "success" => tracing::info!(checked = summary.checked, "startup integrity scan completed cleanly"),
        "warning" => tracing::warn!(checked = summary.checked, warnings = summary.warnings, "startup integrity scan completed with warnings"),
        _ => tracing::error!(checked = summary.checked, failures = summary.failures, "startup integrity scan found integrity failures"),
    }
}

fn scan_policy_sidecars(summary: &mut ScanSummary) {
    let path = config::config_path();
    summary.checked += 1;
    if !path.exists() {
        summary.warnings += 1;
        tracing::warn!(path = %path.display(), "policy store is not present yet; first-run seeding is expected to create it");
        return;
    }

    let sig = path.with_extension("json.sig");
    let bak = path.with_extension("json.bak");
    let bak_sig = path.with_extension("json.bak.sig");
    let key = path
        .parent()
        .map(|parent| parent.join("vigil-policy.key"))
        .unwrap_or_else(|| PathBuf::from("vigil-policy.key"));

    let missing: Vec<String> = [(&sig, "signature"), (&bak, "backup"), (&bak_sig, "backup signature"), (&key, "local integrity key")]
        .into_iter()
        .filter_map(|(p, name)| if p.exists() { None } else { Some(name.to_string()) })
        .collect();
    if missing.is_empty() {
        summary.ok += 1;
        tracing::info!(path = %path.display(), "policy integrity sidecars are present");
    } else {
        summary.warnings += 1;
        tracing::warn!(path = %path.display(), missing = ?missing, "policy integrity sidecars are incomplete");
    }
}

fn scan_artifact_manifests(summary: &mut ScanSummary) {
    let root = config::data_dir().join("artifacts");
    if !root.exists() {
        return;
    }
    let mut manifests = Vec::new();
    collect_manifest_paths(&root, &mut manifests, 0);
    for manifest_path in manifests {
        summary.checked += 1;
        match verify_artifact_manifest(&manifest_path) {
            Ok(()) => summary.ok += 1,
            Err(err) => {
                summary.failures += 1;
                tracing::error!(manifest = %manifest_path.display(), %err, "forensic artifact manifest verification failed");
            }
        }
    }
}

fn collect_manifest_paths(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 6 || out.len() >= 512 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        tracing::warn!(path = %dir.display(), "could not read artifact directory during integrity scan");
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_manifest_paths(&path, out, depth + 1);
            continue;
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".manifest.json"))
        {
            out.push(path);
            if out.len() >= 512 {
                break;
            }
        }
    }
}

fn verify_artifact_manifest(manifest_path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(manifest_path)
        .map_err(|e| format!("failed to read manifest: {e}"))?;
    let manifest: ArtifactManifestScan = serde_json::from_str(&text)
        .map_err(|e| format!("failed to parse manifest JSON: {e}"))?;
    let artifact_path = PathBuf::from(&manifest.artifact_path);
    let metadata = fs::metadata(&artifact_path).map_err(|e| {
        format!(
            "referenced artifact {} is not readable: {e}",
            artifact_path.display()
        )
    })?;
    if metadata.len() != manifest.size_bytes {
        return Err(format!(
            "artifact size mismatch for {}: manifest={} actual={}",
            artifact_path.display(),
            manifest.size_bytes,
            metadata.len()
        ));
    }
    let actual_hash = sha256_file(&artifact_path)?;
    if !actual_hash.eq_ignore_ascii_case(manifest.sha256.trim()) {
        return Err(format!(
            "artifact SHA-256 mismatch for {}",
            artifact_path.display()
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn verifies_matching_artifact_manifest() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("sample.bin");
        fs::write(&artifact, b"abc").unwrap();
        let manifest = dir.join("sample.bin.manifest.json");
        fs::write(
            &manifest,
            format!(
                "{{\"artifact_path\":\"{}\",\"size_bytes\":3,\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}}",
                artifact.display().to_string().replace('\\', "\\\\")
            ),
        )
        .unwrap();
        assert!(verify_artifact_manifest(&manifest).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detects_artifact_manifest_hash_mismatch() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("sample.bin");
        fs::write(&artifact, b"abc").unwrap();
        let manifest = dir.join("sample.bin.manifest.json");
        fs::write(
            &manifest,
            format!(
                "{{\"artifact_path\":\"{}\",\"size_bytes\":3,\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}",
                artifact.display().to_string().replace('\\', "\\\\")
            ),
        )
        .unwrap();
        assert!(verify_artifact_manifest(&manifest).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-startup-integrity-test-{nanos}"))
    }
}
