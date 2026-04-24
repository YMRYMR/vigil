//! Startup integrity scan for Phase 15.
//!
//! This is intentionally read-only for operator-managed files, but it can move
//! corrupted Vigil-owned forensic artifacts into an integrity quarantine so they
//! no longer sit beside trusted evidence. Existing load paths still perform
//! their own recovery where recovery is safe.

use crate::{
    audit, config,
    security::{file_quarantine, operator_provenance},
};
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
    record_summary("startup_integrity_scan", &summary);
}

pub fn scan_operator_inputs(cfg: &config::Config) {
    let mut summary = ScanSummary::default();
    for path in &cfg.blocklist_paths {
        if path.trim().is_empty() {
            continue;
        }
        observe_operator_path(&mut summary, "blocklist", Path::new(path.trim()));
    }
    if !cfg.response_rules_path.trim().is_empty() {
        observe_operator_path(
            &mut summary,
            "response_rules",
            Path::new(cfg.response_rules_path.trim()),
        );
    }
    record_summary("startup_operator_file_scan", &summary);
}

fn observe_operator_path(summary: &mut ScanSummary, kind: &str, path: &Path) {
    summary.checked += 1;
    match operator_provenance::observe_operator_file(kind, path) {
        operator_provenance::Observation::Unchanged => summary.ok += 1,
        operator_provenance::Observation::FirstSeen | operator_provenance::Observation::Changed => {
            summary.warnings += 1;
        }
        operator_provenance::Observation::Missing | operator_provenance::Observation::Unreadable => {
            summary.failures += 1;
        }
    }
}

fn record_summary(action: &str, summary: &ScanSummary) {
    let outcome = if summary.failures > 0 {
        "error"
    } else if summary.warnings > 0 {
        "warning"
    } else {
        "success"
    };
    audit::record(
        action,
        outcome,
        json!({
            "checked": summary.checked,
            "ok": summary.ok,
            "warnings": summary.warnings,
            "failures": summary.failures,
        }),
    );
    match outcome {
        "success" => tracing::info!(action, checked = summary.checked, "integrity scan completed cleanly"),
        "warning" => tracing::warn!(action, checked = summary.checked, warnings = summary.warnings, "integrity scan completed with warnings"),
        _ => tracing::error!(action, checked = summary.checked, failures = summary.failures, "integrity scan found failures"),
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
    let artifact_root = match root.canonicalize() {
        Ok(root) => root,
        Err(err) => {
            summary.failures += 1;
            tracing::error!(path = %root.display(), %err, "could not canonicalize artifact root for integrity scan");
            return;
        }
    };
    let mut manifests = Vec::new();
    collect_manifest_paths(&artifact_root, &artifact_root, &mut manifests, 0);
    for manifest_path in manifests {
        summary.checked += 1;
        match verify_artifact_manifest(&manifest_path) {
            Ok(()) => summary.ok += 1,
            Err(err) => {
                summary.failures += 1;
                let related = related_artifact_paths(&manifest_path, &artifact_root).unwrap_or_else(|related_err| {
                    tracing::warn!(manifest = %manifest_path.display(), %related_err, "could not derive related artifact paths for quarantine");
                    Vec::new()
                });
                match file_quarantine::quarantine_integrity_failure(&manifest_path, &related, &err) {
                    Ok(dest) => tracing::error!(manifest = %manifest_path.display(), quarantine = %dest.display(), %err, "forensic artifact manifest verification failed and was quarantined"),
                    Err(quarantine_err) => tracing::error!(manifest = %manifest_path.display(), %err, %quarantine_err, "forensic artifact manifest verification failed and quarantine failed"),
                }
            }
        }
    }
}

fn related_artifact_paths(manifest_path: &Path, artifact_root: &Path) -> Result<Vec<PathBuf>, String> {
    let text = fs::read_to_string(manifest_path)
        .map_err(|e| format!("failed to read manifest for quarantine: {e}"))?;
    let manifest: ArtifactManifestScan = serde_json::from_str(&text)
        .map_err(|e| format!("failed to parse manifest for quarantine: {e}"))?;
    let artifact_path = PathBuf::from(manifest.artifact_path);
    if !artifact_path.exists() {
        return Ok(Vec::new());
    }
    let artifact_root = canonical_artifact_root(artifact_root)?;
    let artifact_path = artifact_path.canonicalize().map_err(|e| {
        format!(
            "failed to canonicalize manifest artifact path {}: {e}",
            artifact_path.display()
        )
    })?;
    if !artifact_path.starts_with(&artifact_root) {
        return Err(format!(
            "refusing to quarantine artifact outside Vigil artifact directory: {}",
            artifact_path.display()
        ));
    }
    let metadata = fs::metadata(&artifact_path)
        .map_err(|e| format!("failed to stat manifest artifact path {}: {e}", artifact_path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "refusing to quarantine non-regular artifact path {}",
            artifact_path.display()
        ));
    }
    Ok(vec![artifact_path])
}

fn canonical_artifact_root(artifact_root: &Path) -> Result<PathBuf, String> {
    artifact_root.canonicalize().map_err(|e| {
        format!(
            "failed to canonicalize artifact root {}: {e}",
            artifact_root.display()
        )
    })
}

fn collect_manifest_paths(dir: &Path, artifact_root: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 6 || out.len() >= 512 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        tracing::warn!(path = %dir.display(), "could not read artifact directory during integrity scan");
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            tracing::warn!(path = %path.display(), "could not inspect artifact path type during integrity scan");
            continue;
        };
        if file_type.is_symlink() {
            tracing::warn!(path = %path.display(), "skipping symlink during artifact integrity scan");
            continue;
        }
        if file_type.is_dir() {
            collect_manifest_paths(&path, artifact_root, out, depth + 1);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".manifest.json"))
        {
            match path.canonicalize() {
                Ok(canonical) if canonical.starts_with(artifact_root) => out.push(canonical),
                Ok(canonical) => tracing::warn!(path = %canonical.display(), "skipping manifest outside artifact root after canonicalization"),
                Err(err) => tracing::warn!(path = %path.display(), %err, "could not canonicalize manifest path during integrity scan"),
            }
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
    if !metadata.is_file() {
        return Err(format!(
            "referenced artifact {} is not a regular file",
            artifact_path.display()
        ));
    }
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

    #[test]
    fn related_artifact_paths_reads_manifest_artifact_under_root() {
        let dir = unique_temp_dir();
        let root = dir.join("artifacts");
        fs::create_dir_all(&root).unwrap();
        let artifact = root.join("sample.bin");
        fs::write(&artifact, b"abc").unwrap();
        let manifest = root.join("sample.bin.manifest.json");
        fs::write(
            &manifest,
            format!(
                "{{\"artifact_path\":\"{}\",\"size_bytes\":3,\"sha256\":\"abc\"}}",
                artifact.display().to_string().replace('\\', "\\\\")
            ),
        )
        .unwrap();
        assert_eq!(related_artifact_paths(&manifest, &root).unwrap(), vec![artifact.canonicalize().unwrap()]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn related_artifact_paths_rejects_paths_outside_artifact_root() {
        let dir = unique_temp_dir();
        let root = dir.join("artifacts");
        fs::create_dir_all(&root).unwrap();
        let outside = dir.join("outside.bin");
        fs::write(&outside, b"abc").unwrap();
        let manifest = root.join("crafted.manifest.json");
        fs::write(
            &manifest,
            format!(
                "{{\"artifact_path\":\"{}\",\"size_bytes\":3,\"sha256\":\"abc\"}}",
                outside.display().to_string().replace('\\', "\\\\")
            ),
        )
        .unwrap();
        let err = related_artifact_paths(&manifest, &root).unwrap_err();
        assert!(err.contains("outside Vigil artifact directory"));
        assert!(outside.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn collect_manifest_paths_skips_symlinked_directories() {
        let dir = unique_temp_dir();
        let root = dir.join("artifacts");
        let outside = dir.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let outside_manifest = outside.join("outside.manifest.json");
        fs::write(&outside_manifest, b"{}").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("link-out")).unwrap();
            let mut manifests = Vec::new();
            let root = root.canonicalize().unwrap();
            collect_manifest_paths(&root, &root, &mut manifests, 0);
            assert!(manifests.is_empty());
        }
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
