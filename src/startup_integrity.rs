//! Startup integrity scan for Phase 15.
//!
//! This is intentionally read-only for operator-managed files, but it can move
//! corrupted Vigil-owned forensic artifacts into an integrity quarantine so they
//! no longer sit beside trusted evidence. Existing load paths still perform
//! their own recovery where recovery is safe.

use crate::{
    audit, config,
    security::{file_quarantine, integrity, operator_provenance},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const REPORT_FILE: &str = "startup-integrity-report.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StartupIntegrityReport {
    #[serde(default)]
    pub created_unix: u64,
    #[serde(default)]
    pub checked: usize,
    #[serde(default)]
    pub ok: usize,
    #[serde(default)]
    pub warnings: usize,
    #[serde(default)]
    pub failures: usize,
    #[serde(default)]
    pub issues: Vec<IntegrityIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityIssue {
    pub severity: IssueSeverity,
    pub scope: String,
    pub message: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub quarantine_dir: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IssueSeverity {
    Warning,
    Failure,
}

#[derive(Debug, Deserialize)]
struct ArtifactManifestScan {
    artifact_path: String,
    size_bytes: u64,
    sha256: String,
}

pub fn run() {
    let mut report = StartupIntegrityReport {
        created_unix: unix_now(),
        ..Default::default()
    };
    scan_policy_sidecars(&mut report);
    scan_artifact_manifests(&mut report);
    record_summary("startup_integrity_scan", &report);
    if let Err(err) = save_report(&report) {
        tracing::error!(%err, "failed to save startup integrity report");
    }
}

pub fn scan_operator_inputs(cfg: &config::Config) {
    let mut report = load_report().unwrap_or_else(|| StartupIntegrityReport {
        created_unix: unix_now(),
        ..Default::default()
    });
    for path in &cfg.blocklist_paths {
        if path.trim().is_empty() {
            continue;
        }
        observe_operator_path(&mut report, "blocklist", Path::new(path.trim()));
    }
    if !cfg.response_rules_path.trim().is_empty() {
        observe_operator_path(
            &mut report,
            "response_rules",
            Path::new(cfg.response_rules_path.trim()),
        );
    }
    record_summary("startup_operator_file_scan", &report);
    if let Err(err) = save_report(&report) {
        tracing::error!(%err, "failed to save startup operator-file integrity report");
    }
}

pub fn load_report() -> Option<StartupIntegrityReport> {
    load_report_at(&report_path()).ok().flatten()
}

fn operator_input_purpose(kind: &str) -> &'static str {
    match kind {
        "response_rules" => "response rules",
        _ => "blocklist",
    }
}

fn verification_context(status: &integrity::VerificationStatus) -> String {
    match status {
        integrity::VerificationStatus::Verified { sidecar } => {
            format!(
                " and its SHA-256 sidecar {} verified cleanly",
                sidecar.display()
            )
        }
    }
}

fn observe_operator_path(report: &mut StartupIntegrityReport, kind: &str, path: &Path) {
    observe_operator_path_with_registry(
        report,
        kind,
        path,
        &config::data_dir().join("operator-file-provenance.json"),
    );
}

fn observe_operator_path_with_registry(
    report: &mut StartupIntegrityReport,
    kind: &str,
    path: &Path,
    registry_path: &Path,
) {
    report.checked += 1;
    let verification = match integrity::read_verified(path, operator_input_purpose(kind)) {
        Ok((_data, status)) => status,
        Err(err) => {
            note_issue(
                report,
                IssueSeverity::Failure,
                kind,
                path,
                format!(
                    "{kind} file {} failed integrity verification or could not be read: {err}",
                    path.display()
                ),
            );
            return;
        }
    };
    match operator_provenance::observe_operator_file_at(kind, path, registry_path) {
        Ok(operator_provenance::Observation::Unchanged) => report.ok += 1,
        Ok(operator_provenance::Observation::FirstSeen) => {
            note_issue(
                report,
                IssueSeverity::Warning,
                kind,
                path,
                format!(
                    "{kind} file {} was first seen on this startup{}; review the source if you did not expect a new operator-managed input",
                    path.display(),
                    verification_context(&verification),
                ),
            );
        }
        Ok(operator_provenance::Observation::Changed) => note_issue(
            report,
            IssueSeverity::Warning,
            kind,
            path,
            format!(
                "{kind} file {} changed since the last recorded startup{}",
                path.display(),
                verification_context(&verification),
            ),
        ),
        Ok(operator_provenance::Observation::Missing) => note_issue(
            report,
            IssueSeverity::Failure,
            kind,
            path,
            format!("{kind} file {} is missing", path.display()),
        ),
        Ok(operator_provenance::Observation::Unreadable) => note_issue(
            report,
            IssueSeverity::Failure,
            kind,
            path,
            format!("{kind} file {} is unreadable", path.display()),
        ),
        Err(err) => {
            note_issue(
                report,
                IssueSeverity::Failure,
                kind,
                path,
                format!(
                    "{kind} file {} could not be checked against the protected provenance registry: {err}",
                    path.display()
                ),
            );
        }
    }
}

fn record_summary(action: &str, report: &StartupIntegrityReport) {
    let outcome = if report.failures > 0 {
        "error"
    } else if report.warnings > 0 {
        "warning"
    } else {
        "success"
    };
    audit::record(
        action,
        outcome,
        json!({
            "checked": report.checked,
            "ok": report.ok,
            "warnings": report.warnings,
            "failures": report.failures,
            "issues": report.issues,
        }),
    );
    match outcome {
        "success" => tracing::info!(
            action,
            checked = report.checked,
            "integrity scan completed cleanly"
        ),
        "warning" => tracing::warn!(
            action,
            checked = report.checked,
            warnings = report.warnings,
            "integrity scan completed with warnings"
        ),
        _ => tracing::error!(
            action,
            checked = report.checked,
            failures = report.failures,
            "integrity scan found failures"
        ),
    }
}

fn scan_policy_sidecars(report: &mut StartupIntegrityReport) {
    let path = config::config_path();
    report.checked += 1;
    if !path.exists() {
        note_issue(
            report,
            IssueSeverity::Warning,
            "policy",
            &path,
            format!(
                "policy store {} is not present yet; first-run seeding is expected to create it",
                path.display()
            ),
        );
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

    let missing: Vec<String> = [
        (&sig, "signature"),
        (&bak, "backup"),
        (&bak_sig, "backup signature"),
        (&key, "local integrity key"),
    ]
    .into_iter()
    .filter_map(|(p, name)| {
        if p.exists() {
            None
        } else {
            Some(name.to_string())
        }
    })
    .collect();
    if missing.is_empty() {
        report.ok += 1;
        tracing::info!(path = %path.display(), "policy integrity sidecars are present");
    } else {
        note_issue(
            report,
            IssueSeverity::Warning,
            "policy",
            &path,
            format!(
                "policy integrity metadata for {} is incomplete: missing {}",
                path.display(),
                missing.join(", ")
            ),
        );
        tracing::warn!(path = %path.display(), missing = ?missing, "policy integrity sidecars are incomplete");
    }
}

fn scan_artifact_manifests(report: &mut StartupIntegrityReport) {
    let root = config::data_dir().join("artifacts");
    if !root.exists() {
        return;
    }
    let artifact_root = match root.canonicalize() {
        Ok(root) => root,
        Err(err) => {
            note_issue(
                report,
                IssueSeverity::Failure,
                "artifacts",
                &root,
                format!(
                    "could not canonicalize artifact root {} for integrity scan: {err}",
                    root.display()
                ),
            );
            tracing::error!(path = %root.display(), %err, "could not canonicalize artifact root for integrity scan");
            return;
        }
    };
    let mut manifests = Vec::new();
    collect_manifest_paths(&artifact_root, &artifact_root, &mut manifests, 0);
    for manifest_path in manifests {
        report.checked += 1;
        match verify_artifact_manifest(&manifest_path) {
            Ok(()) => report.ok += 1,
            Err(err) => {
                let related = related_artifact_paths(&manifest_path, &artifact_root).unwrap_or_else(|related_err| {
                    tracing::warn!(manifest = %manifest_path.display(), %related_err, "could not derive related artifact paths for quarantine");
                    Vec::new()
                });
                match file_quarantine::quarantine_integrity_failure(&manifest_path, &related, &err)
                {
                    Ok(dest) => {
                        note_issue_with_quarantine(
                            report,
                            "artifact_manifest",
                            &manifest_path,
                            format!(
                                "forensic artifact manifest verification failed for {} and the related files were moved to {}",
                                manifest_path.display(),
                                dest.display()
                            ),
                            dest.as_path(),
                        );
                        tracing::error!(manifest = %manifest_path.display(), quarantine = %dest.display(), %err, "forensic artifact manifest verification failed and was quarantined")
                    }
                    Err(quarantine_err) => {
                        note_issue(
                            report,
                            IssueSeverity::Failure,
                            "artifact_manifest",
                            &manifest_path,
                            format!(
                                "forensic artifact manifest verification failed for {} and quarantine also failed: {err}; {quarantine_err}",
                                manifest_path.display()
                            ),
                        );
                        tracing::error!(manifest = %manifest_path.display(), %err, %quarantine_err, "forensic artifact manifest verification failed and quarantine failed")
                    }
                }
            }
        }
    }
}

fn related_artifact_paths(
    manifest_path: &Path,
    artifact_root: &Path,
) -> Result<Vec<PathBuf>, String> {
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
    let metadata = fs::metadata(&artifact_path).map_err(|e| {
        format!(
            "failed to stat manifest artifact path {}: {e}",
            artifact_path.display()
        )
    })?;
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
                Ok(canonical) => {
                    tracing::warn!(path = %canonical.display(), "skipping manifest outside artifact root after canonicalization")
                }
                Err(err) => {
                    tracing::warn!(path = %path.display(), %err, "could not canonicalize manifest path during integrity scan")
                }
            }
            if out.len() >= 512 {
                break;
            }
        }
    }
}

fn verify_artifact_manifest(manifest_path: &Path) -> Result<(), String> {
    let text =
        fs::read_to_string(manifest_path).map_err(|e| format!("failed to read manifest: {e}"))?;
    let manifest: ArtifactManifestScan =
        serde_json::from_str(&text).map_err(|e| format!("failed to parse manifest JSON: {e}"))?;
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
    let mut file =
        fs::File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
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
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn note_issue(
    report: &mut StartupIntegrityReport,
    severity: IssueSeverity,
    scope: &str,
    path: &Path,
    message: String,
) {
    match severity {
        IssueSeverity::Warning => report.warnings += 1,
        IssueSeverity::Failure => report.failures += 1,
    }
    report.issues.push(IntegrityIssue {
        severity,
        scope: scope.to_string(),
        message,
        path: Some(path.display().to_string()),
        quarantine_dir: None,
    });
}

fn note_issue_with_quarantine(
    report: &mut StartupIntegrityReport,
    scope: &str,
    path: &Path,
    message: String,
    quarantine_dir: &Path,
) {
    report.failures += 1;
    report.issues.push(IntegrityIssue {
        severity: IssueSeverity::Failure,
        scope: scope.to_string(),
        message,
        path: Some(path.display().to_string()),
        quarantine_dir: Some(quarantine_dir.display().to_string()),
    });
}

fn report_path() -> PathBuf {
    config::data_dir().join(REPORT_FILE)
}

fn load_report_at(path: &Path) -> Result<Option<StartupIntegrityReport>, String> {
    let Some(bytes) = crate::security::policy::load_json_with_integrity(path)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|e| {
        format!(
            "failed to parse startup integrity report {}: {e}",
            path.display()
        )
    })
}

fn save_report(report: &StartupIntegrityReport) -> Result<(), String> {
    save_report_at(&report_path(), report)
}

fn save_report_at(path: &Path, report: &StartupIntegrityReport) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(report)
        .map_err(|e| format!("failed to serialize startup integrity report: {e}"))?;
    crate::security::policy::save_json_with_integrity(path, &data)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
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
        assert_eq!(
            related_artifact_paths(&manifest, &root).unwrap(),
            vec![artifact.canonicalize().unwrap()]
        );
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

    #[test]
    fn startup_integrity_report_round_trips_through_protected_store() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("startup-report.json");
        let report = StartupIntegrityReport {
            created_unix: 123,
            checked: 4,
            ok: 2,
            warnings: 1,
            failures: 1,
            issues: vec![
                IntegrityIssue {
                    severity: IssueSeverity::Warning,
                    scope: "policy".into(),
                    message: "missing sidecar".into(),
                    path: Some("/tmp/vigil.json".into()),
                    quarantine_dir: None,
                },
                IntegrityIssue {
                    severity: IssueSeverity::Failure,
                    scope: "artifact_manifest".into(),
                    message: "quarantined".into(),
                    path: Some("/tmp/sample.manifest.json".into()),
                    quarantine_dir: Some("/tmp/quarantine".into()),
                },
            ],
        };
        save_report_at(&path, &report).unwrap();
        let loaded = load_report_at(&path).unwrap().unwrap();
        assert_eq!(loaded.checked, 4);
        assert_eq!(loaded.warnings, 1);
        assert_eq!(loaded.failures, 1);
        assert_eq!(loaded.issues.len(), 2);
        assert_eq!(
            loaded.issues[1].quarantine_dir.as_deref(),
            Some("/tmp/quarantine")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn operator_input_change_is_a_warning_when_sidecar_verifies() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rules.yaml");
        let registry = dir.join("operator-file-provenance.json");
        let original = "rules: []\n";
        fs::write(&file, original).unwrap();
        write_sidecar(&file, original);
        crate::security::operator_provenance::observe_operator_file_at(
            "response_rules",
            &file,
            &registry,
        )
        .unwrap();

        let changed = "rules:\n  - name: isolate\n    action: quarantine\n";
        fs::write(&file, changed).unwrap();
        write_sidecar(&file, changed);

        let mut report = StartupIntegrityReport::default();
        observe_operator_path_with_registry(&mut report, "response_rules", &file, &registry);

        assert_eq!(report.checked, 1);
        assert_eq!(report.failures, 0);
        assert_eq!(report.warnings, 1);
        assert!(report.issues[0]
            .message
            .contains("changed since the last recorded startup"));
        assert!(report.issues[0].message.contains("SHA-256 sidecar"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn operator_input_sidecar_mismatch_is_a_failure() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("blocklist.txt");
        fs::write(&file, "203.0.113.10\n").unwrap();
        write_sidecar(&file, "198.51.100.10\n");

        let mut report = StartupIntegrityReport::default();
        observe_operator_path_with_registry(
            &mut report,
            "blocklist",
            &file,
            &dir.join("operator-file-provenance.json"),
        );

        assert_eq!(report.checked, 1);
        assert_eq!(report.warnings, 0);
        assert_eq!(report.failures, 1);
        assert!(report.issues[0]
            .message
            .contains("failed SHA-256 verification"));
        let _ = fs::remove_dir_all(dir);
    }

    fn write_sidecar(path: &Path, content: &str) {
        let digest = Sha256::digest(content.as_bytes());
        fs::write(
            crate::security::integrity::sidecar_path(path),
            format!(
                "{}  {}\n",
                hex(&digest),
                path.file_name().unwrap().to_string_lossy()
            ),
        )
        .unwrap();
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-startup-integrity-test-{nanos}"))
    }
}
