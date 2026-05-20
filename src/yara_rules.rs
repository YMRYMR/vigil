//! Local YARA rule intake foundations.
//!
//! Phase 20 needs a safe place for operator-supplied `.yar` and `.yara` files
//! before the runtime scan engine lands. This module reuses Vigil's existing
//! integrity sidecars and provenance tracking so untrusted rules fail closed.

use crate::security::{integrity, operator_provenance};
use std::fs;
use std::path::{Path, PathBuf};

const RULE_DIR: &str = "yara-rules";
const MAX_RULE_FILES: usize = 256;
const MAX_RULE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SCAN_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRuleFile {
    pub path: PathBuf,
    pub source_text: String,
    pub observation: operator_provenance::Observation,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleLoadReport {
    pub root: PathBuf,
    pub verified: usize,
    pub warnings: usize,
    pub failures: usize,
    pub sidecars: usize,
    pub skipped: usize,
    pub files: Vec<VerifiedRuleFile>,
    pub errors: Vec<String>,
}

pub fn rule_dir() -> PathBuf {
    crate::config::data_dir().join(RULE_DIR)
}

pub fn load_verified_rules() -> Result<RuleLoadReport, String> {
    load_verified_rules_with_registry(&rule_dir(), &operator_provenance::registry_file_path())
}

pub fn run_status_cli() -> Result<(), String> {
    let report = load_verified_rules()?;
    println!("YARA rule directory: {}", report.root.display());
    if !report.root.exists() {
        println!("No local YARA rule directory found yet.");
        return Ok(());
    }

    println!("Verified rules: {}", report.verified);
    println!("Warnings: {}", report.warnings);
    println!("Failures: {}", report.failures);
    println!("Rule sidecars: {}", report.sidecars);
    println!("Skipped non-rule files: {}", report.skipped);

    for file in &report.files {
        println!(
            "  [{}] {}",
            observation_label(&file.observation),
            file.path.display()
        );
    }
    for err in &report.errors {
        eprintln!("  [error] {err}");
    }

    if report.failures > 0 {
        return Err(format!(
            "one or more local YARA rules failed integrity intake ({})",
            report.failures
        ));
    }
    Ok(())
}

fn load_verified_rules_with_registry(
    root: &Path,
    registry_path: &Path,
) -> Result<RuleLoadReport, String> {
    let mut report = RuleLoadReport {
        root: root.to_path_buf(),
        ..RuleLoadReport::default()
    };
    if !root.exists() {
        return Ok(report);
    }
    if !root.is_dir() {
        return Err(format!(
            "YARA rule path {} exists but is not a directory",
            root.display()
        ));
    }

    let mut candidates = Vec::new();
    collect_rule_files(root, &mut candidates, 0, &mut report)?;
    candidates.sort();
    if candidates.len() > MAX_RULE_FILES {
        return Err(format!(
            "refusing to load more than {MAX_RULE_FILES} YARA rule files from {}",
            root.display()
        ));
    }

    for path in candidates {
        let metadata = fs::metadata(&path)
            .map_err(|e| format!("failed to stat YARA rule {}: {e}", path.display()))?;
        if metadata.len() > MAX_RULE_FILE_BYTES {
            report.failures += 1;
            report.errors.push(format!(
                "YARA rule {} exceeds the {} byte safety limit",
                path.display(),
                MAX_RULE_FILE_BYTES
            ));
            continue;
        }

        let (source_text, _) = match integrity::read_verified_to_string(&path, "YARA rule") {
            Ok(ok) => ok,
            Err(err) => {
                report.failures += 1;
                report.errors.push(err);
                continue;
            }
        };

        let observation = match operator_provenance::observe_operator_file_at(
            "yara_rule",
            &path,
            registry_path,
        ) {
            Ok(observation) => observation,
            Err(err) => {
                report.failures += 1;
                report.errors.push(format!(
                    "failed to record YARA rule provenance for {}: {err}",
                    path.display()
                ));
                continue;
            }
        };

        match observation {
            operator_provenance::Observation::Unchanged => {
                report.verified += 1;
            }
            operator_provenance::Observation::FirstSeen
            | operator_provenance::Observation::Changed => {
                report.verified += 1;
                report.warnings += 1;
            }
            operator_provenance::Observation::Missing
            | operator_provenance::Observation::Unreadable => {
                report.failures += 1;
                report.errors.push(format!(
                    "YARA rule {} could not be tracked as a readable operator file",
                    path.display()
                ));
                continue;
            }
        }

        report.files.push(VerifiedRuleFile {
            path,
            source_text,
            observation,
        });
    }

    Ok(report)
}

fn collect_rule_files(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    depth: usize,
    report: &mut RuleLoadReport,
) -> Result<(), String> {
    if depth > MAX_SCAN_DEPTH {
        return Ok(());
    }
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("failed to read YARA rule directory {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read YARA directory entry: {e}"))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| {
            format!(
                "failed to inspect YARA directory entry {}: {e}",
                path.display()
            )
        })?;
        if file_type.is_symlink() {
            report.skipped += 1;
            continue;
        }
        if file_type.is_dir() {
            collect_rule_files(&path, out, depth + 1, report)?;
            continue;
        }
        if !file_type.is_file() {
            report.skipped += 1;
            continue;
        }
        if is_rule_sidecar_file(&path) {
            report.sidecars += 1;
            continue;
        }
        if is_rule_file(&path) {
            out.push(path);
        } else {
            report.skipped += 1;
        }
    }
    Ok(())
}

fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yar") | Some("yara")
    )
}

fn is_rule_sidecar_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("sha256")
    ) && matches!(
        path.file_stem()
            .map(Path::new)
            .and_then(|stem| stem.extension())
            .and_then(|ext| ext.to_str()),
        Some("yar") | Some("yara")
    )
}

fn observation_label(observation: &operator_provenance::Observation) -> &'static str {
    match observation {
        operator_provenance::Observation::Unchanged => "verified",
        operator_provenance::Observation::FirstSeen => "new",
        operator_provenance::Observation::Changed => "changed",
        operator_provenance::Observation::Missing => "missing",
        operator_provenance::Observation::Unreadable => "unreadable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn empty_rule_directory_reports_clean_status() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let registry = dir.join("operator-file-provenance.json");

        let report = load_verified_rules_with_registry(&dir, &registry).unwrap();
        assert_eq!(report.verified, 0);
        assert_eq!(report.failures, 0);
        assert_eq!(report.sidecars, 0);
        assert!(report.files.is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verified_rule_file_loads_with_sidecar() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let registry = dir.join("operator-file-provenance.json");
        let path = dir.join("sample.yar");
        let body = "rule sample { condition: true }\n";
        fs::write(&path, body).unwrap();
        fs::write(
            integrity::sidecar_path(&path),
            format!("{}  sample.yar\n", sha256_hex(body.as_bytes())),
        )
        .unwrap();

        let report = load_verified_rules_with_registry(&dir, &registry).unwrap();
        assert_eq!(report.verified, 1);
        assert_eq!(report.warnings, 1);
        assert_eq!(report.failures, 0);
        assert_eq!(report.sidecars, 1);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.files[0].source_text, body);

        let report = load_verified_rules_with_registry(&dir, &registry).unwrap();
        assert_eq!(report.verified, 1);
        assert_eq!(report.warnings, 0);
        assert_eq!(report.failures, 0);
        assert_eq!(report.sidecars, 1);
        assert_eq!(report.skipped, 0);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn mismatched_sidecar_fails_closed() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let registry = dir.join("operator-file-provenance.json");
        let path = dir.join("broken.yar");
        fs::write(&path, "rule broken { condition: true }\n").unwrap();
        fs::write(
            integrity::sidecar_path(&path),
            "0000000000000000000000000000000000000000000000000000000000000000  broken.yar\n",
        )
        .unwrap();

        let report = load_verified_rules_with_registry(&dir, &registry).unwrap();
        assert_eq!(report.verified, 0);
        assert_eq!(report.failures, 1);
        assert_eq!(report.sidecars, 1);
        assert_eq!(report.files.len(), 0);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn non_rule_files_are_skipped() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let registry = dir.join("operator-file-provenance.json");
        fs::write(dir.join("notes.txt"), "ignore\n").unwrap();

        let report = load_verified_rules_with_registry(&dir, &registry).unwrap();
        assert_eq!(report.verified, 0);
        assert_eq!(report.sidecars, 0);
        assert_eq!(report.skipped, 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn orphaned_rule_sidecars_are_not_counted_as_skipped_files() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let registry = dir.join("operator-file-provenance.json");
        fs::write(dir.join("orphan.yar.sha256"), "deadbeef\n").unwrap();

        let report = load_verified_rules_with_registry(&dir, &registry).unwrap();
        assert_eq!(report.verified, 0);
        assert_eq!(report.failures, 0);
        assert_eq!(report.sidecars, 1);
        assert_eq!(report.skipped, 0);

        let _ = fs::remove_dir_all(dir);
    }

    fn sha256_hex(data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-yara-rule-test-{nanos}"))
    }
}
