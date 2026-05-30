//! Local YARA rule intake foundations.
//!
//! Phase 20 needs a safe place for operator-supplied `.yar` and `.yara` files
//! before the runtime scan engine lands. This module reuses Vigil's existing
//! integrity sidecars and provenance tracking so untrusted rules fail closed.

use crate::security::{integrity, operator_provenance};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const RULE_DIR: &str = "yara-rules";
const MAX_RULE_FILES: usize = 256;
const MAX_RULE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SCAN_DEPTH: usize = 4;
const BUNDLED_PACK_MANIFEST_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bundled_yara_pack_manifest.json"));

#[derive(Debug, Clone, Copy)]
struct EmbeddedBundledRuleFile {
    relative_path: &'static str,
    source_text: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/bundled_yara_pack_files.rs"));

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundledPackStatus {
    manifest: BundledPackManifest,
    files: Vec<BundledPackFileStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundledPackFileStatus {
    relative_path: String,
    rule_count: usize,
    category: Option<String>,
    source_reference: String,
    source_url: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct BundledPackManifest {
    schema_version: u32,
    pack_name: String,
    pack_version: String,
    generated_at: String,
    upstream_name: String,
    upstream_source_url: String,
    upstream_reference: String,
    license: String,
    files: Vec<BundledPackManifestFile>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct BundledPackManifestFile {
    relative_path: String,
    sha256: String,
    rule_count: usize,
    source_url: String,
    source_reference: String,
    category: Option<String>,
}

pub fn rule_dir() -> PathBuf {
    crate::config::data_dir().join(RULE_DIR)
}

pub fn load_verified_rules() -> Result<RuleLoadReport, String> {
    load_verified_rules_with_registry(&rule_dir(), &operator_provenance::registry_file_path())
}

pub fn run_status_cli() -> Result<(), String> {
    print_bundled_pack_status()?;
    println!();

    let report = load_verified_rules()?;
    println!("Local YARA rule directory: {}", report.root.display());
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

fn print_bundled_pack_status() -> Result<(), String> {
    let Some(pack) = load_bundled_pack_status()? else {
        println!("Bundled YARA pack: none");
        return Ok(());
    };

    println!(
        "Bundled YARA pack: {} {}",
        pack.manifest.pack_name, pack.manifest.pack_version
    );
    println!("Generated at: {}", pack.manifest.generated_at);
    println!(
        "Upstream: {} ({})",
        pack.manifest.upstream_name, pack.manifest.license
    );
    println!("Source URL: {}", pack.manifest.upstream_source_url);
    println!("Source reference: {}", pack.manifest.upstream_reference);
    println!("Bundled files: {}", pack.files.len());
    for file in &pack.files {
        let category = file.category.as_deref().unwrap_or("uncategorized");
        println!(
            "  [bundled] {} ({category}, {} rules)",
            file.relative_path, file.rule_count
        );
    }

    Ok(())
}

fn load_bundled_pack_status() -> Result<Option<BundledPackStatus>, String> {
    if EMBEDDED_BUNDLED_RULE_FILES.is_empty() {
        return Ok(None);
    }
    validate_bundled_pack(BUNDLED_PACK_MANIFEST_JSON, EMBEDDED_BUNDLED_RULE_FILES).map(Some)
}

fn validate_bundled_pack(
    manifest_json: &str,
    embedded_files: &[EmbeddedBundledRuleFile],
) -> Result<BundledPackStatus, String> {
    let manifest: BundledPackManifest = serde_json::from_str(manifest_json)
        .map_err(|e| format!("failed to parse bundled YARA pack manifest: {e}"))?;
    validate_bundled_pack_manifest(&manifest, embedded_files)
}

fn validate_bundled_pack_manifest(
    manifest: &BundledPackManifest,
    embedded_files: &[EmbeddedBundledRuleFile],
) -> Result<BundledPackStatus, String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported bundled YARA manifest schema version {}",
            manifest.schema_version
        ));
    }
    ensure_non_empty(&manifest.pack_name, "pack_name")?;
    ensure_non_empty(&manifest.pack_version, "pack_version")?;
    ensure_non_empty(&manifest.generated_at, "generated_at")?;
    ensure_non_empty(&manifest.upstream_name, "upstream_name")?;
    ensure_non_empty(&manifest.upstream_source_url, "upstream_source_url")?;
    ensure_non_empty(&manifest.upstream_reference, "upstream_reference")?;
    ensure_non_empty(&manifest.license, "license")?;
    if manifest.files.is_empty() {
        return Err("bundled YARA pack manifest must list at least one file".into());
    }

    let mut embedded_by_path = HashMap::with_capacity(embedded_files.len());
    for file in embedded_files {
        if embedded_by_path.insert(file.relative_path, file.source_text).is_some() {
            return Err(format!(
                "bundled YARA pack embeds duplicate relative path {}",
                file.relative_path
            ));
        }
    }

    let mut seen_paths = HashSet::with_capacity(manifest.files.len());
    let mut files = Vec::with_capacity(manifest.files.len());
    for file in &manifest.files {
        ensure_non_empty(&file.relative_path, "files[].relative_path")?;
        ensure_normalized_relative_path(&file.relative_path, "files[].relative_path")?;
        if !seen_paths.insert(file.relative_path.clone()) {
            return Err(format!(
                "bundled YARA pack manifest lists duplicate relative path {}",
                file.relative_path
            ));
        }
        ensure_lower_hex_sha256(&file.sha256, "files[].sha256")?;
        if file.rule_count == 0 {
            return Err(format!(
                "bundled YARA pack file {} must have a positive rule_count",
                file.relative_path
            ));
        }
        ensure_non_empty(&file.source_url, "files[].source_url")?;
        ensure_non_empty(&file.source_reference, "files[].source_reference")?;
        if let Some(category) = &file.category {
            ensure_non_empty(category, "files[].category")?;
        }

        let Some(source_text) = embedded_by_path.get(file.relative_path.as_str()) else {
            return Err(format!(
                "bundled YARA pack file {} is listed in the manifest but missing from the embedded file index",
                file.relative_path
            ));
        };
        let actual_sha = sha256_hex(source_text.as_bytes());
        if actual_sha != file.sha256 {
            return Err(format!(
                "bundled YARA pack file {} failed SHA-256 verification",
                file.relative_path
            ));
        }
        let actual_rule_count = count_rule_definitions(source_text);
        if actual_rule_count != file.rule_count {
            return Err(format!(
                "bundled YARA pack file {} advertises {} rules but contains {}",
                file.relative_path, file.rule_count, actual_rule_count
            ));
        }

        files.push(BundledPackFileStatus {
            relative_path: file.relative_path.clone(),
            rule_count: file.rule_count,
            category: file.category.clone(),
            source_reference: file.source_reference.clone(),
            source_url: file.source_url.clone(),
        });
    }

    if embedded_by_path.len() != seen_paths.len() {
        return Err(
            "bundled YARA embedded file index contains files that are missing from the manifest"
                .into(),
        );
    }

    Ok(BundledPackStatus {
        manifest: manifest.clone(),
        files,
    })
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

fn ensure_non_empty(value: &str, field_name: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field_name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_lower_hex_sha256(value: &str, field_name: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("{field_name} must be exactly 64 lowercase hex characters"));
    }
    Ok(())
}

fn ensure_normalized_relative_path(path: &str, field_name: &str) -> Result<(), String> {
    if path.contains('\\') {
        return Err(format!("{field_name} must use slash-separated relative paths: {path}"));
    }
    let candidate = Path::new(path);
    for component in candidate.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(format!(
                    "{field_name} must stay normalized and relative: {path}"
                ));
            }
        }
    }
    Ok(())
}

fn count_rule_definitions(source_text: &str) -> usize {
    source_text
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("rule ")
                || trimmed.starts_with("private rule ")
                || trimmed.starts_with("global rule ")
                || trimmed.starts_with("private global rule ")
                || trimmed.starts_with("global private rule ")
        })
        .count()
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(report.skipped >= 1);

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

    #[test]
    fn bundled_pack_validation_rejects_traversal_paths() {
        let manifest = BundledPackManifest {
            schema_version: 1,
            pack_name: "community-core".into(),
            pack_version: "2026.05.22.1".into(),
            generated_at: "2026-05-22T10:20:00Z".into(),
            upstream_name: "InQuest yara-rules".into(),
            upstream_source_url: "https://github.com/InQuest/yara-rules".into(),
            upstream_reference: "fd87530863cca77384f37ae5485707a02207d715".into(),
            license: "MIT".into(),
            files: vec![BundledPackManifestFile {
                relative_path: "../escape.rule".into(),
                sha256: sha256_hex(b"rule sample { condition: true }\n"),
                rule_count: 1,
                source_url: "https://example.invalid/rule".into(),
                source_reference: "abc123".into(),
                category: Some("research".into()),
            }],
        };

        let embedded = [EmbeddedBundledRuleFile {
            relative_path: "../escape.rule",
            source_text: "rule sample { condition: true }\n",
        }];
        let err = validate_bundled_pack_manifest(&manifest, &embedded).unwrap_err();
        assert!(err.contains("normalized and relative"));
    }

    #[test]
    fn bundled_pack_validation_rejects_hash_mismatch() {
        let manifest = BundledPackManifest {
            schema_version: 1,
            pack_name: "community-core".into(),
            pack_version: "2026.05.22.1".into(),
            generated_at: "2026-05-22T10:20:00Z".into(),
            upstream_name: "InQuest yara-rules".into(),
            upstream_source_url: "https://github.com/InQuest/yara-rules".into(),
            upstream_reference: "fd87530863cca77384f37ae5485707a02207d715".into(),
            license: "MIT".into(),
            files: vec![BundledPackManifestFile {
                relative_path: "research/sample.rule".into(),
                sha256: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                rule_count: 1,
                source_url: "https://example.invalid/rule".into(),
                source_reference: "abc123".into(),
                category: Some("research".into()),
            }],
        };

        let embedded = [EmbeddedBundledRuleFile {
            relative_path: "research/sample.rule",
            source_text: "rule sample { condition: true }\n",
        }];
        let err = validate_bundled_pack_manifest(&manifest, &embedded).unwrap_err();
        assert!(err.contains("SHA-256 verification"));
    }

    #[test]
    fn count_rule_definitions_handles_private_and_global_rules() {
        let source = r#"
private rule hidden_sample {
    condition:
        true
}

global rule visible_sample {
    condition:
        true
}
"#;
        assert_eq!(count_rule_definitions(source), 2);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-yara-rule-test-{nanos}"))
    }
}
