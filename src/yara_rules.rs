//! Local YARA rule intake foundations.
//!
//! Phase 20 needs a safe place for operator-supplied `.yar` and `.yara` files
//! before the runtime scan engine lands. This module reuses Vigil's existing
//! integrity sidecars and provenance tracking so untrusted rules fail closed.

use crate::security::{integrity, operator_provenance};
use crate::storage::db::StorageDb;
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const RULE_DIR: &str = "yara-rules";
const MAX_RULE_FILES: usize = 256;
const MAX_RULE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SCAN_DEPTH: usize = 4;
const PACK_MANIFEST_SCHEMA_VERSION: u32 = 1;
const LOCAL_SOURCE_KEY: &str = "operator-local";
const LOCAL_SOURCE_KIND: &str = "operator_local";
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
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub source_text: String,
    pub observation: operator_provenance::Observation,
    pub parsed_rules: Vec<ParsedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRule {
    pub rule_name: String,
    pub namespace: String,
    pub category: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub tags: Vec<String>,
    pub strings_count: usize,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleLoadReport {
    pub root: PathBuf,
    pub verified: usize,
    pub warnings: usize,
    pub failures: usize,
    pub sidecars: usize,
    pub skipped: usize,
    pub cataloged_rules: usize,
    pub files: Vec<VerifiedRuleFile>,
    pub errors: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PersistSummary {
    mirrored_files: usize,
    mirrored_rules: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackManifestSummary {
    manifest: BundledPackManifest,
    total_rules: usize,
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
    let persist = persist_rule_catalog(&report)?;
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
    println!("Cataloged rules: {}", report.cataloged_rules);
    println!(
        "Mirrored local YARA catalog into state DB: {} files, {} rules",
        persist.mirrored_files, persist.mirrored_rules
    );

    for file in &report.files {
        println!(
            "  [{}] {} ({} rules)",
            observation_label(&file.observation),
            file.path.display(),
            file.parsed_rules.len()
        );
        for rule in &file.parsed_rules {
            println!("      - {}", rule.rule_name);
        }
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

pub fn run_pack_manifest_cli(path: &Path) -> Result<(), String> {
    let summary = validate_pack_manifest_path(path)?;
    println!("YARA pack manifest: {}", path.display());
    println!("Schema version: {}", summary.manifest.schema_version);
    println!("Pack name: {}", summary.manifest.pack_name);
    println!("Pack version: {}", summary.manifest.pack_version);
    println!("Generated at: {}", summary.manifest.generated_at);
    println!("Upstream name: {}", summary.manifest.upstream_name);
    println!("Upstream source: {}", summary.manifest.upstream_source_url);
    println!(
        "Upstream reference: {}",
        summary.manifest.upstream_reference
    );
    println!("License: {}", summary.manifest.license);
    println!("Files: {}", summary.manifest.files.len());
    println!("Declared rules: {}", summary.total_rules);

    for file in &summary.manifest.files {
        match file.category.as_deref() {
            Some(category) => println!(
                "  - {} ({category}, {} rules)",
                file.relative_path, file.rule_count
            ),
            None => println!("  - {} ({} rules)", file.relative_path, file.rule_count),
        }
    }

    Ok(())
}

fn persist_rule_catalog(report: &RuleLoadReport) -> Result<PersistSummary, String> {
    let db = StorageDb::global()?;
    ensure_catalog_tables(&db)?;
    db.begin()?;
    match replace_catalog_rows(&db, report) {
        Ok(summary) => {
            db.commit()?;
            db.checkpoint()?;
            Ok(summary)
        }
        Err(err) => {
            let _ = db.rollback();
            Err(err)
        }
    }
}

fn ensure_catalog_tables(db: &StorageDb) -> Result<(), String> {
    let conn = db.conn()?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS yara_source (
            source_key    TEXT PRIMARY KEY NOT NULL,
            source_kind   TEXT NOT NULL,
            source_url    TEXT NOT NULL DEFAULT '',
            fetched_unix  INTEGER NOT NULL DEFAULT 0,
            expires_unix  INTEGER NOT NULL DEFAULT 0,
            status        TEXT NOT NULL DEFAULT 'ok',
            last_error    TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS yara_rule_file (
            file_key           TEXT PRIMARY KEY NOT NULL,
            source_key         TEXT NOT NULL REFERENCES yara_source(source_key),
            path_or_relative_path TEXT NOT NULL DEFAULT '',
            sha256             TEXT NOT NULL DEFAULT '',
            size_bytes         INTEGER NOT NULL DEFAULT 0,
            rule_count         INTEGER NOT NULL DEFAULT 0,
            enabled            INTEGER NOT NULL DEFAULT 1,
            observation        TEXT NOT NULL DEFAULT '',
            payload_json       TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS yara_rule (
            rule_key        TEXT PRIMARY KEY NOT NULL,
            file_key        TEXT NOT NULL REFERENCES yara_rule_file(file_key),
            rule_name       TEXT NOT NULL,
            namespace       TEXT NOT NULL DEFAULT '',
            category        TEXT NOT NULL DEFAULT '',
            author          TEXT NOT NULL DEFAULT '',
            description     TEXT NOT NULL DEFAULT '',
            reference       TEXT NOT NULL DEFAULT '',
            tags_json       TEXT NOT NULL DEFAULT '[]',
            strings_count   INTEGER NOT NULL DEFAULT 0,
            payload_json    TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_yara_rule_file_source
            ON yara_rule_file(source_key);
        CREATE INDEX IF NOT EXISTS idx_yara_rule_file_sha256
            ON yara_rule_file(sha256);
        CREATE INDEX IF NOT EXISTS idx_yara_rule_source_name
            ON yara_rule(rule_name);
        CREATE INDEX IF NOT EXISTS idx_yara_rule_file_key
            ON yara_rule(file_key);
        ",
    )
    .map_err(|e| format!("bootstrap YARA catalog tables: {e}"))?;
    Ok(())
}

fn replace_catalog_rows(db: &StorageDb, report: &RuleLoadReport) -> Result<PersistSummary, String> {
    let conn = db.conn()?;
    let fetched_unix = i64::try_from(unix_now()).unwrap_or(i64::MAX);
    conn.execute(
        "INSERT INTO yara_source
         (source_key, source_kind, source_url, fetched_unix, expires_unix, status, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(source_key) DO UPDATE SET
         source_kind = excluded.source_kind,
         source_url = excluded.source_url,
         fetched_unix = excluded.fetched_unix,
         expires_unix = excluded.expires_unix,
         status = excluded.status,
         last_error = excluded.last_error",
        params![
            LOCAL_SOURCE_KEY,
            LOCAL_SOURCE_KIND,
            "",
            fetched_unix,
            0i64,
            if report.failures > 0 { "error" } else { "ok" },
            report.errors.join(" | "),
        ],
    )
    .map_err(|e| format!("upsert YARA source: {e}"))?;

    conn.execute(
        "DELETE FROM yara_rule
         WHERE file_key IN (
             SELECT file_key FROM yara_rule_file WHERE source_key = ?1
         )",
        [LOCAL_SOURCE_KEY],
    )
    .map_err(|e| format!("clear YARA rules: {e}"))?;
    conn.execute(
        "DELETE FROM yara_rule_file WHERE source_key = ?1",
        [LOCAL_SOURCE_KEY],
    )
    .map_err(|e| format!("clear YARA rule files: {e}"))?;

    let mut file_stmt = conn
        .prepare(
            "INSERT INTO yara_rule_file
             (file_key, source_key, path_or_relative_path, sha256, size_bytes,
              rule_count, enabled, observation, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .map_err(|e| format!("prepare YARA file insert: {e}"))?;
    let mut rule_stmt = conn
        .prepare(
            "INSERT INTO yara_rule
             (rule_key, file_key, rule_name, namespace, category, author,
              description, reference, tags_json, strings_count, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .map_err(|e| format!("prepare YARA rule insert: {e}"))?;

    let mut mirrored_rules = 0usize;
    for file in &report.files {
        let file_key = stable_key("yara_file", &file.relative_path);
        let file_payload = json!({
            "relative_path": file.relative_path,
            "absolute_path": file.path.display().to_string(),
            "sha256": file.sha256,
            "size_bytes": file.size_bytes,
            "observation": observation_label(&file.observation),
            "rule_names": file
                .parsed_rules
                .iter()
                .map(|rule| rule.rule_name.clone())
                .collect::<Vec<_>>(),
        });
        let size_bytes = i64::try_from(file.size_bytes).unwrap_or(i64::MAX);
        let rule_count = i64::try_from(file.parsed_rules.len()).unwrap_or(i64::MAX);
        file_stmt
            .execute(params![
                file_key,
                LOCAL_SOURCE_KEY,
                file.relative_path,
                file.sha256,
                size_bytes,
                rule_count,
                1i64,
                observation_label(&file.observation),
                file_payload.to_string(),
            ])
            .map_err(|e| format!("insert YARA rule file {}: {e}", file.relative_path))?;

        for rule in &file.parsed_rules {
            let rule_key = stable_key(
                "yara_rule",
                &format!("{}::{}", file.relative_path, rule.rule_name),
            );
            let payload = json!({
                "metadata": rule.metadata,
                "tags": rule.tags,
            });
            let strings_count = i64::try_from(rule.strings_count).unwrap_or(i64::MAX);
            rule_stmt
                .execute(params![
                    rule_key,
                    file_key,
                    rule.rule_name,
                    rule.namespace,
                    rule.category.clone().unwrap_or_default(),
                    rule.author.clone().unwrap_or_default(),
                    rule.description.clone().unwrap_or_default(),
                    rule.reference.clone().unwrap_or_default(),
                    serde_json::to_string(&rule.tags).unwrap_or_else(|_| "[]".to_string()),
                    strings_count,
                    payload.to_string(),
                ])
                .map_err(|e| format!("insert YARA rule {}: {e}", rule.rule_name))?;
            mirrored_rules += 1;
        }
    }

    Ok(PersistSummary {
        mirrored_files: report.files.len(),
        mirrored_rules,
    })
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

fn validate_pack_manifest_path(path: &Path) -> Result<PackManifestSummary, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read YARA pack manifest {}: {e}", path.display()))?;
    validate_pack_manifest_json(&content)
}

fn validate_pack_manifest_json(content: &str) -> Result<PackManifestSummary, String> {
    let manifest: BundledPackManifest = serde_json::from_str(content)
        .map_err(|e| format!("invalid YARA pack manifest JSON: {e}"))?;
    validate_pack_manifest_document(&manifest)
}

fn validate_pack_manifest_document(
    manifest: &BundledPackManifest,
) -> Result<PackManifestSummary, String> {
    if manifest.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "unsupported YARA pack manifest schema version {}; expected {}",
            manifest.schema_version, PACK_MANIFEST_SCHEMA_VERSION
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
        return Err("YARA pack manifest must include at least one file entry".into());
    }

    let mut seen_paths = HashSet::with_capacity(manifest.files.len());
    let mut total_rules = 0usize;
    for (idx, file) in manifest.files.iter().enumerate() {
        validate_pack_manifest_file(idx, file)?;
        if !seen_paths.insert(file.relative_path.clone()) {
            return Err(format!(
                "YARA pack manifest files[{idx}] reuses duplicate relative_path {}",
                file.relative_path
            ));
        }
        total_rules = total_rules.saturating_add(file.rule_count);
    }

    Ok(PackManifestSummary {
        manifest: manifest.clone(),
        total_rules,
    })
}

fn validate_pack_manifest_file(idx: usize, file: &BundledPackManifestFile) -> Result<(), String> {
    ensure_non_empty(&file.relative_path, &format!("files[{idx}].relative_path"))?;
    ensure_normalized_relative_path(&file.relative_path, &format!("files[{idx}].relative_path"))?;
    ensure_lower_hex_sha256(&file.sha256, &format!("files[{idx}].sha256"))?;
    if file.rule_count == 0 {
        return Err(format!("files[{idx}].rule_count must be greater than zero"));
    }
    ensure_non_empty(&file.source_url, &format!("files[{idx}].source_url"))?;
    ensure_non_empty(
        &file.source_reference,
        &format!("files[{idx}].source_reference"),
    )?;
    if let Some(category) = &file.category {
        ensure_non_empty(category, &format!("files[{idx}].category"))?;
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
    validate_pack_manifest_document(manifest)?;

    let mut embedded_by_path = HashMap::with_capacity(embedded_files.len());
    for file in embedded_files {
        if embedded_by_path
            .insert(file.relative_path, file.source_text)
            .is_some()
        {
            return Err(format!(
                "bundled YARA pack embeds duplicate relative path {}",
                file.relative_path
            ));
        }
    }

    let mut files = Vec::with_capacity(manifest.files.len());
    for file in &manifest.files {
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

    if embedded_by_path.len() != manifest.files.len() {
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

        let relative_path = relative_rule_path(root, &path)?;
        let parsed_rules = parse_rule_definitions(&source_text, &relative_path);
        report.cataloged_rules += parsed_rules.len();
        report.files.push(VerifiedRuleFile {
            path,
            relative_path,
            sha256: sha256_hex(source_text.as_bytes()),
            size_bytes: metadata.len(),
            source_text,
            observation,
            parsed_rules,
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

fn parse_rule_definitions(source_text: &str, relative_path: &str) -> Vec<ParsedRule> {
    let namespace = Path::new(relative_path)
        .parent()
        .map(|parent| parent.to_string_lossy().replace('\\', "/"))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "default".to_string());

    let mut rules = Vec::new();
    let mut current_header = String::new();
    let mut current_body = Vec::new();
    let mut brace_depth = 0i32;
    let mut inside_rule = false;

    for line in source_text.lines() {
        if !inside_rule {
            if looks_like_rule_start(line) {
                inside_rule = true;
                current_header = line.trim().to_string();
                brace_depth = line.chars().filter(|ch| *ch == '{').count() as i32
                    - line.chars().filter(|ch| *ch == '}').count() as i32;
                current_body.clear();
                if line.contains('{') && brace_depth <= 0 {
                    if let Some(rule) =
                        parse_rule_from_header_and_body(&current_header, &current_body, &namespace)
                    {
                        rules.push(rule);
                    }
                    current_header.clear();
                    inside_rule = false;
                }
            }
            continue;
        }

        brace_depth += line.chars().filter(|ch| *ch == '{').count() as i32;
        brace_depth -= line.chars().filter(|ch| *ch == '}').count() as i32;
        current_body.push(line.to_string());
        if brace_depth <= 0 {
            if let Some(rule) =
                parse_rule_from_header_and_body(&current_header, &current_body, &namespace)
            {
                rules.push(rule);
            }
            current_header.clear();
            current_body.clear();
            inside_rule = false;
        }
    }

    rules
}

fn parse_rule_from_header_and_body(
    header: &str,
    body: &[String],
    namespace: &str,
) -> Option<ParsedRule> {
    let header_without_brace = header.split('{').next()?.trim();
    let header_tokens: Vec<&str> = header_without_brace.split_whitespace().collect();
    let rule_index = header_tokens.iter().position(|token| *token == "rule")?;
    let rule_name = header_tokens.get(rule_index + 1)?.trim().to_string();
    if rule_name.is_empty() {
        return None;
    }

    let tags = header_without_brace
        .split(':')
        .nth(1)
        .map(|tail| {
            tail.split_whitespace()
                .map(|tag| tag.trim_matches(',').to_string())
                .filter(|tag| !tag.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut metadata_lines = Vec::new();
    let mut strings_count = 0usize;
    let mut in_meta = false;
    let mut in_strings = false;

    for line in body {
        let trimmed = line.trim();
        if trimmed == "meta:" {
            in_meta = true;
            in_strings = false;
            continue;
        }
        if trimmed == "strings:" {
            in_meta = false;
            in_strings = true;
            continue;
        }
        if trimmed == "condition:" {
            in_meta = false;
            in_strings = false;
            continue;
        }
        if in_meta {
            metadata_lines.push(trimmed.to_string());
        }
        if in_strings && trimmed.starts_with('$') {
            strings_count += 1;
        }
    }

    let metadata = parse_meta_section(&metadata_lines);
    let category = metadata.get("category").cloned();
    let author = metadata.get("author").cloned();
    let description = metadata
        .get("description")
        .cloned()
        .or_else(|| metadata.get("desc").cloned());
    let reference = metadata
        .get("reference")
        .cloned()
        .or_else(|| metadata.get("ref").cloned());

    Some(ParsedRule {
        rule_name,
        namespace: namespace.to_string(),
        category,
        author,
        description,
        reference,
        tags,
        strings_count,
        metadata,
    })
}

fn parse_meta_section(lines: &[String]) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        let Some((key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = normalize_meta_value(raw_value);
        if !key.is_empty() && !value.is_empty() {
            metadata.insert(key, value);
        }
    }
    metadata
}

fn normalize_meta_value(raw_value: &str) -> String {
    let trimmed = raw_value.trim().trim_end_matches(',').trim();
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(trimmed);
    unquoted.trim().to_string()
}

fn looks_like_rule_start(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("rule ")
        || trimmed.starts_with("private rule ")
        || trimmed.starts_with("global rule ")
        || trimmed.starts_with("private global rule ")
        || trimmed.starts_with("global private rule ")
}

fn relative_rule_path(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|e| format!("failed to normalize YARA rule path {}: {e}", path.display()))?;
    let display = relative.to_string_lossy().replace('\\', "/");
    ensure_normalized_relative_path(&display, "local_rule.relative_path")?;
    Ok(display)
}

fn stable_key(kind: &str, value: &str) -> String {
    sha256_hex(format!("{kind}:{value}").as_bytes())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "{field_name} must be exactly 64 lowercase hex characters"
        ));
    }
    Ok(())
}

fn ensure_normalized_relative_path(path: &str, field_name: &str) -> Result<(), String> {
    if path.contains('\\') {
        return Err(format!(
            "{field_name} must use slash-separated relative paths: {path}"
        ));
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
        .filter(|line| looks_like_rule_start(line))
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

    #[test]
    fn empty_rule_directory_reports_clean_status() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let registry = dir.join("operator-file-provenance.json");

        let report = load_verified_rules_with_registry(&dir, &registry).unwrap();
        assert_eq!(report.verified, 0);
        assert_eq!(report.failures, 0);
        assert_eq!(report.sidecars, 0);
        assert_eq!(report.cataloged_rules, 0);
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
        assert_eq!(report.cataloged_rules, 1);
        assert_eq!(report.files[0].source_text, body);
        assert_eq!(report.files[0].parsed_rules.len(), 1);

        let report = load_verified_rules_with_registry(&dir, &registry).unwrap();
        assert_eq!(report.verified, 1);
        assert_eq!(report.warnings, 0);
        assert_eq!(report.failures, 0);
        assert_eq!(report.sidecars, 1);
        assert_eq!(report.cataloged_rules, 1);
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
        assert_eq!(report.cataloged_rules, 0);
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
        assert_eq!(report.cataloged_rules, 0);

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
        assert_eq!(report.cataloged_rules, 0);

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

    #[test]
    fn parser_extracts_rule_metadata_and_tags() {
        let source = r#"
private rule suspicious_sample : malware c2 {
    meta:
        author = "analyst"
        description = "suspicious sample"
        reference = "https://example.invalid/rule"
        category = "research"
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        any of them
}
"#;
        let rules = parse_rule_definitions(source, "research/sample.yar");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.rule_name, "suspicious_sample");
        assert_eq!(rule.namespace, "research");
        assert_eq!(rule.category.as_deref(), Some("research"));
        assert_eq!(rule.author.as_deref(), Some("analyst"));
        assert_eq!(rule.description.as_deref(), Some("suspicious sample"));
        assert_eq!(
            rule.reference.as_deref(),
            Some("https://example.invalid/rule")
        );
        assert_eq!(rule.tags, vec!["malware".to_string(), "c2".to_string()]);
        assert_eq!(rule.strings_count, 2);
    }

    #[test]
    fn parser_extracts_split_header_rule_metadata_and_tags() {
        let source = r#"
rule split_header_sample : malware c2
{
    meta:
        author = "analyst"
        description = "split header sample"
        category = "research"
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        any of them
}
"#;
        let rules = parse_rule_definitions(source, "research/split.yar");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.rule_name, "split_header_sample");
        assert_eq!(rule.namespace, "research");
        assert_eq!(rule.category.as_deref(), Some("research"));
        assert_eq!(rule.author.as_deref(), Some("analyst"));
        assert_eq!(rule.description.as_deref(), Some("split header sample"));
        assert_eq!(rule.tags, vec!["malware".to_string(), "c2".to_string()]);
        assert_eq!(rule.strings_count, 2);
    }

    #[test]
    fn example_pack_manifest_validates() {
        let summary =
            validate_pack_manifest_json(include_str!("../docs/YARA-PACK-MANIFEST.example.json"))
                .unwrap();
        assert_eq!(summary.manifest.pack_name, "community-core");
        assert_eq!(summary.manifest.files.len(), 2);
        assert_eq!(summary.total_rules, 16);
    }

    #[test]
    fn pack_manifest_rejects_duplicate_paths() {
        let manifest = format!(
            r#"{{
  "schema_version": 1,
  "pack_name": "community-core",
  "pack_version": "2026.05.22.1",
  "generated_at": "2026-05-22T00:00:00Z",
  "upstream_name": "Example",
  "upstream_source_url": "https://example.invalid/source",
  "upstream_reference": "refs/tags/test",
  "license": "Apache-2.0",
  "files": [
    {{
      "relative_path": "malware/core.yar",
      "sha256": "{sha}",
      "rule_count": 1,
      "source_url": "https://example.invalid/source/core.yar",
      "source_reference": "refs/tags/test"
    }},
    {{
      "relative_path": "malware/core.yar",
      "sha256": "{sha}",
      "rule_count": 2,
      "source_url": "https://example.invalid/source/core-v2.yar",
      "source_reference": "refs/tags/test"
    }}
  ]
}}"#,
            sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        let err = validate_pack_manifest_json(&manifest).unwrap_err();
        assert!(err.contains("duplicate relative_path"));
    }

    #[test]
    fn pack_manifest_rejects_traversal_path() {
        let manifest = format!(
            r#"{{
  "schema_version": 1,
  "pack_name": "community-core",
  "pack_version": "2026.05.22.1",
  "generated_at": "2026-05-22T00:00:00Z",
  "upstream_name": "Example",
  "upstream_source_url": "https://example.invalid/source",
  "upstream_reference": "refs/tags/test",
  "license": "Apache-2.0",
  "files": [
    {{
      "relative_path": "../escape.yar",
      "sha256": "{sha}",
      "rule_count": 1,
      "source_url": "https://example.invalid/source/escape.yar",
      "source_reference": "refs/tags/test"
    }}
  ]
}}"#,
            sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        let err = validate_pack_manifest_json(&manifest).unwrap_err();
        assert!(err.contains("normalized and relative"));
    }

    #[test]
    fn pack_manifest_rejects_uppercase_sha() {
        let manifest = r#"{
  "schema_version": 1,
  "pack_name": "community-core",
  "pack_version": "2026.05.22.1",
  "generated_at": "2026-05-22T00:00:00Z",
  "upstream_name": "Example",
  "upstream_source_url": "https://example.invalid/source",
  "upstream_reference": "refs/tags/test",
  "license": "Apache-2.0",
  "files": [
    {
      "relative_path": "malware/core.yar",
      "sha256": "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      "rule_count": 1,
      "source_url": "https://example.invalid/source/core.yar",
      "source_reference": "refs/tags/test"
    }
  ]
}"#;
        let err = validate_pack_manifest_json(manifest).unwrap_err();
        assert!(err.contains("64 lowercase hex characters"));
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-yara-rule-test-{nanos}"))
    }
}
