//! Optional forensic artifact capture.
//!
//! Current Phase 11 implementation focuses on process memory dumps for
//! high-confidence alerts. The feature is opt-in, Windows-only, audited, and
//! rate-limited per PID so a noisy process does not flood disk with dumps.

use crate::{artifact_provenance, audit, config::Config, storage::db::StorageDb, types::ConnInfo};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use yara_x::{Compiler, Scanner, SourceCode};

static LAST_DUMP_AT: OnceLock<Mutex<HashMap<u32, u64>>> = OnceLock::new();
static LAST_GLOBAL_DUMP_AT: OnceLock<Mutex<u64>> = OnceLock::new();
const GLOBAL_COOLDOWN_SECS: u64 = 30;
const MAX_PROCESS_DUMP_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MEMORY_MATCHED_RULES_RECORDED: usize = 8;
const PACK_MANIFEST_SCHEMA_VERSION: u32 = 1;
const BUNDLED_PACK_MANIFEST_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bundled_yara_pack_manifest.json"));

#[derive(Debug, Clone, Copy)]
struct EmbeddedBundledRuleFile {
    relative_path: &'static str,
    source_text: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/bundled_yara_pack_files.rs"));

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
struct BundledPackManifestFile {
    relative_path: String,
    sha256: String,
    rule_count: usize,
    source_url: String,
    source_reference: String,
    category: Option<String>,
}

#[derive(Debug, Clone)]
struct MemoryDumpScanTarget {
    path: PathBuf,
    size_bytes: u64,
    modified_unix_nanos: u64,
    created_unix_nanos: u64,
}

#[derive(Debug, Clone)]
struct MemoryDumpMatchedRule {
    identifier: String,
    attack_tags: Vec<String>,
}

#[derive(Debug, Clone)]
struct MemoryDumpScanVerdict {
    matched_rules: Vec<MemoryDumpMatchedRule>,
    ruleset_digest: String,
    scanned_unix: u64,
    target_sha256: String,
}

#[derive(Debug, Clone)]
struct MemoryRuntimeRuleSource {
    namespace: String,
    relative_path: String,
    source_text: String,
}

struct MemoryCompiledRuleSet {
    digest: String,
    rules: yara_x::Rules,
}

pub fn maybe_capture_process_dump(info: &ConnInfo, cfg: &Config) {
    if !cfg.process_dump_on_alert || info.score < cfg.process_dump_min_score || info.pid == 0 {
        return;
    }
    if info.proc_name.starts_with('<') && info.proc_name.ends_with('>') {
        return;
    }

    let now = unix_now();
    let gate = LAST_DUMP_AT.get_or_init(|| Mutex::new(HashMap::new()));
    let mut last = match gate.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    if let Some(previous) = last.get(&info.pid).copied() {
        if now.saturating_sub(previous) < cfg.process_dump_cooldown_secs {
            return;
        }
    }

    // Global cooldown: only one dump per GLOBAL_COOLDOWN_SECS across all PIDs.
    let global_gate = LAST_GLOBAL_DUMP_AT.get_or_init(|| Mutex::new(0));
    if let Ok(global_last) = global_gate.lock() {
        if now.saturating_sub(*global_last) < GLOBAL_COOLDOWN_SECS {
            return;
        }
    }

    match platform::capture_process_dump(info, cfg) {
        Ok(path) => {
            last.insert(info.pid, now);
            if let Ok(mut global_last) = global_gate.lock() {
                *global_last = now;
            }
            let manifest = match artifact_provenance::write_manifest(
                &path,
                "process_dump",
                info,
                json!({
                    "dump_format": "full",
                    "capture_method": "rundll32 comsvcs MiniDump",
                }),
            ) {
                Ok(manifest) => Some(manifest),
                Err(err) => {
                    audit::record(
                        "artifact_manifest",
                        "error",
                        json!({
                            "artifact_kind": "process_dump",
                            "artifact_path": path.display().to_string(),
                            "pid": info.pid,
                            "proc_name": info.proc_name,
                            "error": err,
                        }),
                    );
                    None
                }
            };
            audit::record(
                "process_dump_on_alert",
                "success",
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "path": path.display().to_string(),
                    "manifest": manifest.as_ref().map(|p| p.display().to_string()),
                    "score": info.score,
                }),
            );
            tracing::warn!(pid = info.pid, proc = %info.proc_name, dump = %path.display(), manifest = ?manifest.as_ref().map(|p| p.display().to_string()), "captured process dump on alert");
            enqueue_process_dump_yara_scan(path, info.clone(), manifest);
        }
        Err(err) => {
            audit::record(
                "process_dump_on_alert",
                "error",
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "score": info.score,
                    "error": err,
                }),
            );
            tracing::warn!(pid = info.pid, proc = %info.proc_name, %err, "failed to capture process dump on alert");
        }
    }
}

fn enqueue_process_dump_yara_scan(path: PathBuf, info: ConnInfo, manifest: Option<PathBuf>) {
    if let Err(err) = std::thread::Builder::new()
        .name("vigil-yara-dump-scan".into())
        .spawn(move || run_process_dump_yara_scan(path, info, manifest))
    {
        audit::record(
            "process_dump_yara_scan",
            "error",
            json!({ "error": format!("failed to spawn process dump YARA scan worker: {err}") }),
        );
    }
}

fn run_process_dump_yara_scan(path: PathBuf, info: ConnInfo, manifest: Option<PathBuf>) {
    let target = match memory_dump_scan_target(&path) {
        Ok(target) => target,
        Err(err) => {
            audit::record(
                "process_dump_yara_scan",
                "skipped",
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "path": path.display().to_string(),
                    "manifest": manifest.as_ref().map(|p| p.display().to_string()),
                    "error": err,
                }),
            );
            tracing::warn!(pid = info.pid, proc = %info.proc_name, dump = %path.display(), "skipped process dump YARA scan: {err}");
            return;
        }
    };

    let compiled = match compile_memory_runtime_rules() {
        Ok(Some(compiled)) => compiled,
        Ok(None) => {
            audit::record(
                "process_dump_yara_scan",
                "skipped",
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "path": target.path.display().to_string(),
                    "manifest": manifest.as_ref().map(|p| p.display().to_string()),
                    "error": "no compiled YARA rules available",
                }),
            );
            return;
        }
        Err(err) => {
            audit::record(
                "process_dump_yara_scan",
                "error",
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "path": target.path.display().to_string(),
                    "manifest": manifest.as_ref().map(|p| p.display().to_string()),
                    "error": err,
                }),
            );
            tracing::warn!(pid = info.pid, proc = %info.proc_name, dump = %target.path.display(), "failed to compile YARA rules for process dump scan: {err}");
            return;
        }
    };

    match scan_memory_dump_target(&compiled, &target) {
        Ok(verdict) => {
            if let Err(err) =
                persist_memory_dump_scan_result(&target, &verdict, &info, manifest.as_deref())
            {
                audit::record(
                    "process_dump_yara_scan",
                    "error",
                    json!({
                        "pid": info.pid,
                        "proc_name": info.proc_name,
                        "path": target.path.display().to_string(),
                        "manifest": manifest.as_ref().map(|p| p.display().to_string()),
                        "ruleset_digest": verdict.ruleset_digest,
                        "error": err,
                    }),
                );
                return;
            }

            let status = if verdict.matched_rules.is_empty() {
                "clean"
            } else {
                "matched"
            };
            audit::record(
                "process_dump_yara_scan",
                status,
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "path": target.path.display().to_string(),
                    "manifest": manifest.as_ref().map(|p| p.display().to_string()),
                    "ruleset_digest": verdict.ruleset_digest,
                    "target_sha256": verdict.target_sha256,
                    "matched_rules": verdict.matched_rules.iter().map(|rule| json!({
                        "identifier": rule.identifier,
                        "attack_tags": rule.attack_tags,
                    })).collect::<Vec<_>>(),
                }),
            );
            if !verdict.matched_rules.is_empty() {
                tracing::warn!(pid = info.pid, proc = %info.proc_name, dump = %target.path.display(), matches = verdict.matched_rules.len(), "process dump YARA scan matched rules");
            }
        }
        Err(err) => {
            audit::record(
                "process_dump_yara_scan",
                "error",
                json!({
                    "pid": info.pid,
                    "proc_name": info.proc_name,
                    "path": target.path.display().to_string(),
                    "manifest": manifest.as_ref().map(|p| p.display().to_string()),
                    "error": err,
                }),
            );
            tracing::warn!(pid = info.pid, proc = %info.proc_name, dump = %target.path.display(), "process dump YARA scan failed: {err}");
        }
    }
}

fn compile_memory_runtime_rules() -> Result<Option<MemoryCompiledRuleSet>, String> {
    let mut compiler = Compiler::new();
    let mut hasher = Sha256::new();
    let mut compiled_sources = 0usize;

    for source in memory_runtime_rule_sources()? {
        compiler.new_namespace(&source.namespace);
        let source_code =
            SourceCode::from(source.source_text.as_str()).with_origin(&source.relative_path);
        match compiler.add_source(source_code) {
            Ok(_) => {
                hasher.update(source.relative_path.as_bytes());
                hasher.update(b"\n");
                hasher.update(source.source_text.as_bytes());
                hasher.update(b"\n");
                compiled_sources += 1;
            }
            Err(err) => {
                tracing::warn!(
                    origin = %source.relative_path,
                    error = %err,
                    "skipping YARA source that failed compilation for process dump scan"
                );
            }
        }
    }

    if compiled_sources == 0 {
        return Ok(None);
    }

    let digest = hasher.finalize();
    Ok(Some(MemoryCompiledRuleSet {
        digest: hex_encode(digest.as_ref()),
        rules: compiler.build(),
    }))
}

fn memory_runtime_rule_sources() -> Result<Vec<MemoryRuntimeRuleSource>, String> {
    validate_bundled_pack(BUNDLED_PACK_MANIFEST_JSON, EMBEDDED_BUNDLED_RULE_FILES)?;

    let mut sources = Vec::new();
    for file in EMBEDDED_BUNDLED_RULE_FILES {
        let relative_path = format!("bundled/{}", file.relative_path);
        sources.push(MemoryRuntimeRuleSource {
            namespace: namespace_for_relative_path(&relative_path),
            relative_path,
            source_text: file.source_text.to_string(),
        });
    }

    let report = crate::yara_rules::load_verified_rules()?;
    for file in report.files {
        let relative_path = format!("local/{}", file.relative_path);
        sources.push(MemoryRuntimeRuleSource {
            namespace: namespace_for_relative_path(&relative_path),
            relative_path,
            source_text: file.source_text,
        });
    }

    Ok(sources)
}

fn validate_bundled_pack(
    manifest_json: &str,
    embedded_files: &[EmbeddedBundledRuleFile],
) -> Result<(), String> {
    let manifest: BundledPackManifest = serde_json::from_str(manifest_json)
        .map_err(|e| format!("failed to parse bundled YARA pack manifest: {e}"))?;
    validate_bundled_pack_manifest(&manifest, embedded_files)
}

fn validate_bundled_pack_manifest(
    manifest: &BundledPackManifest,
    embedded_files: &[EmbeddedBundledRuleFile],
) -> Result<(), String> {
    if manifest.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "unsupported bundled YARA manifest schema version {}; expected {}",
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

    let mut seen_paths = HashSet::with_capacity(manifest.files.len());
    for (idx, file) in manifest.files.iter().enumerate() {
        validate_bundled_pack_manifest_file(idx, file)?;
        if !seen_paths.insert(file.relative_path.clone()) {
            return Err(format!(
                "YARA pack manifest files[{idx}] reuses duplicate relative_path {}",
                file.relative_path
            ));
        }

        let Some(source_text) = embedded_by_path.get(file.relative_path.as_str()) else {
            return Err(format!(
                "bundled YARA pack file {} is listed in the manifest but missing from the embedded file index",
                file.relative_path
            ));
        };
        let actual_sha = sha256_digest_hex(source_text.as_bytes());
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
    }

    if embedded_by_path.len() != manifest.files.len() {
        return Err(
            "bundled YARA embedded file index contains files that are missing from the manifest"
                .into(),
        );
    }

    Ok(())
}

fn validate_bundled_pack_manifest_file(
    idx: usize,
    file: &BundledPackManifestFile,
) -> Result<(), String> {
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

fn memory_dump_scan_target(path: &Path) -> Result<MemoryDumpScanTarget, String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("read metadata for process dump {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "process dump target is not a file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_PROCESS_DUMP_SCAN_BYTES {
        return Err(format!(
            "process dump target {} is {} bytes, above the {} byte scan limit",
            path.display(),
            metadata.len(),
            MAX_PROCESS_DUMP_SCAN_BYTES
        ));
    }

    Ok(MemoryDumpScanTarget {
        path: path.to_path_buf(),
        size_bytes: metadata.len(),
        modified_unix_nanos: metadata
            .modified()
            .ok()
            .and_then(system_time_to_unix_nanos)
            .unwrap_or_default(),
        created_unix_nanos: metadata
            .created()
            .ok()
            .and_then(system_time_to_unix_nanos)
            .unwrap_or_default(),
    })
}

fn scan_memory_dump_target(
    compiled: &MemoryCompiledRuleSet,
    target: &MemoryDumpScanTarget,
) -> Result<MemoryDumpScanVerdict, String> {
    let target_sha256 = sha256_file(&target.path)?;
    let mut scanner = Scanner::new(&compiled.rules);
    scanner.use_mmap(false);
    scanner.set_timeout(Duration::from_secs(10));
    let results = scanner
        .scan_file(&target.path)
        .map_err(|e| format!("scan process dump {}: {e}", target.path.display()))?;

    let mut matched_rules = Vec::new();
    for rule in results
        .matching_rules()
        .take(MAX_MEMORY_MATCHED_RULES_RECORDED)
    {
        let attack_tags = rule
            .tags()
            .map(|tag| tag.identifier().to_string())
            .filter(|tag| looks_like_attack_tag(tag))
            .collect::<Vec<_>>();
        matched_rules.push(MemoryDumpMatchedRule {
            identifier: rule.identifier().to_string(),
            attack_tags,
        });
    }

    Ok(MemoryDumpScanVerdict {
        matched_rules,
        ruleset_digest: compiled.digest.clone(),
        scanned_unix: unix_now(),
        target_sha256,
    })
}

fn persist_memory_dump_scan_result(
    target: &MemoryDumpScanTarget,
    verdict: &MemoryDumpScanVerdict,
    info: &ConnInfo,
    manifest: Option<&Path>,
) -> Result<(), String> {
    let db = StorageDb::global()?;
    ensure_scan_result_table(&db)?;
    db.begin()?;
    let result = (|| -> Result<(), String> {
        let target_identity = target.path.to_string_lossy().to_string();
        let conn = db.conn()?;
        conn.execute(
            "DELETE FROM yara_scan_result WHERE target_kind = ?1 AND target_identity = ?2",
            params!["process_dump", target_identity.as_str()],
        )
        .map_err(|e| format!("clear prior process dump YARA scan result: {e}"))?;

        let payload = json!({
            "pid": info.pid,
            "proc_name": info.proc_name,
            "proc_path": info.proc_path,
            "score": info.score,
            "manifest": manifest.map(|p| p.display().to_string()),
            "size_bytes": target.size_bytes,
            "modified_unix_nanos": target.modified_unix_nanos,
            "created_unix_nanos": target.created_unix_nanos,
            "matched_rules": verdict
                .matched_rules
                .iter()
                .map(|rule| {
                    json!({
                        "identifier": rule.identifier,
                        "attack_tags": rule.attack_tags,
                    })
                })
                .collect::<Vec<_>>(),
        });
        let verdict_name = if verdict.matched_rules.is_empty() {
            "clean"
        } else {
            "matched"
        };
        let scanned_unix = i64::try_from(verdict.scanned_unix).unwrap_or(i64::MAX);
        let match_count = i64::try_from(verdict.matched_rules.len()).unwrap_or(i64::MAX);

        conn.execute(
            "INSERT INTO yara_scan_result
             (result_key, target_kind, target_identity, target_sha256, ruleset_digest,
              scanned_unix, verdict, match_count, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                stable_key(
                    "yara_scan_result",
                    &format!("process_dump:{target_identity}:{}", verdict.ruleset_digest)
                ),
                "process_dump",
                target_identity.as_str(),
                verdict.target_sha256.as_str(),
                verdict.ruleset_digest.as_str(),
                scanned_unix,
                verdict_name,
                match_count,
                payload.to_string(),
            ],
        )
        .map_err(|e| format!("insert process dump YARA scan result: {e}"))?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            db.commit()?;
            db.checkpoint()?;
            Ok(())
        }
        Err(err) => {
            let _ = db.rollback();
            Err(err)
        }
    }
}

fn ensure_scan_result_table(db: &StorageDb) -> Result<(), String> {
    let conn = db.conn()?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS yara_scan_result (
            result_key      TEXT PRIMARY KEY NOT NULL,
            target_kind     TEXT NOT NULL DEFAULT '',
            target_identity TEXT NOT NULL DEFAULT '',
            target_sha256   TEXT NOT NULL DEFAULT '',
            ruleset_digest  TEXT NOT NULL DEFAULT '',
            scanned_unix    INTEGER NOT NULL DEFAULT 0,
            verdict         TEXT NOT NULL DEFAULT '',
            match_count     INTEGER NOT NULL DEFAULT 0,
            payload_json    TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_yara_scan_target
            ON yara_scan_result(target_kind, target_identity);
        CREATE INDEX IF NOT EXISTS idx_yara_scan_ruleset
            ON yara_scan_result(ruleset_digest);
        CREATE INDEX IF NOT EXISTS idx_yara_scan_verdict
            ON yara_scan_result(verdict, scanned_unix);
        ",
    )
    .map_err(|e| format!("bootstrap YARA scan result table: {e}"))?;
    Ok(())
}

fn namespace_for_relative_path(relative_path: &str) -> String {
    Path::new(relative_path)
        .parent()
        .map(|parent| parent.to_string_lossy().replace('\\', "/"))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "default".to_string())
}

fn looks_like_attack_tag(tag: &str) -> bool {
    let normalized = tag.trim();
    if normalized.is_empty() {
        return false;
    }
    let candidate = normalized
        .strip_prefix("ATT&CK:")
        .or_else(|| normalized.strip_prefix("ATTACK:"))
        .unwrap_or(normalized);
    let Some(rest) = candidate.strip_prefix('T') else {
        return false;
    };
    let (head, tail) = rest.split_once('.').unwrap_or((rest, ""));
    if head.len() != 4 || !head.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    if tail.is_empty() {
        return true;
    }
    tail.len() == 3 && tail.chars().all(|ch| ch.is_ascii_digit())
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

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|e| format!("open {} for sha256: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("read {} for sha256: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    Ok(hex_encode(digest.as_ref()))
}

fn stable_key(kind: &str, value: &str) -> String {
    sha256_digest_hex(format!("{kind}:{value}").as_bytes())
}

fn sha256_digest_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex_encode(digest.as_ref())
}

fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn system_time_to_unix_nanos(time: SystemTime) -> Option<u64> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_nanos()).ok()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(dead_code)]
fn dump_root(cfg: &Config) -> PathBuf {
    if !cfg.process_dump_dir.trim().is_empty() {
        PathBuf::from(cfg.process_dump_dir.trim())
    } else {
        crate::config::data_dir()
            .join("artifacts")
            .join("process-dumps")
    }
}

#[allow(dead_code)]
fn safe_name(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('_');
    if cleaned.is_empty() {
        "process".to_string()
    } else {
        cleaned.to_string()
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::platform::command_paths;
    use std::process::Command;

    pub fn capture_process_dump(info: &ConnInfo, cfg: &Config) -> Result<PathBuf, String> {
        let dir = dump_root(cfg);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("failed to create {}: {e}", dir.display()))?;

        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        let filename = format!(
            "{}-pid{}-score{}-{}.dmp",
            stamp,
            info.pid,
            info.score,
            safe_name(&info.proc_name)
        );
        let out = dir.join(filename);

        let status = Command::new(command_paths::resolve("rundll32.exe")?)
            .arg("C:\\Windows\\System32\\comsvcs.dll,MiniDump")
            .arg(info.pid.to_string())
            .arg(&out)
            .arg("full")
            .status()
            .map_err(|e| format!("failed to spawn rundll32.exe: {e}"))?;

        if !status.success() {
            return Err(format!("rundll32 MiniDump exited with status {status}"));
        }
        if !out.exists() {
            return Err(format!(
                "expected dump file {} was not created",
                out.display()
            ));
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn capture_process_dump(_info: &ConnInfo, _cfg: &Config) -> Result<PathBuf, String> {
        Err("process dump on alert is not implemented on this platform".into())
    }
}
