//! Async executable YARA scan worker.
//!
//! This keeps expensive YARA file scans out of the real-time connection
//! enrichment path. The monitor only consults cached verdicts inline and
//! schedules background scans for first-seen executables.

use crate::storage::db::StorageDb;
use crate::types::{ConnEvent, ConnInfo};
use dashmap::DashMap;
use rusqlite::params;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use yara_x::{Compiler, Scanner, SourceCode};

const BUNDLED_PACK_MANIFEST_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bundled_yara_pack_manifest.json"));
const SCAN_QUEUE_CAPACITY: usize = 512;
const MAX_SCAN_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MATCHED_RULES_RECORDED: usize = 8;
const YARA_SCORE_BASE: u8 = 5;

static GLOBAL_SCHEDULER: OnceLock<Arc<YaraScanScheduler>> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
struct EmbeddedBundledRuleFile {
    relative_path: &'static str,
    source_text: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/bundled_yara_pack_files.rs"));

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ScanTargetKey {
    path: String,
    size_bytes: u64,
    modified_unix: u64,
}

#[derive(Debug, Clone)]
struct ScanRequest {
    key: ScanTargetKey,
    info: ConnInfo,
    threshold: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchedRule {
    identifier: String,
    attack_tags: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CachedScanVerdict {
    matched_rules: Vec<MatchedRule>,
    ruleset_digest: String,
    scanned_unix: u64,
    target_sha256: String,
}

#[derive(Debug, Clone)]
struct RuntimeRuleSource {
    namespace: String,
    relative_path: String,
    source_text: String,
}

struct CompiledRuleSet {
    digest: String,
    rules: yara_x::Rules,
}

pub struct YaraScanScheduler {
    tx: SyncSender<ScanRequest>,
    pending: Arc<Mutex<HashSet<ScanTargetKey>>>,
    cache: Arc<DashMap<ScanTargetKey, CachedScanVerdict>>,
}

pub fn ensure_started(tx: broadcast::Sender<ConnEvent>) -> Arc<YaraScanScheduler> {
    Arc::clone(GLOBAL_SCHEDULER.get_or_init(|| YaraScanScheduler::start(tx)))
}

pub fn apply_cached_verdict(
    proc_path: &str,
    score: &mut u8,
    reasons: &mut Vec<String>,
    attack_tags: &mut Vec<String>,
) -> bool {
    let Some(scheduler) = GLOBAL_SCHEDULER.get() else {
        return false;
    };
    let Some(key) = scan_target_key(proc_path) else {
        return false;
    };
    let Some(verdict) = scheduler.cache.get(&key) else {
        return false;
    };
    apply_verdict_overlay(score, reasons, attack_tags, verdict.value())
}

pub fn enqueue_process_scan(info: ConnInfo, threshold: u8) {
    let Some(scheduler) = GLOBAL_SCHEDULER.get() else {
        return;
    };
    scheduler.enqueue(info, threshold);
}

impl YaraScanScheduler {
    fn start(tx: broadcast::Sender<ConnEvent>) -> Arc<Self> {
        let (queue_tx, queue_rx) = mpsc::sync_channel::<ScanRequest>(SCAN_QUEUE_CAPACITY);
        let pending = Arc::new(Mutex::new(HashSet::new()));
        let cache = Arc::new(DashMap::new());
        let scheduler = Arc::new(Self {
            tx: queue_tx,
            pending: Arc::clone(&pending),
            cache: Arc::clone(&cache),
        });

        std::thread::Builder::new()
            .name("vigil-yara-scan".to_string())
            .spawn(move || {
                let compiled = match compile_runtime_rules() {
                    Ok(compiled) => compiled,
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to compile runtime YARA rules");
                        None
                    }
                };
                if compiled.is_none() {
                    tracing::info!("YARA runtime scan worker started without any compiled rules");
                }

                while let Ok(request) = queue_rx.recv() {
                    let result = if let Some(compiled_rules) = compiled.as_ref() {
                        match scan_target(compiled_rules, &request.key) {
                            Ok(verdict) => Some(verdict),
                            Err(err) => {
                                tracing::warn!(
                                    path = %request.key.path,
                                    error = %err,
                                    "YARA scan failed for executable"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };

                    if let Some(verdict) = result {
                        cache.insert(request.key.clone(), verdict.clone());
                        if let Err(err) = persist_scan_result(&request.key, &verdict) {
                            tracing::warn!(
                                path = %request.key.path,
                                error = %err,
                                "failed to persist YARA scan result"
                            );
                        }

                        if !verdict.matched_rules.is_empty() {
                            let mut updated = request.info.clone();
                            let matched = apply_verdict_overlay(
                                &mut updated.score,
                                &mut updated.reasons,
                                &mut updated.attack_tags,
                                &verdict,
                            );
                            if matched {
                                let event = if updated.score >= request.threshold {
                                    ConnEvent::Alert(updated)
                                } else {
                                    ConnEvent::New(updated)
                                };
                                let _ = tx.send(event);
                            }
                        }
                    }

                    if let Ok(mut guard) = pending.lock() {
                        guard.remove(&request.key);
                    }
                }
            })
            .expect("spawn YARA scan worker");

        scheduler
    }

    fn enqueue(&self, info: ConnInfo, threshold: u8) {
        let Some(key) = scan_target_key(&info.proc_path) else {
            return;
        };
        if self.cache.contains_key(&key) {
            return;
        }

        {
            let Ok(mut pending) = self.pending.lock() else {
                tracing::warn!("YARA scan queue lock poisoned");
                return;
            };
            if !pending.insert(key.clone()) {
                return;
            }
        }

        let request = ScanRequest {
            key: key.clone(),
            info,
            threshold,
        };
        match self.tx.try_send(request) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                if let Ok(mut pending) = self.pending.lock() {
                    pending.remove(&key);
                }
                tracing::warn!(
                    path = %key.path,
                    capacity = SCAN_QUEUE_CAPACITY,
                    "YARA scan queue full; dropping scan request"
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                if let Ok(mut pending) = self.pending.lock() {
                    pending.remove(&key);
                }
                tracing::warn!("YARA scan worker unavailable; dropping scan request");
            }
        }
    }
}

fn compile_runtime_rules() -> Result<Option<CompiledRuleSet>, String> {
    let mut compiler = Compiler::new();
    let mut hasher = Sha256::new();
    let mut compiled_sources = 0usize;

    for source in runtime_rule_sources()? {
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
                    "skipping YARA source that failed compilation"
                );
            }
        }
    }

    if compiled_sources == 0 {
        return Ok(None);
    }

    Ok(Some(CompiledRuleSet {
        digest: sha256_hex(&hasher.finalize()),
        rules: compiler.build(),
    }))
}

fn runtime_rule_sources() -> Result<Vec<RuntimeRuleSource>, String> {
    validate_bundled_manifest_shape(BUNDLED_PACK_MANIFEST_JSON)?;

    let mut sources = Vec::new();
    for file in EMBEDDED_BUNDLED_RULE_FILES {
        let relative_path = format!("bundled/{}", file.relative_path);
        sources.push(RuntimeRuleSource {
            namespace: namespace_for_relative_path(&relative_path),
            relative_path,
            source_text: file.source_text.to_string(),
        });
    }

    let report = crate::yara_rules::load_verified_rules()?;
    for file in report.files {
        let relative_path = format!("local/{}", file.relative_path);
        sources.push(RuntimeRuleSource {
            namespace: namespace_for_relative_path(&relative_path),
            relative_path,
            source_text: file.source_text,
        });
    }

    Ok(sources)
}

fn validate_bundled_manifest_shape(manifest_json: &str) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|e| format!("parse bundled YARA manifest: {e}"))?;
    let schema_version = value
        .get("schema_version")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| "bundled YARA manifest missing schema_version".to_string())?;
    if schema_version != 1 {
        return Err(format!(
            "unsupported bundled YARA manifest schema version {schema_version}; expected 1"
        ));
    }
    Ok(())
}

fn scan_target(
    compiled: &CompiledRuleSet,
    key: &ScanTargetKey,
) -> Result<CachedScanVerdict, String> {
    let path = Path::new(&key.path);
    let target_sha256 = sha256_file(path)?;
    let mut scanner = Scanner::new(&compiled.rules);
    scanner.use_mmap(false);
    scanner.set_timeout(Duration::from_secs(10));
    let results = scanner
        .scan_file(path)
        .map_err(|e| format!("scan file {}: {e}", path.display()))?;

    let mut matched_rules = Vec::new();
    for rule in results.matching_rules().take(MAX_MATCHED_RULES_RECORDED) {
        let attack_tags = rule
            .tags()
            .map(|tag| tag.identifier().to_string())
            .filter(|tag| looks_like_attack_tag(tag))
            .collect::<Vec<_>>();
        matched_rules.push(MatchedRule {
            identifier: rule.identifier().to_string(),
            attack_tags,
        });
    }

    Ok(CachedScanVerdict {
        matched_rules,
        ruleset_digest: compiled.digest.clone(),
        scanned_unix: unix_now(),
        target_sha256,
    })
}

fn persist_scan_result(key: &ScanTargetKey, verdict: &CachedScanVerdict) -> Result<(), String> {
    let db = StorageDb::global()?;
    ensure_scan_result_table(&db)?;
    db.begin()?;
    let result = (|| -> Result<(), String> {
        let conn = db.conn()?;
        conn.execute(
            "DELETE FROM yara_scan_result WHERE target_kind = ?1 AND target_identity = ?2",
            params!["executable_path", key.path.as_str()],
        )
        .map_err(|e| format!("clear prior YARA scan result: {e}"))?;

        let payload = json!({
            "size_bytes": key.size_bytes,
            "modified_unix": key.modified_unix,
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

        conn.execute(
            "INSERT INTO yara_scan_result
             (result_key, target_kind, target_identity, target_sha256, ruleset_digest,
              scanned_unix, verdict, match_count, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                stable_key(
                    "yara_scan_result",
                    &format!("{}:{}", key.path, verdict.ruleset_digest)
                ),
                "executable_path",
                key.path.as_str(),
                verdict.target_sha256.as_str(),
                verdict.ruleset_digest.as_str(),
                verdict.scanned_unix,
                verdict_name,
                verdict.matched_rules.len(),
                payload.to_string(),
            ],
        )
        .map_err(|e| format!("insert YARA scan result: {e}"))?;
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

fn apply_verdict_overlay(
    score: &mut u8,
    reasons: &mut Vec<String>,
    attack_tags: &mut Vec<String>,
    verdict: &CachedScanVerdict,
) -> bool {
    if verdict.matched_rules.is_empty() {
        return false;
    }

    *score = score.saturating_add(yara_score_delta(verdict.matched_rules.len()));
    for rule in &verdict.matched_rules {
        let reason = format!("YARA rule: {}", rule.identifier);
        if !reasons.iter().any(|existing| existing == &reason) {
            reasons.push(reason);
        }
        for tag in &rule.attack_tags {
            if looks_like_attack_tag(tag) && !attack_tags.iter().any(|existing| existing == tag) {
                attack_tags.push(tag.clone());
            }
        }
    }
    true
}

fn yara_score_delta(match_count: usize) -> u8 {
    let bonus = match_count.saturating_sub(1).min(3) as u8;
    YARA_SCORE_BASE.saturating_add(bonus)
}

fn scan_target_key(proc_path: &str) -> Option<ScanTargetKey> {
    if proc_path.trim().is_empty() {
        return None;
    }
    let metadata = fs::metadata(proc_path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_SCAN_FILE_BYTES {
        return None;
    }
    let modified_unix = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    Some(ScanTargetKey {
        path: proc_path.to_string(),
        size_bytes: metadata.len(),
        modified_unix,
    })
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
    Ok(sha256_hex(&hasher.finalize()))
}

fn stable_key(kind: &str, value: &str) -> String {
    sha256_hex(format!("{kind}:{value}").as_bytes())
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_tag_filter_accepts_attack_ids_only() {
        assert!(looks_like_attack_tag("T1055"));
        assert!(looks_like_attack_tag("T1055.001"));
        assert!(looks_like_attack_tag("ATT&CK:T1071"));
        assert!(!looks_like_attack_tag("credential_access"));
        assert!(!looks_like_attack_tag("T10"));
        assert!(!looks_like_attack_tag("ATT&CK:TA0001"));
    }

    #[test]
    fn verdict_overlay_adds_reasons_and_tags_once() {
        let verdict = CachedScanVerdict {
            matched_rules: vec![
                MatchedRule {
                    identifier: "test_one".into(),
                    attack_tags: vec!["T1055".into(), "T1055".into()],
                },
                MatchedRule {
                    identifier: "test_two".into(),
                    attack_tags: vec!["ATT&CK:T1071".into()],
                },
            ],
            ..CachedScanVerdict::default()
        };

        let mut score = 10u8;
        let mut reasons = vec!["YARA rule: test_one".to_string()];
        let mut attack_tags = vec!["T1055".to_string()];

        assert!(apply_verdict_overlay(
            &mut score,
            &mut reasons,
            &mut attack_tags,
            &verdict
        ));
        assert_eq!(score, 16);
        assert_eq!(reasons.len(), 2);
        assert!(reasons.iter().any(|reason| reason == "YARA rule: test_two"));
        assert_eq!(attack_tags.len(), 2);
        assert!(attack_tags.iter().any(|tag| tag == "ATT&CK:T1071"));
    }
}
