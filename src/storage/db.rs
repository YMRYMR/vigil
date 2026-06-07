//! SQLite-backed state store with signed checkpoint manifests.
//!
//! This module replaces the legacy HMAC-protected JSON file cache with a
//! single SQLite database while preserving Vigil's integrity model via
//! deterministic digest manifests signed through the existing policy layer.
//!
//! # Integrity model
//!
//! 1. Writes are batched inside explicit transactions.
//! 2. After every write transaction the caller should call `checkpoint`.
//! 3. `checkpoint` computes a deterministic digest over the current DB
//!    state and persists it via `security::policy::save_struct_with_integrity`.
//! 4. On startup `verify` re-computes the digest and compares it to the
//!    manifest, failing closed on mismatch.

use rusqlite::{types::ValueRef, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const DB_FILENAME: &str = "vigil-state.db";
const MANIFEST_FILENAME: &str = "vigil-state.manifest.json";
const SCHEMA_VERSION: i64 = 1;
const SCHEMA_VERSION_KEY: &str = "schema_version";

static GLOBAL_DB: Mutex<Option<StorageDb>> = Mutex::new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageManifest {
    pub schema_version: i64,
    pub generated_unix: u64,
    pub digest: String,
    pub table_count: usize,
}

pub struct StorageDb {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    path: PathBuf,
    manifest_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FirewallRuleRow {
    pub rule_name: String,
    pub rule_type: String,
    pub target: String,
    pub direction: String,
    pub pid: u32,
    pub path: String,
    pub created_unix: u64,
    pub expires_unix: Option<u64>,
}

#[allow(dead_code)]
impl StorageDb {
    /// Returns a reference to the global singleton database instance
    /// (initialising it on first call) or an error.
    ///
    /// The reference is valid only while the returned guard is alive;
    /// callers should not stash the reference beyond the guard scope.
    pub fn global() -> Result<DbGuard, String> {
        let mut guard = GLOBAL_DB
            .lock()
            .map_err(|e| format!("global db lock: {e}"))?;
        if guard.is_none() {
            *guard = Some(Self::open_inner()?);
        }
        Ok(DbGuard(guard))
    }

    /// Open a standalone database instance (bypasses the singleton).
    /// Prefer `global()` for normal use; this is useful for tests or
    /// scenarios that need an isolated connection.
    pub fn open() -> Result<Self, String> {
        Self::open_inner()
    }

    fn open_inner() -> Result<Self, String> {
        let dir = crate::config::data_dir();
        std::fs::create_dir_all(&dir).map_err(|e| format!("create data dir: {e}"))?;
        let path = dir.join(DB_FILENAME);
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let conn = Connection::open(&path).map_err(|e| format!("open db: {e}"))?;
        let db = Self {
            conn: Mutex::new(conn),
            path,
            manifest_path,
        };
        db.bootstrap()?;
        Ok(db)
    }

    fn bootstrap(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("lock: {e}"))?;
        conn.execute_batch(
            "            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA synchronous=NORMAL;
            PRAGMA cache_size=-8000;
            PRAGMA busy_timeout=5000;
            PRAGMA journal_size_limit=16777216;",
        )
        .map_err(|e| format!("pragmas: {e}"))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS advisory_source (
                source_key   TEXT PRIMARY KEY NOT NULL,
                source_kind  TEXT NOT NULL,
                source_url   TEXT NOT NULL DEFAULT '',
                imported_from TEXT,
                imported_from_batch_json TEXT NOT NULL DEFAULT '[]',
                fetched_unix INTEGER NOT NULL DEFAULT 0,
                expires_unix INTEGER NOT NULL DEFAULT 0,
                snapshot_sha256 TEXT NOT NULL DEFAULT '',
                total_results INTEGER NOT NULL DEFAULT 0,
                status       TEXT NOT NULL DEFAULT 'ok',
                last_attempt_unix INTEGER NOT NULL DEFAULT 0,
                last_error   TEXT NOT NULL DEFAULT '',
                retry_after_unix INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS advisory_record (
                primary_id    TEXT NOT NULL,
                source_key    TEXT NOT NULL REFERENCES advisory_source(source_key),
                source_kind   TEXT NOT NULL,
                published_unix INTEGER NOT NULL DEFAULT 0,
                updated_unix  INTEGER NOT NULL DEFAULT 0,
                severity      TEXT NOT NULL DEFAULT '',
                exploited     INTEGER NOT NULL DEFAULT 0,
                payload_json  TEXT NOT NULL DEFAULT '{}',
                created_unix  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (primary_id, source_key)
            );

            CREATE INDEX IF NOT EXISTS idx_advisory_record_source
                ON advisory_record(source_kind, source_key);
            CREATE INDEX IF NOT EXISTS idx_advisory_record_updated
                ON advisory_record(updated_unix);
            CREATE INDEX IF NOT EXISTS idx_advisory_record_primary
                ON advisory_record(primary_id);

            CREATE TABLE IF NOT EXISTS advisory_product_index (
                identity_key TEXT NOT NULL,
                primary_id   TEXT NOT NULL,
                source_key   TEXT NOT NULL,
                source_kind  TEXT NOT NULL,
                PRIMARY KEY (identity_key, primary_id, source_key)
            );

            CREATE INDEX IF NOT EXISTS idx_advisory_product_index_identity
                ON advisory_product_index(identity_key);
            CREATE INDEX IF NOT EXISTS idx_advisory_product_index_record
                ON advisory_product_index(primary_id, source_key);

            CREATE TABLE IF NOT EXISTS advisory_record_search (
                primary_id  TEXT NOT NULL,
                source_key  TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                search_text TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (primary_id, source_key)
            );

            CREATE INDEX IF NOT EXISTS idx_advisory_record_search_text
                ON advisory_record_search(search_text);

            CREATE TABLE IF NOT EXISTS advisory_change_event (
                change_id   TEXT NOT NULL,
                primary_id  TEXT NOT NULL,
                source_key  TEXT NOT NULL,
                change_unix INTEGER NOT NULL,
                event_name  TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (change_id, primary_id, source_key)
            );

            CREATE INDEX IF NOT EXISTS idx_change_event_cve
                ON advisory_change_event(primary_id, change_unix);
            CREATE INDEX IF NOT EXISTS idx_change_event_source
                ON advisory_change_event(source_key);

            CREATE TABLE IF NOT EXISTS software_inventory (
                product_key      TEXT PRIMARY KEY NOT NULL,
                display_name     TEXT NOT NULL DEFAULT '',
                executable_path  TEXT NOT NULL DEFAULT '',
                publisher_hint   TEXT NOT NULL DEFAULT '',
                version_hint     TEXT NOT NULL DEFAULT '',
                source           TEXT NOT NULL DEFAULT '',
                updated_unix     INTEGER NOT NULL DEFAULT 0,
                payload_json     TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_inventory_path
                ON software_inventory(executable_path);

            CREATE TABLE IF NOT EXISTS firewall_rule (
                rule_name       TEXT PRIMARY KEY NOT NULL,
                rule_type       TEXT NOT NULL DEFAULT 'ip',
                target          TEXT NOT NULL DEFAULT '',
                direction       TEXT NOT NULL DEFAULT 'out',
                pid             INTEGER NOT NULL DEFAULT 0,
                path            TEXT NOT NULL DEFAULT '',
                created_unix    INTEGER NOT NULL DEFAULT 0,
                expires_unix    INTEGER,
                removed         INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_firewall_rule_type
                ON firewall_rule(rule_type, removed);
            ",
        )
        .map_err(|e| format!("bootstrap schema: {e}"))?;

        let version: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [SCHEMA_VERSION_KEY],
                |row| row.get(0),
            )
            .ok();
        if version.is_none() {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![SCHEMA_VERSION_KEY, SCHEMA_VERSION.to_string()],
            )
            .map_err(|e| format!("set schema version: {e}"))?;
        }

        // Migration: add columns that may be missing on databases created
        // with earlier schema versions.
        let _ = conn.execute_batch(
            "ALTER TABLE software_inventory ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}';",
        );
        let _ = conn.execute_batch(
            "ALTER TABLE advisory_source ADD COLUMN retry_after_unix INTEGER NOT NULL DEFAULT 0;",
        );
        let _ = conn.execute_batch("ALTER TABLE advisory_source ADD COLUMN imported_from TEXT;");
        let _ = conn.execute_batch(
            "ALTER TABLE advisory_source ADD COLUMN imported_from_batch_json TEXT NOT NULL DEFAULT '[]';",
        );
        let _ = conn.execute_batch(
            "ALTER TABLE advisory_source ADD COLUMN snapshot_sha256 TEXT NOT NULL DEFAULT '';",
        );
        let _ = conn.execute_batch(
            "ALTER TABLE advisory_source ADD COLUMN total_results INTEGER NOT NULL DEFAULT 0;",
        );
        let _ = conn.execute_batch(
            "ALTER TABLE advisory_source ADD COLUMN last_attempt_unix INTEGER NOT NULL DEFAULT 0;",
        );
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS advisory_product_index (
                identity_key TEXT NOT NULL,
                primary_id   TEXT NOT NULL,
                source_key   TEXT NOT NULL,
                source_kind  TEXT NOT NULL,
                PRIMARY KEY (identity_key, primary_id, source_key)
            );
            CREATE INDEX IF NOT EXISTS idx_advisory_product_index_identity
                ON advisory_product_index(identity_key);
            CREATE INDEX IF NOT EXISTS idx_advisory_product_index_record
                ON advisory_product_index(primary_id, source_key);",
        )
        .map_err(|e| format!("ensure advisory product index: {e}"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS advisory_record_search (
                primary_id  TEXT NOT NULL,
                source_key  TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                search_text TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (primary_id, source_key)
            );
            CREATE INDEX IF NOT EXISTS idx_advisory_record_search_text
                ON advisory_record_search(search_text);",
        )
        .map_err(|e| format!("ensure advisory search index: {e}"))?;
        ensure_advisory_product_index_populated(&conn)?;
        ensure_advisory_search_index_populated(&conn)?;

        // Performance pragmas (best-effort, applied each session).
        let _ = conn.execute_batch(
            "PRAGMA auto_vacuum=INCREMENTAL;
             PRAGMA mmap_size=268435456;
             PRAGMA temp_store=MEMORY;",
        );

        // Optimise page size on new databases only (existing DBs are
        // unaffected since page_size must be set before any tables).
        let _ = conn.execute_batch("PRAGMA page_size=8192;");
        Ok(())
    }

    // ── Transaction helpers ────────────────────────────────────────

    /// Begin an explicit transaction. Caller must match with `commit` or
    /// `rollback`. Nested transactions (savepoints) are not supported.
    pub fn begin(&self) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| format!("begin transaction: {e}"))
    }

    /// Commit the current transaction.
    pub fn commit(&self) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute_batch("COMMIT;")
            .map_err(|e| format!("commit transaction: {e}"))
    }

    /// Roll back the current transaction.
    pub fn rollback(&self) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute_batch("ROLLBACK;")
            .map_err(|e| format!("rollback transaction: {e}"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.conn.lock().map_err(|e| format!("lock db: {e}"))
    }

    // -- Advisory source helpers ----------------------------------------

    pub fn replace_advisory_sources(
        &self,
        sources: &[crate::advisory::AdvisorySourceCache],
    ) -> Result<(), String> {
        let conn = self.conn()?;
        // Keep the replacement order FK-safe so source metadata refreshes
        // cannot leave the mirror partially stale.
        conn.execute("DELETE FROM advisory_change_event", [])
            .map_err(|e| format!("clear change events: {e}"))?;
        conn.execute("DELETE FROM advisory_product_index", [])
            .map_err(|e| format!("clear advisory product index: {e}"))?;
        conn.execute("DELETE FROM advisory_record_search", [])
            .map_err(|e| format!("clear advisory search index: {e}"))?;
        conn.execute("DELETE FROM advisory_record", [])
            .map_err(|e| format!("clear records: {e}"))?;
        conn.execute("DELETE FROM advisory_source", [])
            .map_err(|e| format!("clear sources: {e}"))?;
        let mut stmt = conn
            .prepare(
                "INSERT INTO advisory_source
                 (source_key, source_kind, source_url, imported_from, imported_from_batch_json,
                  fetched_unix, expires_unix, snapshot_sha256, total_results, status,
                  last_attempt_unix, last_error, retry_after_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )
            .map_err(|e| format!("prepare source insert: {e}"))?;
        for src in sources {
            let status = match &src.status {
                crate::advisory::SourceHealth::Fresh => "fresh",
                crate::advisory::SourceHealth::Stale => "stale",
                crate::advisory::SourceHealth::Error => "error",
            };
            let imported_from_batch = serde_json::to_string(&src.imported_from_batch)
                .map_err(|e| format!("encode source batch {}: {e}", src.source_key))?;
            stmt.execute(rusqlite::params![
                src.source_key,
                src.source_kind,
                src.source_url,
                src.imported_from,
                imported_from_batch,
                src.fetched_unix as i64,
                src.expires_unix as i64,
                src.snapshot_sha256,
                src.total_results as i64,
                status,
                src.last_attempt_unix as i64,
                src.last_error.as_deref().unwrap_or(""),
                src.retry_after_unix as i64,
            ])
            .map_err(|e| format!("insert source {}: {e}", src.source_key))?;
        }
        Ok(())
    }

    pub fn upsert_advisory_source(
        &self,
        src: &crate::advisory::AdvisorySourceCache,
    ) -> Result<(), String> {
        let conn = self.conn()?;
        let status = match &src.status {
            crate::advisory::SourceHealth::Fresh => "fresh",
            crate::advisory::SourceHealth::Stale => "stale",
            crate::advisory::SourceHealth::Error => "error",
        };
        let imported_from_batch = serde_json::to_string(&src.imported_from_batch)
            .map_err(|e| format!("encode source batch {}: {e}", src.source_key))?;
        conn.execute(
            "INSERT INTO advisory_source
             (source_key, source_kind, source_url, imported_from, imported_from_batch_json,
              fetched_unix, expires_unix, snapshot_sha256, total_results, status,
              last_attempt_unix, last_error, retry_after_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(source_key) DO UPDATE SET
              source_kind = excluded.source_kind,
              source_url = excluded.source_url,
              imported_from = excluded.imported_from,
              imported_from_batch_json = excluded.imported_from_batch_json,
              fetched_unix = excluded.fetched_unix,
              expires_unix = excluded.expires_unix,
              snapshot_sha256 = excluded.snapshot_sha256,
              total_results = excluded.total_results,
              status = excluded.status,
              last_attempt_unix = excluded.last_attempt_unix,
              last_error = excluded.last_error,
              retry_after_unix = excluded.retry_after_unix",
            rusqlite::params![
                src.source_key,
                src.source_kind,
                src.source_url,
                src.imported_from,
                imported_from_batch,
                src.fetched_unix as i64,
                src.expires_unix as i64,
                src.snapshot_sha256,
                src.total_results as i64,
                status,
                src.last_attempt_unix as i64,
                src.last_error.as_deref().unwrap_or(""),
                src.retry_after_unix as i64,
            ],
        )
        .map_err(|e| format!("upsert source {}: {e}", src.source_key))?;
        Ok(())
    }

    pub fn load_advisory_sources(
        &self,
    ) -> Result<Vec<crate::advisory::AdvisorySourceCache>, String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT source_key, source_kind, source_url, imported_from,
                        imported_from_batch_json, fetched_unix, expires_unix,
                        snapshot_sha256, total_results, status,
                        last_attempt_unix, last_error, retry_after_unix
                 FROM advisory_source ORDER BY source_key",
            )
            .map_err(|e| format!("prepare source select: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                let source_key: String = row.get(0)?;
                let source_kind: String = row.get(1)?;
                let source_url: String = row.get(2)?;
                let imported_from: Option<String> = row.get(3)?;
                let imported_from_batch_json: String = row.get(4)?;
                let fetched_unix: i64 = row.get(5)?;
                let expires_unix: i64 = row.get(6)?;
                let snapshot_sha256: String = row.get(7)?;
                let total_results: i64 = row.get(8)?;
                let status_str: String = row.get(9)?;
                let last_attempt_unix: i64 = row.get(10)?;
                let last_error: String = row.get(11)?;
                let retry_after_unix: i64 = row.get(12)?;
                let status = match status_str.as_str() {
                    "stale" => crate::advisory::SourceHealth::Stale,
                    "error" => crate::advisory::SourceHealth::Error,
                    _ => crate::advisory::SourceHealth::Fresh,
                };
                let imported_from_batch =
                    serde_json::from_str(&imported_from_batch_json).unwrap_or_default();
                Ok(crate::advisory::AdvisorySourceCache {
                    source_key,
                    source_kind,
                    source_url,
                    imported_from,
                    imported_from_batch,
                    fetched_unix: fetched_unix.max(0) as u64,
                    expires_unix: expires_unix.max(0) as u64,
                    snapshot_sha256,
                    total_results: total_results.max(0) as usize,
                    status,
                    last_attempt_unix: last_attempt_unix.max(0) as u64,
                    last_error: if last_error.is_empty() {
                        None
                    } else {
                        Some(last_error)
                    },
                    retry_after_unix: retry_after_unix.max(0) as u64,
                })
            })
            .map_err(|e| format!("query sources: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("read source row: {e}"))?);
        }
        Ok(result)
    }

    // -- Advisory record helpers ----------------------------------------

    pub fn replace_advisory_records(
        &self,
        records: &[crate::advisory::VulnerabilityRecord],
        source_key: &str,
        source_kind: &str,
    ) -> Result<(), String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "INSERT INTO advisory_record
                 (primary_id, source_key, source_kind, published_unix, updated_unix,
                  severity, exploited, payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(primary_id, source_key) DO UPDATE SET
                 source_kind = excluded.source_kind,
                 published_unix = excluded.published_unix,
                 updated_unix = excluded.updated_unix,
                 severity = excluded.severity,
                 exploited = excluded.exploited,
                 payload_json = excluded.payload_json",
            )
            .map_err(|e| format!("prepare record upsert: {e}"))?;
        let mut clear_index_stmt = conn
            .prepare(
                "DELETE FROM advisory_product_index
                 WHERE primary_id = ?1 AND source_key = ?2",
            )
            .map_err(|e| format!("prepare product index clear: {e}"))?;
        let mut search_stmt = conn
            .prepare(
                "INSERT OR REPLACE INTO advisory_record_search
                 (primary_id, source_key, source_kind, search_text)
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(|e| format!("prepare advisory search upsert: {e}"))?;
        let mut index_stmt = conn
            .prepare(
                "INSERT OR IGNORE INTO advisory_product_index
                 (identity_key, primary_id, source_key, source_kind)
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(|e| format!("prepare product index upsert: {e}"))?;
        for rec in records {
            let published_unix = parse_nvd_timestamp(&rec.published).unwrap_or(0);
            let updated_unix = parse_nvd_timestamp(&rec.last_modified).unwrap_or(0);
            let severity = rec
                .severities
                .first()
                .map(|s| s.severity.as_str())
                .unwrap_or("");
            let payload = serde_json::to_string(rec).unwrap_or_default();
            stmt.execute(rusqlite::params![
                rec.primary_id,
                source_key,
                source_kind,
                published_unix as i64,
                updated_unix as i64,
                severity,
                rec.known_exploited as i64,
                payload,
            ])
            .map_err(|e| format!("insert record {}: {e}", rec.primary_id))?;
            clear_index_stmt
                .execute(rusqlite::params![&rec.primary_id, source_key])
                .map_err(|e| format!("clear product index {}: {e}", rec.primary_id))?;
            search_stmt
                .execute(rusqlite::params![
                    &rec.primary_id,
                    source_key,
                    source_kind,
                    advisory_record_search_text(rec)
                ])
                .map_err(|e| format!("upsert advisory search index {}: {e}", rec.primary_id))?;
            for identity_key in advisory_record_identity_keys(rec) {
                index_stmt
                    .execute(rusqlite::params![
                        &identity_key,
                        &rec.primary_id,
                        source_key,
                        source_kind
                    ])
                    .map_err(|e| format!("insert product index {}: {e}", rec.primary_id))?;
            }
        }
        Ok(())
    }

    pub fn count_advisory_records_for_source(
        &self,
        source_key: &str,
        source_kind: &str,
    ) -> Result<usize, String> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM advisory_record
                 WHERE source_key = ?1 AND source_kind = ?2",
                rusqlite::params![source_key, source_kind],
                |row| row.get(0),
            )
            .map_err(|e| format!("count records for {source_kind}/{source_key}: {e}"))?;
        Ok(count as usize)
    }

    pub fn count_advisory_records(&self) -> Result<usize, String> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM advisory_record", [], |row| row.get(0))
            .map_err(|e| format!("count records: {e}"))?;
        Ok(count as usize)
    }

    pub fn search_advisory_records(
        &self,
        filter: &str,
        limit: usize,
    ) -> Result<Vec<crate::advisory::VulnerabilityRecord>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let conn = self.conn()?;
        let limit = limit.min(1_000) as i64;
        let filter = filter.trim().to_lowercase();
        let mut records = Vec::new();

        let mut push_payload = |payload: String| {
            if let Ok(record) =
                serde_json::from_str::<crate::advisory::VulnerabilityRecord>(&payload)
            {
                records.push(record);
            }
        };

        if filter.is_empty() {
            let mut stmt = conn
                .prepare(
                    "SELECT payload_json FROM advisory_record
                     ORDER BY exploited DESC,
                              CASE lower(severity)
                                  WHEN 'critical' THEN 4
                                  WHEN 'high' THEN 3
                                  WHEN 'medium' THEN 2
                                  WHEN 'low' THEN 1
                                  ELSE 0
                              END DESC,
                              updated_unix DESC,
                              primary_id ASC
                     LIMIT ?1",
                )
                .map_err(|e| format!("prepare advisory browse query: {e}"))?;
            let rows = stmt
                .query_map(rusqlite::params![limit], |row| {
                    let payload: String = row.get(0)?;
                    Ok(payload)
                })
                .map_err(|e| format!("query advisory browse records: {e}"))?;
            for row in rows {
                push_payload(row.map_err(|e| format!("read advisory browse row: {e}"))?);
            }
            return Ok(records);
        }

        let needle = format!("%{filter}%");
        let mut stmt = conn
            .prepare(
                "SELECT r.payload_json FROM advisory_record r
                 JOIN advisory_record_search s
                   ON s.primary_id = r.primary_id
                  AND s.source_key = r.source_key
                 WHERE s.search_text LIKE ?1
                 ORDER BY r.exploited DESC,
                          CASE lower(r.severity)
                              WHEN 'critical' THEN 4
                              WHEN 'high' THEN 3
                              WHEN 'medium' THEN 2
                              WHEN 'low' THEN 1
                              ELSE 0
                          END DESC,
                          r.updated_unix DESC,
                          r.primary_id ASC
                 LIMIT ?2",
            )
            .map_err(|e| format!("prepare advisory search query: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![needle, limit], |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })
            .map_err(|e| format!("query advisory search records: {e}"))?;
        for row in rows {
            push_payload(row.map_err(|e| format!("read advisory search row: {e}"))?);
        }
        Ok(records)
    }

    pub fn load_advisory_records_for_identity_keys(
        &self,
        identity_keys: &[String],
        limit: usize,
    ) -> Result<Vec<crate::advisory::VulnerabilityRecord>, String> {
        if identity_keys.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }

        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT r.primary_id, r.source_key, r.payload_json
                 FROM advisory_product_index i
                 JOIN advisory_record r
                   ON r.primary_id = i.primary_id
                  AND r.source_key = i.source_key
                 WHERE i.identity_key = ?1
                 ORDER BY r.exploited DESC,
                          CASE lower(r.severity)
                              WHEN 'critical' THEN 4
                              WHEN 'high' THEN 3
                              WHEN 'medium' THEN 2
                              WHEN 'low' THEN 1
                              ELSE 0
                          END DESC,
                          r.updated_unix DESC,
                          r.primary_id ASC
                 LIMIT ?2",
            )
            .map_err(|e| format!("prepare advisory identity query: {e}"))?;

        let mut seen = BTreeSet::new();
        let mut records = Vec::new();
        for identity_key in identity_keys {
            if records.len() >= limit {
                break;
            }
            let remaining = limit.saturating_sub(records.len()) as i64;
            let rows = stmt
                .query_map(rusqlite::params![identity_key, remaining], |row| {
                    let primary_id: String = row.get(0)?;
                    let source_key: String = row.get(1)?;
                    let payload: String = row.get(2)?;
                    Ok((primary_id, source_key, payload))
                })
                .map_err(|e| format!("query advisory identity {identity_key}: {e}"))?;

            for row in rows {
                let (primary_id, source_key, payload) =
                    row.map_err(|e| format!("read advisory identity row: {e}"))?;
                if !seen.insert((primary_id.clone(), source_key)) {
                    continue;
                }
                if let Ok(record) =
                    serde_json::from_str::<crate::advisory::VulnerabilityRecord>(&payload)
                {
                    records.push(record);
                }
                if records.len() >= limit {
                    break;
                }
            }
        }
        Ok(records)
    }

    /// Query advisory records updated after a given timestamp.
    /// Useful for incremental sync: only reload recently changed records.
    pub fn load_advisory_records_since(
        &self,
        since_unix: u64,
    ) -> Result<Vec<crate::advisory::VulnerabilityRecord>, String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT payload_json FROM advisory_record
                 WHERE updated_unix >= ?1 ORDER BY updated_unix",
            )
            .map_err(|e| format!("prepare records-since query: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![since_unix as i64], |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })
            .map_err(|e| format!("query records since {since_unix}: {e}"))?;
        let mut records = Vec::new();
        for row in rows {
            let payload = row.map_err(|e| format!("read record: {e}"))?;
            if let Ok(rec) = serde_json::from_str::<crate::advisory::VulnerabilityRecord>(&payload)
            {
                records.push(rec);
            }
        }
        Ok(records)
    }

    /// Returns the most recent `updated_unix` across all advisory records,
    /// or `None` when the table is empty.
    pub fn max_advisory_updated_unix(&self) -> Result<Option<u64>, String> {
        let conn = self.conn()?;
        let max: Option<Option<i64>> = conn
            .query_row("SELECT MAX(updated_unix) FROM advisory_record", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| format!("max updated_unix: {e}"))?;
        Ok(max.unwrap_or(None).map(|value| value.max(0) as u64))
    }

    pub fn max_advisory_updated_unix_for_source(
        &self,
        source_key: &str,
        source_kind: &str,
    ) -> Result<Option<u64>, String> {
        let conn = self.conn()?;
        let max: Option<Option<i64>> = conn
            .query_row(
                "SELECT MAX(updated_unix) FROM advisory_record
                 WHERE source_key = ?1 AND source_kind = ?2",
                rusqlite::params![source_key, source_kind],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("max updated_unix for {source_kind}/{source_key}: {e}"))?;
        Ok(max.unwrap_or(None).map(|value| value.max(0) as u64))
    }

    pub fn load_advisory_cache(&self) -> Result<Option<crate::advisory::AdvisoryCache>, String> {
        let sources = self.load_advisory_sources()?;
        if sources.is_empty() {
            return Ok(None);
        }
        let conn = self.conn()?;
        let mut records = Vec::new();
        for src in &sources {
            let mut stmt = conn
                .prepare(
                    "SELECT payload_json FROM advisory_record
                     WHERE source_key = ?1 AND source_kind = ?2",
                )
                .map_err(|e| format!("prepare record select: {e}"))?;
            let rows = stmt
                .query_map(rusqlite::params![src.source_key, src.source_kind], |row| {
                    let payload: String = row.get(0)?;
                    Ok(payload)
                })
                .map_err(|e| format!("query records for {}: {e}", src.source_key))?;
            for row in rows {
                let payload = row.map_err(|e| format!("read record: {e}"))?;
                if let Ok(rec) =
                    serde_json::from_str::<crate::advisory::VulnerabilityRecord>(&payload)
                {
                    records.push(rec);
                }
            }
        }
        Ok(Some(crate::advisory::AdvisoryCache {
            schema_version: 1,
            generated_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            sources,
            records,
        }))
    }

    // ── Software inventory helpers ──────────────────────────────────────

    pub fn replace_software_inventory(
        &self,
        entries: &[crate::software_inventory::InstalledSoftware],
    ) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM software_inventory", [])
            .map_err(|e| format!("clear inventory: {e}"))?;
        let mut stmt = conn
            .prepare(
                "INSERT INTO software_inventory
                 (product_key, display_name, executable_path, publisher_hint,
                  version_hint, source, updated_unix, payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .map_err(|e| format!("prepare inventory insert: {e}"))?;
        for entry in entries {
            let payload = serde_json::to_string(entry).unwrap_or_default();
            stmt.execute(rusqlite::params![
                entry.product_key,
                entry.display_name,
                entry.executable_path,
                entry.publisher_hint.as_deref().unwrap_or(""),
                entry.version_hint.as_deref().unwrap_or(""),
                format!("{:?}", entry.source),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                payload,
            ])
            .map_err(|e| format!("insert inventory {}: {e}", entry.product_key))?;
        }
        Ok(())
    }

    pub fn load_software_inventory(
        &self,
    ) -> Result<Vec<crate::software_inventory::InstalledSoftware>, String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT payload_json FROM software_inventory ORDER BY product_key")
            .map_err(|e| format!("prepare inventory select: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                let payload: String = row.get(0)?;
                Ok(payload)
            })
            .map_err(|e| format!("query inventory: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            let payload = row.map_err(|e| format!("read inventory row: {e}"))?;
            if let Ok(entry) =
                serde_json::from_str::<crate::software_inventory::InstalledSoftware>(&payload)
            {
                result.push(entry);
            }
        }
        Ok(result)
    }

    /// Count advisory records grouped by source.
    pub fn count_advisory_records_by_source(&self) -> Result<Vec<(String, usize)>, String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT source_key, COUNT(*) FROM advisory_record GROUP BY source_key")
            .map_err(|e| format!("prepare count-by-source: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((key, count as usize))
            })
            .map_err(|e| format!("query count-by-source: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("read count row: {e}"))?);
        }
        Ok(result)
    }

    // ── Firewall rule helpers ─────────────────────────────────────────

    pub fn save_firewall_rules(&self, rules: &[FirewallRuleRow]) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| format!("begin firewall_rule transaction: {e}"))?;
        let result = (|| -> Result<(), String> {
            conn.execute("DELETE FROM firewall_rule WHERE removed = 0", [])
                .map_err(|e| format!("clear active firewall rules: {e}"))?;
            let mut stmt = conn
                .prepare(
                    "INSERT OR REPLACE INTO firewall_rule
                     (rule_name, rule_type, target, direction, pid, path,
                      created_unix, expires_unix, removed)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )
                .map_err(|e| format!("prepare firewall_rule insert: {e}"))?;
            for rule in rules {
                stmt.execute(rusqlite::params![
                    rule.rule_name,
                    rule.rule_type,
                    rule.target,
                    rule.direction,
                    rule.pid,
                    rule.path,
                    rule.created_unix as i64,
                    rule.expires_unix.map(|value| value as i64),
                    0i32,
                ])
                .map_err(|e| format!("insert firewall rule {}: {e}", rule.rule_name))?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                conn.execute_batch("COMMIT;")
                    .map_err(|e| format!("commit firewall_rule: {e}"))?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        }
    }

    pub fn load_firewall_rules(&self) -> Result<Vec<FirewallRuleRow>, String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT rule_name, rule_type, target, direction, pid, path,
                        created_unix, expires_unix
                 FROM firewall_rule WHERE removed = 0 ORDER BY rule_name",
            )
            .map_err(|e| format!("prepare firewall_rule select: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(FirewallRuleRow {
                    rule_name: row.get(0)?,
                    rule_type: row.get(1)?,
                    target: row.get(2)?,
                    direction: row.get(3)?,
                    pid: row.get(4)?,
                    path: row.get(5)?,
                    created_unix: row.get::<_, i64>(6)?.max(0) as u64,
                    expires_unix: row
                        .get::<_, Option<i64>>(7)?
                        .map(|value| value.max(0) as u64),
                })
            })
            .map_err(|e| format!("query firewall rules: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("read firewall rule: {e}"))?);
        }
        Ok(result)
    }

    // ── Change-history helpers ─────────────────────────────────────

    pub fn replace_change_events(
        &self,
        changes: &[crate::advisory_history::CveChangeEvent],
        source_key: &str,
    ) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM advisory_change_event WHERE source_key = ?1",
            [source_key],
        )
        .map_err(|e| format!("clear changes for {source_key}: {e}"))?;
        for evt in changes {
            let change_unix = parse_nvd_timestamp(&evt.created).unwrap_or(0);
            let details = serde_json::to_string(evt).unwrap_or_default();
            conn.execute(
                "INSERT INTO advisory_change_event
                 (change_id, primary_id, source_key, change_unix, event_name, details_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    evt.change_id,
                    evt.cve_id,
                    source_key,
                    change_unix as i64,
                    evt.event_name,
                    details,
                ],
            )
            .map_err(|e| format!("insert change {}: {e}", evt.change_id))?;
        }
        Ok(())
    }

    pub fn load_change_history_cache(
        &self,
    ) -> Result<Option<crate::advisory_history::ChangeHistoryCache>, String> {
        use crate::advisory_history::{ChangeHistoryCache, CveChangeEvent};
        let sources = self
            .load_advisory_sources()?
            .into_iter()
            .filter(|source| source.source_key == "nvd-cve-history")
            .collect::<Vec<_>>();
        if sources.is_empty() {
            return Ok(None);
        }
        let conn = self.conn()?;
        let mut changes = Vec::new();
        for src in &sources {
            let mut stmt = conn
                .prepare(
                    "SELECT details_json FROM advisory_change_event
                     WHERE source_key = ?1 ORDER BY change_unix",
                )
                .map_err(|e| format!("prepare change select: {e}"))?;
            let rows = stmt
                .query_map(rusqlite::params![src.source_key], |row| {
                    let payload: String = row.get(0)?;
                    Ok(payload)
                })
                .map_err(|e| format!("query changes for {}: {e}", src.source_key))?;
            for row in rows {
                let payload = row.map_err(|e| format!("read change: {e}"))?;
                if let Ok(evt) = serde_json::from_str::<CveChangeEvent>(&payload) {
                    changes.push(evt);
                }
            }
        }
        Ok(Some(ChangeHistoryCache {
            schema_version: 1,
            generated_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            sources,
            changes,
        }))
    }

    pub fn verify(&self) -> Result<bool, String> {
        let stored: Option<StorageManifest> =
            crate::security::policy::load_struct_with_integrity(&self.manifest_path)
                .map_err(|e| format!("load manifest: {e}"))?;
        let Some(manifest) = stored else {
            return Ok(false);
        };
        let current_digest = self.compute_digest()?;
        Ok(manifest.digest == current_digest)
    }

    /// Rebuild the query planner statistics. Call this after bulk imports
    /// so the planner can make better index choices.
    pub fn analyze(&self) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute_batch("ANALYZE;")
            .map_err(|e| format!("analyze: {e}"))
    }

    /// Perform WAL checkpoint to keep the WAL file from growing unbounded.
    /// Call this periodically (e.g. after every batch of writes).
    pub fn wal_checkpoint(&self) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| format!("WAL checkpoint: {e}"))
    }

    pub fn checkpoint(&self) -> Result<StorageManifest, String> {
        // Flush WAL before computing digest so the digest covers
        // all committed data and the WAL stays bounded.
        let _ = self.wal_checkpoint();
        // Refresh query planner statistics after writes.
        let _ = self.analyze();
        let digest = self.compute_digest()?;
        let table_count = {
            let conn = self.conn()?;
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| format!("count tables: {e}"))?;
            count as usize
        };
        let manifest = StorageManifest {
            schema_version: SCHEMA_VERSION,
            generated_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            digest,
            table_count,
        };
        crate::security::policy::save_struct_with_integrity(&self.manifest_path, &manifest)
            .map_err(|e| format!("save manifest: {e}"))?;
        Ok(manifest)
    }

    fn compute_digest(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};

        let conn = self.conn()?;
        let table_rows: Vec<(String, String)> = conn
            .prepare("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name")
            .map_err(|e| format!("list tables: {e}"))?
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let sql: Option<String> = row.get(1)?;
                Ok((name, sql.unwrap_or_default()))
            })
            .map_err(|e| format!("query tables: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

        let mut hasher = Sha256::new();
        for (table, create_sql) in &table_rows {
            hasher.update(b"table:");
            hasher.update(table.as_bytes());
            hasher.update(b"\nsql:");
            hasher.update(create_sql.as_bytes());
            hasher.update(b"\n");

            let columns = table_columns(&conn, table)?;
            if columns.is_empty() {
                continue;
            }
            for column in &columns {
                hasher.update(b"column:");
                hasher.update(column.as_bytes());
                hasher.update(b"\n");
            }

            let sql = ordered_row_digest_query(table, &columns);
            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| format!("prepare digest query for {table}: {e}"))?;
            let mut rows = stmt
                .query([])
                .map_err(|e| format!("run digest query for {table}: {e}"))?;
            while let Some(row) = rows
                .next()
                .map_err(|e| format!("read digest row for {table}: {e}"))?
            {
                hasher.update(b"row:");
                for (index, column) in columns.iter().enumerate() {
                    hasher.update(column.as_bytes());
                    hasher.update(b"=");
                    let value = row
                        .get_ref(index)
                        .map_err(|e| format!("read {table}.{column}: {e}"))?;
                    update_hash_with_value(&mut hasher, value);
                    hasher.update(b"|");
                }
                hasher.update(b"\n");
            }
        }

        let result = hasher.finalize();
        Ok(result.iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// RAII guard that derefs to `StorageDb` so callers can use
/// `StorageDb::global()?.some_method()` directly.
pub struct DbGuard(pub std::sync::MutexGuard<'static, Option<StorageDb>>);

impl std::ops::Deref for DbGuard {
    type Target = StorageDb;
    fn deref(&self) -> &StorageDb {
        self.0
            .as_ref()
            .expect("DbGuard value is always Some after global()")
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>, String> {
    let sql = format!("PRAGMA table_info({})", quote_identifier(table));
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("prepare table info for {table}: {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get(1))
        .map_err(|e| format!("query table info for {table}: {e}"))?;
    let mut columns = Vec::new();
    for row in rows {
        columns.push(row.map_err(|e| format!("read table info for {table}: {e}"))?);
    }
    Ok(columns)
}

fn ordered_row_digest_query(table: &str, columns: &[String]) -> String {
    let quoted_columns: Vec<String> = columns
        .iter()
        .map(|column| quote_identifier(column))
        .collect();
    format!(
        "SELECT {} FROM {} ORDER BY {}",
        quoted_columns.join(", "),
        quote_identifier(table),
        quoted_columns.join(", ")
    )
}

fn update_hash_with_value<D: sha2::Digest>(hasher: &mut D, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update(b"null"),
        ValueRef::Integer(v) => hasher.update(format!("int:{v}").as_bytes()),
        ValueRef::Real(v) => hasher.update(format!("real:{:016x}", v.to_bits()).as_bytes()),
        ValueRef::Text(bytes) => {
            hasher.update(b"text:");
            hasher.update(bytes);
        }
        ValueRef::Blob(bytes) => {
            hasher.update(format!("blob:{}:", bytes.len()).as_bytes());
            hasher.update(bytes);
        }
    }
}

fn advisory_record_identity_keys(
    record: &crate::advisory::VulnerabilityRecord,
) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for affected in &record.affected_products {
        let affected_ref = crate::advisory_match::AffectedProductRef {
            criteria: &affected.criteria,
            match_criteria_id: affected.match_criteria_id.as_deref(),
            cpe_name: affected.cpe_name.as_deref(),
            vulnerable: affected.vulnerable,
            version_start_including: affected.version_start_including.as_deref(),
            version_start_excluding: affected.version_start_excluding.as_deref(),
            version_end_including: affected.version_end_including.as_deref(),
            version_end_excluding: affected.version_end_excluding.as_deref(),
        };
        keys.extend(crate::advisory_match::affected_product_identity_keys(
            &affected_ref,
        ));
    }
    keys
}

fn advisory_record_search_text(record: &crate::advisory::VulnerabilityRecord) -> String {
    let mut parts = vec![
        record.primary_id.as_str(),
        record.provenance.source_kind.as_str(),
        record.provenance.source_key.as_str(),
        record.summary.as_str(),
    ];
    for alias in &record.aliases {
        parts.push(alias.as_str());
    }
    for severity in &record.severities {
        parts.push(severity.source.as_str());
        parts.push(severity.scheme.as_str());
        parts.push(severity.severity.as_str());
        if let Some(vector) = severity.vector.as_ref() {
            parts.push(vector.as_str());
        }
    }
    for affected in &record.affected_products {
        parts.push(affected.criteria.as_str());
        if let Some(match_criteria_id) = affected.match_criteria_id.as_ref() {
            parts.push(match_criteria_id.as_str());
        }
        if let Some(cpe_name) = affected.cpe_name.as_ref() {
            parts.push(cpe_name.as_str());
        }
    }
    for reference in &record.references {
        parts.push(reference.url.as_str());
        if let Some(source) = reference.source.as_ref() {
            parts.push(source.as_str());
        }
        for tag in &reference.tags {
            parts.push(tag.as_str());
        }
    }
    for mitigation in &record.mitigations {
        parts.push(mitigation.as_str());
    }
    if let Some(fix_version) = record.fix_version.as_ref() {
        parts.push(fix_version.as_str());
    }
    for workaround in &record.workaround_instructions {
        parts.push(workaround.as_str());
    }
    for upgrade in &record.upgrade_instructions {
        parts.push(upgrade.as_str());
    }
    parts.join(" ").to_lowercase()
}

fn ensure_advisory_product_index_populated(conn: &Connection) -> Result<(), String> {
    let record_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM advisory_record", [], |row| row.get(0))
        .map_err(|e| format!("count advisory records for product index: {e}"))?;
    if record_count == 0 {
        return Ok(());
    }
    let index_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM advisory_product_index", [], |row| {
            row.get(0)
        })
        .map_err(|e| format!("count advisory product index: {e}"))?;
    if index_count > 0 {
        return Ok(());
    }

    let mut select = conn
        .prepare("SELECT primary_id, source_key, source_kind, payload_json FROM advisory_record")
        .map_err(|e| format!("prepare advisory product index backfill: {e}"))?;
    let mut insert = conn
        .prepare(
            "INSERT OR IGNORE INTO advisory_product_index
             (identity_key, primary_id, source_key, source_kind)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .map_err(|e| format!("prepare advisory product index insert: {e}"))?;
    let rows = select
        .query_map([], |row| {
            let primary_id: String = row.get(0)?;
            let source_key: String = row.get(1)?;
            let source_kind: String = row.get(2)?;
            let payload: String = row.get(3)?;
            Ok((primary_id, source_key, source_kind, payload))
        })
        .map_err(|e| format!("query advisory records for product index: {e}"))?;

    for row in rows {
        let (primary_id, source_key, source_kind, payload) =
            row.map_err(|e| format!("read advisory record for product index: {e}"))?;
        let Ok(record) = serde_json::from_str::<crate::advisory::VulnerabilityRecord>(&payload)
        else {
            continue;
        };
        for identity_key in advisory_record_identity_keys(&record) {
            insert
                .execute(rusqlite::params![
                    &identity_key,
                    &primary_id,
                    &source_key,
                    &source_kind
                ])
                .map_err(|e| format!("insert advisory product index row: {e}"))?;
        }
    }
    Ok(())
}

fn ensure_advisory_search_index_populated(conn: &Connection) -> Result<(), String> {
    let record_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM advisory_record", [], |row| row.get(0))
        .map_err(|e| format!("count advisory records for search index: {e}"))?;
    if record_count == 0 {
        return Ok(());
    }
    let index_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM advisory_record_search", [], |row| {
            row.get(0)
        })
        .map_err(|e| format!("count advisory search index: {e}"))?;
    if index_count >= record_count {
        return Ok(());
    }

    let mut select = conn
        .prepare("SELECT primary_id, source_key, source_kind, payload_json FROM advisory_record")
        .map_err(|e| format!("prepare advisory search index backfill: {e}"))?;
    let mut insert = conn
        .prepare(
            "INSERT OR REPLACE INTO advisory_record_search
             (primary_id, source_key, source_kind, search_text)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .map_err(|e| format!("prepare advisory search index insert: {e}"))?;
    let rows = select
        .query_map([], |row| {
            let primary_id: String = row.get(0)?;
            let source_key: String = row.get(1)?;
            let source_kind: String = row.get(2)?;
            let payload: String = row.get(3)?;
            Ok((primary_id, source_key, source_kind, payload))
        })
        .map_err(|e| format!("query advisory records for search index: {e}"))?;

    for row in rows {
        let (primary_id, source_key, source_kind, payload) =
            row.map_err(|e| format!("read advisory record for search index: {e}"))?;
        let Ok(record) = serde_json::from_str::<crate::advisory::VulnerabilityRecord>(&payload)
        else {
            continue;
        };
        insert
            .execute(rusqlite::params![
                &primary_id,
                &source_key,
                &source_kind,
                advisory_record_search_text(&record)
            ])
            .map_err(|e| format!("insert advisory search index row: {e}"))?;
    }
    Ok(())
}

fn parse_nvd_timestamp(ts: &Option<String>) -> Option<u64> {
    let s = ts.as_ref()?;
    if let Ok(dt) =
        chrono::NaiveDateTime::parse_from_str(s.split('.').next().unwrap_or(s), "%Y-%m-%dT%H:%M:%S")
    {
        return Some(dt.and_utc().timestamp() as u64);
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp() as u64);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> StorageDb {
        let unique = format!(
            "vigil-db-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DB_FILENAME);
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let conn = Connection::open(&path).unwrap();
        let db = StorageDb {
            conn: Mutex::new(conn),
            path,
            manifest_path,
        };
        db.bootstrap().unwrap();
        db
    }

    fn sample_source(source_key: &str, source_kind: &str) -> crate::advisory::AdvisorySourceCache {
        crate::advisory::AdvisorySourceCache {
            source_key: source_key.to_string(),
            source_kind: source_kind.to_string(),
            source_url: format!("https://example.test/{source_key}"),
            fetched_unix: 1,
            expires_unix: 2,
            status: crate::advisory::SourceHealth::Fresh,
            ..Default::default()
        }
    }

    fn sample_record(
        primary_id: &str,
        source_key: &str,
        source_kind: &str,
    ) -> crate::advisory::VulnerabilityRecord {
        crate::advisory::VulnerabilityRecord {
            primary_id: primary_id.to_string(),
            summary: "test record".to_string(),
            published: Some("2026-05-19T08:00:00".to_string()),
            last_modified: Some("2026-05-19T08:05:00".to_string()),
            severities: vec![crate::advisory::VulnerabilitySeverity {
                source: source_kind.to_string(),
                scheme: "cvss".to_string(),
                severity: "HIGH".to_string(),
                score: Some(7.5),
                vector: None,
            }],
            provenance: crate::advisory::VulnerabilityProvenance {
                source_kind: source_kind.to_string(),
                source_key: source_key.to_string(),
                source_url: format!("https://example.test/{source_key}"),
                imported_unix: 1,
            },
            ..Default::default()
        }
    }

    #[test]
    fn bootstrap_creates_tables() {
        let db = test_db();
        let conn = db.conn().unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(tables.contains(&"meta".to_string()), "meta table");
        assert!(
            tables.contains(&"advisory_source".to_string()),
            "advisory_source table"
        );
        assert!(
            tables.contains(&"advisory_record".to_string()),
            "advisory_record table"
        );
        assert!(
            tables.contains(&"advisory_change_event".to_string()),
            "advisory_change_event table"
        );
        assert!(
            tables.contains(&"advisory_record_search".to_string()),
            "advisory_record_search table"
        );
        assert!(
            tables.contains(&"software_inventory".to_string()),
            "software_inventory table"
        );
    }

    #[test]
    fn schema_version_is_stored() {
        let db = test_db();
        let conn = db.conn().unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn compute_digest_is_stable() {
        let db = test_db();
        let d1 = db.compute_digest().unwrap();
        let d2 = db.compute_digest().unwrap();
        assert_eq!(d1, d2, "digest should be deterministic on empty db");
    }

    #[test]
    fn checkpoint_and_verify_round_trip() {
        let db = test_db();
        let manifest = db.checkpoint().unwrap();
        assert_eq!(manifest.schema_version, 1);
        assert!(manifest.generated_unix > 0);
        assert!(!manifest.digest.is_empty());

        let verified = db.verify().unwrap();
        assert!(verified, "verify after checkpoint");
    }

    #[test]
    fn verify_fails_after_tamper() {
        let db = test_db();
        db.checkpoint().unwrap();

        {
            let conn = db.conn().unwrap();
            conn.execute("INSERT INTO meta (key, value) VALUES ('tamper', 'yes')", [])
                .unwrap();
        }

        let verified = db.verify().unwrap();
        assert!(!verified, "verify should fail after tamper");
    }

    #[test]
    fn verify_fails_after_record_content_tamper() {
        let db = test_db();
        let source = sample_source("nvd-cve", "nvd");
        let record = sample_record("CVE-2026-0001", &source.source_key, &source.source_kind);
        db.replace_advisory_sources(std::slice::from_ref(&source))
            .unwrap();
        db.replace_advisory_records(
            std::slice::from_ref(&record),
            &source.source_key,
            &source.source_kind,
        )
        .unwrap();
        db.checkpoint().unwrap();

        {
            let conn = db.conn().unwrap();
            conn.execute(
                "UPDATE advisory_record SET payload_json = ?1 WHERE primary_id = ?2",
                rusqlite::params!["{\"tampered\":true}", record.primary_id],
            )
            .unwrap();
        }

        let verified = db.verify().unwrap();
        assert!(!verified, "verify should fail after record-content tamper");
    }

    #[test]
    fn replace_advisory_sources_clears_dependent_rows_before_replacing_sources() {
        let db = test_db();
        let source1 = sample_source("nvd-cve", "nvd");
        let source2 = sample_source("bsi", "bsi");
        let record1 = sample_record("CVE-2026-0001", &source1.source_key, &source1.source_kind);
        let record2 = sample_record("BSI-2026-0002", &source2.source_key, &source2.source_kind);

        db.replace_advisory_sources(std::slice::from_ref(&source1))
            .unwrap();
        db.replace_advisory_records(
            std::slice::from_ref(&record1),
            &source1.source_key,
            &source1.source_kind,
        )
        .unwrap();

        db.replace_advisory_sources(&[source1.clone(), source2.clone()])
            .unwrap();
        db.replace_advisory_records(
            std::slice::from_ref(&record1),
            &source1.source_key,
            &source1.source_kind,
        )
        .unwrap();
        db.replace_advisory_records(
            std::slice::from_ref(&record2),
            &source2.source_key,
            &source2.source_kind,
        )
        .unwrap();

        let sources = db.load_advisory_sources().unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(db.count_advisory_records().unwrap(), 2);
    }

    #[test]
    fn advisory_product_index_loads_matching_records_by_identity_key() {
        let db = test_db();
        let source = sample_source("nvd-cve", "nvd");
        let mut chrome = sample_record("CVE-2026-0001", &source.source_key, &source.source_kind);
        chrome.affected_products = vec![crate::advisory::AffectedProduct {
            criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*".to_string(),
            vulnerable: true,
            ..Default::default()
        }];
        let mut firefox = sample_record("CVE-2026-0002", &source.source_key, &source.source_kind);
        firefox.affected_products = vec![crate::advisory::AffectedProduct {
            criteria: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*".to_string(),
            vulnerable: true,
            ..Default::default()
        }];

        db.replace_advisory_sources(std::slice::from_ref(&source))
            .unwrap();
        db.replace_advisory_records(&[chrome, firefox], &source.source_key, &source.source_kind)
            .unwrap();

        let records = db
            .load_advisory_records_for_identity_keys(&["google-chrome".to_string()], 10)
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].primary_id, "CVE-2026-0001");
    }

    #[test]
    fn advisory_product_index_query_is_bounded() {
        let db = test_db();
        let source = sample_source("nvd-cve", "nvd");
        let mut first = sample_record("CVE-2026-0001", &source.source_key, &source.source_kind);
        let mut second = sample_record("CVE-2026-0002", &source.source_key, &source.source_kind);
        for record in [&mut first, &mut second] {
            record.affected_products = vec![crate::advisory::AffectedProduct {
                criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*".to_string(),
                vulnerable: true,
                ..Default::default()
            }];
        }

        db.replace_advisory_sources(std::slice::from_ref(&source))
            .unwrap();
        db.replace_advisory_records(&[first, second], &source.source_key, &source.source_kind)
            .unwrap();

        let records = db
            .load_advisory_records_for_identity_keys(&["chrome".to_string()], 1)
            .unwrap();

        assert_eq!(records.len(), 1);
    }

    #[test]
    fn search_advisory_records_filters_and_limits() {
        let db = test_db();
        let source = sample_source("nvd-cve", "nvd");
        let mut chrome = sample_record("CVE-2026-0001", &source.source_key, &source.source_kind);
        chrome.summary = "Google Chrome renderer issue".to_string();
        chrome.known_exploited = true;
        chrome.affected_products = vec![crate::advisory::AffectedProduct {
            criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*".to_string(),
            vulnerable: true,
            ..Default::default()
        }];
        chrome.references = vec![crate::advisory::VulnerabilityReference {
            url: "https://vendor.example/chrome/security".to_string(),
            source: Some("vendor".to_string()),
            tags: vec!["patch".to_string()],
        }];
        let mut openssl = sample_record("CVE-2026-0002", &source.source_key, &source.source_kind);
        openssl.summary = "OpenSSL parsing issue".to_string();

        db.replace_advisory_sources(std::slice::from_ref(&source))
            .unwrap();
        db.replace_advisory_records(&[chrome, openssl], &source.source_key, &source.source_kind)
            .unwrap();

        let records = db.search_advisory_records("chrome", 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].primary_id, "CVE-2026-0001");

        let records = db.search_advisory_records("vendor.example", 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].primary_id, "CVE-2026-0001");

        let records = db.search_advisory_records("nvd", 10).unwrap();
        assert_eq!(records.len(), 2);

        let records = db.search_advisory_records("", 1).unwrap();
        assert_eq!(records.len(), 1);
    }
}
