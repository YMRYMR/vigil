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
    path: PathBuf,
    manifest_path: PathBuf,
}

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
                fetched_unix INTEGER NOT NULL DEFAULT 0,
                expires_unix INTEGER NOT NULL DEFAULT 0,
                status       TEXT NOT NULL DEFAULT 'ok',
                last_error   TEXT NOT NULL DEFAULT ''
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
        conn.execute("DELETE FROM advisory_record", [])
            .map_err(|e| format!("clear records: {e}"))?;
        conn.execute("DELETE FROM advisory_source", [])
            .map_err(|e| format!("clear sources: {e}"))?;
        let mut stmt = conn
            .prepare(
                "INSERT INTO advisory_source
                 (source_key, source_kind, source_url, fetched_unix, expires_unix, status, last_error, retry_after_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .map_err(|e| format!("prepare source insert: {e}"))?;
        for src in sources {
            let status = match &src.status {
                crate::advisory::SourceHealth::Fresh => "fresh",
                crate::advisory::SourceHealth::Stale => "stale",
                crate::advisory::SourceHealth::Error => "error",
            };
            stmt.execute(rusqlite::params![
                src.source_key,
                src.source_kind,
                src.source_url,
                src.fetched_unix,
                src.expires_unix,
                status,
                src.last_error.as_deref().unwrap_or(""),
                src.retry_after_unix,
            ])
            .map_err(|e| format!("insert source {}: {e}", src.source_key))?;
        }
        Ok(())
    }

    pub fn load_advisory_sources(
        &self,
    ) -> Result<Vec<crate::advisory::AdvisorySourceCache>, String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT source_key, source_kind, source_url, fetched_unix,
                        expires_unix, status, last_error, retry_after_unix
                 FROM advisory_source ORDER BY source_key",
            )
            .map_err(|e| format!("prepare source select: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                let source_key: String = row.get(0)?;
                let source_kind: String = row.get(1)?;
                let source_url: String = row.get(2)?;
                let fetched_unix: u64 = row.get(3)?;
                let expires_unix: u64 = row.get(4)?;
                let status_str: String = row.get(5)?;
                let last_error: String = row.get(6)?;
                let retry_after_unix: u64 = row.get(7)?;
                let status = match status_str.as_str() {
                    "stale" => crate::advisory::SourceHealth::Stale,
                    "error" => crate::advisory::SourceHealth::Error,
                    _ => crate::advisory::SourceHealth::Fresh,
                };
                Ok(crate::advisory::AdvisorySourceCache {
                    source_key,
                    source_kind,
                    source_url,
                    imported_from: None,
                    imported_from_batch: Vec::new(),
                    fetched_unix,
                    expires_unix,
                    snapshot_sha256: String::new(),
                    total_results: 0,
                    status,
                    last_attempt_unix: 0,
                    last_error: if last_error.is_empty() {
                        None
                    } else {
                        Some(last_error)
                    },
                    retry_after_unix,
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
                published_unix,
                updated_unix,
                severity,
                rec.known_exploited as i64,
                payload,
            ])
            .map_err(|e| format!("insert record {}: {e}", rec.primary_id))?;
        }
        Ok(())
    }

    pub fn count_advisory_records(&self) -> Result<usize, String> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM advisory_record", [], |row| row.get(0))
            .map_err(|e| format!("count records: {e}"))?;
        Ok(count as usize)
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
            .query_map(rusqlite::params![since_unix], |row| {
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
        let max: Option<Option<u64>> = conn
            .query_row("SELECT MAX(updated_unix) FROM advisory_record", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| format!("max updated_unix: {e}"))?;
        Ok(max.unwrap_or(None))
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
                    .as_secs(),
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
                    change_unix,
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
        let sources = self.load_advisory_sources()?;
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
}
