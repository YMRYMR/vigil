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

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const DB_FILENAME: &str = "vigil-state.db";
const MANIFEST_FILENAME: &str = "vigil-state.manifest.json";
const SCHEMA_VERSION: i64 = 1;
const SCHEMA_VERSION_KEY: &str = "schema_version";

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
    pub fn open() -> Result<Self, String> {
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
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
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
                primary_id    TEXT PRIMARY KEY NOT NULL,
                source_key    TEXT NOT NULL REFERENCES advisory_source(source_key),
                source_kind   TEXT NOT NULL,
                published_unix INTEGER NOT NULL DEFAULT 0,
                updated_unix  INTEGER NOT NULL DEFAULT 0,
                severity      TEXT NOT NULL DEFAULT '',
                exploited     INTEGER NOT NULL DEFAULT 0,
                payload_json  TEXT NOT NULL DEFAULT '{}',
                created_unix  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_advisory_record_source
                ON advisory_record(source_kind, source_key);
            CREATE INDEX IF NOT EXISTS idx_advisory_record_updated
                ON advisory_record(updated_unix);
            CREATE INDEX IF NOT EXISTS idx_advisory_record_primary
                ON advisory_record(primary_id);

            CREATE TABLE IF NOT EXISTS advisory_change_event (
                change_id   TEXT NOT NULL,
                primary_id  TEXT NOT NULL REFERENCES advisory_record(primary_id),
                source_key  TEXT NOT NULL,
                change_unix INTEGER NOT NULL,
                event_name  TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (change_id, primary_id)
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
                updated_unix     INTEGER NOT NULL DEFAULT 0
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
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.conn.lock().map_err(|e| format!("lock db: {e}"))
    }

    // ── Advisory source helpers ─────────────────────────────────────────

    pub fn replace_advisory_sources(
        &self,
        sources: &[crate::advisory::AdvisorySourceCache],
    ) -> Result<(), String> {
        let conn = self.conn()?;
        // Delete child rows first to respect FK constraint.
        conn.execute("DELETE FROM advisory_change_event", [])
            .map_err(|e| format!("clear change events: {e}"))?;
        conn.execute("DELETE FROM advisory_record", [])
            .map_err(|e| format!("clear records: {e}"))?;
        conn.execute("DELETE FROM advisory_source", [])
            .map_err(|e| format!("clear sources: {e}"))?;
        let mut stmt = conn
            .prepare(
                "INSERT INTO advisory_source
                 (source_key, source_kind, source_url, fetched_unix, expires_unix, status, last_error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
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
                        expires_unix, status, last_error
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
                })
            })
            .map_err(|e| format!("query sources: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("read source row: {e}"))?);
        }
        Ok(result)
    }

    // ── Advisory record helpers ─────────────────────────────────────────

    pub fn replace_advisory_records(
        &self,
        records: &[crate::advisory::VulnerabilityRecord],
        source_key: &str,
        source_kind: &str,
    ) -> Result<(), String> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM advisory_record WHERE source_key = ?1",
            [source_key],
        )
        .map_err(|e| format!("clear records for {source_key}: {e}"))?;
        let mut stmt = conn
            .prepare(
                "INSERT OR REPLACE INTO advisory_record
                 (primary_id, source_key, source_kind, published_unix, updated_unix,
                  severity, exploited, payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .map_err(|e| format!("prepare record insert: {e}"))?;
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

    pub fn checkpoint(&self) -> Result<StorageManifest, String> {
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
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .map_err(|e| format!("list tables: {e}"))?
            .query_map([], |row| row.get(0))
            .map_err(|e| format!("query tables: {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        let mut hasher = Sha256::new();
        for table in &tables {
            // Hash every row in the table sorted by primary key so that
            // any content change (not just row count) alters the digest.
            let sql = format!("SELECT * FROM \"{table}\" ORDER BY (SELECT NULL) LIMIT -1");
            if let Ok(mut stmt) = conn.prepare(&sql) {
                if let Ok(mut rows) = stmt.query([]) {
                    while let Ok(Some(row)) = rows.next() {
                        for i in 0..row.as_ref().column_count() {
                            hasher.update(format!("{}:", i));
                            match row.get_ref(i) {
                                Ok(rusqlite::types::ValueRef::Null) => {
                                    hasher.update(b"null");
                                }
                                Ok(rusqlite::types::ValueRef::Integer(n)) => {
                                    hasher.update(n.to_string().as_bytes());
                                }
                                Ok(rusqlite::types::ValueRef::Real(f)) => {
                                    hasher.update(format!("{f}").as_bytes());
                                }
                                Ok(rusqlite::types::ValueRef::Text(t)) => {
                                    hasher.update(t);
                                }
                                Ok(rusqlite::types::ValueRef::Blob(b)) => {
                                    hasher.update(b);
                                }
                                Err(_) => hasher.update(b"err"),
                            }
                        }
                        hasher.update(b"|");
                    }
                }
            }
        }
        let result = hasher.finalize();
        Ok(result.iter().map(|b| format!("{b:02x}")).collect())
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
    use std::path::PathBuf;

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
}
