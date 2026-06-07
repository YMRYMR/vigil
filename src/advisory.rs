//! Public vulnerability intelligence foundations.
//!
//! Phase 16 starts with NVD ingestion, but the full roadmap item includes
//! scheduling, rate-limit-aware sync, CPE/CPE-match ingestion, and broader
//! source correlation. This module implements the smallest safe slice:
//!
//! - a normalized vulnerability record model
//! - protected local cache storage for imported NVD CVE snapshots
//! - preserved CPE match metadata such as `matchCriteriaId` and `cpeName`
//!   so future CPE-match joins keep the original NVD identifiers intact
//! - a CLI import path for offline or operator-driven snapshot ingestion,
//!   including batched page or incremental-file imports
//! - live NVD CVE sync with conservative rate limiting and incremental
//!   last-modified windows
//! - startup status logging so the cache state is visible to operators

use chrono::Datelike;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DB_SCHEMA_VERSION: u32 = 1;
const DEFAULT_SOURCE_TTL_SECS: u64 = 24 * 60 * 60;
const NVD_SOURCE_KEY: &str = "nvd-cve";
const NVD_SOURCE_KIND: &str = "nvd";
const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_FEED_BASE_URL: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
const NVD_FIRST_FEED_YEAR: i32 = 2002;
const NVD_RESULTS_PER_PAGE: usize = 2_000;
const NVD_MIN_SYNC_INTERVAL_SECS: u64 = 2 * 60 * 60;
const NVD_MAX_INCREMENTAL_WINDOW_DAYS: i64 = 120;
const NVD_REQUEST_DELAY_NO_KEY_SECS: u64 = 6;
const NVD_REQUEST_DELAY_WITH_KEY_SECS: u64 = 1;
const HTTP_TIMEOUT_SECS: u64 = 20;
const MAX_RETRY_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdvisoryCache {
    pub schema_version: u32,
    pub generated_unix: u64,
    pub sources: Vec<AdvisorySourceCache>,
    pub records: Vec<VulnerabilityRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdvisorySourceCache {
    pub source_key: String,
    pub source_kind: String,
    pub source_url: String,
    pub imported_from: Option<String>,
    #[serde(default)]
    pub imported_from_batch: Vec<String>,
    pub fetched_unix: u64,
    pub expires_unix: u64,
    pub snapshot_sha256: String,
    pub total_results: usize,
    pub status: SourceHealth,
    #[serde(default)]
    pub last_attempt_unix: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub retry_after_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceHealth {
    #[default]
    Fresh,
    Stale,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityRecord {
    pub primary_id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub published: Option<String>,
    pub last_modified: Option<String>,
    pub known_exploited: bool,
    pub severities: Vec<VulnerabilitySeverity>,
    pub affected_products: Vec<AffectedProduct>,
    pub references: Vec<VulnerabilityReference>,
    pub mitigations: Vec<String>,
    #[serde(default)]
    pub fix_version: Option<String>,
    #[serde(default)]
    pub workaround_instructions: Vec<String>,
    #[serde(default)]
    pub upgrade_instructions: Vec<String>,
    pub provenance: VulnerabilityProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilitySeverity {
    pub source: String,
    pub scheme: String,
    pub severity: String,
    pub score: Option<f32>,
    pub vector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AffectedProduct {
    pub criteria: String,
    pub match_criteria_id: Option<String>,
    pub cpe_name: Option<String>,
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityReference {
    pub url: String,
    pub source: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityProvenance {
    pub source_kind: String,
    pub source_key: String,
    pub source_url: String,
    pub imported_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    pub imported_files: usize,
    pub imported_records: usize,
    pub known_exploited: usize,
    pub total_records: usize,
    pub total_sources: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheSummary {
    pub records: usize,
    pub sources: usize,
    pub stale_sources: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSummary {
    pub requested_pages: usize,
    pub imported_records: usize,
    pub total_records: usize,
    pub total_sources: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    Updated(SyncSummary),
    SkippedRateLimit { remaining_secs: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NvdSyncRequest {
    start_index: usize,
    results_per_page: usize,
    last_mod_start_date: Option<String>,
    last_mod_end_date: Option<String>,
}

#[derive(Debug)]
struct FetchedNvdPage {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug)]
struct FetchedNvdBatch {
    temp_dir: PathBuf,
    pages: Vec<FetchedNvdPage>,
    imported_records: usize,
    total_results: usize,
}

struct NvdFeed {
    label: String,
    url: String,
    counts_toward_full_total: bool,
}

trait NvdFetcher {
    fn fetch_page(&self, request: &NvdSyncRequest) -> Result<Vec<u8>, String>;
}

struct HttpNvdFetcher {
    client: reqwest::blocking::Client,
    base_url: String,
    api_key: Option<String>,
    last_request_started: Mutex<Option<Instant>>,
}

impl HttpNvdFetcher {
    fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|err| format!("failed to build NVD HTTP client: {err}"))?;
        Ok(Self {
            client,
            base_url: std::env::var("VIGIL_NVD_API_BASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| NVD_API_URL.to_string()),
            api_key: std::env::var("VIGIL_NVD_API_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            last_request_started: Mutex::new(None),
        })
    }

    fn request_delay(&self) -> Duration {
        if self.api_key.is_some() {
            Duration::from_secs(NVD_REQUEST_DELAY_WITH_KEY_SECS)
        } else {
            Duration::from_secs(NVD_REQUEST_DELAY_NO_KEY_SECS)
        }
    }

    fn wait_for_request_slot(&self) {
        let delay = self.request_delay();
        let now = Instant::now();
        let mut last_request_started = self.last_request_started.lock().unwrap();
        let remaining = next_request_delay(*last_request_started, now, delay);
        if !remaining.is_zero() {
            std::thread::sleep(remaining);
        }
        *last_request_started = Some(Instant::now());
    }
}

impl NvdFetcher for HttpNvdFetcher {
    fn fetch_page(&self, request: &NvdSyncRequest) -> Result<Vec<u8>, String> {
        let mut attempt = 0usize;
        loop {
            if attempt == 0 {
                self.wait_for_request_slot();
            }
            let mut http = self.client.get(&self.base_url).query(&[
                ("resultsPerPage", request.results_per_page.to_string()),
                ("startIndex", request.start_index.to_string()),
            ]);
            if let Some(last_mod_start) = request.last_mod_start_date.as_deref() {
                http = http.query(&[("lastModStartDate", last_mod_start)]);
            }
            if let Some(last_mod_end) = request.last_mod_end_date.as_deref() {
                http = http.query(&[("lastModEndDate", last_mod_end)]);
            }
            if let Some(api_key) = self.api_key.as_deref() {
                http = http.header("apiKey", api_key);
            }
            http = http.header(
                reqwest::header::USER_AGENT,
                format!("Vigil/{}", env!("CARGO_PKG_VERSION")),
            );

            let response = http.send().map_err(|err| {
                format!(
                    "failed to fetch NVD page at startIndex {}: {err}",
                    request.start_index
                )
            })?;
            let status = response.status();
            if status.is_success() {
                match response.bytes().map(|bytes| bytes.to_vec()) {
                    Ok(bytes) => return Ok(bytes),
                    Err(_) if attempt + 1 < MAX_RETRY_ATTEMPTS => {
                        std::thread::sleep(self.request_delay().max(Duration::from_secs(1)));
                        attempt += 1;
                        continue;
                    }
                    Err(err) => {
                        return Err(format!(
                            "failed to read NVD response body at startIndex {}: {err}",
                            request.start_index
                        ));
                    }
                }
            }

            if (status.as_u16() == 429 || status.as_u16() == 503)
                && attempt + 1 < MAX_RETRY_ATTEMPTS
            {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(self.request_delay().as_secs());
                std::thread::sleep(Duration::from_secs(retry_after.max(1)));
                attempt += 1;
                continue;
            }

            let body = response.text().unwrap_or_default();
            return Err(format!(
                "NVD request failed with HTTP {} at startIndex {}{}",
                status.as_u16(),
                request.start_index,
                if body.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", body.trim())
                }
            ));
        }
    }
}

fn next_request_delay(
    last_request_started: Option<Instant>,
    now: Instant,
    delay: Duration,
) -> Duration {
    let Some(last_request_started) = last_request_started else {
        return Duration::ZERO;
    };
    delay.saturating_sub(now.saturating_duration_since(last_request_started))
}

pub fn run_import_cli(paths: &[PathBuf]) -> Result<(), String> {
    let summary = if paths.len() == 1 {
        import_nvd_snapshot(&paths[0])?
    } else {
        import_nvd_snapshots(paths)?
    };
    println!(
        "Merged {} NVD CVE records from {} snapshot file(s) into the advisory database ({} marked known exploited in this import set). Database now holds {} records across {} sources.",
        summary.imported_records,
        summary.imported_files,
        summary.known_exploited,
        summary.total_records,
        summary.total_sources
    );
    Ok(())
}

pub fn run_sync_cli(force: bool) -> Result<SyncOutcome, String> {
    let outcome = sync_nvd(force)?;
    match &outcome {
        SyncOutcome::Updated(summary) => {
            println!(
                "Fetched {} NVD page(s) and merged {} CVE record(s) into the advisory database. Database now holds {} records across {} sources.",
                summary.requested_pages,
                summary.imported_records,
                summary.total_records,
                summary.total_sources
            );
        }
        SyncOutcome::SkippedRateLimit { remaining_secs } => {
            println!(
                "Skipped NVD sync because the last automated pull is still inside the 2-hour minimum interval ({}s remaining). Use --sync-nvd --force to override.",
                remaining_secs
            );
        }
    }
    Ok(outcome)
}

pub fn import_nvd_snapshot(path: &Path) -> Result<ImportSummary, String> {
    import_nvd_snapshots(&[path.to_path_buf()])
}

pub fn import_nvd_snapshots(paths: &[PathBuf]) -> Result<ImportSummary, String> {
    if paths.is_empty() {
        return Err("expected at least one NVD snapshot path".into());
    }

    let imported_cache = load_nvd_snapshot_batch(paths)?;
    let imported_records = imported_cache.records.len();
    let known_exploited = imported_cache
        .records
        .iter()
        .filter(|record| record.known_exploited)
        .count();
    let cache = merge_cache(load_cache_for_import()?, imported_cache);
    let summary = ImportSummary {
        imported_files: paths.len(),
        imported_records,
        known_exploited,
        total_records: cache.records.len(),
        total_sources: cache.sources.len(),
    };
    save_cache(&cache)?;
    Ok(summary)
}

pub fn sync_nvd(force: bool) -> Result<SyncOutcome, String> {
    let now = unix_now();
    let existing_source = load_nvd_source_metadata()?;
    if !force {
        if let Some(remaining_secs) = nvd_source_rate_limit_remaining(existing_source.as_ref(), now)
        {
            return Ok(SyncOutcome::SkippedRateLimit { remaining_secs });
        }
    }

    let latest_modified = load_latest_nvd_last_modified_from_db(existing_source.as_ref())?;
    let fetched_result = match latest_modified.as_ref() {
        Some(_) => {
            let fetcher = HttpNvdFetcher::new()?;
            fetch_nvd_increment(latest_modified.clone(), &fetcher, now)
        }
        None => fetch_nvd_initial_feeds(now),
    };
    let mut fetched = match fetched_result {
        Ok(fetched) => fetched,
        Err(err) => {
            let failed_source = nvd_sync_failure_source(existing_source.as_ref(), &err, now);
            if let Err(save_err) = save_nvd_source_status(&failed_source) {
                tracing::warn!(%save_err, "failed to persist NVD sync failure state");
            }
            return Err(err);
        }
    };
    if latest_modified.is_some() {
        if let Some(source) = existing_source.as_ref() {
            fetched.total_results = fetched.total_results.max(source.total_results);
        }
    }
    let fetched_pages = fetched.pages.len();
    let imported_records = fetched.imported_records;
    if let Err(err) = save_fetched_nvd_batch(&fetched, now) {
        let failed_source = nvd_sync_failure_source(existing_source.as_ref(), &err, now);
        if let Err(save_err) = save_nvd_source_status(&failed_source) {
            tracing::warn!(%save_err, "failed to persist NVD sync failure state");
        }
        let _ = fs::remove_dir_all(&fetched.temp_dir);
        return Err(err);
    }
    let _ = fs::remove_dir_all(&fetched.temp_dir);
    let db = crate::storage::db::StorageDb::global()?;
    let summary = SyncSummary {
        requested_pages: fetched_pages,
        imported_records,
        total_records: db.count_advisory_records()?,
        total_sources: db.load_advisory_sources()?.len(),
    };
    Ok(SyncOutcome::Updated(summary))
}

pub fn log_cache_status() {
    match load_cache_summary() {
        Ok(Some(summary)) => {
            tracing::info!(
                records = summary.records,
                sources = summary.sources,
                stale_sources = summary.stale_sources,
                "public advisory cache loaded"
            );
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(%err, "failed to load public advisory cache");
        }
    }
}

#[allow(dead_code)]
pub fn refresh_nvd_in_background_if_due() {
    if !nvd_refresh_due() {
        return;
    }

    match sync_nvd(false) {
        Ok(SyncOutcome::Updated(summary)) => {
            tracing::info!(
                requested_pages = summary.requested_pages,
                imported_records = summary.imported_records,
                total_records = summary.total_records,
                total_sources = summary.total_sources,
                "refreshed NVD advisory cache"
            );
        }
        Ok(SyncOutcome::SkippedRateLimit { remaining_secs }) => {
            tracing::debug!(
                remaining_secs,
                "skipped NVD advisory refresh because the rate-limit interval is still active"
            );
        }
        Err(err) => {
            tracing::warn!(%err, "failed to refresh NVD advisory cache");
        }
    }
}

fn load_cache_summary() -> Result<Option<CacheSummary>, String> {
    let Some(cache) = load_cache()? else {
        return Ok(None);
    };
    let now = unix_now();
    Ok(Some(CacheSummary {
        records: cache.records.len(),
        sources: cache.sources.len(),
        stale_sources: cache
            .sources
            .iter()
            .filter(|source| source.expires_unix > 0 && source.expires_unix < now)
            .count(),
    }))
}

fn load_cache() -> Result<Option<AdvisoryCache>, String> {
    let db = crate::storage::db::StorageDb::global()?;
    db.load_advisory_cache()
}

fn load_cache_for_import() -> Result<Option<AdvisoryCache>, String> {
    match load_cache() {
        Ok(cache) => Ok(cache),
        Err(err) if err.contains("unsupported schema version") => {
            tracing::warn!(%err, "ignoring incompatible advisory cache during import");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn save_cache(cache: &AdvisoryCache) -> Result<(), String> {
    let update_started = Instant::now();
    let db = crate::storage::db::StorageDb::global()?;
    db.begin()?;
    let result = (|| -> Result<(), String> {
        db.replace_advisory_sources(&cache.sources)?;
        for source in &cache.sources {
            let source_records: Vec<_> = cache
                .records
                .iter()
                .filter(|r| r.provenance.source_key == source.source_key)
                .cloned()
                .collect();
            if !source_records.is_empty() {
                db.replace_advisory_records(
                    &source_records,
                    &source.source_key,
                    &source.source_kind,
                )?;
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            db.commit()?;
            db.checkpoint()?;
            tracing::info!(
                sources = cache.sources.len(),
                records = cache.records.len(),
                elapsed_ms = update_started.elapsed().as_millis() as u64,
                "updated advisory database"
            );
            // Extract IOCs from advisory records and feed into blocklist engine.
            let iocs = crate::advisory_ioc::extract_iocs(&cache.records);
            if !iocs.is_empty() {
                crate::blocklist::add_advisory_iocs(
                    "advisory",
                    iocs.ips,
                    iocs.domains,
                    iocs.hashes,
                );
            }
            Ok(())
        }
        Err(err) => {
            let _ = db.rollback();
            Err(err)
        }
    }
}

fn save_nvd_source_status(source: &AdvisorySourceCache) -> Result<(), String> {
    let db = crate::storage::db::StorageDb::global()?;
    db.begin()?;
    let result = db.upsert_advisory_source(source);
    match result {
        Ok(()) => {
            db.commit()?;
            db.checkpoint().map(|_| ())
        }
        Err(err) => {
            let _ = db.rollback();
            Err(err)
        }
    }
}

fn load_nvd_snapshot_batch(paths: &[PathBuf]) -> Result<AdvisoryCache, String> {
    let mut imported = None;
    let mut page_hashes = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes =
            std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        page_hashes.push(sha256_hex(&bytes));
        let cache = parse_nvd_snapshot(&bytes, Some(path))?;
        imported = Some(match imported {
            Some(existing) => merge_import_batch_cache(existing, cache),
            None => cache,
        });
    }

    let mut imported =
        imported.ok_or_else(|| "expected at least one NVD snapshot path".to_string())?;
    finalize_import_batch_metadata(&mut imported, &page_hashes);
    Ok(imported)
}

fn fetch_nvd_increment(
    latest_modified: Option<String>,
    fetcher: &dyn NvdFetcher,
    now: u64,
) -> Result<FetchedNvdBatch, String> {
    let sync_started = Instant::now();
    let temp_dir = nvd_sync_temp_dir(now)?;
    let result = (|| -> Result<FetchedNvdBatch, String> {
        let mut pages = Vec::new();
        let mut imported_records = 0usize;
        let mut batch_total_results = 0usize;
        for (last_mod_start_date, last_mod_end_date) in
            nvd_sync_windows_from_latest(latest_modified.as_deref(), now)
        {
            let request_template = NvdSyncRequest {
                start_index: 0,
                results_per_page: NVD_RESULTS_PER_PAGE,
                last_mod_start_date,
                last_mod_end_date,
            };

            let mut start_index = 0usize;
            loop {
                let request = NvdSyncRequest {
                    start_index,
                    ..request_template.clone()
                };
                let fetch_started = Instant::now();
                let bytes = fetcher.fetch_page(&request)?;
                let fetch_elapsed = fetch_started.elapsed();
                let byte_count = bytes.len();
                let page_sha256 = sha256_hex(&bytes);
                let page = parse_nvd_snapshot(&bytes, None)?;
                let total_results = page
                    .sources
                    .first()
                    .map(|source| source.total_results)
                    .unwrap_or(page.records.len());
                batch_total_results = batch_total_results.max(total_results);
                let page_records = page.records.len();
                let path = temp_dir.join(format!("nvd-page-{}.json", pages.len()));
                fs::write(&path, &bytes)
                    .map_err(|err| format!("failed to spool NVD page {}: {err}", pages.len()))?;
                tracing::info!(
                    source = NVD_SOURCE_KIND,
                    start_index = request.start_index,
                    results_per_page = request.results_per_page,
                    bytes = byte_count,
                    records = page_records,
                    elapsed_ms = fetch_elapsed.as_millis() as u64,
                    "fetched NVD advisory page"
                );
                imported_records += page_records;
                pages.push(FetchedNvdPage {
                    path,
                    sha256: page_sha256,
                });

                if page_records == 0
                    || start_index.saturating_add(request.results_per_page) >= total_results
                {
                    break;
                }
                start_index = start_index.saturating_add(request.results_per_page);
            }
        }

        tracing::info!(
            source = NVD_SOURCE_KIND,
            pages = pages.len(),
            records = imported_records,
            elapsed_ms = sync_started.elapsed().as_millis() as u64,
            "fetched NVD advisories from internet"
        );
        Ok(FetchedNvdBatch {
            temp_dir: temp_dir.clone(),
            pages,
            imported_records,
            total_results: batch_total_results,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temp_dir);
    }
    result
}

fn nvd_sync_temp_dir(now: u64) -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_dir = std::env::temp_dir().join(format!(
        "vigil-nvd-sync-{}-{now}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir)
        .map_err(|err| format!("failed to create NVD sync temp dir: {err}"))?;
    Ok(temp_dir)
}

fn fetch_nvd_initial_feeds(now: u64) -> Result<FetchedNvdBatch, String> {
    let sync_started = Instant::now();
    let temp_dir = nvd_sync_temp_dir(now)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS * 6))
        .build()
        .map_err(|err| format!("failed to build NVD feed HTTP client: {err}"))?;
    let result = (|| -> Result<FetchedNvdBatch, String> {
        let feeds = nvd_initial_feed_list();
        let mut pages = Vec::with_capacity(feeds.len());
        let mut imported_records = 0usize;
        let mut full_total_results = 0usize;
        for feed in feeds {
            let fetch_started = Instant::now();
            let compressed = fetch_nvd_feed_bytes(&client, &feed)?;
            let compressed_bytes = compressed.len();
            let bytes = decompress_gzip(&compressed)
                .map_err(|err| format!("failed to decompress {}: {err}", feed.label))?;
            let page_sha256 = sha256_hex(&bytes);
            let page = parse_nvd_snapshot(&bytes, None)?;
            let page_records = page.records.len();
            if feed.counts_toward_full_total {
                full_total_results = full_total_results.saturating_add(page_records);
            }
            let path = temp_dir.join(format!("nvd-feed-{}.json", pages.len()));
            fs::write(&path, &bytes)
                .map_err(|err| format!("failed to spool NVD feed {}: {err}", feed.label))?;
            tracing::info!(
                source = NVD_SOURCE_KIND,
                feed = feed.label,
                bytes = compressed_bytes,
                records = page_records,
                elapsed_ms = fetch_started.elapsed().as_millis() as u64,
                "fetched NVD advisory feed"
            );
            imported_records += page_records;
            pages.push(FetchedNvdPage {
                path,
                sha256: page_sha256,
            });
        }
        tracing::info!(
            source = NVD_SOURCE_KIND,
            feeds = pages.len(),
            records = imported_records,
            full_total_results,
            elapsed_ms = sync_started.elapsed().as_millis() as u64,
            "fetched initial NVD advisory feeds from internet"
        );
        Ok(FetchedNvdBatch {
            temp_dir: temp_dir.clone(),
            pages,
            imported_records,
            total_results: full_total_results,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temp_dir);
    }
    result
}

fn nvd_initial_feed_list() -> Vec<NvdFeed> {
    let current_year = chrono::Utc::now().year();
    let mut feeds = (NVD_FIRST_FEED_YEAR..=current_year)
        .map(|year| NvdFeed {
            label: year.to_string(),
            url: format!("{NVD_FEED_BASE_URL}/nvdcve-2.0-{year}.json.gz"),
            counts_toward_full_total: true,
        })
        .collect::<Vec<_>>();
    feeds.push(NvdFeed {
        label: "modified".into(),
        url: format!("{NVD_FEED_BASE_URL}/nvdcve-2.0-modified.json.gz"),
        counts_toward_full_total: false,
    });
    feeds
}

fn fetch_nvd_feed_bytes(
    client: &reqwest::blocking::Client,
    feed: &NvdFeed,
) -> Result<Vec<u8>, String> {
    let mut attempt = 0usize;
    loop {
        let response = client
            .get(&feed.url)
            .header(
                reqwest::header::USER_AGENT,
                format!("Vigil/{}", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .map_err(|err| format!("failed to fetch NVD feed {}: {err}", feed.label))?;
        let status = response.status();
        if status.is_success() {
            match response.bytes().map(|bytes| bytes.to_vec()) {
                Ok(bytes) => return Ok(bytes),
                Err(_) if attempt + 1 < MAX_RETRY_ATTEMPTS => {
                    std::thread::sleep(Duration::from_secs(2));
                    attempt += 1;
                    continue;
                }
                Err(err) => {
                    return Err(format!(
                        "failed to read NVD feed {} response body: {err}",
                        feed.label
                    ));
                }
            }
        }
        if (status.as_u16() == 429 || status.as_u16() == 503) && attempt + 1 < MAX_RETRY_ATTEMPTS {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(2);
            std::thread::sleep(Duration::from_secs(retry_after.max(1)));
            attempt += 1;
            continue;
        }
        let body = response.text().unwrap_or_default();
        return Err(format!(
            "NVD feed {} failed with HTTP {}{}",
            feed.label,
            status.as_u16(),
            if body.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", body.trim())
            }
        ));
    }
}

fn decompress_gzip(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn save_fetched_nvd_batch(batch: &FetchedNvdBatch, now: u64) -> Result<(), String> {
    let update_started = Instant::now();
    let snapshot_sha256 = combined_page_hash(&batch.pages);
    let source = nvd_sync_success_source(batch.total_results, snapshot_sha256, now);
    let db = crate::storage::db::StorageDb::global()?;
    db.begin()?;
    let result = (|| -> Result<(), String> {
        db.upsert_advisory_source(&source)?;
        for page in &batch.pages {
            let bytes = fs::read(&page.path).map_err(|err| {
                format!(
                    "failed to read spooled NVD page {}: {err}",
                    page.path.display()
                )
            })?;
            let cache = parse_nvd_snapshot(&bytes, None)?;
            db.replace_advisory_records(&cache.records, NVD_SOURCE_KEY, NVD_SOURCE_KIND)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            db.commit()?;
            db.checkpoint()?;
            tracing::info!(
                source = NVD_SOURCE_KIND,
                pages = batch.pages.len(),
                records = batch.imported_records,
                total_results = batch.total_results,
                elapsed_ms = update_started.elapsed().as_millis() as u64,
                "updated NVD advisory database from spooled pages"
            );
            Ok(())
        }
        Err(err) => {
            let _ = db.rollback();
            Err(err)
        }
    }
}

fn combined_page_hash(pages: &[FetchedNvdPage]) -> String {
    if pages.len() == 1 {
        return pages[0].sha256.clone();
    }
    let joined = pages
        .iter()
        .map(|page| page.sha256.as_str())
        .collect::<Vec<_>>()
        .join(":");
    sha256_hex(joined.as_bytes())
}

fn nvd_sync_success_source(
    total_results: usize,
    snapshot_sha256: String,
    now: u64,
) -> AdvisorySourceCache {
    AdvisorySourceCache {
        source_key: NVD_SOURCE_KEY.into(),
        source_kind: NVD_SOURCE_KIND.into(),
        source_url: NVD_API_URL.into(),
        imported_from: None,
        imported_from_batch: vec![],
        fetched_unix: now,
        expires_unix: now.saturating_add(DEFAULT_SOURCE_TTL_SECS),
        snapshot_sha256,
        total_results,
        status: SourceHealth::Fresh,
        last_attempt_unix: now,
        last_error: None,
        retry_after_unix: 0,
    }
}

#[cfg(test)]
fn empty_cache(now: u64) -> AdvisoryCache {
    AdvisoryCache {
        schema_version: DB_SCHEMA_VERSION,
        generated_unix: now,
        sources: vec![],
        records: vec![],
    }
}

fn nvd_refresh_due() -> bool {
    let now = unix_now();
    match load_nvd_source_metadata() {
        Ok(source) => source.as_ref().is_none_or(|source| {
            let retry_due = source.retry_after_unix > 0 && source.retry_after_unix <= now;
            let stale_or_error = matches!(source.status, SourceHealth::Error | SourceHealth::Stale);
            source.expires_unix <= now
                || retry_due
                || (stale_or_error
                    && (source.retry_after_unix == 0 || source.retry_after_unix <= now))
        }),
        Err(err) => {
            tracing::warn!(%err, "assuming NVD refresh is due because source metadata could not be read");
            true
        }
    }
}

fn nvd_source_rate_limit_remaining(source: Option<&AdvisorySourceCache>, now: u64) -> Option<u64> {
    let source = source?;
    let last_request_unix = source.last_attempt_unix.max(source.fetched_unix);
    let next_allowed = last_request_unix.saturating_add(NVD_MIN_SYNC_INTERVAL_SECS);
    if next_allowed > now {
        Some(next_allowed - now)
    } else {
        None
    }
}

fn load_nvd_source_metadata() -> Result<Option<AdvisorySourceCache>, String> {
    let db = crate::storage::db::StorageDb::global()?;
    Ok(db.load_advisory_sources()?.into_iter().find(|source| {
        source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY
    }))
}

fn load_latest_nvd_last_modified_from_db(
    source: Option<&AdvisorySourceCache>,
) -> Result<Option<String>, String> {
    if !nvd_source_has_complete_records(source)? {
        return Ok(None);
    }
    let db = crate::storage::db::StorageDb::global()?;
    Ok(db
        .max_advisory_updated_unix_for_source(NVD_SOURCE_KEY, NVD_SOURCE_KIND)?
        .map(|unix| format_datetime(unix_timestamp(unix))))
}

fn nvd_source_has_complete_records(source: Option<&AdvisorySourceCache>) -> Result<bool, String> {
    let Some(source) = source else {
        return Ok(false);
    };
    if source.source_kind != NVD_SOURCE_KIND || source.source_key != NVD_SOURCE_KEY {
        return Ok(false);
    }
    if source.fetched_unix == 0
        || source.total_results == 0
        || matches!(source.status, SourceHealth::Error)
    {
        return Ok(false);
    }
    let db = crate::storage::db::StorageDb::global()?;
    let stored = db.count_advisory_records_for_source(NVD_SOURCE_KEY, NVD_SOURCE_KIND)?;
    Ok(stored >= source.total_results)
}

#[cfg(test)]
fn latest_nvd_last_modified(existing: Option<&AdvisoryCache>) -> Option<String> {
    existing?
        .records
        .iter()
        .filter(|record| {
            record.provenance.source_kind == NVD_SOURCE_KIND
                && record.provenance.source_key == NVD_SOURCE_KEY
        })
        .filter_map(|record| record.last_modified.as_deref())
        .filter_map(parse_timestamp)
        .max()
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

#[cfg(test)]
fn nvd_sync_windows(
    existing: Option<&AdvisoryCache>,
    now: u64,
) -> Vec<(Option<String>, Option<String>)> {
    let latest = latest_nvd_last_modified(existing);
    nvd_sync_windows_from_latest(latest.as_deref(), now)
}

fn nvd_sync_windows_from_latest(
    latest: Option<&str>,
    now: u64,
) -> Vec<(Option<String>, Option<String>)> {
    let now = unix_timestamp(now);
    let latest = latest.and_then(parse_timestamp);
    let Some(mut start) = latest else {
        return vec![(None, None)];
    };

    let max_span = chrono::Duration::days(NVD_MAX_INCREMENTAL_WINDOW_DAYS);
    let mut windows = Vec::new();
    while start < now {
        let end = std::cmp::min(start + max_span, now);
        windows.push((Some(format_datetime(start)), Some(format_datetime(end))));
        start = end;
    }

    if windows.is_empty() {
        windows.push((Some(format_datetime(start)), Some(format_datetime(now))));
    }

    windows
}

fn unix_timestamp(unix: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix as i64, 0).unwrap_or_else(chrono::Utc::now)
}

fn format_datetime(timestamp: chrono::DateTime<chrono::Utc>) -> String {
    timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
fn stamp_nvd_sync_failure(mut cache: AdvisoryCache, err: &str, now: u64) -> AdvisoryCache {
    if let Some(source) = cache
        .sources
        .iter_mut()
        .find(|source| source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY)
    {
        source.status = if source.expires_unix <= now {
            SourceHealth::Stale
        } else {
            SourceHealth::Error
        };
        source.last_error = Some(err.to_string());
        // Capture previous retry delay before updating timestamps.
        let prev_delay = source
            .retry_after_unix
            .saturating_sub(source.last_attempt_unix);
        source.last_attempt_unix = now;
        let next_delay = if prev_delay == 0 || prev_delay > 86400 {
            300
        } else {
            (prev_delay * 2).min(86400)
        };
        source.retry_after_unix = now.saturating_add(next_delay);
    } else {
        cache.sources.push(AdvisorySourceCache {
            source_key: NVD_SOURCE_KEY.into(),
            source_kind: NVD_SOURCE_KIND.into(),
            source_url: NVD_API_URL.into(),
            imported_from: None,
            imported_from_batch: vec![],
            fetched_unix: 0,
            expires_unix: 0,
            snapshot_sha256: String::new(),
            total_results: 0,
            status: SourceHealth::Stale,
            last_attempt_unix: now,
            last_error: Some(err.to_string()),
            retry_after_unix: 0,
        });
    }
    cache
}

fn nvd_sync_failure_source(
    existing: Option<&AdvisorySourceCache>,
    err: &str,
    now: u64,
) -> AdvisorySourceCache {
    let mut source = existing.cloned().unwrap_or_else(|| AdvisorySourceCache {
        source_key: NVD_SOURCE_KEY.into(),
        source_kind: NVD_SOURCE_KIND.into(),
        source_url: NVD_API_URL.into(),
        imported_from: None,
        imported_from_batch: vec![],
        fetched_unix: 0,
        expires_unix: 0,
        snapshot_sha256: String::new(),
        total_results: 0,
        status: SourceHealth::Stale,
        last_attempt_unix: 0,
        last_error: None,
        retry_after_unix: 0,
    });
    source.status = if source.expires_unix <= now {
        SourceHealth::Stale
    } else {
        SourceHealth::Error
    };
    source.last_error = Some(err.to_string());
    let prev_delay = source
        .retry_after_unix
        .saturating_sub(source.last_attempt_unix);
    source.last_attempt_unix = now;
    let next_delay = if prev_delay == 0 || prev_delay > 86400 {
        300
    } else {
        (prev_delay * 2).min(86400)
    };
    source.retry_after_unix = now.saturating_add(next_delay);
    source
}

fn parse_nvd_snapshot(bytes: &[u8], imported_from: Option<&Path>) -> Result<AdvisoryCache, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("failed to parse NVD JSON: {e}"))?;
    let total_results = value
        .get("totalResults")
        .and_then(Value::as_u64)
        .unwrap_or_default() as usize;
    let timestamp = value
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let fetched_unix = parse_timestamp(timestamp)
        .map(|ts| ts.timestamp().max(0) as u64)
        .unwrap_or_else(unix_now);
    let source = AdvisorySourceCache {
        source_key: NVD_SOURCE_KEY.into(),
        source_kind: NVD_SOURCE_KIND.into(),
        source_url: NVD_API_URL.into(),
        imported_from: imported_from.map(|path| path.display().to_string()),
        imported_from_batch: imported_from
            .map(|path| vec![path.display().to_string()])
            .unwrap_or_default(),
        fetched_unix,
        expires_unix: fetched_unix.saturating_add(DEFAULT_SOURCE_TTL_SECS),
        snapshot_sha256: sha256_hex(bytes),
        total_results,
        status: SourceHealth::Fresh,
        last_attempt_unix: 0,
        last_error: None,
        retry_after_unix: 0,
    };

    let imported_unix = fetched_unix;
    let vulnerabilities = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| "NVD snapshot missing vulnerabilities array".to_string())?;
    let records = vulnerabilities
        .iter()
        .filter_map(|item| {
            item.get("cve")
                .and_then(|cve| parse_nvd_record(cve, source.source_url.as_str(), imported_unix))
        })
        .collect::<Vec<_>>();

    Ok(AdvisoryCache {
        schema_version: DB_SCHEMA_VERSION,
        generated_unix: fetched_unix,
        sources: vec![source],
        records,
    })
}

fn merge_cache(existing: Option<AdvisoryCache>, incoming: AdvisoryCache) -> AdvisoryCache {
    let mut merged = existing.unwrap_or_else(|| AdvisoryCache {
        schema_version: DB_SCHEMA_VERSION,
        generated_unix: incoming.generated_unix,
        sources: vec![],
        records: vec![],
    });
    let mut record_index = HashMap::with_capacity(merged.records.len());
    for (idx, record) in merged.records.iter().enumerate() {
        record_index.insert(record_key(record), idx);
    }

    for source in incoming.sources {
        if !source.imported_from_batch.is_empty() {
            merge_batch_source(&mut merged.sources, source);
        } else {
            merge_source(&mut merged.sources, source);
        }
    }

    for record in incoming.records {
        merge_record_indexed(&mut merged.records, &mut record_index, record);
    }
    merged.generated_unix = unix_now();
    merged.schema_version = DB_SCHEMA_VERSION;
    merged
}

fn merge_import_batch_cache(existing: AdvisoryCache, incoming: AdvisoryCache) -> AdvisoryCache {
    merge_cache(Some(existing), incoming)
}

fn merge_source(sources: &mut Vec<AdvisorySourceCache>, source: AdvisorySourceCache) {
    if let Some(existing) = sources.iter_mut().find(|existing| {
        existing.source_key == source.source_key && existing.source_kind == source.source_kind
    }) {
        let mut imported_from_batch = existing.imported_from_batch.clone();
        for path in &source.imported_from_batch {
            if !imported_from_batch
                .iter()
                .any(|existing_path| existing_path == path)
            {
                imported_from_batch.push(path.clone());
            }
        }
        *existing = source;
        existing.imported_from_batch = imported_from_batch;
        if existing.imported_from_batch.len() > 1 {
            existing.imported_from = None;
        }
    } else {
        sources.push(source);
    }
}

fn merge_batch_source(sources: &mut Vec<AdvisorySourceCache>, source: AdvisorySourceCache) {
    merge_source(sources, source);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecordKey {
    primary_id: String,
    source_kind: String,
    source_key: String,
}

fn record_key(record: &VulnerabilityRecord) -> RecordKey {
    RecordKey {
        primary_id: record.primary_id.clone(),
        source_kind: record.provenance.source_kind.clone(),
        source_key: record.provenance.source_key.clone(),
    }
}

fn merge_record_indexed(
    records: &mut Vec<VulnerabilityRecord>,
    index: &mut HashMap<RecordKey, usize>,
    record: VulnerabilityRecord,
) {
    let key = record_key(&record);
    if let Some(&existing_idx) = index.get(&key) {
        let existing = &mut records[existing_idx];
        let keep_existing = match compare_optional_timestamp(
            existing.last_modified.as_deref(),
            record.last_modified.as_deref(),
        ) {
            Some(std::cmp::Ordering::Greater) => true,
            Some(std::cmp::Ordering::Less) => false,
            Some(std::cmp::Ordering::Equal) | None => {
                existing.provenance.imported_unix >= record.provenance.imported_unix
            }
        };
        if !keep_existing {
            *existing = record;
        }
    } else {
        index.insert(key, records.len());
        records.push(record);
    }
}

fn compare_optional_timestamp(
    left: Option<&str>,
    right: Option<&str>,
) -> Option<std::cmp::Ordering> {
    let left = left.and_then(parse_timestamp)?;
    let right = right.and_then(parse_timestamp)?;
    Some(left.cmp(&right))
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
                .ok()
                .map(|ts| {
                    chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(ts, chrono::Utc)
                })
        })
}

fn parse_nvd_record(
    cve: &Value,
    source_url: &str,
    imported_unix: u64,
) -> Option<VulnerabilityRecord> {
    let id = cve.get("id").and_then(Value::as_str)?.trim();
    if id.is_empty() {
        return None;
    }

    let summary = extract_summary(cve);
    let severities = parse_severities(cve);
    let references = parse_references(cve);
    let mitigations = parse_mitigations(cve);
    let affected_products = parse_affected_products(cve);
    let aliases = cve
        .get("weaknesses")
        .and_then(Value::as_array)
        .map(|weaknesses| {
            weaknesses
                .iter()
                .flat_map(|weakness| {
                    weakness
                        .get("description")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|description| description.get("value").and_then(Value::as_str))
                        .map(|value| value.trim().to_string())
                })
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let published = cve
        .get("published")
        .and_then(Value::as_str)
        .map(|value| value.to_string());
    let last_modified = cve
        .get("lastModified")
        .and_then(Value::as_str)
        .map(|value| value.to_string());

    Some(VulnerabilityRecord {
        primary_id: id.to_string(),
        aliases,
        summary,
        published,
        last_modified,
        known_exploited: parse_known_exploited(cve),
        severities,
        affected_products,
        references,
        mitigations,
        fix_version: parse_fix_version(cve),
        workaround_instructions: parse_workaround_instructions(cve),
        upgrade_instructions: parse_upgrade_instructions(cve),
        provenance: VulnerabilityProvenance {
            source_kind: NVD_SOURCE_KIND.into(),
            source_key: NVD_SOURCE_KEY.into(),
            source_url: source_url.to_string(),
            imported_unix,
        },
    })
}

fn extract_summary(cve: &Value) -> String {
    let Some(descriptions) = cve.get("descriptions").and_then(Value::as_array) else {
        return String::new();
    };

    descriptions
        .iter()
        .find_map(|description| {
            let lang = description.get("lang").and_then(Value::as_str)?;
            if !lang.eq_ignore_ascii_case("en") && !lang.to_ascii_lowercase().starts_with("en-") {
                return None;
            }
            let value = description.get("value").and_then(Value::as_str)?.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        })
        .or_else(|| {
            descriptions.iter().find_map(|description| {
                let value = description.get("value").and_then(Value::as_str)?.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                }
            })
        })
        .unwrap_or_default()
}

fn parse_mitigations(cve: &Value) -> Vec<String> {
    let mut mitigations = Vec::new();
    if let Some(references) = cve.get("references").and_then(Value::as_array) {
        for reference in references {
            let Some(url) = reference.get("url").and_then(Value::as_str) else {
                continue;
            };
            let Some(tags) = reference.get("tags").and_then(Value::as_array) else {
                continue;
            };
            if tags.iter().filter_map(Value::as_str).any(|tag| {
                tag.eq_ignore_ascii_case("mitigation")
                    || tag.eq_ignore_ascii_case("vendor advisory")
                    || tag.eq_ignore_ascii_case("patch")
            }) {
                push_unique(&mut mitigations, url.to_string());
            }
        }
    }
    mitigations
}

fn parse_fix_version(cve: &Value) -> Option<String> {
    cve.get("references")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|r| {
            let url = r.get("url").and_then(Value::as_str)?;
            let tags = r.get("tags")?.as_array()?;
            let has_fix_tag = tags.iter().filter_map(Value::as_str).any(|tag| {
                tag.eq_ignore_ascii_case("patch")
                    || tag.eq_ignore_ascii_case("fix")
                    || tag.eq_ignore_ascii_case("vendor fix")
            });
            if has_fix_tag {
                Some(url.to_string())
            } else {
                None
            }
        })
        .next()
}

fn parse_workaround_instructions(cve: &Value) -> Vec<String> {
    extract_instructional_urls(cve, |tag| {
        tag.eq_ignore_ascii_case("workaround") || tag.eq_ignore_ascii_case("mitigation")
    })
}

fn parse_upgrade_instructions(cve: &Value) -> Vec<String> {
    extract_instructional_urls(cve, |tag| {
        tag.eq_ignore_ascii_case("upgrade")
            || tag.eq_ignore_ascii_case("update")
            || tag.eq_ignore_ascii_case("vendor upgrade")
    })
}

fn extract_instructional_urls<F>(cve: &Value, matcher: F) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    let mut result = Vec::new();
    if let Some(references) = cve.get("references").and_then(Value::as_array) {
        for reference in references {
            let Some(url) = reference.get("url").and_then(Value::as_str) else {
                continue;
            };
            let Some(tags) = reference.get("tags").and_then(Value::as_array) else {
                continue;
            };
            if tags.iter().filter_map(Value::as_str).any(&matcher) {
                push_unique(&mut result, url.to_string());
            }
        }
    }
    result
}

fn parse_references(cve: &Value) -> Vec<VulnerabilityReference> {
    cve.get("references")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_reference).collect::<Vec<_>>())
        .unwrap_or_default()
}

fn parse_reference(item: &Value) -> Option<VulnerabilityReference> {
    let url = item.get("url").and_then(Value::as_str)?.trim();
    if url.is_empty() {
        return None;
    }

    Some(VulnerabilityReference {
        url: url.to_string(),
        source: item
            .get("source")
            .and_then(Value::as_str)
            .map(|value| value.to_string()),
        tags: item
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    })
}

fn parse_known_exploited(cve: &Value) -> bool {
    if cve
        .get("cisaExploitAdd")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return true;
    }
    if cve
        .get("cisaRequiredAction")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return true;
    }
    cve.get("cisaKnownExploited")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn parse_severities(cve: &Value) -> Vec<VulnerabilitySeverity> {
    let mut severities = Vec::new();
    let Some(metrics) = cve.get("metrics").and_then(Value::as_object) else {
        return severities;
    };
    for (key, entries) in metrics {
        let Some(entries) = entries.as_array() else {
            continue;
        };
        for entry in entries {
            let Some(cvss) = entry.get("cvssData") else {
                continue;
            };
            let scheme = key
                .strip_prefix("cvssMetric")
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| key.clone());
            let severity = entry
                .get("baseSeverity")
                .and_then(Value::as_str)
                .or_else(|| cvss.get("baseSeverity").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string();
            let vector = cvss
                .get("vectorString")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let score = cvss
                .get("baseScore")
                .and_then(Value::as_f64)
                .map(|value| value as f32);
            severities.push(VulnerabilitySeverity {
                source: "nvd".into(),
                scheme,
                severity,
                score,
                vector,
            });
        }
    }
    severities
}

fn parse_affected_products(cve: &Value) -> Vec<AffectedProduct> {
    let mut products = Vec::new();
    let Some(configurations) = cve.get("configurations") else {
        return products;
    };
    collect_cpe_matches(configurations, &mut products);
    dedupe_products(products)
}

fn finalize_import_batch_metadata(cache: &mut AdvisoryCache, page_hashes: &[String]) {
    if page_hashes.len() <= 1 {
        return;
    }

    let combined_hash = sha256_hex(page_hashes.join(":").as_bytes());
    for source in &mut cache.sources {
        if !source.imported_from_batch.is_empty() {
            source.snapshot_sha256 = combined_hash.clone();
            if source.imported_from_batch.len() > 1 {
                source.imported_from = None;
            }
        }
    }
}

fn collect_cpe_matches(value: &Value, out: &mut Vec<AffectedProduct>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_cpe_matches(item, out);
            }
        }
        Value::Object(map) => {
            if let Some(matches) = map.get("cpeMatch").and_then(Value::as_array) {
                for entry in matches {
                    if let Some(product) = parse_cpe_match(entry) {
                        out.push(product);
                    }
                }
            }
            for value in map.values() {
                collect_cpe_matches(value, out);
            }
        }
        _ => {}
    }
}

fn parse_cpe_match(value: &Value) -> Option<AffectedProduct> {
    let criteria = value.get("criteria").and_then(Value::as_str)?.trim();
    if criteria.is_empty() {
        return None;
    }
    Some(AffectedProduct {
        criteria: criteria.to_string(),
        match_criteria_id: string_field(value, "matchCriteriaId"),
        cpe_name: string_field(value, "cpeName"),
        vulnerable: value
            .get("vulnerable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        version_start_including: string_field(value, "versionStartIncluding"),
        version_start_excluding: string_field(value, "versionStartExcluding"),
        version_end_including: string_field(value, "versionEndIncluding"),
        version_end_excluding: string_field(value, "versionEndExcluding"),
    })
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn dedupe_products(products: Vec<AffectedProduct>) -> Vec<AffectedProduct> {
    let mut deduped = Vec::new();
    for product in products {
        if deduped.iter().any(|existing: &AffectedProduct| {
            existing.criteria == product.criteria
                && existing.match_criteria_id == product.match_criteria_id
                && existing.cpe_name == product.cpe_name
                && existing.vulnerable == product.vulnerable
                && existing.version_start_including == product.version_start_including
                && existing.version_start_excluding == product.version_start_excluding
                && existing.version_end_including == product.version_end_including
                && existing.version_end_excluding == product.version_end_excluding
        }) {
            continue;
        }
        deduped.push(product);
    }
    deduped
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if values.iter().any(|existing| existing == &value) {
        return;
    }
    values.push(value);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_nvd_snapshot_into_normalized_cache() {
        let snapshot = json!({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "timestamp": "2026-04-26T00:00:00.000",
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-12345",
                    "published": "2026-04-25T10:00:00.000",
                    "lastModified": "2026-04-26T10:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Example issue in Vigil dependency handling."}
                    ],
                    "references": [
                        {
                            "url": "https://example.com/advisory",
                            "source": "example",
                            "tags": ["Vendor Advisory", "Mitigation"]
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            },
                            "baseSeverity": "CRITICAL"
                        }]
                    },
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "vulnerable": true,
                                "criteria": "cpe:2.3:a:example:vigil-helper:*:*:*:*:*:*:*:*",
                                "matchCriteriaId": "36FBCF0F-8CEE-474C-8A04-5075AF53FAF4",
                                "cpeName": "cpe:2.3:a:example:vigil-helper:1.0.0:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0.0",
                                "versionEndExcluding": "1.2.0"
                            }]
                        }]
                    }],
                    "cisaExploitAdd": "2026-04-26"
                }
            }]
        });

        let cache = parse_nvd_snapshot(
            serde_json::to_string(&snapshot).unwrap().as_bytes(),
            Some(Path::new("/tmp/nvd.json")),
        )
        .unwrap();

        assert_eq!(cache.schema_version, DB_SCHEMA_VERSION);
        assert_eq!(cache.records.len(), 1);
        assert_eq!(cache.sources[0].source_key, "nvd-cve");
        assert_eq!(cache.sources[0].total_results, 1);

        let record = &cache.records[0];
        assert_eq!(record.primary_id, "CVE-2026-12345");
        assert!(record.known_exploited);
        assert_eq!(
            record.summary,
            "Example issue in Vigil dependency handling."
        );
        assert_eq!(record.severities.len(), 1);
        assert_eq!(record.severities[0].severity, "CRITICAL");
        assert_eq!(record.affected_products.len(), 1);
        assert_eq!(
            record.affected_products[0].criteria,
            "cpe:2.3:a:example:vigil-helper:*:*:*:*:*:*:*:*"
        );
        assert_eq!(
            record.affected_products[0].match_criteria_id.as_deref(),
            Some("36FBCF0F-8CEE-474C-8A04-5075AF53FAF4")
        );
        assert_eq!(
            record.affected_products[0].cpe_name.as_deref(),
            Some("cpe:2.3:a:example:vigil-helper:1.0.0:*:*:*:*:*:*:*")
        );
        assert_eq!(record.references.len(), 1);
        assert_eq!(record.mitigations, vec!["https://example.com/advisory"]);
    }

    #[test]
    fn dedupe_products_keeps_distinct_cpe_metadata_rows() {
        let primary = AffectedProduct {
            criteria: "cpe:2.3:a:example:vigil-helper:*:*:*:*:*:*:*:*".into(),
            match_criteria_id: Some("id-one".into()),
            cpe_name: Some("cpe:2.3:a:example:vigil-helper:1.0.0:*:*:*:*:*:*:*".into()),
            vulnerable: true,
            version_start_including: Some("1.0.0".into()),
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some("1.2.0".into()),
        };
        let secondary = AffectedProduct {
            criteria: "cpe:2.3:a:example:vigil-helper:*:*:*:*:*:*:*:*".into(),
            match_criteria_id: Some("id-two".into()),
            cpe_name: Some("cpe:2.3:a:example:vigil-helper:1.1.0:*:*:*:*:*:*:*".into()),
            vulnerable: true,
            version_start_including: Some("1.0.0".into()),
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some("1.2.0".into()),
        };

        let deduped = dedupe_products(vec![primary.clone(), secondary.clone()]);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].criteria, primary.criteria);
        assert_eq!(deduped[0].match_criteria_id, primary.match_criteria_id);
        assert_eq!(deduped[1].criteria, secondary.criteria);
        assert_eq!(deduped[1].match_criteria_id, secondary.match_criteria_id);
    }

    // The old protected_cache_round_trip_preserves_records test used the
    // legacy JSON path which has been removed. DB round-trip is covered
    // by storage::db::tests::checkpoint_and_verify_round_trip.

    #[test]
    fn merge_cache_keeps_other_sources_and_updates_matching_nvd_records() {
        let existing = AdvisoryCache {
            schema_version: DB_SCHEMA_VERSION,
            generated_unix: 100,
            sources: vec![
                AdvisorySourceCache {
                    source_key: "nvd-cve".into(),
                    source_kind: "nvd".into(),
                    source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                    imported_from: Some("/tmp/old-nvd.json".into()),
                    imported_from_batch: vec!["/tmp/old-nvd.json".into()],
                    fetched_unix: 100,
                    expires_unix: 200,
                    snapshot_sha256: "old".into(),
                    total_results: 1,
                    status: SourceHealth::Fresh,
                    last_attempt_unix: 0,
                    last_error: None,
                    retry_after_unix: 0,
                },
                AdvisorySourceCache {
                    source_key: "euvd".into(),
                    source_kind: "euvd".into(),
                    source_url: "https://euvd.enisa.europa.eu".into(),
                    imported_from: None,
                    imported_from_batch: vec![],
                    fetched_unix: 90,
                    expires_unix: 190,
                    snapshot_sha256: "euvd".into(),
                    total_results: 1,
                    status: SourceHealth::Fresh,
                    last_attempt_unix: 0,
                    last_error: None,
                    retry_after_unix: 0,
                },
            ],
            records: vec![
                VulnerabilityRecord {
                    primary_id: "CVE-2026-12345".into(),
                    summary: "Older NVD record".into(),
                    last_modified: Some("2026-04-25T10:00:00.000".into()),
                    provenance: VulnerabilityProvenance {
                        source_kind: "nvd".into(),
                        source_key: "nvd-cve".into(),
                        source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                        imported_unix: 100,
                    },
                    ..VulnerabilityRecord::default()
                },
                VulnerabilityRecord {
                    primary_id: "EUVD-2026-0001".into(),
                    summary: "Existing EUVD record".into(),
                    provenance: VulnerabilityProvenance {
                        source_kind: "euvd".into(),
                        source_key: "euvd".into(),
                        source_url: "https://euvd.enisa.europa.eu".into(),
                        imported_unix: 90,
                    },
                    ..VulnerabilityRecord::default()
                },
            ],
        };
        let imported = AdvisoryCache {
            schema_version: DB_SCHEMA_VERSION,
            generated_unix: 110,
            sources: vec![AdvisorySourceCache {
                source_key: "nvd-cve".into(),
                source_kind: "nvd".into(),
                source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                imported_from: Some("/tmp/new-nvd.json".into()),
                imported_from_batch: vec!["/tmp/new-nvd.json".into()],
                fetched_unix: 110,
                expires_unix: 210,
                snapshot_sha256: "new".into(),
                total_results: 2,
                status: SourceHealth::Fresh,
                last_attempt_unix: 0,
                last_error: None,
                retry_after_unix: 0,
            }],
            records: vec![
                VulnerabilityRecord {
                    primary_id: "CVE-2026-12345".into(),
                    summary: "Updated NVD record".into(),
                    last_modified: Some("2026-04-26T10:00:00.000".into()),
                    provenance: VulnerabilityProvenance {
                        source_kind: "nvd".into(),
                        source_key: "nvd-cve".into(),
                        source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                        imported_unix: 110,
                    },
                    ..VulnerabilityRecord::default()
                },
                VulnerabilityRecord {
                    primary_id: "CVE-2026-7777".into(),
                    summary: "New NVD record".into(),
                    last_modified: Some("2026-04-26T11:00:00.000".into()),
                    provenance: VulnerabilityProvenance {
                        source_kind: "nvd".into(),
                        source_key: "nvd-cve".into(),
                        source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                        imported_unix: 110,
                    },
                    ..VulnerabilityRecord::default()
                },
            ],
        };

        let merged = merge_cache(Some(existing), imported);

        assert_eq!(merged.sources.len(), 2);
        let nvd_source = merged
            .sources
            .iter()
            .find(|source| source.source_key == "nvd-cve")
            .unwrap();
        assert_eq!(nvd_source.snapshot_sha256, "new");
        assert_eq!(nvd_source.total_results, 2);
        assert_eq!(merged.records.len(), 3);
        assert_eq!(
            merged
                .records
                .iter()
                .find(|record| {
                    record.primary_id == "CVE-2026-12345"
                        && record.provenance.source_key == "nvd-cve"
                })
                .unwrap()
                .summary,
            "Updated NVD record"
        );
        assert!(merged
            .records
            .iter()
            .any(|record| record.primary_id == "EUVD-2026-0001"));
        assert!(merged
            .records
            .iter()
            .any(|record| record.primary_id == "CVE-2026-7777"));
    }

    #[test]
    fn merge_cache_keeps_newer_existing_record_when_import_is_older() {
        let existing_record = VulnerabilityRecord {
            primary_id: "CVE-2026-12345".into(),
            summary: "Newer local NVD record".into(),
            last_modified: Some("2026-04-27T10:00:00.000".into()),
            provenance: VulnerabilityProvenance {
                source_kind: "nvd".into(),
                source_key: "nvd-cve".into(),
                source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                imported_unix: 120,
            },
            ..VulnerabilityRecord::default()
        };
        let imported_record = VulnerabilityRecord {
            primary_id: "CVE-2026-12345".into(),
            summary: "Older imported NVD record".into(),
            last_modified: Some("2026-04-26T10:00:00.000".into()),
            provenance: VulnerabilityProvenance {
                source_kind: "nvd".into(),
                source_key: "nvd-cve".into(),
                source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                imported_unix: 110,
            },
            ..VulnerabilityRecord::default()
        };

        let merged = merge_cache(
            Some(AdvisoryCache {
                schema_version: DB_SCHEMA_VERSION,
                generated_unix: 120,
                sources: vec![],
                records: vec![existing_record],
            }),
            AdvisoryCache {
                schema_version: DB_SCHEMA_VERSION,
                generated_unix: 110,
                sources: vec![],
                records: vec![imported_record],
            },
        );

        assert_eq!(merged.records.len(), 1);
        assert_eq!(merged.records[0].summary, "Newer local NVD record");
    }

    #[test]
    fn compare_optional_timestamp_handles_offset_and_naive_formats() {
        assert_eq!(
            compare_optional_timestamp(
                Some("2026-04-27T10:00:00+01:00"),
                Some("2026-04-27T09:30:00Z")
            ),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            compare_optional_timestamp(
                Some("2026-04-27T10:00:00.000"),
                Some("2026-04-27T09:59:59.999")
            ),
            Some(std::cmp::Ordering::Greater)
        );
    }

    #[test]
    fn import_batch_combines_paged_snapshots_into_one_source() {
        let first = json!({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 2,
            "timestamp": "2026-04-26T00:00:00.000",
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-1000",
                    "published": "2026-04-25T10:00:00.000",
                    "lastModified": "2026-04-25T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": "First page"}]
                }
            }]
        });
        let second = json!({
            "resultsPerPage": 1,
            "startIndex": 1,
            "totalResults": 2,
            "timestamp": "2026-04-26T00:01:00.000",
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-2000",
                    "published": "2026-04-25T11:00:00.000",
                    "lastModified": "2026-04-25T11:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Second page"}]
                }
            }]
        });

        let dir = temp_dir();
        let first_path = dir.join("nvd-page-1.json");
        let second_path = dir.join("nvd-page-2.json");
        fs::write(&first_path, serde_json::to_vec(&first).unwrap()).unwrap();
        fs::write(&second_path, serde_json::to_vec(&second).unwrap()).unwrap();

        let batch = load_nvd_snapshot_batch(&[first_path.clone(), second_path.clone()]).unwrap();

        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.sources.len(), 1);
        assert_eq!(batch.sources[0].total_results, 2);
        assert_eq!(batch.sources[0].imported_from, None);
        assert_eq!(
            batch.sources[0].imported_from_batch,
            vec![
                first_path.display().to_string(),
                second_path.display().to_string()
            ]
        );
        assert!(batch
            .records
            .iter()
            .any(|record| record.primary_id == "CVE-2026-1000"));
        assert!(batch
            .records
            .iter()
            .any(|record| record.primary_id == "CVE-2026-2000"));
    }

    #[test]
    fn extract_summary_prefers_english_locale_and_falls_back() {
        let english_locale = json!({
            "descriptions": [
                {"lang": "fr", "value": "Resume"},
                {"lang": "en-US", "value": "English summary"}
            ]
        });
        assert_eq!(extract_summary(&english_locale), "English summary");

        let fallback = json!({
            "descriptions": [
                {"lang": "fr", "value": "Resume"},
                {"lang": "de", "value": "Zusammenfassung"}
            ]
        });
        assert_eq!(extract_summary(&fallback), "Resume");
    }

    #[test]
    fn nvd_sync_windows_split_long_offline_gaps() {
        let existing = AdvisoryCache {
            schema_version: DB_SCHEMA_VERSION,
            generated_unix: 0,
            sources: vec![],
            records: vec![VulnerabilityRecord {
                primary_id: "CVE-2026-12345".into(),
                last_modified: Some("2026-01-01T00:00:00.000".into()),
                provenance: VulnerabilityProvenance {
                    source_kind: NVD_SOURCE_KIND.into(),
                    source_key: NVD_SOURCE_KEY.into(),
                    source_url: NVD_API_URL.into(),
                    imported_unix: 0,
                },
                ..VulnerabilityRecord::default()
            }],
        };
        let now = parse_timestamp("2026-06-15T00:00:00.000")
            .unwrap()
            .timestamp() as u64;
        let windows = nvd_sync_windows(Some(&existing), now);
        assert_eq!(windows.len(), 2);
        assert_eq!(
            windows[0],
            (
                Some("2026-01-01T00:00:00.000Z".into()),
                Some("2026-05-01T00:00:00.000Z".into())
            )
        );
        assert_eq!(
            windows[1],
            (
                Some("2026-05-01T00:00:00.000Z".into()),
                Some("2026-06-15T00:00:00.000Z".into())
            )
        );
        assert_eq!(nvd_sync_windows(None, now), vec![(None, None)]);
    }

    #[test]
    fn stamp_nvd_sync_failure_creates_source_for_first_failure() {
        let cache = stamp_nvd_sync_failure(empty_cache(0), "boom", 42);
        assert_eq!(cache.sources.len(), 1);
        let source = &cache.sources[0];
        assert_eq!(source.source_key, NVD_SOURCE_KEY);
        assert_eq!(source.source_kind, NVD_SOURCE_KIND);
        assert_eq!(source.last_attempt_unix, 42);
        assert_eq!(source.last_error.as_deref(), Some("boom"));
        assert_eq!(source.status, SourceHealth::Stale);
    }

    #[test]
    fn next_request_delay_only_throttles_close_successive_requests() {
        let now = Instant::now();
        let delay = Duration::from_secs(6);

        assert_eq!(next_request_delay(None, now, delay), Duration::ZERO);
        assert_eq!(
            next_request_delay(now.checked_sub(Duration::from_secs(8)), now, delay),
            Duration::ZERO
        );
        assert_eq!(
            next_request_delay(now.checked_sub(Duration::from_secs(2)), now, delay),
            Duration::from_secs(4)
        );
    }

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vigil-advisory-test-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
