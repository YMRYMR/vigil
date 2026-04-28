//! Public vulnerability intelligence foundations.
//!
//! Phase 16 starts with NVD ingestion, but the full roadmap item includes
//! scheduling, rate-limit-aware sync, CPE/CPE-match ingestion, and broader
//! source correlation. This module implements the smallest safe slice:
//!
//! - a normalized vulnerability record model
//! - protected local cache storage for imported NVD CVE snapshots
//! - a CLI import path for offline or operator-driven snapshot ingestion,
//!   including batched page or incremental-file imports
//! - live NVD CVE sync with conservative rate limiting and incremental
//!   last-modified windows
//! - startup status logging so the cache state is visible to operators

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CACHE_FILE: &str = "vigil-advisory-cache.json";
const CACHE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_SOURCE_TTL_SECS: u64 = 24 * 60 * 60;
const NVD_SOURCE_KEY: &str = "nvd-cve";
const NVD_SOURCE_KIND: &str = "nvd";
const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
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
                return response.bytes().map(|bytes| bytes.to_vec()).map_err(|err| {
                    format!(
                        "failed to read NVD response body at startIndex {}: {err}",
                        request.start_index
                    )
                });
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
        "Merged {} NVD CVE records from {} snapshot file(s) into the protected advisory cache ({} marked known exploited in this import set). Cache now holds {} records across {} sources.",
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
                "Fetched {} NVD page(s) and merged {} CVE record(s) into the protected advisory cache. Cache now holds {} records across {} sources.",
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
    let existing = load_cache_for_import()?;
    let now = unix_now();
    if !force {
        if let Some(remaining_secs) = nvd_rate_limit_remaining(existing.as_ref(), now) {
            return Ok(SyncOutcome::SkippedRateLimit { remaining_secs });
        }
    }

    let fetcher = HttpNvdFetcher::new()?;
    let (cache, fetched_pages, imported_records) =
        match sync_nvd_with_fetcher(existing.clone(), &fetcher, now) {
            Ok(result) => result,
            Err(err) => {
                let failed_cache =
                    stamp_nvd_sync_failure(existing.unwrap_or_else(|| empty_cache(now)), &err, now);
                if let Err(save_err) = save_cache(&failed_cache) {
                    tracing::warn!(%save_err, "failed to persist NVD sync failure state");
                }
                return Err(err);
            }
        };
    let summary = SyncSummary {
        requested_pages: fetched_pages,
        imported_records,
        total_records: cache.records.len(),
        total_sources: cache.sources.len(),
    };
    save_cache(&cache)?;
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
    let path = cache_path();
    if !path.exists() {
        return Ok(None);
    }
    let loaded: Option<AdvisoryCache> = crate::security::policy::load_struct_with_integrity(&path)
        .map_err(|e| {
            format!(
                "failed to load protected advisory cache {}: {e}",
                path.display()
            )
        })?;
    let Some(cache) = loaded else {
        return Ok(None);
    };
    if cache.schema_version != CACHE_SCHEMA_VERSION {
        return Err(format!(
            "protected advisory cache {} used unsupported schema version {}",
            path.display(),
            cache.schema_version
        ));
    }
    Ok(Some(cache))
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
    let path = cache_path();
    crate::security::policy::save_struct_with_integrity(&path, cache).map_err(|e| {
        format!(
            "failed to save protected advisory cache {}: {e}",
            path.display()
        )
    })
}

fn cache_path() -> PathBuf {
    crate::config::data_dir().join(CACHE_FILE)
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

fn sync_nvd_with_fetcher(
    existing: Option<AdvisoryCache>,
    fetcher: &dyn NvdFetcher,
    now: u64,
) -> Result<(AdvisoryCache, usize, usize), String> {
    let mut imported = None;
    let mut page_hashes = Vec::new();
    let mut page_count = 0usize;
    let mut imported_records = 0usize;
    for (last_mod_start_date, last_mod_end_date) in nvd_sync_windows(existing.as_ref(), now) {
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
            let bytes = fetcher.fetch_page(&request)?;
            page_hashes.push(sha256_hex(&bytes));
            let page = parse_nvd_snapshot(&bytes, None)?;
            let total_results = page
                .sources
                .first()
                .map(|source| source.total_results)
                .unwrap_or(page.records.len());
            let page_records = page.records.len();
            imported_records += page_records;
            imported = Some(match imported {
                Some(existing_pages) => merge_import_batch_cache(existing_pages, page),
                None => page,
            });
            page_count += 1;

            if page_records == 0
                || start_index.saturating_add(request.results_per_page) >= total_results
            {
                break;
            }
            start_index = start_index.saturating_add(request.results_per_page);
        }
    }

    let mut imported = imported.unwrap_or_else(|| empty_cache(now));
    finalize_import_batch_metadata(&mut imported, &page_hashes);
    let mut merged = merge_cache(existing, imported);
    stamp_nvd_sync_success(&mut merged, page_count, now);
    Ok((merged, page_count, imported_records))
}

fn empty_cache(now: u64) -> AdvisoryCache {
    AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: now,
        sources: vec![],
        records: vec![],
    }
}

fn nvd_refresh_due() -> bool {
    let now = unix_now();
    match load_cache() {
        Ok(Some(cache)) => cache
            .sources
            .iter()
            .find(|source| {
                source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY
            })
            .is_none_or(|source| {
                source.expires_unix <= now
                    || matches!(source.status, SourceHealth::Error | SourceHealth::Stale)
            }),
        Ok(None) => true,
        Err(err) => {
            tracing::warn!(%err, "assuming NVD refresh is due because the cache could not be read");
            true
        }
    }
}

fn nvd_rate_limit_remaining(existing: Option<&AdvisoryCache>, now: u64) -> Option<u64> {
    let source = existing?.sources.iter().find(|source| {
        source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY
    })?;
    let last_request_unix = source.last_attempt_unix.max(source.fetched_unix);
    let next_allowed = last_request_unix.saturating_add(NVD_MIN_SYNC_INTERVAL_SECS);
    if next_allowed > now {
        Some(next_allowed - now)
    } else {
        None
    }
}

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

fn nvd_sync_windows(
    existing: Option<&AdvisoryCache>,
    now: u64,
) -> Vec<(Option<String>, Option<String>)> {
    let now = unix_timestamp(now);
    let latest = latest_nvd_last_modified(existing).and_then(|value| parse_timestamp(&value));
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

fn stamp_nvd_sync_success(cache: &mut AdvisoryCache, requested_pages: usize, now: u64) {
    if let Some(source) = cache
        .sources
        .iter_mut()
        .find(|source| source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY)
    {
        source.fetched_unix = now;
        source.last_attempt_unix = now;
        source.expires_unix = now.saturating_add(DEFAULT_SOURCE_TTL_SECS);
        source.status = SourceHealth::Fresh;
        source.last_error = None;
        if requested_pages > 1 {
            source.imported_from = None;
        }
    } else {
        cache.sources.push(AdvisorySourceCache {
            source_key: NVD_SOURCE_KEY.into(),
            source_kind: NVD_SOURCE_KIND.into(),
            source_url: NVD_API_URL.into(),
            imported_from: None,
            imported_from_batch: vec![],
            fetched_unix: now,
            expires_unix: now.saturating_add(DEFAULT_SOURCE_TTL_SECS),
            snapshot_sha256: String::new(),
            total_results: 0,
            status: SourceHealth::Fresh,
            last_attempt_unix: now,
            last_error: None,
        });
    }
}

fn stamp_nvd_sync_failure(mut cache: AdvisoryCache, err: &str, now: u64) -> AdvisoryCache {
    if let Some(source) = cache
        .sources
        .iter_mut()
        .find(|source| source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY)
    {
        source.last_attempt_unix = now;
        source.status = if source.expires_unix <= now {
            SourceHealth::Stale
        } else {
            SourceHealth::Error
        };
        source.last_error = Some(err.to_string());
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
        });
    }
    cache
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
    };

    let imported_unix = fetched_unix;
    let records = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(|vulnerabilities| {
            vulnerabilities
                .iter()
                .filter_map(|item| {
                    item.get("cve").and_then(|cve| {
                        parse_nvd_record(cve, source.source_url.as_str(), imported_unix)
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: fetched_unix,
        sources: vec![source],
        records,
    })
}

fn empty_source_health() -> SourceHealth {
    SourceHealth::Fresh
}

fn merge_cache(existing: Option<AdvisoryCache>, incoming: AdvisoryCache) -> AdvisoryCache {
    let mut merged = existing.unwrap_or_else(|| AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: incoming.generated_unix,
        sources: vec![],
        records: vec![],
    });

    for source in incoming.sources {
        if !source.imported_from_batch.is_empty() {
            merge_batch_source(&mut merged.sources, source);
        } else {
            merge_source(&mut merged.sources, source);
        }
    }

    for record in incoming.records {
        merge_record(&mut merged.records, record);
    }
    merged.generated_unix = unix_now();
    merged.schema_version = CACHE_SCHEMA_VERSION;
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

fn merge_record(records: &mut Vec<VulnerabilityRecord>, record: VulnerabilityRecord) {
    if let Some(existing) = records.iter_mut().find(|existing| {
        existing.primary_id == record.primary_id
            && existing.provenance.source_kind == record.provenance.source_kind
            && existing.provenance.source_key == record.provenance.source_key
    }) {
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
        if keep_existing {
            return;
        }
        *existing = record;
    } else {
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

fn parse_references(cve: &Value) -> Vec<VulnerabilityReference> {
    cve.get("references")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| parse_reference(item))
                .collect::<Vec<_>>()
        })
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

        assert_eq!(cache.schema_version, CACHE_SCHEMA_VERSION);
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
        assert_eq!(record.references.len(), 1);
        assert_eq!(record.mitigations, vec!["https://example.com/advisory"]);
    }

    #[test]
    fn protected_cache_round_trip_preserves_records() {
        let dir = temp_dir();
        let path = dir.join(CACHE_FILE);
        let cache = AdvisoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
            generated_unix: 42,
            sources: vec![AdvisorySourceCache {
                source_key: "nvd-cve".into(),
                source_kind: "nvd".into(),
                source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                imported_from: Some("/tmp/nvd.json".into()),
                imported_from_batch: vec!["/tmp/nvd.json".into()],
                fetched_unix: 42,
                expires_unix: 84,
                snapshot_sha256: "abc".into(),
                total_results: 1,
                status: SourceHealth::Fresh,
                last_attempt_unix: 0,
                last_error: None,
            }],
            records: vec![VulnerabilityRecord {
                primary_id: "CVE-2026-9999".into(),
                summary: "Test record".into(),
                ..VulnerabilityRecord::default()
            }],
        };

        crate::security::policy::save_struct_with_integrity(&path, &cache).unwrap();
        let loaded: AdvisoryCache = crate::security::policy::load_struct_with_integrity(&path)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.records.len(), 1);
        assert_eq!(loaded.records[0].primary_id, "CVE-2026-9999");
    }

    #[test]
    fn merge_cache_keeps_other_sources_and_updates_matching_nvd_records() {
        let existing = AdvisoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
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
            schema_version: CACHE_SCHEMA_VERSION,
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
                schema_version: CACHE_SCHEMA_VERSION,
                generated_unix: 120,
                sources: vec![],
                records: vec![existing_record],
            }),
            AdvisoryCache {
                schema_version: CACHE_SCHEMA_VERSION,
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
            schema_version: CACHE_SCHEMA_VERSION,
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
