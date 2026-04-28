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
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
        })
    }

    fn request_delay(&self) -> Duration {
        if self.api_key.is_some() {
            Duration::from_secs(NVD_REQUEST_DELAY_WITH_KEY_SECS)
        } else {
            Duration::from_secs(NVD_REQUEST_DELAY_NO_KEY_SECS)
        }
    }
}

impl NvdFetcher for HttpNvdFetcher {
    fn fetch_page(&self, request: &NvdSyncRequest) -> Result<Vec<u8>, String> {
        let mut attempt = 0usize;
        loop {
            if request.start_index > 0 && attempt == 0 {
                std::thread::sleep(self.request_delay());
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

pub fn run_sync_cli(force: bool) -> Result<(), String> {
    match sync_nvd(force)? {
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
    Ok(())
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
                if let Some(cache) = existing {
                    let failed_cache = stamp_nvd_sync_failure(cache, &err, now);
                    if let Err(save_err) = save_cache(&failed_cache) {
                        tracing::warn!(%save_err, "failed to persist NVD sync failure state");
                    }
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

    let mut imported = imported.unwrap_or_else(|| AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: now,
        sources: vec![],
        records: vec![],
    });
    finalize_import_batch_metadata(&mut imported, &page_hashes);
    let mut merged = merge_cache(existing, imported);
    stamp_nvd_sync_success(&mut merged, page_count, now);
    Ok((merged, page_count, imported_records))
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

fn format_nvd_timestamp(unix: u64) -> String {
    format_datetime(unix_timestamp(unix))
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
    }
    cache
}

fn parse_nvd_snapshot(bytes: &[u8], imported_from: Option<&Path>) -> Result<AdvisoryCache, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("failed to parse NVD JSON: {e}"))?;
    let vulnerabilities = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| "NVD snapshot did not contain a vulnerabilities array".to_string())?;

    let now = unix_now();
    let source_url = value
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("https://services.nvd.nist.gov/rest/json/cves/2.0")
        .to_string();

    let mut records = Vec::with_capacity(vulnerabilities.len());
    for item in vulnerabilities {
        if let Some(record) = parse_nvd_record(item, now, &source_url)? {
            records.push(record);
        }
    }

    let total_results = value
        .get("totalResults")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(records.len());

    Ok(AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: now,
        sources: vec![AdvisorySourceCache {
            source_key: NVD_SOURCE_KEY.into(),
            source_kind: NVD_SOURCE_KIND.into(),
            source_url: source_url.clone(),
            imported_from: imported_from.map(|path| path.display().to_string()),
            imported_from_batch: imported_from
                .map(|path| vec![path.display().to_string()])
                .unwrap_or_default(),
            fetched_unix: now,
            expires_unix: now.saturating_add(DEFAULT_SOURCE_TTL_SECS),
            snapshot_sha256: sha256_hex(bytes),
            total_results,
            status: SourceHealth::Fresh,
            last_attempt_unix: now,
            last_error: None,
        }],
        records,
    })
}

fn finalize_import_batch_metadata(cache: &mut AdvisoryCache, page_hashes: &[String]) {
    let combined_sha = combined_page_sha(page_hashes);
    for source in &mut cache.sources {
        source.fetched_unix = cache.generated_unix;
        source.expires_unix = cache.generated_unix.saturating_add(DEFAULT_SOURCE_TTL_SECS);
        source.status = SourceHealth::Fresh;
        source.last_attempt_unix = cache.generated_unix;
        source.last_error = None;
        if !combined_sha.is_empty() {
            source.snapshot_sha256 = combined_sha.clone();
        }
        if source.imported_from_batch.len() > 1 {
            source.imported_from = None;
        }
    }
}

fn combined_page_sha(page_hashes: &[String]) -> String {
    if page_hashes.is_empty() {
        return String::new();
    }
    if page_hashes.len() == 1 {
        return page_hashes[0].clone();
    }

    let joined = page_hashes.join(":");
    sha256_hex(joined.as_bytes())
}

fn merge_cache(existing: Option<AdvisoryCache>, imported: AdvisoryCache) -> AdvisoryCache {
    let Some(mut merged) = existing else {
        return imported;
    };

    merged.schema_version = CACHE_SCHEMA_VERSION;
    merged.generated_unix = merged.generated_unix.max(imported.generated_unix);
    let mut record_index = merged
        .records
        .iter()
        .enumerate()
        .map(|(index, record)| (record_identity_key(record), index))
        .collect::<HashMap<_, _>>();

    for source in imported.sources {
        merge_source(&mut merged.sources, source);
    }
    for record in imported.records {
        merge_record(&mut merged.records, &mut record_index, record);
    }

    merged
}

fn merge_source(sources: &mut Vec<AdvisorySourceCache>, imported: AdvisorySourceCache) {
    if let Some(existing) = sources
        .iter_mut()
        .find(|candidate| same_source_identity(candidate, &imported))
    {
        *existing = imported;
    } else {
        sources.push(imported);
    }
}

fn merge_import_batch_cache(existing: AdvisoryCache, imported: AdvisoryCache) -> AdvisoryCache {
    let mut merged = merge_cache(Some(existing), imported);
    if let Some(total_results) = merged
        .sources
        .iter()
        .find(|source| source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY)
        .map(|source| source.total_results)
    {
        if let Some(existing_source) = merged.sources.iter_mut().find(|candidate| {
            candidate.source_kind == NVD_SOURCE_KIND && candidate.source_key == NVD_SOURCE_KEY
        }) {
            existing_source.total_results = total_results.max(
                merged
                    .records
                    .iter()
                    .filter(|record| {
                        record.provenance.source_kind == NVD_SOURCE_KIND
                            && record.provenance.source_key == NVD_SOURCE_KEY
                    })
                    .count(),
            );
        }
    }
    merged
}

fn same_source_identity(lhs: &AdvisorySourceCache, rhs: &AdvisorySourceCache) -> bool {
    lhs.source_kind == rhs.source_kind && lhs.source_key == rhs.source_key
}

fn record_identity_key(record: &VulnerabilityRecord) -> (String, String, String) {
    (
        record.provenance.source_kind.clone(),
        record.provenance.source_key.clone(),
        record.primary_id.clone(),
    )
}

fn merge_record(
    records: &mut Vec<VulnerabilityRecord>,
    index: &mut HashMap<(String, String, String), usize>,
    imported: VulnerabilityRecord,
) {
    let key = record_identity_key(&imported);
    if let Some(existing_index) = index.get(&key).copied() {
        if should_replace_record(&records[existing_index], &imported) {
            records[existing_index] = imported;
        }
        return;
    }

    let new_index = records.len();
    records.push(imported);
    index.insert(key, new_index);
}

fn should_replace_record(existing: &VulnerabilityRecord, imported: &VulnerabilityRecord) -> bool {
    match compare_optional_timestamp(
        imported.last_modified.as_deref(),
        existing.last_modified.as_deref(),
    ) {
        Some(std::cmp::Ordering::Greater) => true,
        Some(std::cmp::Ordering::Less) => false,
        _ => imported.provenance.imported_unix >= existing.provenance.imported_unix,
    }
}

fn compare_optional_timestamp(lhs: Option<&str>, rhs: Option<&str>) -> Option<std::cmp::Ordering> {
    let lhs = lhs.and_then(parse_timestamp)?;
    let rhs = rhs.and_then(parse_timestamp)?;
    Some(lhs.cmp(&rhs))
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f")
                .ok()
                .map(|timestamp| timestamp.and_utc())
        })
}

fn stamp_nvd_sync_failure_in_cache(cache: &mut AdvisoryCache, err: &str, now: u64) {
    if let Some(source) = cache
        .sources
        .iter_mut()
        .find(|candidate| candidate.source_kind == NVD_SOURCE_KIND && candidate.source_key == NVD_SOURCE_KEY)
    {
        source.last_attempt_unix = now;
        source.status = SourceHealth::Error;
        source.last_error = Some(err.to_string());
    }
}

fn parse_nvd_record(
    item: &Value,
    imported_unix: u64,
    source_url: &str,
) -> Result<Option<VulnerabilityRecord>, String> {
    let Some(cve) = item.get("cve") else {
        return Ok(None);
    };

    let Some(primary_id) = cve.get("id").and_then(Value::as_str).map(str::trim) else {
        return Ok(None);
    };
    if primary_id.is_empty() {
        return Ok(None);
    }

    let references = cve
        .get("references")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(parse_reference)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mitigations = references
        .iter()
        .filter(|reference| {
            reference.tags.iter().any(|tag| {
                let lower = tag.to_ascii_lowercase();
                lower.contains("mitigation") || lower.contains("workaround")
            })
        })
        .map(|reference| reference.url.clone())
        .collect::<Vec<_>>();
    let severities = parse_severities(cve.get("metrics"));
    let affected_products = parse_affected_products(cve.get("configurations"));
    let summary = cve
        .get("descriptions")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries.iter().find_map(|entry| {
                if entry.get("lang").and_then(Value::as_str) == Some("en") {
                    entry.get("value").and_then(Value::as_str).map(str::trim)
                } else {
                    None
                }
            })
        })
        .unwrap_or("")
        .to_string();
    let aliases = cve
        .get("weaknesses")
        .and_then(Value::as_array)
        .map(|_| vec![primary_id.to_string()])
        .unwrap_or_else(|| vec![primary_id.to_string()]);

    Ok(Some(VulnerabilityRecord {
        primary_id: primary_id.to_string(),
        aliases,
        summary,
        published: cve
            .get("published")
            .and_then(Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        last_modified: cve
            .get("lastModified")
            .and_then(Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        known_exploited: cve
            .get("cisaExploitAdd")
            .and_then(Value::as_str)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false),
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
    }))
}

fn parse_reference(value: &Value) -> Option<VulnerabilityReference> {
    let url = value.get("url").and_then(Value::as_str).map(str::trim)?;
    if url.is_empty() {
        return None;
    }

    let source = value
        .get("source")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned);
    let tags = value
        .get("tags")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(VulnerabilityReference {
        url: url.to_string(),
        source,
        tags,
    })
}

fn parse_severities(metrics: Option<&Value>) -> Vec<VulnerabilitySeverity> {
    let Some(metrics) = metrics else {
        return vec![];
    };

    let mut severities = Vec::new();
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let Some(entries) = metrics.get(key).and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            let source = entry
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("nvd")
                .to_string();
            let Some(cvss) = entry.get("cvssData") else {
                continue;
            };
            let scheme = cvss
                .get("version")
                .and_then(Value::as_str)
                .map(|version| format!("CVSS {version}"))
                .unwrap_or_else(|| key.to_string());
            let severity = entry
                .get("baseSeverity")
                .or_else(|| {
                    entry
                        .get("cvssData")
                        .and_then(|value| value.get("baseSeverity"))
                })
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let score = cvss
                .get("baseScore")
                .and_then(Value::as_f64)
                .map(|value| value as f32);
            let vector = cvss
                .get("vectorString")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            severities.push(VulnerabilitySeverity {
                source,
                scheme,
                severity,
                score,
                vector,
            });
        }
    }
    severities
}

fn parse_affected_products(configurations: Option<&Value>) -> Vec<AffectedProduct> {
    let Some(configurations) = configurations else {
        return vec![];
    };

    let mut products = Vec::new();
    collect_affected_products(configurations, &mut products);
    products
}

fn collect_affected_products(value: &Value, products: &mut Vec<AffectedProduct>) {
    match value {
        Value::Array(entries) => {
            for entry in entries {
                collect_affected_products(entry, products);
            }
        }
        Value::Object(map) => {
            if let Some(cpe_matches) = map.get("cpeMatch").and_then(Value::as_array) {
                for cpe in cpe_matches {
                    let Some(criteria) = cpe.get("criteria").and_then(Value::as_str) else {
                        continue;
                    };
                    products.push(AffectedProduct {
                        criteria: criteria.to_string(),
                        vulnerable: cpe
                            .get("vulnerable")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        version_start_including: cpe
                            .get("versionStartIncluding")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        version_start_excluding: cpe
                            .get("versionStartExcluding")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        version_end_including: cpe
                            .get("versionEndIncluding")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        version_end_excluding: cpe
                            .get("versionEndExcluding")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                    });
                }
            }
            for entry in map.values() {
                collect_affected_products(entry, products);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::sync::{Arc, Mutex};
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
                last_attempt_unix: 42,
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
                    last_attempt_unix: 100,
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
                    last_attempt_unix: 90,
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
                last_attempt_unix: 110,
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
    fn sync_nvd_uses_incremental_last_modified_cursor_and_updates_cache() {
        let existing = AdvisoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
            generated_unix: 100,
            sources: vec![AdvisorySourceCache {
                source_key: NVD_SOURCE_KEY.into(),
                source_kind: NVD_SOURCE_KIND.into(),
                source_url: NVD_API_URL.into(),
                imported_from: None,
                imported_from_batch: vec![],
                fetched_unix: 100,
                expires_unix: 120,
                snapshot_sha256: "old".into(),
                total_results: 1,
                status: SourceHealth::Fresh,
                last_attempt_unix: 100,
                last_error: None,
            }],
            records: vec![VulnerabilityRecord {
                primary_id: "CVE-2026-12345".into(),
                summary: "Older record".into(),
                last_modified: Some("2026-04-27T10:00:00.000".into()),
                provenance: VulnerabilityProvenance {
                    source_kind: NVD_SOURCE_KIND.into(),
                    source_key: NVD_SOURCE_KEY.into(),
                    source_url: NVD_API_URL.into(),
                    imported_unix: 100,
                },
                ..VulnerabilityRecord::default()
            }],
        };
        let fetcher = FakeFetcher::new(vec![json!({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-12345",
                    "published": "2026-04-25T10:00:00.000",
                    "lastModified": "2026-04-28T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Updated from sync"}]
                }
            }]
        })]);

        let now = parse_timestamp("2026-04-28T00:00:00Z").unwrap().timestamp() as u64;
        let (cache, requested_pages, imported_records) =
            sync_nvd_with_fetcher(Some(existing), &fetcher, now).unwrap();

        assert_eq!(requested_pages, 1);
        assert_eq!(imported_records, 1);
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].last_mod_start_date.as_deref(),
            Some("2026-04-27T10:00:00.000Z")
        );
        assert_eq!(
            requests[0].last_mod_end_date.as_deref(),
            Some("2026-04-28T00:00:00.000Z")
        );
        drop(requests);

        let source = cache
            .sources
            .iter()
            .find(|source| source.source_key == NVD_SOURCE_KEY)
            .unwrap();
        assert_eq!(source.fetched_unix, now);
        assert_eq!(source.last_attempt_unix, now);
        assert_eq!(source.status, SourceHealth::Fresh);
        assert!(source.last_error.is_none());
        assert_eq!(cache.records[0].summary, "Updated from sync");
    }

    #[test]
    fn sync_nvd_omits_last_modified_window_on_first_sync() {
        let fetcher = FakeFetcher::new(vec![json!({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-50000",
                    "published": "2026-04-25T10:00:00.000",
                    "lastModified": "2026-04-28T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Fresh install sync"}]
                }
            }]
        })]);

        let now = parse_timestamp("2026-04-28T00:00:00Z").unwrap().timestamp() as u64;
        let (_cache, requested_pages, imported_records) =
            sync_nvd_with_fetcher(None, &fetcher, now).unwrap();

        assert_eq!(requested_pages, 1);
        assert_eq!(imported_records, 1);
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].last_mod_start_date.is_none());
        assert!(requests[0].last_mod_end_date.is_none());
    }

    #[test]
    fn sync_nvd_omits_last_modified_window_when_cached_cursor_is_unparseable() {
        let existing = AdvisoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
            generated_unix: 100,
            sources: vec![AdvisorySourceCache {
                source_key: NVD_SOURCE_KEY.into(),
                source_kind: NVD_SOURCE_KIND.into(),
                source_url: NVD_API_URL.into(),
                imported_from: None,
                imported_from_batch: vec![],
                fetched_unix: 100,
                expires_unix: 120,
                snapshot_sha256: "old".into(),
                total_results: 1,
                status: SourceHealth::Fresh,
                last_attempt_unix: 100,
                last_error: None,
            }],
            records: vec![VulnerabilityRecord {
                primary_id: "CVE-2025-99999".into(),
                summary: "Corrupt cursor".into(),
                last_modified: Some("not-a-timestamp".into()),
                provenance: VulnerabilityProvenance {
                    source_kind: NVD_SOURCE_KIND.into(),
                    source_key: NVD_SOURCE_KEY.into(),
                    source_url: NVD_API_URL.into(),
                    imported_unix: 100,
                },
                ..VulnerabilityRecord::default()
            }],
        };
        let fetcher = FakeFetcher::new(vec![json!({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-50001",
                    "published": "2026-04-25T10:00:00.000",
                    "lastModified": "2026-04-28T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Fallback to full sync"}]
                }
            }]
        })]);

        let now = parse_timestamp("2026-04-28T00:00:00Z").unwrap().timestamp() as u64;
        let (_cache, requested_pages, imported_records) =
            sync_nvd_with_fetcher(Some(existing), &fetcher, now).unwrap();

        assert_eq!(requested_pages, 1);
        assert_eq!(imported_records, 1);
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].last_mod_start_date.is_none());
        assert!(requests[0].last_mod_end_date.is_none());
    }

    #[test]
    fn sync_nvd_splits_incremental_windows_larger_than_120_days() {
        let existing = AdvisoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
            generated_unix: 100,
            sources: vec![AdvisorySourceCache {
                source_key: NVD_SOURCE_KEY.into(),
                source_kind: NVD_SOURCE_KIND.into(),
                source_url: NVD_API_URL.into(),
                imported_from: None,
                imported_from_batch: vec![],
                fetched_unix: 100,
                expires_unix: 120,
                snapshot_sha256: "old".into(),
                total_results: 1,
                status: SourceHealth::Fresh,
                last_attempt_unix: 100,
                last_error: None,
            }],
            records: vec![VulnerabilityRecord {
                primary_id: "CVE-2025-11111".into(),
                summary: "Older record".into(),
                last_modified: Some("2025-01-01T00:00:00.000".into()),
                provenance: VulnerabilityProvenance {
                    source_kind: NVD_SOURCE_KIND.into(),
                    source_key: NVD_SOURCE_KEY.into(),
                    source_url: NVD_API_URL.into(),
                    imported_unix: 100,
                },
                ..VulnerabilityRecord::default()
            }],
        };
        let fetcher = FakeFetcher::new(vec![
            json!({
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 0,
                "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "vulnerabilities": []
            }),
            json!({
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 0,
                "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "vulnerabilities": []
            }),
        ]);

        let now = parse_timestamp("2025-08-01T00:00:00Z").unwrap().timestamp() as u64;
        let (_cache, requested_pages, imported_records) =
            sync_nvd_with_fetcher(Some(existing), &fetcher, now).unwrap();

        assert_eq!(requested_pages, 2);
        assert_eq!(imported_records, 0);
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].last_mod_start_date.as_deref(),
            Some("2025-01-01T00:00:00.000Z")
        );
        assert_eq!(
            requests[0].last_mod_end_date.as_deref(),
            Some("2025-05-01T00:00:00.000Z")
        );
        assert_eq!(
            requests[1].last_mod_start_date.as_deref(),
            Some("2025-05-01T00:00:00.000Z")
        );
        assert_eq!(
            requests[1].last_mod_end_date.as_deref(),
            Some("2025-08-01T00:00:00.000Z")
        );
    }

    #[test]
    fn nvd_rate_limit_remaining_uses_last_attempt_time() {
        let cache = AdvisoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
            generated_unix: 100,
            sources: vec![AdvisorySourceCache {
                source_key: NVD_SOURCE_KEY.into(),
                source_kind: NVD_SOURCE_KIND.into(),
                source_url: NVD_API_URL.into(),
                imported_from: None,
                imported_from_batch: vec![],
                fetched_unix: 100,
                expires_unix: 200,
                snapshot_sha256: String::new(),
                total_results: 0,
                status: SourceHealth::Fresh,
                last_attempt_unix: 120,
                last_error: None,
            }],
            records: vec![],
        };

        assert_eq!(nvd_rate_limit_remaining(Some(&cache), 7_200), Some(120));
        assert_eq!(nvd_rate_limit_remaining(Some(&cache), 7_320), None);
    }

    #[test]
    fn stamp_nvd_sync_failure_marks_cache_error_state() {
        let cache = AdvisoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
            generated_unix: 100,
            sources: vec![AdvisorySourceCache {
                source_key: NVD_SOURCE_KEY.into(),
                source_kind: NVD_SOURCE_KIND.into(),
                source_url: NVD_API_URL.into(),
                imported_from: None,
                imported_from_batch: vec![],
                fetched_unix: 100,
                expires_unix: 500,
                snapshot_sha256: String::new(),
                total_results: 0,
                status: SourceHealth::Fresh,
                last_attempt_unix: 100,
                last_error: None,
            }],
            records: vec![],
        };

        let failed = stamp_nvd_sync_failure(cache, "network timeout", 200);
        let source = failed.sources.first().unwrap();
        assert_eq!(source.last_attempt_unix, 200);
        assert_eq!(source.status, SourceHealth::Error);
        assert_eq!(source.last_error.as_deref(), Some("network timeout"));
    }

    struct FakeFetcher {
        responses: Vec<Vec<u8>>,
        requests: Arc<Mutex<Vec<NvdSyncRequest>>>,
    }

    impl FakeFetcher {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                responses: responses
                    .into_iter()
                    .map(|value| serde_json::to_vec(&value).unwrap())
                    .collect(),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl NvdFetcher for FakeFetcher {
        fn fetch_page(&self, request: &NvdSyncRequest) -> Result<Vec<u8>, String> {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.clone());
            let index = requests.len() - 1;
            drop(requests);
            self.responses
                .get(index)
                .cloned()
                .ok_or_else(|| "unexpected page request".to_string())
        }
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
