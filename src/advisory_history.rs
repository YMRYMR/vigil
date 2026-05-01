//! NVD CVE change-history ingestion foundations.
//!
//! This is a narrow Phase 16 slice that keeps Vigil's advisory work explainable
//! and operator-auditable without prematurely deciding software matching or
//! scoring policy. The module provides:
//!
//! - protected local cache storage for NVD CVE change-history snapshots
//! - offline import for operator-supplied JSON snapshots, including paged batches
//! - live NVD CVE change-history sync with conservative rate limiting and
//!   incremental `changeStartDate` / `changeEndDate` windows
//! - startup logging and an operator CLI for cache/source visibility

use crate::advisory::{AdvisorySourceCache, SourceHealth};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CACHE_FILE: &str = "vigil-advisory-change-history-cache.json";
const CACHE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_SOURCE_TTL_SECS: u64 = 24 * 60 * 60;
const NVD_SOURCE_KEY: &str = "nvd-cve-history";
const NVD_SOURCE_KIND: &str = "nvd";
const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0";
const NVD_RESULTS_PER_PAGE: usize = 5_000;
const NVD_MIN_SYNC_INTERVAL_SECS: u64 = 2 * 60 * 60;
const NVD_MAX_INCREMENTAL_WINDOW_DAYS: i64 = 120;
const NVD_REQUEST_DELAY_NO_KEY_SECS: u64 = 6;
const NVD_REQUEST_DELAY_WITH_KEY_SECS: u64 = 1;
const HTTP_TIMEOUT_SECS: u64 = 20;
const MAX_RETRY_ATTEMPTS: usize = 3;
const NVD_API_ATTRIBUTION_NOTICE: &str =
    "This product uses the NVD API but is not endorsed or certified by the NVD.";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChangeHistoryCache {
    pub schema_version: u32,
    pub generated_unix: u64,
    pub sources: Vec<AdvisorySourceCache>,
    pub changes: Vec<CveChangeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CveChangeEvent {
    pub cve_id: String,
    pub event_name: String,
    pub change_id: String,
    pub source_identifier: String,
    pub created: Option<String>,
    pub details: Vec<CveChangeDetail>,
    pub provenance: ChangeHistoryProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CveChangeDetail {
    pub action: String,
    pub kind: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChangeHistoryProvenance {
    pub source_kind: String,
    pub source_key: String,
    pub source_url: String,
    pub imported_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    pub imported_files: usize,
    pub imported_changes: usize,
    pub total_changes: usize,
    pub total_sources: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheSummary {
    pub changes: usize,
    pub sources: usize,
    pub stale_sources: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSummary {
    pub requested_pages: usize,
    pub imported_changes: usize,
    pub total_changes: usize,
    pub total_sources: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    Updated(SyncSummary),
    SkippedRateLimit { remaining_secs: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NvdHistorySyncRequest {
    start_index: usize,
    results_per_page: usize,
    change_start_date: Option<String>,
    change_end_date: Option<String>,
}

trait NvdFetcher {
    fn fetch_page(&self, request: &NvdHistorySyncRequest) -> Result<Vec<u8>, String>;
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
            .map_err(|err| format!("failed to build NVD change-history HTTP client: {err}"))?;
        Ok(Self {
            client,
            base_url: std::env::var("VIGIL_NVD_CHANGE_HISTORY_API_BASE_URL")
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
    fn fetch_page(&self, request: &NvdHistorySyncRequest) -> Result<Vec<u8>, String> {
        let mut attempt = 0usize;
        loop {
            if attempt == 0 {
                self.wait_for_request_slot();
            }

            let mut http = self.client.get(&self.base_url).query(&[
                ("resultsPerPage", request.results_per_page.to_string()),
                ("startIndex", request.start_index.to_string()),
            ]);
            if let Some(change_start) = request.change_start_date.as_deref() {
                http = http.query(&[("changeStartDate", change_start)]);
            }
            if let Some(change_end) = request.change_end_date.as_deref() {
                http = http.query(&[("changeEndDate", change_end)]);
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
                    "failed to fetch NVD change-history page at startIndex {}: {err}",
                    request.start_index
                )
            })?;
            let status = response.status();
            if status.is_success() {
                return response.bytes().map(|bytes| bytes.to_vec()).map_err(|err| {
                    format!(
                        "failed to read NVD change-history response body at startIndex {}: {err}",
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
                "NVD change-history request failed with HTTP {} at startIndex {}{}",
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
        import_nvd_change_history_snapshot(&paths[0])?
    } else {
        import_nvd_change_history_snapshots(paths)?
    };
    println!(
        "Merged {} NVD CVE change event(s) from {} snapshot file(s) into the protected change-history cache. Cache now holds {} change event(s) across {} sources.",
        summary.imported_changes,
        summary.imported_files,
        summary.total_changes,
        summary.total_sources
    );
    Ok(())
}

pub fn run_sync_cli(force: bool) -> Result<SyncOutcome, String> {
    let outcome = sync_nvd_change_history(force)?;
    match &outcome {
        SyncOutcome::Updated(summary) => {
            println!(
                "Fetched {} NVD change-history page(s) and merged {} CVE change event(s) into the protected change-history cache. Cache now holds {} change event(s) across {} sources.",
                summary.requested_pages,
                summary.imported_changes,
                summary.total_changes,
                summary.total_sources
            );
        }
        SyncOutcome::SkippedRateLimit { remaining_secs } => {
            println!(
                "Skipped NVD change-history sync because the last automated pull is still inside the 2-hour minimum interval ({}s remaining). Use --sync-nvd-change-history --force to override.",
                remaining_secs
            );
        }
    }
    Ok(outcome)
}

pub fn run_status_cli() -> Result<(), String> {
    let path = cache_path();
    if !path.exists() {
        println!("NVD change history cache: empty (no protected cache found).");
        return Ok(());
    }

    let loaded: Option<ChangeHistoryCache> = crate::security::policy::load_struct_with_integrity(&path)
        .map_err(|e| {
            format!(
                "failed to load protected change-history cache {}: {e}",
                path.display()
            )
        })?;
    let Some(cache) = loaded else {
        println!(
            "NVD change history cache: unavailable (protected cache could not be verified or restored)."
        );
        return Ok(());
    };
    if cache.schema_version != CACHE_SCHEMA_VERSION {
        return Err(format!(
            "protected change-history cache {} used unsupported schema version {}",
            path.display(),
            cache.schema_version
        ));
    }

    let now = unix_now();
    let stale_sources = cache
        .sources
        .iter()
        .filter(|source| {
            is_source_stale(source.expires_unix, now)
                || matches!(source.status, SourceHealth::Stale | SourceHealth::Error)
        })
        .count();

    println!(
        "NVD change history cache: {} change event(s), {} sources ({} stale/error)",
        cache.changes.len(),
        cache.sources.len(),
        stale_sources
    );

    for source in &cache.sources {
        println!(
            "- {} ({}) [{}] results={} fetched={} expires={} sha256={}",
            source.source_key,
            source.source_kind,
            source_state(source, now),
            source.total_results,
            source.fetched_unix,
            source.expires_unix,
            source.snapshot_sha256,
        );
        if let Some(imported_from) = &source.imported_from {
            println!("  imported_from={imported_from}");
        }
        if source.imported_from_batch.len() > 1 {
            println!(
                "  imported_from_batch={}",
                source.imported_from_batch.join(", ")
            );
        }
        if !source.source_url.trim().is_empty() {
            println!("  source_url={}", source.source_url);
        }
        println!("  attribution={NVD_API_ATTRIBUTION_NOTICE}");
        if source.last_attempt_unix > 0 {
            println!("  last_attempt={}", source.last_attempt_unix);
        }
        if let Some(last_error) = source.last_error.as_deref() {
            if !last_error.trim().is_empty() {
                println!("  last_error={last_error}");
            }
        }
    }

    Ok(())
}

pub fn log_cache_status() {
    match load_cache_summary() {
        Ok(Some(summary)) => {
            tracing::info!(
                change_events = summary.changes,
                sources = summary.sources,
                stale_sources = summary.stale_sources,
                "NVD change-history cache loaded"
            );
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(%err, "failed to load NVD change-history cache");
        }
    }
}

pub fn refresh_nvd_in_background_if_due() {
    if !nvd_refresh_due() {
        return;
    }

    match sync_nvd_change_history(false) {
        Ok(SyncOutcome::Updated(summary)) => {
            tracing::info!(
                requested_pages = summary.requested_pages,
                imported_changes = summary.imported_changes,
                total_changes = summary.total_changes,
                total_sources = summary.total_sources,
                "refreshed NVD change-history cache"
            );
        }
        Ok(SyncOutcome::SkippedRateLimit { remaining_secs }) => {
            tracing::debug!(
                remaining_secs,
                "skipped NVD change-history refresh because the rate-limit interval is still active"
            );
        }
        Err(err) => {
            tracing::warn!(%err, "failed to refresh NVD change-history cache");
        }
    }
}

pub fn import_nvd_change_history_snapshot(path: &Path) -> Result<ImportSummary, String> {
    import_nvd_change_history_snapshots(&[path.to_path_buf()])
}

pub fn import_nvd_change_history_snapshots(paths: &[PathBuf]) -> Result<ImportSummary, String> {
    if paths.is_empty() {
        return Err("expected at least one NVD change-history snapshot path".into());
    }

    let imported_cache = load_snapshot_batch(paths)?;
    let imported_changes = imported_cache.changes.len();
    let cache = merge_cache(load_cache_for_import()?, imported_cache);
    let summary = ImportSummary {
        imported_files: paths.len(),
        imported_changes,
        total_changes: cache.changes.len(),
        total_sources: cache.sources.len(),
    };
    save_cache(&cache)?;
    Ok(summary)
}

pub fn sync_nvd_change_history(force: bool) -> Result<SyncOutcome, String> {
    let existing = load_cache_for_import()?;
    let now = unix_now();
    if !force {
        if let Some(remaining_secs) = nvd_rate_limit_remaining(existing.as_ref(), now) {
            return Ok(SyncOutcome::SkippedRateLimit { remaining_secs });
        }
    }

    let fetcher = HttpNvdFetcher::new()?;
    let (cache, requested_pages, imported_changes) =
        match sync_with_fetcher(existing.clone(), &fetcher, now) {
            Ok(result) => result,
            Err(err) => {
                let failed_cache = stamp_sync_failure(
                    existing.unwrap_or_else(|| empty_cache(now)),
                    &err,
                    now,
                );
                if let Err(save_err) = save_cache(&failed_cache) {
                    tracing::warn!(%save_err, "failed to persist NVD change-history sync failure state");
                }
                return Err(err);
            }
        };

    let summary = SyncSummary {
        requested_pages,
        imported_changes,
        total_changes: cache.changes.len(),
        total_sources: cache.sources.len(),
    };
    save_cache(&cache)?;
    Ok(SyncOutcome::Updated(summary))
}

fn load_cache_summary() -> Result<Option<CacheSummary>, String> {
    let Some(cache) = load_cache()? else {
        return Ok(None);
    };
    let now = unix_now();
    Ok(Some(CacheSummary {
        changes: cache.changes.len(),
        sources: cache.sources.len(),
        stale_sources: cache
            .sources
            .iter()
            .filter(|source| {
                is_source_stale(source.expires_unix, now)
                    || matches!(source.status, SourceHealth::Stale | SourceHealth::Error)
            })
            .count(),
    }))
}

fn load_cache() -> Result<Option<ChangeHistoryCache>, String> {
    let path = cache_path();
    if !path.exists() {
        return Ok(None);
    }
    let loaded: Option<ChangeHistoryCache> =
        crate::security::policy::load_struct_with_integrity(&path).map_err(|e| {
            format!(
                "failed to load protected change-history cache {}: {e}",
                path.display()
            )
        })?;
    let Some(cache) = loaded else {
        return Ok(None);
    };
    if cache.schema_version != CACHE_SCHEMA_VERSION {
        return Err(format!(
            "protected change-history cache {} used unsupported schema version {}",
            path.display(),
            cache.schema_version
        ));
    }
    Ok(Some(cache))
}

fn load_cache_for_import() -> Result<Option<ChangeHistoryCache>, String> {
    match load_cache() {
        Ok(cache) => Ok(cache),
        Err(err) if err.contains("unsupported schema version") => {
            tracing::warn!(%err, "ignoring incompatible change-history cache during import");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn save_cache(cache: &ChangeHistoryCache) -> Result<(), String> {
    let path = cache_path();
    crate::security::policy::save_struct_with_integrity(&path, cache).map_err(|e| {
        format!(
            "failed to save protected change-history cache {}: {e}",
            path.display()
        )
    })
}

fn cache_path() -> PathBuf {
    crate::config::data_dir().join(CACHE_FILE)
}

fn load_snapshot_batch(paths: &[PathBuf]) -> Result<ChangeHistoryCache, String> {
    let mut imported = None;
    let mut page_hashes = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes =
            std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        page_hashes.push(sha256_hex(&bytes));
        let cache = parse_snapshot(&bytes, Some(path))?;
        imported = Some(match imported {
            Some(existing) => merge_import_batch_cache(existing, cache),
            None => cache,
        });
    }

    let mut imported = imported.ok_or_else(|| {
        "expected at least one NVD change-history snapshot path".to_string()
    })?;
    finalize_import_batch_metadata(&mut imported, &page_hashes);
    Ok(imported)
}

fn sync_with_fetcher(
    existing: Option<ChangeHistoryCache>,
    fetcher: &dyn NvdFetcher,
    now: u64,
) -> Result<(ChangeHistoryCache, usize, usize), String> {
    let mut imported = None;
    let mut page_hashes = Vec::new();
    let mut page_count = 0usize;
    let mut imported_changes = 0usize;

    for (change_start_date, change_end_date) in sync_windows(existing.as_ref(), now) {
        let request_template = NvdHistorySyncRequest {
            start_index: 0,
            results_per_page: NVD_RESULTS_PER_PAGE,
            change_start_date,
            change_end_date,
        };

        let mut start_index = 0usize;
        loop {
            let request = NvdHistorySyncRequest {
                start_index,
                ..request_template.clone()
            };
            let bytes = fetcher.fetch_page(&request)?;
            page_hashes.push(sha256_hex(&bytes));
            let page = parse_snapshot(&bytes, None)?;
            let total_results = page
                .sources
                .first()
                .map(|source| source.total_results)
                .unwrap_or(page.changes.len());
            let page_changes = page.changes.len();
            imported_changes += page_changes;
            imported = Some(match imported {
                Some(existing_pages) => merge_import_batch_cache(existing_pages, page),
                None => page,
            });
            page_count += 1;

            if page_changes == 0
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
    stamp_sync_success(&mut merged, page_count, now);
    Ok((merged, page_count, imported_changes))
}

fn empty_cache(now: u64) -> ChangeHistoryCache {
    ChangeHistoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: now,
        sources: vec![],
        changes: vec![],
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
                    || matches!(source.status, SourceHealth::Stale | SourceHealth::Error)
            }),
        Ok(None) => true,
        Err(err) => {
            tracing::warn!(%err, "assuming NVD change-history refresh is due because the cache could not be read");
            true
        }
    }
}

fn nvd_rate_limit_remaining(existing: Option<&ChangeHistoryCache>, now: u64) -> Option<u64> {
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

fn latest_change_created(existing: Option<&ChangeHistoryCache>) -> Option<String> {
    existing?
        .changes
        .iter()
        .filter(|change| {
            change.provenance.source_kind == NVD_SOURCE_KIND
                && change.provenance.source_key == NVD_SOURCE_KEY
        })
        .filter_map(|change| change.created.as_deref())
        .filter_map(parse_timestamp)
        .max()
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn sync_windows(
    existing: Option<&ChangeHistoryCache>,
    now: u64,
) -> Vec<(Option<String>, Option<String>)> {
    let now = unix_timestamp(now);
    let latest = latest_change_created(existing).and_then(|value| parse_timestamp(&value));
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

fn stamp_sync_success(cache: &mut ChangeHistoryCache, requested_pages: usize, now: u64) {
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
            total_results: cache.changes.len(),
            status: SourceHealth::Fresh,
            last_attempt_unix: now,
            last_error: None,
        });
    }
    cache.generated_unix = now;
}

fn stamp_sync_failure(
    mut cache: ChangeHistoryCache,
    err: &str,
    now: u64,
) -> ChangeHistoryCache {
    if let Some(source) = cache
        .sources
        .iter_mut()
        .find(|source| source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY)
    {
        source.last_attempt_unix = now;
        source.last_error = Some(err.to_string());
        source.status = SourceHealth::Error;
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
            status: SourceHealth::Error,
            last_attempt_unix: now,
            last_error: Some(err.to_string()),
        });
    }
    cache.generated_unix = now;
    cache
}

fn source_state(source: &AdvisorySourceCache, now: u64) -> &'static str {
    if is_source_stale(source.expires_unix, now) {
        return "stale";
    }
    match source.status {
        SourceHealth::Fresh => "fresh",
        SourceHealth::Stale => "stale",
        SourceHealth::Error => "error",
    }
}

fn is_source_stale(expires_unix: u64, now: u64) -> bool {
    expires_unix > 0 && expires_unix < now
}

fn parse_snapshot(bytes: &[u8], imported_from: Option<&Path>) -> Result<ChangeHistoryCache, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|err| format!("failed to parse NVD change-history JSON: {err}"))?;

    let fetched_unix = value
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)
        .map(|timestamp| timestamp.timestamp() as u64)
        .unwrap_or_else(unix_now);
    let total_results = value
        .get("totalResults")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;

    let changes = value
        .get("cveChanges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| parse_change_event(entry, fetched_unix))
        .collect::<Result<Vec<_>, _>>()?;

    let imported_from_value = imported_from.map(|path| path.display().to_string());
    let source = AdvisorySourceCache {
        source_key: NVD_SOURCE_KEY.into(),
        source_kind: NVD_SOURCE_KIND.into(),
        source_url: NVD_API_URL.into(),
        imported_from: imported_from_value.clone(),
        imported_from_batch: imported_from_value.into_iter().collect(),
        fetched_unix,
        expires_unix: fetched_unix.saturating_add(DEFAULT_SOURCE_TTL_SECS),
        snapshot_sha256: sha256_hex(bytes),
        total_results,
        status: SourceHealth::Fresh,
        last_attempt_unix: 0,
        last_error: None,
    };

    Ok(ChangeHistoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: fetched_unix,
        sources: vec![source],
        changes,
    })
}

fn parse_change_event(value: &Value, imported_unix: u64) -> Result<CveChangeEvent, String> {
    let change = value.get("change").unwrap_or(value);
    let cve_id = string_field(change, "cveId")
        .ok_or_else(|| "NVD change-history entry missing change.cveId".to_string())?;
    let event_name = string_field(change, "eventName").unwrap_or_else(|| "Unknown".into());
    let change_id = string_field(change, "cveChangeId")
        .unwrap_or_else(|| format!("{cve_id}:{event_name}:{imported_unix}"));
    let source_identifier = string_field(change, "sourceIdentifier").unwrap_or_default();
    let created = string_field(change, "created");
    let details = change
        .get("details")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(parse_change_detail)
        .collect::<Vec<_>>();

    Ok(CveChangeEvent {
        cve_id,
        event_name,
        change_id,
        source_identifier,
        created,
        details,
        provenance: ChangeHistoryProvenance {
            source_kind: NVD_SOURCE_KIND.into(),
            source_key: NVD_SOURCE_KEY.into(),
            source_url: NVD_API_URL.into(),
            imported_unix,
        },
    })
}

fn parse_change_detail(value: &Value) -> CveChangeDetail {
    CveChangeDetail {
        action: string_field(value, "action").unwrap_or_default(),
        kind: string_field(value, "type").unwrap_or_default(),
        old_value: string_field(value, "oldValue"),
        new_value: string_field(value, "newValue"),
    }
}

fn merge_import_batch_cache(
    mut existing: ChangeHistoryCache,
    imported: ChangeHistoryCache,
) -> ChangeHistoryCache {
    existing.generated_unix = existing.generated_unix.max(imported.generated_unix);
    for source in imported.sources {
        merge_source(&mut existing.sources, source);
    }
    for change in imported.changes {
        merge_change(&mut existing.changes, change);
    }
    existing
}

fn finalize_import_batch_metadata(cache: &mut ChangeHistoryCache, page_hashes: &[String]) {
    if let Some(source) = cache
        .sources
        .iter_mut()
        .find(|source| source.source_kind == NVD_SOURCE_KIND && source.source_key == NVD_SOURCE_KEY)
    {
        source.snapshot_sha256 = if page_hashes.len() <= 1 {
            page_hashes.first().cloned().unwrap_or_default()
        } else {
            page_hashes.join(",")
        };
        if source.imported_from_batch.len() > 1 {
            source.imported_from = None;
        }
        source.total_results = source.total_results.max(cache.changes.len());
    }
}

fn merge_cache(
    existing: Option<ChangeHistoryCache>,
    imported: ChangeHistoryCache,
) -> ChangeHistoryCache {
    let mut merged = existing.unwrap_or_else(|| empty_cache(imported.generated_unix));
    merged.generated_unix = merged.generated_unix.max(imported.generated_unix);

    for source in imported.sources {
        merge_source(&mut merged.sources, source);
    }
    for change in imported.changes {
        merge_change(&mut merged.changes, change);
    }

    merged
}

fn merge_source(sources: &mut Vec<AdvisorySourceCache>, imported: AdvisorySourceCache) {
    if let Some(existing) = sources.iter_mut().find(|source| {
        source.source_kind == imported.source_kind && source.source_key == imported.source_key
    }) {
        existing.source_url = imported.source_url;
        existing.fetched_unix = existing.fetched_unix.max(imported.fetched_unix);
        existing.expires_unix = existing.expires_unix.max(imported.expires_unix);
        existing.total_results = existing.total_results.max(imported.total_results);
        existing.status = imported.status;
        if !imported.snapshot_sha256.trim().is_empty() {
            existing.snapshot_sha256 = imported.snapshot_sha256;
        }
        if let Some(imported_from) = imported.imported_from {
            push_unique(&mut existing.imported_from_batch, imported_from.clone());
            if existing.imported_from_batch.len() == 1 {
                existing.imported_from = Some(imported_from);
            } else {
                existing.imported_from = None;
            }
        }
        for path in imported.imported_from_batch {
            push_unique(&mut existing.imported_from_batch, path);
        }
        if existing.imported_from_batch.len() > 1 {
            existing.imported_from = None;
        }
        if imported.last_attempt_unix > 0 {
            existing.last_attempt_unix = existing.last_attempt_unix.max(imported.last_attempt_unix);
        }
        if imported.last_error.is_some() {
            existing.last_error = imported.last_error;
        }
        return;
    }
    sources.push(imported);
}

fn merge_change(changes: &mut Vec<CveChangeEvent>, imported: CveChangeEvent) {
    if let Some(existing) = changes
        .iter_mut()
        .find(|change| change_key(change) == change_key(&imported))
    {
        if compare_optional_timestamp(imported.created.as_deref(), existing.created.as_deref())
            == Some(std::cmp::Ordering::Greater)
        {
            *existing = imported;
        }
        return;
    }
    changes.push(imported);
}

fn change_key(change: &CveChangeEvent) -> (&str, &str) {
    (&change.cve_id, &change.change_id)
}

fn compare_optional_timestamp(a: Option<&str>, b: Option<&str>) -> Option<std::cmp::Ordering> {
    let a = a.and_then(parse_timestamp)?;
    let b = b.and_then(parse_timestamp)?;
    Some(a.cmp(&b))
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|timestamp| {
                    chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                        timestamp,
                        chrono::Utc,
                    )
                })
        })
        .ok()
}

fn unix_timestamp(unix: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix as i64, 0)
        .unwrap_or_else(chrono::Utc::now)
}

fn format_datetime(timestamp: chrono::DateTime<chrono::Utc>) -> String {
    timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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
    fn parses_nvd_change_history_snapshot() {
        let snapshot = json!({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "timestamp": "2026-04-26T00:00:00.000",
            "cveChanges": [
                {
                    "change": {
                        "cveId": "CVE-2026-12345",
                        "eventName": "Initial Analysis",
                        "cveChangeId": "5DEF54B9-7FF3-4436-9763-2958C5B78731",
                        "sourceIdentifier": "nvd@example.com",
                        "created": "2026-04-26T10:00:00.000",
                        "details": [
                            {
                                "action": "Added",
                                "type": "CVSS V3.1",
                                "newValue": "NIST AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            },
                            {
                                "action": "Changed",
                                "type": "Reference Type",
                                "oldValue": "https://example.com No Types Assigned",
                                "newValue": "https://example.com Vendor Advisory"
                            }
                        ]
                    }
                }
            ]
        });

        let cache = parse_snapshot(
            serde_json::to_string(&snapshot).unwrap().as_bytes(),
            Some(Path::new("/tmp/nvd-history.json")),
        )
        .unwrap();

        assert_eq!(cache.schema_version, CACHE_SCHEMA_VERSION);
        assert_eq!(cache.changes.len(), 1);
        assert_eq!(cache.sources[0].source_key, NVD_SOURCE_KEY);
        assert_eq!(cache.sources[0].total_results, 1);
        assert_eq!(
            cache.sources[0].imported_from.as_deref(),
            Some("/tmp/nvd-history.json")
        );

        let change = &cache.changes[0];
        assert_eq!(change.cve_id, "CVE-2026-12345");
        assert_eq!(change.event_name, "Initial Analysis");
        assert_eq!(change.change_id, "5DEF54B9-7FF3-4436-9763-2958C5B78731");
        assert_eq!(change.details.len(), 2);
        assert_eq!(change.details[0].kind, "CVSS V3.1");
        assert_eq!(
            change.details[1].old_value.as_deref(),
            Some("https://example.com No Types Assigned")
        );
    }

    #[test]
    fn import_batch_combines_paged_snapshots_into_one_source() {
        let first = json!({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 2,
            "timestamp": "2026-04-26T00:00:00.000",
            "cveChanges": [
                {
                    "change": {
                        "cveId": "CVE-2026-1000",
                        "eventName": "Initial Analysis",
                        "cveChangeId": "change-1",
                        "sourceIdentifier": "nvd@example.com",
                        "created": "2026-04-26T00:00:01.000",
                        "details": []
                    }
                }
            ]
        });
        let second = json!({
            "resultsPerPage": 1,
            "startIndex": 1,
            "totalResults": 2,
            "timestamp": "2026-04-26T00:01:00.000",
            "cveChanges": [
                {
                    "change": {
                        "cveId": "CVE-2026-2000",
                        "eventName": "Reanalysis",
                        "cveChangeId": "change-2",
                        "sourceIdentifier": "nvd@example.com",
                        "created": "2026-04-26T00:01:01.000",
                        "details": []
                    }
                }
            ]
        });

        let dir = temp_dir();
        let first_path = dir.join("nvd-history-page-1.json");
        let second_path = dir.join("nvd-history-page-2.json");
        fs::write(&first_path, serde_json::to_vec(&first).unwrap()).unwrap();
        fs::write(&second_path, serde_json::to_vec(&second).unwrap()).unwrap();

        let batch = load_snapshot_batch(&[first_path.clone(), second_path.clone()]).unwrap();

        assert_eq!(batch.changes.len(), 2);
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
    }

    #[test]
    fn protected_cache_round_trip_preserves_change_events() {
        let dir = temp_dir();
        let path = dir.join(CACHE_FILE);
        let cache = ChangeHistoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
            generated_unix: 42,
            sources: vec![AdvisorySourceCache {
                source_key: NVD_SOURCE_KEY.into(),
                source_kind: NVD_SOURCE_KIND.into(),
                source_url: NVD_API_URL.into(),
                imported_from: Some("/tmp/nvd-history.json".into()),
                imported_from_batch: vec!["/tmp/nvd-history.json".into()],
                fetched_unix: 42,
                expires_unix: 84,
                snapshot_sha256: "abc".into(),
                total_results: 1,
                status: SourceHealth::Fresh,
                last_attempt_unix: 0,
                last_error: None,
            }],
            changes: vec![CveChangeEvent {
                cve_id: "CVE-2026-9999".into(),
                event_name: "Initial Analysis".into(),
                change_id: "change-9999".into(),
                source_identifier: "nvd@example.com".into(),
                created: Some("2026-04-26T10:00:00.000".into()),
                details: vec![],
                provenance: ChangeHistoryProvenance {
                    source_kind: NVD_SOURCE_KIND.into(),
                    source_key: NVD_SOURCE_KEY.into(),
                    source_url: NVD_API_URL.into(),
                    imported_unix: 42,
                },
            }],
        };

        crate::security::policy::save_struct_with_integrity(&path, &cache).unwrap();
        let loaded: ChangeHistoryCache = crate::security::policy::load_struct_with_integrity(&path)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.changes.len(), 1);
        assert_eq!(loaded.changes[0].cve_id, "CVE-2026-9999");
    }

    #[test]
    fn sync_windows_split_long_offline_gaps() {
        let existing = ChangeHistoryCache {
            schema_version: CACHE_SCHEMA_VERSION,
            generated_unix: 0,
            sources: vec![],
            changes: vec![CveChangeEvent {
                cve_id: "CVE-2026-12345".into(),
                event_name: "Initial Analysis".into(),
                change_id: "change-1".into(),
                source_identifier: "nvd@example.com".into(),
                created: Some("2026-01-01T00:00:00.000".into()),
                details: vec![],
                provenance: ChangeHistoryProvenance {
                    source_kind: NVD_SOURCE_KIND.into(),
                    source_key: NVD_SOURCE_KEY.into(),
                    source_url: NVD_API_URL.into(),
                    imported_unix: 0,
                },
            }],
        };
        let now = parse_timestamp("2026-06-15T00:00:00.000")
            .unwrap()
            .timestamp() as u64;
        let windows = sync_windows(Some(&existing), now);
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
        assert_eq!(sync_windows(None, now), vec![(None, None)]);
    }

    #[test]
    fn stamp_sync_failure_creates_source_for_first_failure() {
        let cache = stamp_sync_failure(empty_cache(0), "boom", 42);
        assert_eq!(cache.sources.len(), 1);
        let source = &cache.sources[0];
        assert_eq!(source.source_key, NVD_SOURCE_KEY);
        assert_eq!(source.source_kind, NVD_SOURCE_KIND);
        assert_eq!(source.last_attempt_unix, 42);
        assert_eq!(source.last_error.as_deref(), Some("boom"));
        assert_eq!(source.status, SourceHealth::Error);
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
        let dir = std::env::temp_dir().join(format!("vigil-advisory-history-test-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
