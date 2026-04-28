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

    fn run_sync_cli(force: bool) -> Result<(), String> {
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

    fn import_nvd_snapshot(path: &Path) -> Result<ImportSummary, String> {
    import_nvd_snapshots(&[path.to_path_buf()])
}

    fn import_nvd_snapshots(paths: &[PathBuf]) -> Result<ImportSummary, String> {
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

