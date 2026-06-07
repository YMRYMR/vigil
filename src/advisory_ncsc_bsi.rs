//! NCSC and BSI public advisory ingestion foundations.
//!
//! Parsing stays independent from transport so offline imports, live
//! background sync, and tests share the same normalization path.

use crate::advisory::{
    AdvisoryCache, AdvisorySourceCache, AffectedProduct, SourceHealth, VulnerabilityProvenance,
    VulnerabilityRecord, VulnerabilityReference, VulnerabilitySeverity,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CACHE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_SOURCE_TTL_SECS: u64 = 24 * 60 * 60;
const LIVE_SYNC_RETRY_SECS: u64 = 15 * 60;
const HTTP_TIMEOUT_SECS: u64 = 20;
const NCSC_SOURCE_KEY: &str = "ncsc-advisories";
const NCSC_SOURCE_KIND: &str = "ncsc";
const NCSC_SOURCE_URL: &str = "https://advisories.ncsc.nl/";
const NCSC_RSS_URL: &str = "https://advisories.ncsc.nl/rss/advisories";
const BSI_SOURCE_KEY: &str = "bsi-advisories";
const BSI_SOURCE_KIND: &str = "bsi";
const BSI_SOURCE_URL: &str = "https://www.bsi.bund.de/";
const BSI_RSS_URL: &str = "https://wid.cert-bund.de/content/public/securityAdvisory/rss";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NationalAdvisorySourceKind {
    Ncsc,
    Bsi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NationalAdvisoryImportSummary {
    pub imported_files: usize,
    pub imported_records: usize,
    pub known_exploited: usize,
    pub total_records: usize,
    pub total_sources: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NationalAdvisorySyncSummary {
    pub requested_sources: usize,
    pub requested_feeds: usize,
    pub imported_records: usize,
    pub failed_sources: usize,
    pub total_records: usize,
    pub total_sources: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NationalAdvisorySyncOutcome {
    Updated(NationalAdvisorySyncSummary),
    SkippedFresh { remaining_secs: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecordKey {
    primary_id: String,
    source_kind: String,
    source_key: String,
}

trait NationalAdvisoryFetcher {
    fn fetch_url(&self, url: &str) -> Result<Vec<u8>, String>;
}

struct HttpNationalAdvisoryFetcher {
    client: reqwest::blocking::Client,
}

impl HttpNationalAdvisoryFetcher {
    fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|err| format!("failed to build national advisory HTTP client: {err}"))?;
        Ok(Self { client })
    }
}

impl NationalAdvisoryFetcher for HttpNationalAdvisoryFetcher {
    fn fetch_url(&self, url: &str) -> Result<Vec<u8>, String> {
        let response = self
            .client
            .get(url)
            .header(
                reqwest::header::USER_AGENT,
                format!("Vigil/{}", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .map_err(|err| format!("failed to fetch {url}: {err}"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(format!(
                "request to {url} failed with HTTP {}{}",
                status.as_u16(),
                if body.is_empty() {
                    String::new()
                } else {
                    format!(": {}", body.chars().take(200).collect::<String>())
                }
            ));
        }
        response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|err| format!("failed to read {url} response body: {err}"))
    }
}

pub fn run_import_ncsc_cli(paths: &[PathBuf]) -> Result<(), String> {
    let summary = import_snapshots(NationalAdvisorySourceKind::Ncsc, paths)?;
    println!(
        "Merged {} NCSC advisory record(s) from {} snapshot file(s) into the advisory database. Database now holds {} records across {} sources.",
        summary.imported_records,
        summary.imported_files,
        summary.total_records,
        summary.total_sources,
    );
    Ok(())
}

pub fn run_import_bsi_cli(paths: &[PathBuf]) -> Result<(), String> {
    let summary = import_snapshots(NationalAdvisorySourceKind::Bsi, paths)?;
    println!(
        "Merged {} BSI/CERT-Bund advisory record(s) from {} snapshot file(s) into the advisory database. Database now holds {} records across {} sources.",
        summary.imported_records,
        summary.imported_files,
        summary.total_records,
        summary.total_sources,
    );
    Ok(())
}

pub fn run_sync_national_sources_cli(force: bool) -> Result<(), String> {
    match sync_national_sources(force)? {
        NationalAdvisorySyncOutcome::Updated(summary) => {
            println!(
                "Fetched {} NCSC/BSI feed(s) across {} source(s), merged {} record(s), and recorded {} source failure(s). Database now holds {} records across {} sources.",
                summary.requested_feeds,
                summary.requested_sources,
                summary.imported_records,
                summary.failed_sources,
                summary.total_records,
                summary.total_sources,
            );
        }
        NationalAdvisorySyncOutcome::SkippedFresh { remaining_secs } => {
            println!(
                "Skipped NCSC/BSI advisory refresh because sources are fresh for another {} second(s). Use --force to refresh now.",
                remaining_secs
            );
        }
    }
    Ok(())
}

pub fn sync_national_sources(force: bool) -> Result<NationalAdvisorySyncOutcome, String> {
    let now = unix_now();
    let sources = load_source_metadata()?;
    let due = [
        NationalAdvisorySourceKind::Ncsc,
        NationalAdvisorySourceKind::Bsi,
    ]
    .into_iter()
    .filter(|source_kind| {
        force
            || source_refresh_due(
                sources
                    .iter()
                    .find(|source| source.source_key == source_kind.source_key()),
                now,
            )
    })
    .collect::<Vec<_>>();

    if due.is_empty() {
        let remaining_secs = sources
            .iter()
            .filter(|source| {
                source.source_key == NationalAdvisorySourceKind::Ncsc.source_key()
                    || source.source_key == NationalAdvisorySourceKind::Bsi.source_key()
            })
            .filter_map(|source| source.expires_unix.checked_sub(now))
            .min()
            .unwrap_or(DEFAULT_SOURCE_TTL_SECS);
        return Ok(NationalAdvisorySyncOutcome::SkippedFresh { remaining_secs });
    }

    let fetcher = HttpNationalAdvisoryFetcher::new()?;
    sync_national_sources_with_fetcher(&due, &fetcher, now)
}

#[allow(dead_code)]
pub fn refresh_national_sources_in_background_if_due() {
    match sync_national_sources(false) {
        Ok(NationalAdvisorySyncOutcome::Updated(summary)) => {
            tracing::info!(
                requested_feeds = summary.requested_feeds,
                imported_records = summary.imported_records,
                failed_sources = summary.failed_sources,
                total_records = summary.total_records,
                total_sources = summary.total_sources,
                "refreshed NCSC/BSI advisory feeds"
            );
        }
        Ok(NationalAdvisorySyncOutcome::SkippedFresh { remaining_secs }) => {
            tracing::debug!(
                remaining_secs,
                "skipped NCSC/BSI advisory refresh because sources are still fresh"
            );
        }
        Err(err) => {
            tracing::warn!(%err, "failed to refresh NCSC/BSI advisory feeds");
        }
    }
}

pub fn import_snapshots(
    source_kind: NationalAdvisorySourceKind,
    paths: &[PathBuf],
) -> Result<NationalAdvisoryImportSummary, String> {
    if paths.is_empty() {
        return Err(format!(
            "expected at least one {} snapshot path",
            source_kind.label()
        ));
    }

    let imported = load_snapshot_batch(source_kind, paths)?;
    let imported_records = imported.records.len();
    let known_exploited = imported
        .records
        .iter()
        .filter(|record| record.known_exploited)
        .count();
    let cache = merge_cache(load_cache_for_import()?, imported);
    let summary = NationalAdvisoryImportSummary {
        imported_files: paths.len(),
        imported_records,
        known_exploited,
        total_records: cache.records.len(),
        total_sources: cache.sources.len(),
    };
    save_cache(&cache)?;
    Ok(summary)
}

fn sync_national_sources_with_fetcher(
    source_kinds: &[NationalAdvisorySourceKind],
    fetcher: &dyn NationalAdvisoryFetcher,
    now: u64,
) -> Result<NationalAdvisorySyncOutcome, String> {
    let mut requested_feeds = 0usize;
    let mut imported_records = 0usize;
    let mut failed_sources = 0usize;
    let mut errors = Vec::new();

    for source_kind in source_kinds {
        match fetch_live_source_batch(*source_kind, fetcher, now) {
            Ok((cache, feeds)) => {
                requested_feeds += feeds;
                imported_records += cache.records.len();
                let update_started = Instant::now();
                save_live_cache_increment(&cache)?;
                tracing::info!(
                    source = source_kind.label(),
                    records = cache.records.len(),
                    feeds,
                    elapsed_ms = update_started.elapsed().as_millis() as u64,
                    "updated national advisory database source"
                );
            }
            Err(err) => {
                failed_sources += 1;
                errors.push(format!("{}: {err}", source_kind.label()));
                let existing = load_source_metadata().ok().and_then(|sources| {
                    sources
                        .into_iter()
                        .find(|source| source.source_key == source_kind.source_key())
                });
                save_live_source_status(&source_failure_cache(
                    *source_kind,
                    existing.as_ref(),
                    &err,
                    now,
                ))?;
            }
        }
    }

    let db = crate::storage::db::StorageDb::global()?;
    let total_records = db.count_advisory_records()?;
    let total_sources = db.load_advisory_sources()?.len();

    if requested_feeds == 0 && !errors.is_empty() {
        return Err(errors.join("; "));
    }

    Ok(NationalAdvisorySyncOutcome::Updated(
        NationalAdvisorySyncSummary {
            requested_sources: source_kinds.len(),
            requested_feeds,
            imported_records,
            failed_sources,
            total_records,
            total_sources,
        },
    ))
}

fn load_snapshot_batch(
    source_kind: NationalAdvisorySourceKind,
    paths: &[PathBuf],
) -> Result<AdvisoryCache, String> {
    let mut imported = empty_cache(unix_now());
    let mut page_hashes = Vec::with_capacity(paths.len());
    let mut imported_from_batch = Vec::with_capacity(paths.len());
    let mut latest_fetch = 0u64;

    for path in paths {
        let bytes = std::fs::read(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        page_hashes.push(sha256_hex(&bytes));
        imported_from_batch.push(path.display().to_string());
        let page = parse_snapshot(source_kind, &bytes, Some(path))?;
        latest_fetch = latest_fetch.max(page.generated_unix);
        imported = merge_cache(Some(imported), page);
    }

    latest_fetch = latest_fetch.max(unix_now());
    let source = source_cache(
        source_kind,
        latest_fetch,
        Some(imported_from_batch.clone()),
        page_hashes.join(","),
        imported.records.len(),
    );
    replace_source(&mut imported.sources, source);
    imported.generated_unix = latest_fetch;
    Ok(imported)
}

fn parse_snapshot(
    source_kind: NationalAdvisorySourceKind,
    bytes: &[u8],
    path: Option<&Path>,
) -> Result<AdvisoryCache, String> {
    let trimmed = String::from_utf8_lossy(bytes);
    let trimmed = trimmed.strip_prefix('\u{feff}').unwrap_or(trimmed.as_ref());
    if trimmed.trim_start().starts_with('<') {
        parse_rss_snapshot(source_kind, trimmed, bytes, path)
    } else {
        parse_json_snapshot(source_kind, bytes, path)
    }
}

fn fetch_live_source_batch(
    source_kind: NationalAdvisorySourceKind,
    fetcher: &dyn NationalAdvisoryFetcher,
    now: u64,
) -> Result<(AdvisoryCache, usize), String> {
    let batch_started = Instant::now();
    let mut imported = empty_cache(now);
    let mut page_hashes = Vec::new();
    let mut imported_from_batch = Vec::new();
    let mut fetched_feeds = 0usize;

    for url in source_kind.live_urls() {
        let fetch_started = Instant::now();
        let bytes = fetcher.fetch_url(url)?;
        let fetch_elapsed = fetch_started.elapsed();
        let byte_count = bytes.len();
        page_hashes.push(sha256_hex(&bytes));
        imported_from_batch.push((*url).to_string());
        let page = parse_snapshot(source_kind, &bytes, None)?;
        tracing::info!(
            source = source_kind.label(),
            url,
            bytes = byte_count,
            records = page.records.len(),
            elapsed_ms = fetch_elapsed.as_millis() as u64,
            "fetched national advisory feed"
        );
        imported = merge_cache(Some(imported), page);
        fetched_feeds += 1;
    }

    let source = source_cache(
        source_kind,
        now,
        Some(imported_from_batch),
        page_hashes.join(","),
        imported.records.len(),
    );
    replace_source(&mut imported.sources, source);
    imported.generated_unix = now;
    tracing::info!(
        source = source_kind.label(),
        feeds = fetched_feeds,
        records = imported.records.len(),
        elapsed_ms = batch_started.elapsed().as_millis() as u64,
        "fetched national advisory source from internet"
    );
    Ok((imported, fetched_feeds))
}

fn parse_json_snapshot(
    source_kind: NationalAdvisorySourceKind,
    bytes: &[u8],
    path: Option<&Path>,
) -> Result<AdvisoryCache, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|err| {
        format!(
            "failed to parse {} JSON snapshot: {err}",
            source_kind.label()
        )
    })?;
    let fetched_unix = snapshot_timestamp(&value).unwrap_or_else(unix_now);
    let records = record_array(&value)
        .ok_or_else(|| {
            format!(
                "{} snapshot did not contain a recognizable records array",
                source_kind.label()
            )
        })?
        .iter()
        .filter_map(|item| parse_json_record(source_kind, item, fetched_unix))
        .collect::<Vec<_>>();

    Ok(AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: fetched_unix,
        sources: vec![source_cache(
            source_kind,
            fetched_unix,
            path.map(|path| vec![path.display().to_string()]),
            sha256_hex(bytes),
            records.len(),
        )],
        records,
    })
}

fn parse_rss_snapshot(
    source_kind: NationalAdvisorySourceKind,
    xml: &str,
    bytes: &[u8],
    path: Option<&Path>,
) -> Result<AdvisoryCache, String> {
    let fetched_unix = unix_now();
    let records = xml_items(xml)
        .into_iter()
        .filter_map(|item| parse_rss_item(source_kind, &item, fetched_unix))
        .collect::<Vec<_>>();

    Ok(AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: fetched_unix,
        sources: vec![source_cache(
            source_kind,
            fetched_unix,
            path.map(|path| vec![path.display().to_string()]),
            sha256_hex(bytes),
            records.len(),
        )],
        records,
    })
}

fn parse_json_record(
    source_kind: NationalAdvisorySourceKind,
    value: &Value,
    imported_unix: u64,
) -> Option<VulnerabilityRecord> {
    let title = first_string(value, &["title", "summary", "name", "headline"]);
    let summary = first_string(
        value,
        &[
            "summary",
            "description",
            "title",
            "name",
            "content",
            "details",
        ],
    )
    .unwrap_or_else(|| title.clone().unwrap_or_default());
    let record_url = first_string(
        value,
        &["url", "link", "href", "sourceUrl", "source_url", "guid"],
    );
    let source_url = record_url
        .clone()
        .unwrap_or_else(|| source_kind.source_url().to_string());
    let primary_id = first_string(
        value,
        &[
            "id",
            "identifier",
            "guid",
            "advisoryId",
            "advisory_id",
            "trackingId",
            "tracking_id",
        ],
    )
    .or_else(|| first_cve(value))
    .unwrap_or_else(|| {
        fallback_identifier(
            source_kind,
            record_url.as_deref().unwrap_or(""),
            title
                .as_deref()
                .or_else(|| (!summary.trim().is_empty()).then_some(summary.as_str())),
            imported_unix,
        )
    });
    let mut aliases = unique_strings(flatten_strings_from_keys(
        value,
        &[
            "aliases",
            "alias",
            "cve",
            "cves",
            "cveId",
            "cve_id",
            "identifier",
        ],
    ));
    if !aliases.iter().any(|alias| alias == &primary_id) {
        aliases.push(primary_id.clone());
    }

    let mut mitigations = unique_strings(flatten_strings_from_keys(
        value,
        &[
            "mitigation",
            "mitigations",
            "remediation",
            "remediations",
            "guidance",
            "guidanceSummary",
            "solution",
            "solutions",
        ],
    ));
    mitigations.extend(urls_from_keys(
        value,
        &[
            "mitigationUrl",
            "mitigation_url",
            "remediationUrl",
            "remediation_url",
            "guidanceUrl",
            "guidance_url",
            "vendorUrl",
            "vendor_url",
        ],
    ));
    mitigations = unique_strings(mitigations);

    Some(VulnerabilityRecord {
        primary_id,
        aliases,
        summary,
        published: first_string(
            value,
            &[
                "published",
                "pubDate",
                "datePublished",
                "created",
                "issued",
                "dc:date",
            ],
        ),
        last_modified: first_string(
            value,
            &[
                "lastModified",
                "last_modified",
                "updated",
                "modified",
                "reviewed",
                "reviewed_at",
            ],
        ),
        known_exploited: bool_from_keys(
            value,
            &[
                "knownExploited",
                "known_exploited",
                "exploited",
                "isExploited",
                "exploitationDetected",
            ],
        ),
        severities: severities_from_value(value, source_kind.source_name()),
        affected_products: products_from_value(value),
        references: references_from_value(value, source_kind.source_name(), &source_url),
        mitigations,
        fix_version: None,
        workaround_instructions: vec![],
        upgrade_instructions: vec![],
        provenance: VulnerabilityProvenance {
            source_kind: source_kind.source_kind().into(),
            source_key: source_kind.source_key().into(),
            source_url,
            imported_unix,
        },
    })
}

fn parse_rss_item(
    source_kind: NationalAdvisorySourceKind,
    item: &str,
    imported_unix: u64,
) -> Option<VulnerabilityRecord> {
    let title = xml_tag(item, "title").unwrap_or_default();
    let item_link = xml_tag(item, "link").filter(|link| !link.trim().is_empty());
    let source_url = item_link
        .clone()
        .unwrap_or_else(|| source_kind.source_url().to_string());
    let description = xml_tag(item, "description").unwrap_or_default();
    let identifier = xml_tag(item, "guid")
        .or_else(|| xml_tag(item, "dc:identifier"))
        .or_else(|| item_link.clone())
        .or_else(|| first_cve_text(&title))
        .or_else(|| first_cve_text(&description))
        .unwrap_or_else(|| fallback_identifier(source_kind, "", Some(&title), imported_unix));
    let mut aliases = Vec::new();
    if let Some(cve) = first_cve_text(&title).or_else(|| first_cve_text(&description)) {
        aliases.push(cve);
    }
    aliases.push(identifier.clone());
    let severities = severities_from_rss_item(source_kind.source_name(), item, &title);

    let mut references = vec![VulnerabilityReference {
        url: source_url.clone(),
        source: Some(source_kind.source_name().into()),
        tags: vec!["source".into()],
    }];
    for enclosure in xml_tags(item, "enclosure") {
        if let Some(url) = xml_attr(&enclosure, "url") {
            push_reference(
                &mut references,
                &url,
                source_kind.source_name(),
                vec!["attachment".into()],
            );
        }
    }

    Some(VulnerabilityRecord {
        primary_id: identifier,
        aliases: unique_strings(aliases),
        summary: if description.is_empty() {
            title.clone()
        } else {
            description
        },
        published: xml_tag(item, "pubDate")
            .or_else(|| xml_tag(item, "dc:date"))
            .or_else(|| xml_tag(item, "published")),
        last_modified: xml_tag(item, "dcterms:modified")
            .or_else(|| xml_tag(item, "updated"))
            .or_else(|| xml_tag(item, "modified")),
        known_exploited: false,
        severities,
        affected_products: Vec::new(),
        references,
        mitigations: Vec::new(),
        fix_version: None,
        workaround_instructions: vec![],
        upgrade_instructions: vec![],
        provenance: VulnerabilityProvenance {
            source_kind: source_kind.source_kind().into(),
            source_key: source_kind.source_key().into(),
            source_url,
            imported_unix,
        },
    })
}

fn load_cache_for_import() -> Result<Option<AdvisoryCache>, String> {
    let db = crate::storage::db::StorageDb::global()?;
    match db.load_advisory_cache()? {
        Some(cache) if cache.schema_version == CACHE_SCHEMA_VERSION => Ok(Some(cache)),
        Some(cache) => {
            tracing::warn!(
                schema_version = cache.schema_version,
                "ignoring incompatible advisory database during NCSC/BSI import"
            );
            Ok(None)
        }
        None => Ok(None),
    }
}

fn save_cache(cache: &AdvisoryCache) -> Result<(), String> {
    let update_started = Instant::now();
    let db = crate::storage::db::StorageDb::global()?;
    db.begin()?;
    let result = (|| -> Result<(), String> {
        db.replace_advisory_sources(&cache.sources)?;
        for source in &cache.sources {
            let source_records = cache
                .records
                .iter()
                .filter(|record| record.provenance.source_key == source.source_key)
                .cloned()
                .collect::<Vec<_>>();
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
                "updated national advisory database"
            );
            Ok(())
        }
        Err(err) => {
            let _ = db.rollback();
            Err(err)
        }
    }
}

fn save_live_cache_increment(cache: &AdvisoryCache) -> Result<(), String> {
    let db = crate::storage::db::StorageDb::global()?;
    db.begin()?;
    let result = (|| -> Result<(), String> {
        for source in &cache.sources {
            db.upsert_advisory_source(source)?;
            let source_records = cache
                .records
                .iter()
                .filter(|record| record.provenance.source_key == source.source_key)
                .cloned()
                .collect::<Vec<_>>();
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
            db.checkpoint().map(|_| ())
        }
        Err(err) => {
            let _ = db.rollback();
            Err(err)
        }
    }
}

fn save_live_source_status(source: &AdvisorySourceCache) -> Result<(), String> {
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

fn merge_cache(existing: Option<AdvisoryCache>, incoming: AdvisoryCache) -> AdvisoryCache {
    let mut merged = existing.unwrap_or_else(|| empty_cache(incoming.generated_unix));
    let mut record_index = HashMap::with_capacity(merged.records.len());
    for (idx, record) in merged.records.iter().enumerate() {
        record_index.insert(record_key(record), idx);
    }
    for source in incoming.sources {
        replace_source(&mut merged.sources, source);
    }
    for record in incoming.records {
        let key = record_key(&record);
        if let Some(&existing_idx) = record_index.get(&key) {
            let keep_existing = newer_or_equal(&merged.records[existing_idx], &record);
            if !keep_existing {
                merged.records[existing_idx] = record;
            }
        } else {
            record_index.insert(key, merged.records.len());
            merged.records.push(record);
        }
    }
    merged.schema_version = CACHE_SCHEMA_VERSION;
    merged.generated_unix = unix_now();
    merged
}

fn replace_source(sources: &mut Vec<AdvisorySourceCache>, source: AdvisorySourceCache) {
    if let Some(existing) = sources.iter_mut().find(|existing| {
        existing.source_kind == source.source_kind && existing.source_key == source.source_key
    }) {
        let mut imported_from_batch = existing.imported_from_batch.clone();
        for path in &source.imported_from_batch {
            if !imported_from_batch.iter().any(|existing| existing == path) {
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

fn newer_or_equal(existing: &VulnerabilityRecord, incoming: &VulnerabilityRecord) -> bool {
    match (record_timestamp(existing), record_timestamp(incoming)) {
        (Some(left), Some(right)) => left >= right,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => existing.provenance.imported_unix >= incoming.provenance.imported_unix,
    }
}

fn record_timestamp(record: &VulnerabilityRecord) -> Option<chrono::DateTime<chrono::Utc>> {
    record
        .last_modified
        .as_deref()
        .and_then(parse_timestamp)
        .or_else(|| record.published.as_deref().and_then(parse_timestamp))
}

fn record_key(record: &VulnerabilityRecord) -> RecordKey {
    RecordKey {
        primary_id: record.primary_id.clone(),
        source_kind: record.provenance.source_kind.clone(),
        source_key: record.provenance.source_key.clone(),
    }
}

fn source_cache(
    source_kind: NationalAdvisorySourceKind,
    fetched_unix: u64,
    imported_from_batch: Option<Vec<String>>,
    snapshot_sha256: String,
    total_results: usize,
) -> AdvisorySourceCache {
    let imported_from_batch = imported_from_batch.unwrap_or_default();
    AdvisorySourceCache {
        source_key: source_kind.source_key().into(),
        source_kind: source_kind.source_kind().into(),
        source_url: source_kind.source_url().into(),
        imported_from: imported_from_batch.first().cloned(),
        imported_from_batch,
        fetched_unix,
        expires_unix: fetched_unix.saturating_add(DEFAULT_SOURCE_TTL_SECS),
        snapshot_sha256,
        total_results,
        status: SourceHealth::Fresh,
        last_attempt_unix: fetched_unix,
        last_error: None,
        retry_after_unix: 0,
    }
}

fn empty_cache(now: u64) -> AdvisoryCache {
    AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: now,
        sources: Vec::new(),
        records: Vec::new(),
    }
}

fn source_failure_cache(
    source_kind: NationalAdvisorySourceKind,
    existing: Option<&AdvisorySourceCache>,
    err: &str,
    now: u64,
) -> AdvisorySourceCache {
    let imported_from_batch = existing
        .map(|source| source.imported_from_batch.clone())
        .filter(|batch| !batch.is_empty())
        .unwrap_or_else(|| {
            source_kind
                .live_urls()
                .iter()
                .map(|url| (*url).to_string())
                .collect()
        });
    let expires_unix = existing.map(|source| source.expires_unix).unwrap_or(0);
    AdvisorySourceCache {
        source_key: source_kind.source_key().into(),
        source_kind: source_kind.source_kind().into(),
        source_url: source_kind.source_url().into(),
        imported_from: existing.and_then(|source| source.imported_from.clone()),
        imported_from_batch,
        fetched_unix: existing.map(|source| source.fetched_unix).unwrap_or(0),
        expires_unix,
        snapshot_sha256: existing
            .map(|source| source.snapshot_sha256.clone())
            .unwrap_or_default(),
        total_results: existing.map(|source| source.total_results).unwrap_or(0),
        status: if expires_unix > now {
            SourceHealth::Error
        } else {
            SourceHealth::Stale
        },
        last_attempt_unix: now,
        last_error: Some(err.to_string()),
        retry_after_unix: now.saturating_add(LIVE_SYNC_RETRY_SECS),
    }
}

fn load_source_metadata() -> Result<Vec<AdvisorySourceCache>, String> {
    let db = crate::storage::db::StorageDb::global()?;
    db.load_advisory_sources()
}

fn source_refresh_due(source: Option<&AdvisorySourceCache>, now: u64) -> bool {
    let Some(source) = source else {
        return true;
    };
    let retry_due = source.retry_after_unix > 0 && source.retry_after_unix <= now;
    let stale_or_error = matches!(source.status, SourceHealth::Error | SourceHealth::Stale);
    source.expires_unix <= now
        || retry_due
        || (stale_or_error && (source.retry_after_unix == 0 || source.retry_after_unix <= now))
}

impl NationalAdvisorySourceKind {
    fn label(self) -> &'static str {
        match self {
            NationalAdvisorySourceKind::Ncsc => "NCSC",
            NationalAdvisorySourceKind::Bsi => "BSI",
        }
    }

    fn source_key(self) -> &'static str {
        match self {
            NationalAdvisorySourceKind::Ncsc => NCSC_SOURCE_KEY,
            NationalAdvisorySourceKind::Bsi => BSI_SOURCE_KEY,
        }
    }

    fn source_kind(self) -> &'static str {
        match self {
            NationalAdvisorySourceKind::Ncsc => NCSC_SOURCE_KIND,
            NationalAdvisorySourceKind::Bsi => BSI_SOURCE_KIND,
        }
    }

    fn source_name(self) -> &'static str {
        match self {
            NationalAdvisorySourceKind::Ncsc => "NCSC",
            NationalAdvisorySourceKind::Bsi => "BSI",
        }
    }

    fn source_url(self) -> &'static str {
        match self {
            NationalAdvisorySourceKind::Ncsc => NCSC_SOURCE_URL,
            NationalAdvisorySourceKind::Bsi => BSI_SOURCE_URL,
        }
    }

    fn live_urls(self) -> &'static [&'static str] {
        match self {
            NationalAdvisorySourceKind::Ncsc => &[NCSC_RSS_URL],
            NationalAdvisorySourceKind::Bsi => &[BSI_RSS_URL],
        }
    }
}

fn fallback_identifier(
    source_kind: NationalAdvisorySourceKind,
    source_url: &str,
    title: Option<&str>,
    imported_unix: u64,
) -> String {
    let seed = if !source_url.trim().is_empty() {
        source_url.trim().to_string()
    } else if let Some(title) = title {
        title.trim().to_string()
    } else {
        format!("{}-{imported_unix}", source_kind.source_key())
    };
    let digest = Sha256::digest(seed.as_bytes());
    let short = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{}-{short}", source_kind.source_key())
}

fn record_array(value: &Value) -> Option<&Vec<Value>> {
    for key in [
        "records",
        "items",
        "data",
        "results",
        "entries",
        "advisories",
    ] {
        if let Some(values) = value.get(key).and_then(Value::as_array) {
            return Some(values);
        }
    }
    value.as_array()
}

fn snapshot_timestamp(value: &Value) -> Option<u64> {
    first_string(
        value,
        &[
            "timestamp",
            "generatedAt",
            "generated_at",
            "updated",
            "lastModified",
            "last_modified",
        ],
    )
    .as_deref()
    .and_then(parse_timestamp)
    .map(|timestamp| timestamp.timestamp().max(0) as u64)
}

fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(*key).and_then(value_to_string) {
            if !found.trim().is_empty() {
                return Some(found.trim().to_string());
            }
        }
    }
    None
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn flatten_strings_from_keys(value: &Value, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for key in keys {
        if let Some(found) = value.get(*key) {
            flatten_strings(found, &mut out);
        }
    }
    out
}

fn flatten_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Number(number) => out.push(number.to_string()),
        Value::Array(values) => {
            for item in values {
                flatten_strings(item, out);
            }
        }
        Value::Object(map) => {
            for key in [
                "id",
                "name",
                "title",
                "value",
                "url",
                "reference",
                "product",
                "vendor",
                "cve",
                "cves",
                "cveId",
                "cve_id",
            ] {
                if let Some(value) = map.get(key) {
                    flatten_strings(value, out);
                }
            }
        }
        _ => {}
    }
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_ascii_lowercase()) {
            unique.push(trimmed.to_string());
        }
    }
    unique
}

fn bool_from_keys(value: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| match value.get(*key) {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::String(text)) => matches!(
            text.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "y" | "1" | "known" | "exploited"
        ),
        Some(Value::Number(number)) => number.as_u64().unwrap_or_default() > 0,
        _ => false,
    })
}

fn first_cve(value: &Value) -> Option<String> {
    let mut values = Vec::new();
    flatten_strings(value, &mut values);
    values.iter().find_map(|value| first_cve_text(value))
}

fn first_cve_text(text: &str) -> Option<String> {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut idx = 0usize;
    while idx + 13 <= bytes.len() {
        if &bytes[idx..idx + 4] == b"CVE-" {
            let tail = &upper[idx..];
            let parts = tail
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
                .next()?;
            if parts.len() >= 13 {
                return Some(parts.to_string());
            }
        }
        idx += 1;
    }
    None
}

fn references_from_value(
    value: &Value,
    source: &str,
    source_url: &str,
) -> Vec<VulnerabilityReference> {
    let mut refs = Vec::new();
    for key in ["references", "reference", "urls", "links", "advisories"] {
        if let Some(found) = value.get(key) {
            collect_references(found, source, &mut refs);
        }
    }
    if !refs.iter().any(|reference| reference.url == source_url) {
        refs.push(VulnerabilityReference {
            url: source_url.into(),
            source: Some(source.into()),
            tags: vec!["source".into()],
        });
    }
    refs
}

fn collect_references(value: &Value, source: &str, refs: &mut Vec<VulnerabilityReference>) {
    match value {
        Value::String(url) => push_reference(refs, url, source, Vec::new()),
        Value::Array(values) => {
            for item in values {
                collect_references(item, source, refs);
            }
        }
        Value::Object(map) => {
            if let Some(url) = map
                .get("url")
                .or_else(|| map.get("href"))
                .or_else(|| map.get("link"))
                .and_then(value_to_string)
            {
                let tags = map
                    .get("tags")
                    .map(|value| {
                        unique_strings({
                            let mut values = Vec::new();
                            flatten_strings(value, &mut values);
                            values
                        })
                    })
                    .unwrap_or_default();
                let reference_source = map
                    .get("source")
                    .and_then(value_to_string)
                    .unwrap_or_else(|| source.into());
                push_reference(refs, &url, &reference_source, tags);
            }
        }
        _ => {}
    }
}

fn push_reference(
    refs: &mut Vec<VulnerabilityReference>,
    url: &str,
    source: &str,
    tags: Vec<String>,
) {
    let url = url.trim();
    if url.is_empty() || refs.iter().any(|reference| reference.url == url) {
        return;
    }
    refs.push(VulnerabilityReference {
        url: url.into(),
        source: Some(source.into()),
        tags,
    });
}

fn urls_from_keys(value: &Value, keys: &[&str]) -> Vec<String> {
    flatten_strings_from_keys(value, keys)
        .into_iter()
        .filter(|value| value.starts_with("http://") || value.starts_with("https://"))
        .collect()
}

fn severities_from_value(value: &Value, source: &str) -> Vec<VulnerabilitySeverity> {
    let mut severities = Vec::new();
    push_severity_from_parts(
        &mut severities,
        source,
        first_string(
            value,
            &[
                "severityScheme",
                "cvssVersion",
                "baseScoreVersion",
                "version",
            ],
        )
        .unwrap_or_else(|| "source".into()),
        first_string(value, &["severity", "cvssSeverity", "baseSeverity"]),
        first_string(value, &["score", "baseScore", "cvssScore"])
            .and_then(|score| parse_score(&score)),
        first_string(
            value,
            &["vector", "vectorString", "cvssVector", "baseScoreVector"],
        ),
    );
    for key in ["cvss", "cvssV3", "cvssV31", "metrics"] {
        if let Some(found) = value.get(key) {
            collect_severities(found, source, &mut severities);
        }
    }
    severities
}

fn collect_severities(value: &Value, source: &str, out: &mut Vec<VulnerabilitySeverity>) {
    match value {
        Value::Array(values) => {
            for item in values {
                collect_severities(item, source, out);
            }
        }
        Value::Object(map) => {
            push_severity_from_parts(
                out,
                source,
                map.get("version")
                    .or_else(|| map.get("scheme"))
                    .or_else(|| map.get("cvssVersion"))
                    .or_else(|| map.get("baseScoreVersion"))
                    .and_then(value_to_string)
                    .unwrap_or_else(|| "cvss".into()),
                map.get("severity")
                    .or_else(|| map.get("baseSeverity"))
                    .or_else(|| map.get("cvssSeverity"))
                    .and_then(value_to_string),
                map.get("score")
                    .or_else(|| map.get("baseScore"))
                    .or_else(|| map.get("cvssScore"))
                    .and_then(value_to_string)
                    .and_then(|score| parse_score(&score)),
                map.get("vector")
                    .or_else(|| map.get("vectorString"))
                    .or_else(|| map.get("cvssVector"))
                    .or_else(|| map.get("baseScoreVector"))
                    .and_then(value_to_string),
            );
            for nested in map.values() {
                collect_severities(nested, source, out);
            }
        }
        _ => {}
    }
}

fn severities_from_rss_item(source: &str, item: &str, title: &str) -> Vec<VulnerabilitySeverity> {
    let mut severities = Vec::new();
    for category in xml_tags(item, "category") {
        push_severity_from_parts(
            &mut severities,
            source,
            "source".into(),
            xml_tag(&category, "category"),
            None,
            None,
        );
    }
    if severities.is_empty() {
        if let Some(label) = severity_from_bracketed_title(title) {
            push_severity_from_parts(
                &mut severities,
                source,
                "source".into(),
                Some(label),
                None,
                None,
            );
        }
    }
    severities
}

fn severity_from_bracketed_title(title: &str) -> Option<String> {
    for part in title.split('[').skip(1) {
        let Some((label, _)) = part.split_once(']') else {
            continue;
        };
        if canonical_severity(label).is_some() {
            return Some(label.to_string());
        }
    }
    None
}

fn push_severity_from_parts(
    out: &mut Vec<VulnerabilitySeverity>,
    source: &str,
    scheme: String,
    severity: Option<String>,
    score: Option<f32>,
    vector: Option<String>,
) {
    let severity = severity
        .as_deref()
        .and_then(canonical_severity)
        .or_else(|| score.and_then(cvss_severity_from_score).map(str::to_string));
    let Some(severity) = severity else {
        return;
    };
    let scheme = if scheme.trim().is_empty() {
        "cvss".into()
    } else {
        scheme.trim().to_string()
    };
    let vector = vector.filter(|value| !value.trim().is_empty());
    let duplicate = out.iter().any(|existing| {
        existing.source == source
            && existing.scheme == scheme
            && existing.severity == severity
            && existing.score == score
            && existing.vector == vector
    });
    if !duplicate {
        out.push(VulnerabilitySeverity {
            source: source.into(),
            scheme,
            severity,
            score,
            vector,
        });
    }
}

fn canonical_severity(severity: &str) -> Option<String> {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" | "kritisch" => Some("CRITICAL".into()),
        "high" | "hoch" => Some("HIGH".into()),
        "medium" | "moderate" | "mittel" => Some("MEDIUM".into()),
        "low" | "niedrig" => Some("LOW".into()),
        _ => None,
    }
}

fn cvss_severity_from_score(score: f32) -> Option<&'static str> {
    if score >= 9.0 {
        Some("CRITICAL")
    } else if score >= 7.0 {
        Some("HIGH")
    } else if score >= 4.0 {
        Some("MEDIUM")
    } else if score > 0.0 {
        Some("LOW")
    } else {
        None
    }
}

fn parse_score(score: &str) -> Option<f32> {
    score.trim().parse::<f32>().ok()
}

fn products_from_value(value: &Value) -> Vec<AffectedProduct> {
    let mut products = Vec::new();
    for key in [
        "affected",
        "affectedProducts",
        "products",
        "vendors",
        "cpe",
        "cpes",
    ] {
        if let Some(found) = value.get(key) {
            collect_products(found, &mut products, None);
        }
    }
    products
}

fn collect_products(value: &Value, out: &mut Vec<AffectedProduct>, inherited_vendor: Option<&str>) {
    match value {
        Value::String(product) => {
            let criteria = inherited_vendor
                .filter(|vendor| !product.contains(vendor))
                .map(|vendor| format!("{vendor}:{product}"))
                .unwrap_or_else(|| product.clone());
            push_product(out, &criteria, None, None, true);
        }
        Value::Array(values) => {
            for item in values {
                collect_products(item, out, inherited_vendor);
            }
        }
        Value::Object(map) => {
            let vendor = map
                .get("vendor")
                .and_then(value_to_string)
                .or_else(|| inherited_vendor.map(str::to_string));
            let product = map
                .get("product")
                .or_else(|| map.get("name"))
                .or_else(|| map.get("title"))
                .or_else(|| map.get("cpe"))
                .or_else(|| map.get("criteria"))
                .and_then(value_to_string);
            if let Some(product) = product {
                let criteria = vendor
                    .as_deref()
                    .filter(|vendor| !product.contains(vendor))
                    .map(|vendor| format!("{vendor}:{product}"))
                    .unwrap_or(product);
                push_product(
                    out,
                    &criteria,
                    map.get("matchCriteriaId").and_then(value_to_string),
                    map.get("cpeName")
                        .or_else(|| map.get("cpe"))
                        .and_then(value_to_string),
                    map.get("vulnerable")
                        .and_then(Value::as_bool)
                        .unwrap_or(true),
                );
            }
            for nested in ["products", "children", "versions"] {
                if let Some(value) = map.get(nested) {
                    collect_products(value, out, vendor.as_deref());
                }
            }
        }
        _ => {}
    }
}

fn push_product(
    out: &mut Vec<AffectedProduct>,
    criteria: &str,
    match_criteria_id: Option<String>,
    cpe_name: Option<String>,
    vulnerable: bool,
) {
    let criteria = criteria.trim();
    if criteria.is_empty()
        || out.iter().any(|product| {
            product.criteria == criteria
                && product.match_criteria_id == match_criteria_id
                && product.cpe_name == cpe_name
                && product.vulnerable == vulnerable
        })
    {
        return;
    }
    out.push(AffectedProduct {
        criteria: criteria.into(),
        match_criteria_id,
        cpe_name,
        vulnerable,
        version_start_including: None,
        version_start_excluding: None,
        version_end_including: None,
        version_end_excluding: None,
    });
}

fn xml_items(xml: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<item") {
        rest = &rest[start..];
        let Some(open_end) = rest.find('>') else {
            break;
        };
        let body_start = open_end + 1;
        let Some(end) = rest[body_start..].find("</item>") else {
            break;
        };
        items.push(rest[body_start..body_start + end].to_string());
        rest = &rest[body_start + end + "</item>".len()..];
    }
    items
}

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{tag}>");
    let open_tag_prefix = format!("<{tag} ");
    let close_tag = format!("</{tag}>");
    let start = xml
        .find(&start_tag)
        .map(|idx| idx + start_tag.len())
        .or_else(|| {
            let idx = xml.find(&open_tag_prefix)?;
            Some(xml[idx..].find('>')? + idx + 1)
        })?;
    let end = xml[start..].find(&close_tag)? + start;
    Some(unescape_xml(xml[start..end].trim()))
}

fn xml_tags(xml: &str, tag: &str) -> Vec<String> {
    let start_tag = format!("<{tag}");
    let attr_tag = format!("<{tag} ");
    let bare_tag = format!("<{tag}>");
    let self_closing_tag = format!("<{tag}/>");
    let close_tag = format!("</{tag}>");
    let mut rest = xml;
    let mut values = Vec::new();
    while let Some(start) = rest.find(&start_tag) {
        rest = &rest[start..];
        let Some(open_end) = rest.find('>') else {
            break;
        };
        let header = &rest[..=open_end];
        let is_target_tag =
            header.starts_with(&attr_tag) || header == bare_tag || header == self_closing_tag;
        if !is_target_tag {
            rest = &rest[open_end + 1..];
            continue;
        }
        if header.trim_end().ends_with("/>") {
            values.push(header.to_string());
            rest = &rest[open_end + 1..];
            continue;
        }
        let body_start = open_end + 1;
        let Some(end) = rest[body_start..].find(&close_tag) else {
            break;
        };
        values.push(rest[..body_start + end].to_string());
        rest = &rest[body_start + end + close_tag.len()..];
    }
    values
}

fn xml_attr(tag_xml: &str, attr: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let needle = format!("{attr}={quote}");
        let Some(start) = tag_xml.find(&needle).map(|idx| idx + needle.len()) else {
            continue;
        };
        let end = tag_xml[start..].find(quote)? + start;
        return Some(unescape_xml(tag_xml[start..end].trim()));
    }
    None
}

fn unescape_xml(value: &str) -> String {
    value
        .replace("<![CDATA[", "")
        .replace("]]>", "")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let value = value.trim();
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::DateTime::parse_from_rfc2822(value)
                .map(|ts| ts.with_timezone(&chrono::Utc))
                .ok()
        })
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
                .ok()
                .map(|ts| {
                    chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(ts, chrono::Utc)
                })
        })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeFetcher {
        responses: HashMap<&'static str, Vec<u8>>,
    }

    impl NationalAdvisoryFetcher for FakeFetcher {
        fn fetch_url(&self, url: &str) -> Result<Vec<u8>, String> {
            self.responses
                .get(url)
                .cloned()
                .ok_or_else(|| format!("unexpected URL {url}"))
        }
    }

    #[test]
    fn parses_ncsc_rss_item_with_guid_and_cve_alias() {
        let xml = r#"<rss><channel><item>
            <title>NCSC guidance for CVE-2026-1234</title>
            <link>https://www.ncsc.gov.uk/report/example-guidance</link>
            <description>Operator guidance for a public issue.</description>
            <pubDate>2026-05-03T00:00:00Z</pubDate>
            <guid>https://www.ncsc.gov.uk/report/example-guidance</guid>
        </item></channel></rss>"#;

        let cache = parse_rss_snapshot(NationalAdvisorySourceKind::Ncsc, xml, xml.as_bytes(), None)
            .unwrap();
        assert_eq!(cache.records.len(), 1);
        let record = &cache.records[0];
        assert_eq!(
            record.primary_id,
            "https://www.ncsc.gov.uk/report/example-guidance"
        );
        assert!(record.aliases.iter().any(|alias| alias == "CVE-2026-1234"));
        assert_eq!(record.references[0].source.as_deref(), Some("NCSC"));
        assert_eq!(record.provenance.source_kind, NCSC_SOURCE_KIND);
    }

    #[test]
    fn live_national_fetch_normalizes_ncsc_and_bsi_rss() {
        let ncsc_xml = r#"<rss><channel><item>
            <title>NCSC-2026-0001 CVE-2026-1234 voorbeeld</title>
            <link>https://advisories.ncsc.nl/2026/ncsc-2026-0001-1</link>
            <description>NCSC advisory.</description>
            <guid>NCSC-2026-0001</guid>
        </item></channel></rss>"#;
        let bsi_xml = r#"<rss><channel><item>
            <title>[NEU] [hoch] WID-SEC-2026-0001 CVE-2026-1234 Beispiel</title>
            <link>https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0001</link>
            <description>BSI advisory.</description>
            <category>hoch</category>
            <guid>WID-SEC-2026-0001</guid>
        </item></channel></rss>"#;
        let fetcher = FakeFetcher {
            responses: HashMap::from([
                (NCSC_RSS_URL, ncsc_xml.as_bytes().to_vec()),
                (BSI_RSS_URL, bsi_xml.as_bytes().to_vec()),
            ]),
        };

        let (ncsc, ncsc_feeds) =
            fetch_live_source_batch(NationalAdvisorySourceKind::Ncsc, &fetcher, 42).unwrap();
        let (bsi, bsi_feeds) =
            fetch_live_source_batch(NationalAdvisorySourceKind::Bsi, &fetcher, 42).unwrap();

        assert_eq!(ncsc_feeds, 1);
        assert_eq!(bsi_feeds, 1);
        assert_eq!(ncsc.records[0].primary_id, "NCSC-2026-0001");
        assert_eq!(bsi.records[0].primary_id, "WID-SEC-2026-0001");
        assert_eq!(bsi.records[0].severities[0].severity, "HIGH");
        assert_eq!(
            ncsc.sources[0].imported_from_batch,
            vec![NCSC_RSS_URL.to_string()]
        );
        assert_eq!(
            bsi.sources[0].imported_from_batch,
            vec![BSI_RSS_URL.to_string()]
        );
    }

    #[test]
    fn national_source_refresh_due_honors_fresh_retry_and_stale_states() {
        let mut source = source_cache(
            NationalAdvisorySourceKind::Ncsc,
            100,
            None,
            String::new(),
            0,
        );
        source.expires_unix = 200;
        assert!(!source_refresh_due(Some(&source), 150));
        assert!(source_refresh_due(Some(&source), 201));

        source.status = SourceHealth::Stale;
        source.expires_unix = 400;
        source.retry_after_unix = 300;
        assert!(!source_refresh_due(Some(&source), 250));
        assert!(source_refresh_due(Some(&source), 300));
    }

    #[test]
    fn national_source_failure_preserves_last_good_metadata() {
        let mut existing = source_cache(
            NationalAdvisorySourceKind::Bsi,
            100,
            Some(vec![BSI_RSS_URL.to_string()]),
            "abc".into(),
            12,
        );
        existing.expires_unix = 500;

        let failed = source_failure_cache(
            NationalAdvisorySourceKind::Bsi,
            Some(&existing),
            "boom",
            200,
        );

        assert_eq!(failed.fetched_unix, 100);
        assert_eq!(failed.expires_unix, 500);
        assert_eq!(failed.snapshot_sha256, "abc");
        assert_eq!(failed.total_results, 12);
        assert_eq!(failed.status, SourceHealth::Error);
        assert_eq!(failed.last_error.as_deref(), Some("boom"));
    }

    #[test]
    fn parses_bsi_json_record_with_metadata() {
        let bytes = br#"{
            "timestamp": "2026-05-03T00:00:00Z",
            "items": [{
                "id": "CERT-BUND-2026-0001",
                "cves": ["CVE-2026-9999"],
                "title": "BSI advisory example",
                "updated": "2026-05-03T01:00:00Z",
                "severity": "HIGH",
                "score": "8.0",
                "affectedProducts": [{"vendor":"Example","product":"Gateway"}],
                "references": [{"url":"https://www.bsi.bund.de/example","tags":["vendor"]}]
            }]
        }"#;

        let cache = parse_json_snapshot(NationalAdvisorySourceKind::Bsi, bytes, None).unwrap();
        assert_eq!(cache.records.len(), 1);
        let record = &cache.records[0];
        assert_eq!(record.primary_id, "CERT-BUND-2026-0001");
        assert!(record.aliases.iter().any(|alias| alias == "CVE-2026-9999"));
        assert_eq!(record.severities.len(), 1);
        assert_eq!(record.severities[0].severity, "HIGH");
        assert_eq!(record.affected_products[0].criteria, "Example:Gateway");
        assert_eq!(record.provenance.source_kind, BSI_SOURCE_KIND);
    }

    #[test]
    fn detects_xml_snapshots_with_utf8_bom() {
        let xml = "\u{feff}<rss><channel><item>
            <title>NCSC guidance with BOM</title>
            <link>https://www.ncsc.gov.uk/report/example-guidance</link>
            <guid>https://www.ncsc.gov.uk/report/example-guidance</guid>
        </item></channel></rss>";

        let cache = parse_snapshot(NationalAdvisorySourceKind::Ncsc, xml.as_bytes(), None).unwrap();
        assert_eq!(cache.records.len(), 1);
        assert_eq!(
            cache.records[0].primary_id,
            "https://www.ncsc.gov.uk/report/example-guidance"
        );
    }

    #[test]
    fn fallback_ids_use_title_when_json_records_lack_item_urls() {
        let bytes = br#"{
            "timestamp": "2026-05-03T00:00:00Z",
            "items": [
                {"title": "First advisory without explicit ID"},
                {"title": "Second advisory without explicit ID"}
            ]
        }"#;

        let cache = parse_json_snapshot(NationalAdvisorySourceKind::Bsi, bytes, None).unwrap();
        assert_eq!(cache.records.len(), 2);
        assert_ne!(cache.records[0].primary_id, cache.records[1].primary_id);
        assert_eq!(
            cache.records[0].provenance.source_url, BSI_SOURCE_URL,
            "records without per-item URLs should still point provenance at the source homepage"
        );
    }

    #[test]
    fn fallback_ids_use_description_when_json_records_lack_titles_and_urls() {
        let bytes = br#"{
            "timestamp": "2026-05-03T00:00:00Z",
            "items": [
                {"description": "First advisory without explicit ID"},
                {"description": "Second advisory without explicit ID"}
            ]
        }"#;

        let cache = parse_json_snapshot(NationalAdvisorySourceKind::Bsi, bytes, None).unwrap();
        assert_eq!(cache.records.len(), 2);
        assert_ne!(cache.records[0].primary_id, cache.records[1].primary_id);
        assert_eq!(
            cache.records[0].summary,
            "First advisory without explicit ID"
        );
        assert_eq!(
            cache.records[1].summary,
            "Second advisory without explicit ID"
        );
    }

    #[test]
    fn json_records_without_explicit_ids_use_cves_as_primary_id() {
        let bytes = br#"{
            "timestamp": "2026-05-03T00:00:00Z",
            "items": [
                {
                    "title": "Advisory with only CVE metadata",
                    "cves": ["CVE-2026-4242"]
                }
            ]
        }"#;

        let cache = parse_json_snapshot(NationalAdvisorySourceKind::Bsi, bytes, None).unwrap();
        assert_eq!(cache.records.len(), 1);
        assert_eq!(cache.records[0].primary_id, "CVE-2026-4242");
    }

    #[test]
    fn parses_self_closing_rss_enclosures_as_attachment_references() {
        let xml = r#"<rss><channel><item>
            <title>NCSC advisory with attachments</title>
            <link>https://www.ncsc.gov.uk/report/example-guidance</link>
            <description>Attachment references should be preserved.</description>
            <enclosure url="https://www.ncsc.gov.uk/files/example-one.pdf" />
            <enclosure url="https://www.ncsc.gov.uk/files/example-two.pdf" />
        </item></channel></rss>"#;

        let cache = parse_rss_snapshot(NationalAdvisorySourceKind::Ncsc, xml, xml.as_bytes(), None)
            .unwrap();
        assert_eq!(cache.records.len(), 1);
        let record = &cache.records[0];
        assert!(record.references.iter().any(|reference| {
            reference.url == "https://www.ncsc.gov.uk/files/example-one.pdf"
                && reference.tags.iter().any(|tag| tag == "attachment")
        }));
        assert!(record.references.iter().any(|reference| {
            reference.url == "https://www.ncsc.gov.uk/files/example-two.pdf"
                && reference.tags.iter().any(|tag| tag == "attachment")
        }));
    }

    #[test]
    fn parses_single_quoted_rss_enclosures_as_attachment_references() {
        let xml = r#"<rss><channel><item>
            <title>NCSC advisory with single-quoted attachments</title>
            <link>https://www.ncsc.gov.uk/report/example-guidance</link>
            <description>Single-quoted attachment references should be preserved.</description>
            <enclosure url='https://www.ncsc.gov.uk/files/example-one.pdf' />
        </item></channel></rss>"#;

        let cache = parse_rss_snapshot(NationalAdvisorySourceKind::Ncsc, xml, xml.as_bytes(), None)
            .unwrap();
        assert_eq!(cache.records.len(), 1);
        let record = &cache.records[0];
        assert!(record.references.iter().any(|reference| {
            reference.url == "https://www.ncsc.gov.uk/files/example-one.pdf"
                && reference.tags.iter().any(|tag| tag == "attachment")
        }));
    }

    #[test]
    fn rss_items_without_guid_prefer_link_over_cve_for_primary_id() {
        let item = r#"<item>
            <title>Advisory update for CVE-2026-1234</title>
            <link>https://www.ncsc.gov.uk/report/shared-cve-update</link>
            <description>Multiple advisories can mention the same CVE.</description>
        </item>"#;

        let record = parse_rss_item(NationalAdvisorySourceKind::Ncsc, item, 42).unwrap();
        assert_eq!(
            record.primary_id,
            "https://www.ncsc.gov.uk/report/shared-cve-update"
        );
        assert!(record.aliases.iter().any(|alias| alias == "CVE-2026-1234"));
        assert_eq!(
            record.provenance.source_url,
            "https://www.ncsc.gov.uk/report/shared-cve-update"
        );
    }

    #[test]
    fn merge_prefers_published_timestamp_over_import_time() {
        let existing = parse_rss_item(
            NationalAdvisorySourceKind::Ncsc,
            r#"<item>
                <title>NCSC advisory</title>
                <link>https://www.ncsc.gov.uk/report/example-guidance</link>
                <description>newer published content</description>
                <pubDate>2026-05-04T00:00:00Z</pubDate>
                <guid>https://www.ncsc.gov.uk/report/example-guidance</guid>
            </item>"#,
            100,
        )
        .unwrap();
        let incoming = parse_rss_item(
            NationalAdvisorySourceKind::Ncsc,
            r#"<item>
                <title>NCSC advisory</title>
                <link>https://www.ncsc.gov.uk/report/example-guidance</link>
                <description>older published content imported later</description>
                <pubDate>2026-05-01T00:00:00Z</pubDate>
                <guid>https://www.ncsc.gov.uk/report/example-guidance</guid>
            </item>"#,
            200,
        )
        .unwrap();

        let mut existing_cache = empty_cache(100);
        existing_cache.records.push(existing);
        let mut incoming_cache = empty_cache(200);
        incoming_cache.records.push(incoming);

        let merged = merge_cache(Some(existing_cache), incoming_cache);
        assert_eq!(merged.records.len(), 1);
        assert_eq!(merged.records[0].summary, "newer published content");
        assert_eq!(
            merged.records[0].published.as_deref(),
            Some("2026-05-04T00:00:00Z")
        );
    }

    #[test]
    fn merge_prefers_rfc2822_published_timestamp_over_import_time() {
        let existing = parse_rss_item(
            NationalAdvisorySourceKind::Ncsc,
            r#"<item>
                <title>NCSC advisory</title>
                <link>https://www.ncsc.gov.uk/report/example-guidance</link>
                <description>newer published content</description>
                <pubDate>Mon, 04 May 2026 00:00:00 GMT</pubDate>
                <guid>https://www.ncsc.gov.uk/report/example-guidance</guid>
            </item>"#,
            100,
        )
        .unwrap();
        let incoming = parse_rss_item(
            NationalAdvisorySourceKind::Ncsc,
            r#"<item>
                <title>NCSC advisory</title>
                <link>https://www.ncsc.gov.uk/report/example-guidance</link>
                <description>older published content imported later</description>
                <pubDate>Fri, 01 May 2026 00:00:00 GMT</pubDate>
                <guid>https://www.ncsc.gov.uk/report/example-guidance</guid>
            </item>"#,
            200,
        )
        .unwrap();

        let mut existing_cache = empty_cache(100);
        existing_cache.records.push(existing);
        let mut incoming_cache = empty_cache(200);
        incoming_cache.records.push(incoming);

        let merged = merge_cache(Some(existing_cache), incoming_cache);
        assert_eq!(merged.records.len(), 1);
        assert_eq!(merged.records[0].summary, "newer published content");
        assert_eq!(
            merged.records[0].published.as_deref(),
            Some("Mon, 04 May 2026 00:00:00 GMT")
        );
    }
}
