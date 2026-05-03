//! NCSC and BSI public advisory ingestion foundations.
//!
//! This module intentionally starts with offline/operator-supplied snapshots so
//! Vigil can ingest public RSS or mirrored JSON without depending on unstable
//! page scraping or closed feeds. The safe first slice is therefore:
//!
//! - normalize NCSC and BSI/CERT-Bund RSS or JSON snapshots into
//!   `VulnerabilityRecord`
//! - preserve source-specific identifiers, CVE aliases, references,
//!   timestamps, severity hints, and provenance
//! - merge imported records into the same protected advisory cache used by NVD,
//!   EUVD, and JVN
//!
//! Live scheduled fetching can build on these parsers once the exact official
//! feed shapes are pinned down conservatively.

use crate::advisory::{
    AdvisoryCache, AdvisorySourceCache, AffectedProduct, SourceHealth, VulnerabilityProvenance,
    VulnerabilityRecord, VulnerabilityReference, VulnerabilitySeverity,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const CACHE_FILE: &str = "vigil-advisory-cache.json";
const CACHE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_SOURCE_TTL_SECS: u64 = 24 * 60 * 60;
const NCSC_SOURCE_KEY: &str = "ncsc-advisories";
const NCSC_SOURCE_KIND: &str = "ncsc";
const NCSC_SOURCE_URL: &str = "https://www.ncsc.gov.uk/";
const BSI_SOURCE_KEY: &str = "bsi-advisories";
const BSI_SOURCE_KIND: &str = "bsi";
const BSI_SOURCE_URL: &str = "https://www.bsi.bund.de/";

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecordKey {
    primary_id: String,
    source_kind: String,
    source_key: String,
}

pub fn run_import_ncsc_cli(paths: &[PathBuf]) -> Result<(), String> {
    let summary = import_snapshots(NationalAdvisorySourceKind::Ncsc, paths)?;
    println!(
        "Merged {} NCSC advisory record(s) from {} snapshot file(s) into the protected advisory cache. Cache now holds {} records across {} sources.",
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
        "Merged {} BSI/CERT-Bund advisory record(s) from {} snapshot file(s) into the protected advisory cache. Cache now holds {} records across {} sources.",
        summary.imported_records,
        summary.imported_files,
        summary.total_records,
        summary.total_sources,
    );
    Ok(())
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
    if trimmed.trim_start().starts_with('<') {
        parse_rss_snapshot(source_kind, &trimmed, bytes, path)
    } else {
        parse_json_snapshot(source_kind, bytes, path)
    }
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
            title.as_deref(),
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
        severities: Vec::new(),
        affected_products: Vec::new(),
        references,
        mitigations: Vec::new(),
        provenance: VulnerabilityProvenance {
            source_kind: source_kind.source_kind().into(),
            source_key: source_kind.source_key().into(),
            source_url,
            imported_unix,
        },
    })
}

fn load_cache_for_import() -> Result<Option<AdvisoryCache>, String> {
    let path = cache_path();
    if !path.exists() {
        return Ok(None);
    }
    let loaded: Option<AdvisoryCache> = crate::security::policy::load_struct_with_integrity(&path)
        .map_err(|err| {
            format!(
                "failed to load protected advisory cache {}: {err}",
                path.display()
            )
        })?;
    match loaded {
        Some(cache) if cache.schema_version == CACHE_SCHEMA_VERSION => Ok(Some(cache)),
        Some(cache) => {
            tracing::warn!(
                schema_version = cache.schema_version,
                "ignoring incompatible advisory cache during NCSC/BSI import"
            );
            Ok(None)
        }
        None => Ok(None),
    }
}

fn save_cache(cache: &AdvisoryCache) -> Result<(), String> {
    let path = cache_path();
    crate::security::policy::save_struct_with_integrity(&path, cache).map_err(|err| {
        format!(
            "failed to save protected advisory cache {}: {err}",
            path.display()
        )
    })
}

fn cache_path() -> PathBuf {
    crate::config::data_dir().join(CACHE_FILE)
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
    if let Some(severity) = first_string(value, &["severity", "cvssSeverity", "baseSeverity"]) {
        severities.push(VulnerabilitySeverity {
            source: source.into(),
            scheme: first_string(value, &["severityScheme", "cvssVersion"])
                .unwrap_or_else(|| "source".into()),
            severity,
            score: first_string(value, &["score", "baseScore", "cvssScore"])
                .and_then(|score| score.parse::<f32>().ok()),
            vector: first_string(value, &["vector", "vectorString", "cvssVector"]),
        });
    }
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
            if let Some(severity) = map
                .get("severity")
                .or_else(|| map.get("baseSeverity"))
                .and_then(value_to_string)
            {
                out.push(VulnerabilitySeverity {
                    source: source.into(),
                    scheme: map
                        .get("version")
                        .or_else(|| map.get("scheme"))
                        .and_then(value_to_string)
                        .unwrap_or_else(|| "cvss".into()),
                    severity,
                    score: map
                        .get("score")
                        .or_else(|| map.get("baseScore"))
                        .and_then(value_to_string)
                        .and_then(|score| score.parse::<f32>().ok()),
                    vector: map
                        .get("vector")
                        .or_else(|| map.get("vectorString"))
                        .and_then(value_to_string),
                });
            }
        }
        _ => {}
    }
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
    let needle = format!("{attr}=\"");
    let start = tag_xml.find(&needle)? + needle.len();
    let end = tag_xml[start..].find('"')? + start;
    Some(unescape_xml(tag_xml[start..end].trim()))
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
}
