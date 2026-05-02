//! EUVD and JVN public advisory ingestion foundations.
//!
//! This module intentionally starts with offline/operator-supplied snapshots.
//! EUVD's public web surface has not exposed a stable documented API contract
//! yet, and JVN has several feed shapes. The safe first slice is therefore:
//!
//! - normalize EUVD JSON exports or mirrored records into `VulnerabilityRecord`
//! - normalize JVN/JVN iPedia JSON snapshots and JVNDBRSS XML items
//! - preserve source-specific identifiers, aliases, references, timestamps,
//!   vendor/product metadata, mitigation/remediation hints, and provenance
//! - merge imported records into the same protected advisory cache used by NVD
//!
//! Live scheduled fetching can build on these parsers once the exact official
//! endpoints and schemas are pinned down.

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
const EUVD_SOURCE_KEY: &str = "euvd-records";
const EUVD_SOURCE_KIND: &str = "euvd";
const EUVD_SOURCE_URL: &str = "https://euvd.enisa.europa.eu/";
const JVN_SOURCE_KEY: &str = "jvn-ipedia";
const JVN_SOURCE_KIND: &str = "jvn";
const JVN_SOURCE_URL: &str = "https://jvndb.jvn.jp/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicSourceKind {
    Euvd,
    Jvn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSourceImportSummary {
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

pub fn run_import_euvd_cli(paths: &[PathBuf]) -> Result<(), String> {
    let summary = import_public_source_snapshots(PublicSourceKind::Euvd, paths)?;
    println!(
        "Merged {} EUVD record(s) from {} snapshot file(s) into the protected advisory cache ({} marked exploited in this import set). Cache now holds {} records across {} sources.",
        summary.imported_records,
        summary.imported_files,
        summary.known_exploited,
        summary.total_records,
        summary.total_sources,
    );
    Ok(())
}

pub fn run_import_jvn_cli(paths: &[PathBuf]) -> Result<(), String> {
    let summary = import_public_source_snapshots(PublicSourceKind::Jvn, paths)?;
    println!(
        "Merged {} JVN/JVN iPedia record(s) from {} snapshot file(s) into the protected advisory cache. Cache now holds {} records across {} sources.",
        summary.imported_records,
        summary.imported_files,
        summary.total_records,
        summary.total_sources,
    );
    Ok(())
}

pub fn import_public_source_snapshots(
    source_kind: PublicSourceKind,
    paths: &[PathBuf],
) -> Result<PublicSourceImportSummary, String> {
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
    let summary = PublicSourceImportSummary {
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
    source_kind: PublicSourceKind,
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
    source_kind: PublicSourceKind,
    bytes: &[u8],
    path: Option<&Path>,
) -> Result<AdvisoryCache, String> {
    match source_kind {
        PublicSourceKind::Euvd => parse_euvd_json_snapshot(bytes, path),
        PublicSourceKind::Jvn => parse_jvn_snapshot(bytes, path),
    }
}

fn parse_euvd_json_snapshot(bytes: &[u8], path: Option<&Path>) -> Result<AdvisoryCache, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|err| format!("failed to parse EUVD JSON snapshot: {err}"))?;
    let fetched_unix = snapshot_timestamp(&value).unwrap_or_else(unix_now);
    let records = record_array(&value)
        .ok_or_else(|| "EUVD snapshot did not contain a recognizable records array".to_string())?
        .iter()
        .filter_map(|item| parse_euvd_record(item, fetched_unix))
        .collect::<Vec<_>>();

    Ok(AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: fetched_unix,
        sources: vec![source_cache(
            PublicSourceKind::Euvd,
            fetched_unix,
            path.map(|path| vec![path.display().to_string()]),
            sha256_hex(bytes),
            records.len(),
        )],
        records,
    })
}

fn parse_jvn_snapshot(bytes: &[u8], path: Option<&Path>) -> Result<AdvisoryCache, String> {
    let trimmed = String::from_utf8_lossy(bytes);
    if trimmed.trim_start().starts_with('<') {
        return parse_jvn_rss_snapshot(&trimmed, bytes, path);
    }

    let value: Value = serde_json::from_slice(bytes)
        .map_err(|err| format!("failed to parse JVN JSON snapshot: {err}"))?;
    let fetched_unix = snapshot_timestamp(&value).unwrap_or_else(unix_now);
    let records = record_array(&value)
        .ok_or_else(|| "JVN snapshot did not contain a recognizable records array".to_string())?
        .iter()
        .filter_map(|item| parse_jvn_json_record(item, fetched_unix))
        .collect::<Vec<_>>();

    Ok(AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: fetched_unix,
        sources: vec![source_cache(
            PublicSourceKind::Jvn,
            fetched_unix,
            path.map(|path| vec![path.display().to_string()]),
            sha256_hex(bytes),
            records.len(),
        )],
        records,
    })
}

fn parse_jvn_rss_snapshot(
    xml: &str,
    bytes: &[u8],
    path: Option<&Path>,
) -> Result<AdvisoryCache, String> {
    let fetched_unix = unix_now();
    let records = xml_items(xml)
        .into_iter()
        .filter_map(|item| parse_jvn_rss_item(&item, fetched_unix))
        .collect::<Vec<_>>();

    Ok(AdvisoryCache {
        schema_version: CACHE_SCHEMA_VERSION,
        generated_unix: fetched_unix,
        sources: vec![source_cache(
            PublicSourceKind::Jvn,
            fetched_unix,
            path.map(|path| vec![path.display().to_string()]),
            sha256_hex(bytes),
            records.len(),
        )],
        records,
    })
}

fn parse_euvd_record(value: &Value, imported_unix: u64) -> Option<VulnerabilityRecord> {
    let primary_id = first_string(value, &["id", "euvd", "euvdId", "euvd_id", "recordId"])
        .or_else(|| first_cve(value))?;
    let source_url = first_string(value, &["url", "sourceUrl", "source_url", "recordUrl"])
        .unwrap_or_else(|| format!("{EUVD_SOURCE_URL}vulnerability/{}", primary_id));
    let mut aliases = unique_strings(flatten_strings_from_keys(
        value,
        &[
            "aliases",
            "alias",
            "cve",
            "cveId",
            "cve_id",
            "cves",
            "vulnerabilityId",
            "vulnerability_id",
        ],
    ));
    if !aliases.iter().any(|alias| alias == &primary_id) {
        aliases.push(primary_id.clone());
    }

    let references = references_from_value(value, "EUVD", &source_url);
    let mut mitigations = unique_strings(flatten_strings_from_keys(
        value,
        &[
            "mitigation",
            "mitigations",
            "remediation",
            "remediations",
            "workaround",
            "workarounds",
            "solution",
            "solutions",
            "recommendation",
            "recommendations",
        ],
    ));
    mitigations.extend(urls_from_keys(value, &["mitigationUrl", "mitigation_url", "remediationUrl"]));
    mitigations = unique_strings(mitigations);

    Some(VulnerabilityRecord {
        primary_id,
        aliases,
        summary: first_string(value, &["summary", "description", "title", "name"])
            .unwrap_or_default(),
        published: first_string(value, &["published", "datePublished", "publishedDate", "created"]),
        last_modified: first_string(value, &["lastModified", "last_modified", "updated", "dateUpdated"]),
        known_exploited: bool_from_keys(
            value,
            &["knownExploited", "exploited", "isExploited", "exploitationDetected"],
        ),
        severities: severities_from_value(value, "EUVD"),
        affected_products: products_from_value(value),
        references,
        mitigations,
        provenance: VulnerabilityProvenance {
            source_kind: EUVD_SOURCE_KIND.into(),
            source_key: EUVD_SOURCE_KEY.into(),
            source_url,
            imported_unix,
        },
    })
}

fn parse_jvn_json_record(value: &Value, imported_unix: u64) -> Option<VulnerabilityRecord> {
    let primary_id = first_string(
        value,
        &["id", "jvnId", "jvn_id", "jvndbId", "jvndb_id", "identifier"],
    )
    .or_else(|| first_cve(value))?;
    let source_url = first_string(value, &["link", "url", "sourceUrl", "source_url"])
        .unwrap_or_else(|| format!("{JVN_SOURCE_URL}ja/contents/{}", primary_id));
    let aliases = unique_strings(flatten_strings_from_keys(
        value,
        &["aliases", "cve", "cveId", "cve_id", "cves", "identifier"],
    ));
    let mut mitigations = unique_strings(flatten_strings_from_keys(
        value,
        &[
            "solution",
            "solutions",
            "remediation",
            "remediations",
            "workaround",
            "workarounds",
            "fix",
            "fixedVersion",
            "fixed_version",
        ],
    ));
    mitigations.extend(urls_from_keys(value, &["solutionUrl", "solution_url", "vendorUrl"]));
    mitigations = unique_strings(mitigations);

    Some(VulnerabilityRecord {
        primary_id,
        aliases,
        summary: first_string(value, &["summary", "description", "title", "name"])
            .unwrap_or_default(),
        published: first_string(value, &["issued", "published", "datePublished", "created"]),
        last_modified: first_string(value, &["modified", "lastModified", "last_modified", "updated"]),
        known_exploited: bool_from_keys(value, &["knownExploited", "exploited"]),
        severities: severities_from_value(value, "JVN"),
        affected_products: products_from_value(value),
        references: references_from_value(value, "JVN", &source_url),
        mitigations,
        provenance: VulnerabilityProvenance {
            source_kind: JVN_SOURCE_KIND.into(),
            source_key: JVN_SOURCE_KEY.into(),
            source_url,
            imported_unix,
        },
    })
}

fn parse_jvn_rss_item(item: &str, imported_unix: u64) -> Option<VulnerabilityRecord> {
    let title = xml_tag(item, "title").unwrap_or_default();
    let link = xml_tag(item, "link").unwrap_or_else(|| JVN_SOURCE_URL.into());
    let description = xml_tag(item, "description").unwrap_or_default();
    let identifier = xml_tag(item, "sec:identifier")
        .or_else(|| xml_tag(item, "identifier"))
        .or_else(|| extract_jvn_id(&link))
        .or_else(|| first_cve_text(&title))
        .or_else(|| first_cve_text(&description))?;
    let mut aliases = Vec::new();
    if let Some(cve) = first_cve_text(&title).or_else(|| first_cve_text(&description)) {
        aliases.push(cve);
    }
    aliases.push(identifier.clone());

    Some(VulnerabilityRecord {
        primary_id: identifier,
        aliases: unique_strings(aliases),
        summary: if description.is_empty() { title } else { description },
        published: xml_tag(item, "dc:date").or_else(|| xml_tag(item, "pubDate")),
        last_modified: xml_tag(item, "dcterms:modified").or_else(|| xml_tag(item, "modified")),
        known_exploited: false,
        severities: Vec::new(),
        affected_products: Vec::new(),
        references: vec![VulnerabilityReference {
            url: link.clone(),
            source: Some("JVN".into()),
            tags: vec!["source".into()],
        }],
        mitigations: Vec::new(),
        provenance: VulnerabilityProvenance {
            source_kind: JVN_SOURCE_KIND.into(),
            source_key: JVN_SOURCE_KEY.into(),
            source_url: link,
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
        .map_err(|err| format!("failed to load protected advisory cache {}: {err}", path.display()))?;
    match loaded {
        Some(cache) if cache.schema_version == CACHE_SCHEMA_VERSION => Ok(Some(cache)),
        Some(cache) => {
            tracing::warn!(
                schema_version = cache.schema_version,
                "ignoring incompatible advisory cache during EUVD/JVN import"
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
    match (
        existing.last_modified.as_deref().and_then(parse_timestamp),
        incoming.last_modified.as_deref().and_then(parse_timestamp),
    ) {
        (Some(left), Some(right)) => left >= right,
        _ => existing.provenance.imported_unix >= incoming.provenance.imported_unix,
    }
}

fn record_key(record: &VulnerabilityRecord) -> RecordKey {
    RecordKey {
        primary_id: record.primary_id.clone(),
        source_kind: record.provenance.source_kind.clone(),
        source_key: record.provenance.source_key.clone(),
    }
}

fn source_cache(
    source_kind: PublicSourceKind,
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

impl PublicSourceKind {
    fn label(self) -> &'static str {
        match self {
            PublicSourceKind::Euvd => "EUVD",
            PublicSourceKind::Jvn => "JVN",
        }
    }

    fn source_key(self) -> &'static str {
        match self {
            PublicSourceKind::Euvd => EUVD_SOURCE_KEY,
            PublicSourceKind::Jvn => JVN_SOURCE_KEY,
        }
    }

    fn source_kind(self) -> &'static str {
        match self {
            PublicSourceKind::Euvd => EUVD_SOURCE_KIND,
            PublicSourceKind::Jvn => JVN_SOURCE_KIND,
        }
    }

    fn source_url(self) -> &'static str {
        match self {
            PublicSourceKind::Euvd => EUVD_SOURCE_URL,
            PublicSourceKind::Jvn => JVN_SOURCE_URL,
        }
    }
}

fn record_array(value: &Value) -> Option<&Vec<Value>> {
    for key in ["records", "vulnerabilities", "items", "data", "results", "entries"] {
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
            for key in ["id", "name", "title", "value", "url", "reference", "product", "vendor"] {
                if let Some(value) = map.get(key) {
                    flatten_strings(value, &mut out);
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
            let parts = tail.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-')).next()?;
            if parts.len() >= 13 {
                return Some(parts.to_string());
            }
        }
        idx += 1;
    }
    None
}

fn references_from_value(value: &Value, source: &str, source_url: &str) -> Vec<VulnerabilityReference> {
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
                    .map(|value| unique_strings({
                        let mut values = Vec::new();
                        flatten_strings(value, &mut values);
                        values
                    }))
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

fn push_reference(refs: &mut Vec<VulnerabilityReference>, url: &str, source: &str, tags: Vec<String>) {
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
    for key in ["affected", "affectedProducts", "products", "vendors", "cpe", "cpes"] {
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
                    map.get("cpeName").or_else(|| map.get("cpe")).and_then(value_to_string),
                    map.get("vulnerable").and_then(Value::as_bool).unwrap_or(true),
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
        let Some(open_end) = rest.find('>') else { break };
        let body_start = open_end + 1;
        let Some(end) = rest[body_start..].find("</item>") else { break };
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

fn extract_jvn_id(link: &str) -> Option<String> {
    link.split('/')
        .find(|part| part.to_ascii_uppercase().starts_with("JVN"))
        .map(|part| part.trim_end_matches(".html").to_string())
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
                .ok()
                .map(|ts| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(ts, chrono::Utc))
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
    fn parses_euvd_json_record_with_metadata() {
        let bytes = br#"{
            "timestamp": "2026-05-01T00:00:00Z",
            "records": [{
                "euvdId": "EUVD-2026-0001",
                "cve": ["CVE-2026-0001"],
                "title": "Example vulnerability",
                "updated": "2026-05-01T01:00:00Z",
                "knownExploited": true,
                "severity": "HIGH",
                "score": "8.8",
                "affectedProducts": [{"vendor":"Example","product":"Agent"}],
                "mitigations": ["Apply the vendor fix"],
                "references": [{"url":"https://example.test/advisory","tags":["vendor"]}]
            }]
        }"#;

        let cache = parse_euvd_json_snapshot(bytes, None).unwrap();
        assert_eq!(cache.records.len(), 1);
        let record = &cache.records[0];
        assert_eq!(record.primary_id, "EUVD-2026-0001");
        assert!(record.aliases.iter().any(|alias| alias == "CVE-2026-0001"));
        assert!(record.known_exploited);
        assert_eq!(record.affected_products[0].criteria, "Example:Agent");
        assert_eq!(record.provenance.source_kind, EUVD_SOURCE_KIND);
    }

    #[test]
    fn preserves_vendor_context_for_nested_products() {
        let bytes = br#"{ 
            "timestamp": "2026-05-01T00:00:00Z",
            "records": [{
                "euvdId": "EUVD-2026-0002",
                "title": "Nested product payload",
                "affectedProducts": [{
                    "vendor": "Example",
                    "products": [
                        {"product": "Agent"},
                        {"product": "Console"}
                    ]
                }]
            }]
        }"#;

        let cache = parse_euvd_json_snapshot(bytes, None).unwrap();
        let record = &cache.records[0];
        assert!(record
            .affected_products
            .iter()
            .any(|product| product.criteria == "Example:Agent"));
        assert!(record
            .affected_products
            .iter()
            .any(|product| product.criteria == "Example:Console"));
    }

    #[test]
    fn keeps_distinct_product_rows_with_shared_criteria() {
        let bytes = br#"{
            "timestamp": "2026-05-01T00:00:00Z",
            "records": [{
                "euvdId": "EUVD-2026-0003",
                "title": "Duplicate criteria payload",
                "affectedProducts": [
                    {
                        "vendor": "Example",
                        "product": "Agent",
                        "matchCriteriaId": "id-one",
                        "cpeName": "cpe:2.3:a:example:agent:1.0.0:*:*:*:*:*:*:*"
                    },
                    {
                        "vendor": "Example",
                        "product": "Agent",
                        "matchCriteriaId": "id-two",
                        "cpeName": "cpe:2.3:a:example:agent:1.1.0:*:*:*:*:*:*:*"
                    }
                ]
            }]
        }"#;

        let cache = parse_euvd_json_snapshot(bytes, None).unwrap();
        let record = &cache.records[0];
        assert_eq!(record.affected_products.len(), 2);
        assert!(record
            .affected_products
            .iter()
            .any(|product| product.match_criteria_id.as_deref() == Some("id-one")));
        assert!(record
            .affected_products
            .iter()
            .any(|product| product.match_criteria_id.as_deref() == Some("id-two")));
    }

    #[test]
    fn parses_jvn_rss_item() {
        let xml = r#"<rss><channel><item>
            <title>JVNDB-2026-000001 CVE-2026-1234 Example product issue</title>
            <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
            <description>Example JVN advisory</description>
            <dc:date>2026-05-01T00:00:00Z</dc:date>
            <sec:identifier>JVNDB-2026-000001</sec:identifier>
        </item></channel></rss>"#;

        let cache = parse_jvn_rss_snapshot(xml, xml.as_bytes(), None).unwrap();
        assert_eq!(cache.records.len(), 1);
        let record = &cache.records[0];
        assert_eq!(record.primary_id, "JVNDB-2026-000001");
        assert!(record.aliases.iter().any(|alias| alias == "CVE-2026-1234"));
        assert_eq!(record.references[0].source.as_deref(), Some("JVN"));
    }
}
