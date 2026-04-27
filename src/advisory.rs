//! Public vulnerability intelligence foundations.
//!
//! Phase 16 starts with NVD ingestion, but the full roadmap item includes
//! scheduling, rate-limit-aware sync, CPE/CPE-match ingestion, and broader
//! source correlation. This module implements the smallest safe slice:
//!
//! - a normalized vulnerability record model
//! - protected local cache storage for imported NVD CVE snapshots
//! - a CLI import path for offline or operator-driven snapshot ingestion
//! - startup status logging so the cache state is visible to operators

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const CACHE_FILE: &str = "vigil-advisory-cache.json";
const CACHE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_SOURCE_TTL_SECS: u64 = 24 * 60 * 60;

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
    pub fetched_unix: u64,
    pub expires_unix: u64,
    pub snapshot_sha256: String,
    pub total_results: usize,
    pub status: SourceHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

pub fn run_import_cli(path: &Path) -> Result<(), String> {
    let summary = import_nvd_snapshot(path)?;
    println!(
        "Merged {} NVD CVE records into the protected advisory cache ({} marked known exploited in this snapshot). Cache now holds {} records across {} sources.",
        summary.imported_records,
        summary.known_exploited,
        summary.total_records,
        summary.total_sources
    );
    Ok(())
}

pub fn import_nvd_snapshot(path: &Path) -> Result<ImportSummary, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let imported_cache = parse_nvd_snapshot(&bytes, Some(path))?;
    let imported_records = imported_cache.records.len();
    let known_exploited = imported_cache
        .records
        .iter()
        .filter(|record| record.known_exploited)
        .count();
    let cache = merge_cache(load_cache_for_import()?, imported_cache);
    let summary = ImportSummary {
        imported_records,
        known_exploited,
        total_records: cache.records.len(),
        total_sources: cache.sources.len(),
    };
    save_cache(&cache)?;
    Ok(summary)
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
            source_key: "nvd-cve".into(),
            source_kind: "nvd".into(),
            source_url: source_url.clone(),
            imported_from: imported_from.map(|path| path.display().to_string()),
            fetched_unix: now,
            expires_unix: now.saturating_add(DEFAULT_SOURCE_TTL_SECS),
            snapshot_sha256: sha256_hex(bytes),
            total_results,
            status: SourceHealth::Fresh,
        }],
        records,
    })
}

fn merge_cache(existing: Option<AdvisoryCache>, imported: AdvisoryCache) -> AdvisoryCache {
    let Some(mut merged) = existing else {
        return imported;
    };

    merged.schema_version = CACHE_SCHEMA_VERSION;
    merged.generated_unix = merged.generated_unix.max(imported.generated_unix);

    for source in imported.sources {
        merge_source(&mut merged.sources, source);
    }
    for record in imported.records {
        merge_record(&mut merged.records, record);
    }

    merged
}

fn merge_source(sources: &mut Vec<AdvisorySourceCache>, incoming: AdvisorySourceCache) {
    if let Some(existing) = sources
        .iter_mut()
        .find(|source| same_source_identity(source, &incoming))
    {
        *existing = incoming;
    } else {
        sources.push(incoming);
    }
}

fn merge_record(records: &mut Vec<VulnerabilityRecord>, incoming: VulnerabilityRecord) {
    if let Some(existing) = records
        .iter_mut()
        .find(|record| same_record_identity(record, &incoming))
    {
        if should_replace_record(existing, &incoming) {
            *existing = incoming;
        }
    } else {
        records.push(incoming);
    }
}

fn same_source_identity(left: &AdvisorySourceCache, right: &AdvisorySourceCache) -> bool {
    left.source_kind == right.source_kind && left.source_key == right.source_key
}

fn same_record_identity(left: &VulnerabilityRecord, right: &VulnerabilityRecord) -> bool {
    left.primary_id == right.primary_id
        && left.provenance.source_kind == right.provenance.source_kind
        && left.provenance.source_key == right.provenance.source_key
}

fn should_replace_record(existing: &VulnerabilityRecord, incoming: &VulnerabilityRecord) -> bool {
    match compare_optional_timestamp(
        incoming.last_modified.as_deref(),
        existing.last_modified.as_deref(),
    ) {
        Some(std::cmp::Ordering::Greater) => true,
        Some(std::cmp::Ordering::Less) => false,
        Some(std::cmp::Ordering::Equal) | None => {
            incoming.provenance.imported_unix >= existing.provenance.imported_unix
        }
    }
}

fn compare_optional_timestamp(
    left: Option<&str>,
    right: Option<&str>,
) -> Option<std::cmp::Ordering> {
    let left = parse_timestamp(left?)?;
    let right = parse_timestamp(right?)?;
    Some(left.cmp(&right))
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

fn parse_nvd_record(
    item: &Value,
    imported_unix: u64,
    source_url: &str,
) -> Result<Option<VulnerabilityRecord>, String> {
    let Some(cve) = item.get("cve") else {
        return Ok(None);
    };
    let Some(primary_id) = cve.get("id").and_then(Value::as_str) else {
        return Ok(None);
    };

    let references = cve
        .get("references")
        .and_then(Value::as_array)
        .map(|refs| refs.iter().filter_map(parse_reference).collect::<Vec<_>>())
        .unwrap_or_default();

    let mut mitigations = Vec::new();
    for reference in &references {
        let lower_tags = reference
            .tags
            .iter()
            .map(|tag| tag.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if lower_tags.iter().any(|tag| {
            tag.contains("mitigation") || tag.contains("vendor advisory") || tag.contains("patch")
        }) {
            push_unique(&mut mitigations, reference.url.clone());
        }
    }

    Ok(Some(VulnerabilityRecord {
        primary_id: primary_id.to_string(),
        aliases: Vec::new(),
        summary: english_description(cve),
        published: cve
            .get("published")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        last_modified: cve
            .get("lastModified")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        known_exploited: parse_known_exploited(cve),
        severities: parse_severities(cve),
        affected_products: parse_affected_products(cve),
        references,
        mitigations,
        provenance: VulnerabilityProvenance {
            source_kind: "nvd".into(),
            source_key: "nvd-cve".into(),
            source_url: source_url.to_string(),
            imported_unix,
        },
    }))
}

fn english_description(cve: &Value) -> String {
    cve.get("descriptions")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                let lang = item.get("lang").and_then(Value::as_str)?;
                if lang.eq_ignore_ascii_case("en") {
                    item.get("value").and_then(Value::as_str)
                } else {
                    None
                }
            })
        })
        .or_else(|| {
            cve.get("descriptions")
                .and_then(Value::as_array)
                .and_then(|items| {
                    items
                        .iter()
                        .find_map(|item| item.get("value").and_then(Value::as_str))
                })
        })
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn parse_reference(value: &Value) -> Option<VulnerabilityReference> {
    let url = value.get("url").and_then(Value::as_str)?.trim();
    if url.is_empty() {
        return None;
    }
    Some(VulnerabilityReference {
        url: url.to_string(),
        source: value
            .get("source")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        tags: value
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
                fetched_unix: 42,
                expires_unix: 84,
                snapshot_sha256: "abc".into(),
                total_results: 1,
                status: SourceHealth::Fresh,
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
                    fetched_unix: 100,
                    expires_unix: 200,
                    snapshot_sha256: "old".into(),
                    total_results: 1,
                    status: SourceHealth::Fresh,
                },
                AdvisorySourceCache {
                    source_key: "euvd".into(),
                    source_kind: "euvd".into(),
                    source_url: "https://euvd.enisa.europa.eu".into(),
                    imported_from: None,
                    fetched_unix: 90,
                    expires_unix: 190,
                    snapshot_sha256: "euvd".into(),
                    total_results: 1,
                    status: SourceHealth::Fresh,
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
                fetched_unix: 110,
                expires_unix: 210,
                snapshot_sha256: "new".into(),
                total_results: 2,
                status: SourceHealth::Fresh,
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
