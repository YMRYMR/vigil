use crate::advisory::{AdvisoryCache, AffectedProduct, VulnerabilityRecord, VulnerabilitySeverity};
use crate::advisory_match::{
    evaluate_affected_product_match, AffectedProductMatch, AffectedProductRef, InstalledProductRef,
    MatchConfidence, VersionMatchStatus,
};
use crate::software_inventory::{
    correlate_runtime_inventory, InstalledSoftware, InventorySource, RuntimeCorrelationConfidence,
    RuntimeInventoryTarget,
};
use crate::storage::{InventoryStore, ProtectedJsonInventoryStore};
use crate::version_compare::VersionSource;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

const ADVISORY_CACHE_FILE: &str = "vigil-advisory-cache.json";
const ADVISORY_CACHE_SCHEMA_VERSION: u32 = 1;
const ADVISORY_LOOKUP_CACHE_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvisoryScoreOutcome {
    pub score_delta: u8,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdvisoryScoreLookupKey {
    process_name: String,
    process_path: String,
    service_name: String,
    publisher: String,
}

#[derive(Debug, Clone)]
struct CachedAdvisoryScore {
    key: AdvisoryScoreLookupKey,
    loaded_at: Instant,
    outcome: AdvisoryScoreOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeAdvisoryCandidate {
    primary_id: String,
    product_name: String,
    severity_label: Option<String>,
    severity_rank: u8,
    known_exploited: bool,
    score_delta: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeveritySummary {
    label: String,
    rank: u8,
}

static ADVISORY_SCORE_CACHE: OnceLock<RwLock<Option<CachedAdvisoryScore>>> = OnceLock::new();

pub fn advisory_score_for_runtime_target(
    target: &RuntimeInventoryTarget<'_>,
) -> AdvisoryScoreOutcome {
    let key = AdvisoryScoreLookupKey {
        process_name: target.process_name.to_string(),
        process_path: target.process_path.to_string(),
        service_name: target.service_name.to_string(),
        publisher: target.publisher.to_string(),
    };
    let cache_lock = ADVISORY_SCORE_CACHE.get_or_init(|| RwLock::new(None));

    {
        let cache = cache_lock.read().unwrap();
        if let Some(cached) = cache.as_ref() {
            if cached.key == key && cached.loaded_at.elapsed() <= ADVISORY_LOOKUP_CACHE_TTL {
                return cached.outcome.clone();
            }
        }
    }

    let outcome = load_advisory_score_for_runtime_target(target);
    let mut cache = cache_lock.write().unwrap();
    *cache = Some(CachedAdvisoryScore {
        key,
        loaded_at: Instant::now(),
        outcome: outcome.clone(),
    });
    outcome
}

fn load_advisory_score_for_runtime_target(
    target: &RuntimeInventoryTarget<'_>,
) -> AdvisoryScoreOutcome {
    let inventory = match ProtectedJsonInventoryStore::new_default().load_inventory() {
        Ok(inventory) => inventory,
        Err(_) => return AdvisoryScoreOutcome::default(),
    };
    if inventory.is_empty() {
        return AdvisoryScoreOutcome::default();
    }

    let cache = match load_advisory_cache() {
        Ok(Some(cache)) => cache,
        Ok(None) | Err(_) => return AdvisoryScoreOutcome::default(),
    };

    advisory_score_from_data(target, &inventory, &cache)
}

fn advisory_score_from_data(
    target: &RuntimeInventoryTarget<'_>,
    inventory: &[InstalledSoftware],
    cache: &AdvisoryCache,
) -> AdvisoryScoreOutcome {
    let Some(runtime_match) = correlate_runtime_inventory(target, inventory) else {
        return AdvisoryScoreOutcome::default();
    };
    if runtime_match.confidence != RuntimeCorrelationConfidence::High {
        return AdvisoryScoreOutcome::default();
    }

    let mut candidates = cache
        .records
        .iter()
        .filter_map(|record| build_candidate(&runtime_match.installed, record))
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        right
            .known_exploited
            .cmp(&left.known_exploited)
            .then_with(|| right.score_delta.cmp(&left.score_delta))
            .then_with(|| right.severity_rank.cmp(&left.severity_rank))
            .then_with(|| left.primary_id.cmp(&right.primary_id))
    });

    let Some(candidate) = candidates.into_iter().next() else {
        return AdvisoryScoreOutcome::default();
    };

    AdvisoryScoreOutcome {
        score_delta: candidate.score_delta,
        reasons: vec![advisory_reason(&candidate)],
    }
}

fn build_candidate(
    installed: &InstalledSoftware,
    record: &VulnerabilityRecord,
) -> Option<RuntimeAdvisoryCandidate> {
    let matched = best_record_match(installed, record)?;
    if matched.confidence != MatchConfidence::High || !matched.applies {
        return None;
    }

    let severity = best_severity(&record.severities);
    let severity_rank = severity.as_ref().map(|summary| summary.rank).unwrap_or(0);
    if !record.known_exploited && severity_rank < severity_label_rank(Some("high")) {
        return None;
    }

    Some(RuntimeAdvisoryCandidate {
        primary_id: record.primary_id.clone(),
        product_name: installed.display_name.clone(),
        severity_label: severity.map(|summary| summary.label),
        severity_rank,
        known_exploited: record.known_exploited,
        score_delta: advisory_score_delta(record.known_exploited, severity_rank),
    })
}

fn advisory_reason(candidate: &RuntimeAdvisoryCandidate) -> String {
    match (
        candidate.severity_label.as_deref(),
        candidate.known_exploited,
    ) {
        (Some(severity), true) => format!(
            "High-confidence advisory match: {} ({severity}, known exploited) applies to {}",
            candidate.primary_id, candidate.product_name
        ),
        (Some(severity), false) => format!(
            "High-confidence advisory match: {} ({severity}) applies to {}",
            candidate.primary_id, candidate.product_name
        ),
        (None, true) => format!(
            "High-confidence advisory match: {} (known exploited) applies to {}",
            candidate.primary_id, candidate.product_name
        ),
        (None, false) => format!(
            "High-confidence advisory match: {} applies to {}",
            candidate.primary_id, candidate.product_name
        ),
    }
}

fn advisory_score_delta(known_exploited: bool, severity_rank: u8) -> u8 {
    match (known_exploited, severity_rank) {
        (true, rank) if rank >= severity_label_rank(Some("critical")) => 3,
        (true, _) => 2,
        (false, rank) if rank >= severity_label_rank(Some("critical")) => 2,
        (false, rank) if rank >= severity_label_rank(Some("high")) => 1,
        _ => 0,
    }
}

fn best_record_match(
    installed: &InstalledSoftware,
    record: &VulnerabilityRecord,
) -> Option<AffectedProductMatch> {
    let installed_ref = InstalledProductRef {
        product_key: &installed.product_key,
        product_aliases: &installed.product_aliases,
        vendor_key: installed.vendor_key.as_deref(),
        version_hint: installed.version_hint.as_deref(),
        version_source: version_source_for_inventory(installed.source),
    };

    record
        .affected_products
        .iter()
        .filter_map(|affected| {
            evaluate_affected_product_match(&installed_ref, &affected_product_ref(affected))
        })
        .max_by_key(|matched| {
            (
                advisory_match_rank(matched.confidence, matched.version_status),
                source_explainability_rank(matched),
            )
        })
}

fn affected_product_ref<'a>(affected: &'a AffectedProduct) -> AffectedProductRef<'a> {
    AffectedProductRef {
        criteria: &affected.criteria,
        match_criteria_id: affected.match_criteria_id.as_deref(),
        cpe_name: affected.cpe_name.as_deref(),
        vulnerable: affected.vulnerable,
        version_start_including: affected.version_start_including.as_deref(),
        version_start_excluding: affected.version_start_excluding.as_deref(),
        version_end_including: affected.version_end_including.as_deref(),
        version_end_excluding: affected.version_end_excluding.as_deref(),
    }
}

fn advisory_match_rank(
    confidence: MatchConfidence,
    version_status: VersionMatchStatus,
) -> (u8, u8, u8) {
    (
        u8::from(matches!(
            version_status,
            VersionMatchStatus::Exact
                | VersionMatchStatus::InRange
                | VersionMatchStatus::NoConstraint
        )),
        confidence_rank(confidence),
        version_status_rank(version_status),
    )
}

fn confidence_rank(confidence: MatchConfidence) -> u8 {
    match confidence {
        MatchConfidence::High => 2,
        MatchConfidence::Medium => 1,
    }
}

fn version_status_rank(status: VersionMatchStatus) -> u8 {
    match status {
        VersionMatchStatus::Exact => 6,
        VersionMatchStatus::InRange => 5,
        VersionMatchStatus::NoConstraint => 4,
        VersionMatchStatus::MissingInstalledVersion => 3,
        VersionMatchStatus::Unknown => 2,
        VersionMatchStatus::OutOfRange => 1,
    }
}

fn source_explainability_rank(matched: &AffectedProductMatch) -> (u8, usize, usize) {
    (
        u8::from(matched.match_criteria_id.is_some()),
        source_id_specificity(&matched.source_id),
        usize::from(!matched.vendor.is_empty()),
    )
}

fn source_id_specificity(source_id: &str) -> usize {
    if source_id.starts_with("cpe:2.3:") {
        source_id
            .split(':')
            .skip(2)
            .filter(|component| !matches!(component.trim(), "" | "*" | "-"))
            .count()
    } else if source_id.trim().is_empty() {
        0
    } else if source_id.contains(':') {
        2
    } else {
        1
    }
}

fn best_severity(severities: &[VulnerabilitySeverity]) -> Option<SeveritySummary> {
    let best = severities.iter().max_by_key(|severity| {
        (
            severity_label_rank(normalize_severity_label(&severity.severity).as_deref()),
            u8::from(severity.score.is_some()),
        )
    })?;
    let normalized = normalize_severity_label(&best.severity)
        .unwrap_or_else(|| best.severity.trim().to_ascii_lowercase());
    if normalized.is_empty() {
        return None;
    }
    let label = if let Some(score) = best.score {
        format!("{normalized} {score:.1}")
    } else {
        normalized.clone()
    };
    Some(SeveritySummary {
        label,
        rank: severity_label_rank(Some(normalized.as_str())),
    })
}

fn normalize_severity_label(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn severity_label_rank(label: Option<&str>) -> u8 {
    match label.unwrap_or_default() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn version_source_for_inventory(source: InventorySource) -> VersionSource {
    match source {
        InventorySource::LinuxDpkgStatus => VersionSource::DebianPackage,
        InventorySource::LinuxRpmDatabase => VersionSource::RpmPackage,
        InventorySource::LinuxApkInstalled => VersionSource::AlpinePackage,
        InventorySource::RunningProcess
        | InventorySource::WindowsUninstallRegistry
        | InventorySource::RunningService => VersionSource::Default,
    }
}

fn load_advisory_cache() -> Result<Option<AdvisoryCache>, String> {
    let path = crate::config::data_dir().join(ADVISORY_CACHE_FILE);
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
    let Some(cache) = loaded else {
        return Ok(None);
    };
    if cache.schema_version != ADVISORY_CACHE_SCHEMA_VERSION {
        return Err(format!(
            "protected advisory cache {} used unsupported schema version {}",
            path.display(),
            cache.schema_version
        ));
    }
    Ok(Some(cache))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::{AffectedProduct, VulnerabilityProvenance};
    use crate::software_inventory::{InstalledSoftware, InventorySource, RuntimeInventoryTarget};

    fn installed(
        product_key: &str,
        display_name: &str,
        vendor_key: Option<&str>,
        version_hint: Option<&str>,
        aliases: &[&str],
        source: InventorySource,
    ) -> InstalledSoftware {
        InstalledSoftware {
            product_key: product_key.into(),
            display_name: display_name.into(),
            executable_path: String::new(),
            publisher_hint: None,
            version_hint: version_hint.map(str::to_string),
            product_aliases: aliases.iter().map(|alias| (*alias).to_string()).collect(),
            vendor_key: vendor_key.map(str::to_string),
            source,
        }
    }

    fn target(
        process_name: &'static str,
        process_path: &'static str,
        publisher: &'static str,
    ) -> RuntimeInventoryTarget<'static> {
        RuntimeInventoryTarget {
            process_name,
            process_path,
            service_name: "",
            publisher,
        }
    }

    fn record(
        primary_id: &str,
        known_exploited: bool,
        severity: &str,
        score: f32,
        affected_products: Vec<AffectedProduct>,
    ) -> VulnerabilityRecord {
        VulnerabilityRecord {
            primary_id: primary_id.into(),
            summary: "Example advisory".into(),
            known_exploited,
            severities: vec![VulnerabilitySeverity {
                source: "nvd".into(),
                scheme: "cvss_v3.1".into(),
                severity: severity.into(),
                score: Some(score),
                vector: None,
            }],
            affected_products,
            provenance: VulnerabilityProvenance {
                source_kind: "nvd".into(),
                source_key: "nvd-cve".into(),
                source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                imported_unix: 0,
            },
            ..VulnerabilityRecord::default()
        }
    }

    fn affected(
        criteria: &str,
        cpe_name: Option<&str>,
        start: Option<&str>,
        end_excluding: Option<&str>,
    ) -> AffectedProduct {
        AffectedProduct {
            criteria: criteria.into(),
            cpe_name: cpe_name.map(str::to_string),
            vulnerable: true,
            version_start_including: start.map(str::to_string),
            version_end_excluding: end_excluding.map(str::to_string),
            ..AffectedProduct::default()
        }
    }

    fn cache(records: Vec<VulnerabilityRecord>) -> AdvisoryCache {
        AdvisoryCache {
            schema_version: 1,
            generated_unix: 0,
            sources: vec![],
            records,
        }
    }

    #[test]
    fn known_exploited_critical_match_adds_three_points() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let cache = cache(vec![record(
            "CVE-2026-12345",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                Some("cpe:2.3:a:google:chrome:124.0.6367.91:*:*:*:*:*:*:*"),
                None,
                None,
            )],
        )]);

        let outcome = advisory_score_from_data(
            &target(
                "chrome.exe",
                "C:/Program Files/Google/Chrome/chrome.exe",
                "Google LLC",
            ),
            &inventory,
            &cache,
        );

        assert_eq!(outcome.score_delta, 3);
        assert_eq!(outcome.reasons.len(), 1);
        assert!(outcome.reasons[0].contains("CVE-2026-12345"));
        assert!(outcome.reasons[0].contains("known exploited"));
        assert!(outcome.reasons[0].contains("Google Chrome"));
    }

    #[test]
    fn product_alias_only_match_does_not_raise_score() {
        let inventory = vec![installed(
            "curl",
            "curl",
            Some("fedora"),
            Some("8.8.0-1.fc40"),
            &["curl"],
            InventorySource::LinuxRpmDatabase,
        )];
        let cache = cache(vec![record(
            "CVE-2026-20000",
            false,
            "HIGH",
            8.1,
            vec![affected(
                "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
                None,
                Some("8.0.0-1.fc40"),
                Some("9.0.0-1.fc40"),
            )],
        )]);

        let outcome = advisory_score_from_data(
            &target("curl", "/usr/bin/curl", "Example Vendor"),
            &inventory,
            &cache,
        );

        assert_eq!(outcome, AdvisoryScoreOutcome::default());
    }

    #[test]
    fn out_of_range_match_does_not_raise_score() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("123.0.0"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let cache = cache(vec![record(
            "CVE-2026-30000",
            false,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                Some("124.0.0"),
                Some("125.0.0"),
            )],
        )]);

        let outcome = advisory_score_from_data(
            &target(
                "chrome.exe",
                "C:/Program Files/Google/Chrome/chrome.exe",
                "Google LLC",
            ),
            &inventory,
            &cache,
        );

        assert_eq!(outcome, AdvisoryScoreOutcome::default());
    }

    #[test]
    fn severity_only_critical_match_adds_two_points() {
        let inventory = vec![installed(
            "dnscache",
            "Dnscache",
            Some("microsoft"),
            Some("10.0.0"),
            &["dnscache", "microsoft-dnscache", "svchost"],
            InventorySource::RunningService,
        )];
        let cache = cache(vec![record(
            "CVE-2026-40000",
            false,
            "CRITICAL",
            9.1,
            vec![affected(
                "cpe:2.3:a:microsoft:dnscache:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        )]);

        let target = RuntimeInventoryTarget {
            process_name: "svchost.exe",
            process_path: "C:/Windows/System32/svchost.exe",
            service_name: "Dnscache",
            publisher: "Microsoft Corporation",
        };
        let outcome = advisory_score_from_data(&target, &inventory, &cache);

        assert_eq!(outcome.score_delta, 2);
        assert!(outcome.reasons[0].contains("critical 9.1"));
    }

    #[test]
    fn advisory_score_remains_fail_open_when_inputs_do_not_correlate() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let cache = cache(vec![record(
            "CVE-2026-50000",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        )]);

        let outcome = advisory_score_from_data(
            &target(
                "powershell.exe",
                "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                "Microsoft Corporation",
            ),
            &inventory,
            &cache,
        );

        assert_eq!(outcome, AdvisoryScoreOutcome::default());
    }
}
