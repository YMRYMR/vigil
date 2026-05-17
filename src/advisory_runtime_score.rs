use crate::advisory::{
    AdvisoryCache, AffectedProduct, VulnerabilityRecord, VulnerabilityReference,
    VulnerabilitySeverity,
};
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
    mitigation_guidance: bool,
    vendor_mitigation_guidance: bool,
    missing_fix_version: bool,
    score_delta: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeveritySummary {
    label: String,
    rank: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeAdvisoryMatch {
    matched: AffectedProductMatch,
    missing_fix_version: bool,
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
            .then_with(|| right.missing_fix_version.cmp(&left.missing_fix_version))
            .then_with(|| right.mitigation_guidance.cmp(&left.mitigation_guidance))
            .then_with(|| {
                right
                    .vendor_mitigation_guidance
                    .cmp(&left.vendor_mitigation_guidance)
            })
            .then_with(|| left.primary_id.cmp(&right.primary_id))
    });

    let Some(best_priority) = candidates.first().map(candidate_priority) else {
        return AdvisoryScoreOutcome::default();
    };

    let score_delta = candidates[0].score_delta;
    let reasons = candidates
        .into_iter()
        .filter(|candidate| candidate_priority(candidate) == best_priority)
        .map(|candidate| advisory_reason(&candidate))
        .collect();

    AdvisoryScoreOutcome {
        score_delta,
        reasons,
    }
}

fn build_candidate(
    installed: &InstalledSoftware,
    record: &VulnerabilityRecord,
) -> Option<RuntimeAdvisoryCandidate> {
    let matched = best_record_match(installed, record)?;
    if matched.matched.confidence != MatchConfidence::High || !matched.matched.applies {
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
        mitigation_guidance: has_mitigation_guidance(record),
        vendor_mitigation_guidance: has_vendor_mitigation_guidance(record),
        missing_fix_version: matched.missing_fix_version,
        score_delta: advisory_score_delta(record.known_exploited, severity_rank),
    })
}

fn advisory_reason(candidate: &RuntimeAdvisoryCandidate) -> String {
    let mut details = Vec::new();
    if let Some(severity) = candidate.severity_label.as_deref() {
        details.push(severity.to_string());
    }
    if candidate.known_exploited {
        details.push("known exploited".to_string());
    }
    if candidate.mitigation_guidance {
        details.push("mitigation guidance available".to_string());
    }
    if candidate.vendor_mitigation_guidance {
        details.push("vendor guidance available".to_string());
    }
    if candidate.missing_fix_version {
        details.push("no fixed-version bound".to_string());
    }

    if details.is_empty() {
        format!(
            "High-confidence advisory match: {} applies to {}",
            candidate.primary_id, candidate.product_name
        )
    } else {
        format!(
            "High-confidence advisory match: {} ({}) applies to {}",
            candidate.primary_id,
            details.join(", "),
            candidate.product_name
        )
    }
}

fn candidate_priority(candidate: &RuntimeAdvisoryCandidate) -> (bool, u8, u8) {
    (
        candidate.known_exploited,
        candidate.score_delta,
        candidate.severity_rank,
    )
}

fn has_mitigation_guidance(record: &VulnerabilityRecord) -> bool {
    record
        .mitigations
        .iter()
        .any(|guidance| guidance_text_has_mitigation_guidance(guidance))
        || record
            .references
            .iter()
            .any(reference_has_mitigation_guidance)
}

fn has_vendor_mitigation_guidance(record: &VulnerabilityRecord) -> bool {
    record
        .references
        .iter()
        .any(reference_has_vendor_mitigation_guidance)
}

// Bare fixed-version tokens are version metadata, not actionable mitigation guidance.
fn guidance_text_has_mitigation_guidance(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return true;
    }
    !looks_like_bare_version_hint(trimmed)
}

fn looks_like_bare_version_hint(text: &str) -> bool {
    let mut saw_token = false;
    for token in text
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';' | '/'))
        .filter(|token| !token.is_empty())
    {
        saw_token = true;
        if !version_like_token(token) {
            return false;
        }
    }
    saw_token
}

fn version_like_token(token: &str) -> bool {
    let token = token.trim_matches(|ch: char| matches!(ch, '(' | ')' | '[' | ']'));
    let token = token
        .strip_prefix('v')
        .or_else(|| token.strip_prefix('V'))
        .unwrap_or(token);
    let mut saw_digit = false;
    for ch in token.chars() {
        if ch.is_ascii_digit() {
            saw_digit = true;
            continue;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '+') {
            continue;
        }
        return false;
    }
    saw_digit
}

fn reference_has_mitigation_guidance(reference: &VulnerabilityReference) -> bool {
    !reference.url.trim().is_empty()
        && reference
            .tags
            .iter()
            .any(|tag| mitigation_reference_tag(tag))
}

fn reference_has_vendor_mitigation_guidance(reference: &VulnerabilityReference) -> bool {
    reference_has_mitigation_guidance(reference)
        && reference
            .tags
            .iter()
            .any(|tag| vendor_guidance_reference_tag(tag))
}

fn mitigation_reference_tag(tag: &str) -> bool {
    let normalized = tag
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_', '/'], " ");
    normalized.split_whitespace().any(|token| {
        matches!(
            token,
            "mitigation"
                | "mitigations"
                | "remediation"
                | "remediations"
                | "workaround"
                | "workarounds"
                | "solution"
                | "solutions"
                | "fix"
                | "fixes"
                | "patch"
                | "patches"
                | "update"
                | "updates"
                | "upgrade"
                | "upgrades"
                | "guidance"
                | "guidances"
        )
    })
}

fn vendor_guidance_reference_tag(tag: &str) -> bool {
    let normalized = tag
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_', '/'], " ");
    let tokens = normalized.split_whitespace().collect::<Vec<_>>();
    tokens.contains(&"vendor")
        && tokens.iter().any(|token| {
            matches!(
                *token,
                "advisory"
                    | "advisories"
                    | "bulletin"
                    | "bulletins"
                    | "notice"
                    | "notices"
                    | "fix"
                    | "fixes"
                    | "patch"
                    | "patches"
                    | "update"
                    | "updates"
                    | "upgrade"
                    | "upgrades"
                    | "solution"
                    | "solutions"
                    | "remediation"
                    | "remediations"
                    | "workaround"
                    | "workarounds"
                    | "guidance"
                    | "guidances"
            )
        })
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
) -> Option<RuntimeAdvisoryMatch> {
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
            let matched =
                evaluate_affected_product_match(&installed_ref, &affected_product_ref(affected))?;
            Some(RuntimeAdvisoryMatch {
                matched,
                missing_fix_version: missing_fix_version_bound(affected),
            })
        })
        .max_by_key(|candidate| {
            (
                advisory_match_rank(
                    candidate.matched.confidence,
                    candidate.matched.version_status,
                ),
                source_explainability_rank(&candidate.matched),
            )
        })
}

fn missing_fix_version_bound(affected: &AffectedProduct) -> bool {
    has_lower_version_bound(affected) && !has_upper_version_bound(affected)
}

fn has_lower_version_bound(affected: &AffectedProduct) -> bool {
    affected.version_start_including.is_some() || affected.version_start_excluding.is_some()
}

fn has_upper_version_bound(affected: &AffectedProduct) -> bool {
    affected.version_end_including.is_some() || affected.version_end_excluding.is_some()
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
        assert!(!outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
        assert!(!outcome.reasons[0].contains("no fixed-version bound"));
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
    fn mitigation_guidance_marks_reason_when_record_has_guidance() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-42222",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.mitigations = vec!["https://example.test/vendor-guidance".into()];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn mitigation_guidance_ignores_bare_fixed_version_text() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-42223",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.mitigations = vec!["124.0.6367.99".into()];
        let cache = cache(vec![advisory]);

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
        assert!(!outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn mitigation_guidance_keeps_descriptive_fixed_version_text() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-42224",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.mitigations = vec!["Upgrade to 124.0.6367.99 or later".into()];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn mitigation_guidance_marks_reason_when_record_has_tagged_reference() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-43333",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/patch".into(),
            source: Some("nvd".into()),
            tags: vec!["Patch".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn guidance_reference_tag_marks_reason_when_reference_uses_guidance_word() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-43334",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/guidance".into(),
            source: Some("nvd".into()),
            tags: vec!["Guidance".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn update_reference_tag_marks_reason_when_reference_uses_update_word() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-43335",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/update".into(),
            source: Some("nvd".into()),
            tags: vec!["Update".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn upgrade_reference_tag_marks_reason_when_reference_uses_upgrade_word() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-43336",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/upgrade".into(),
            source: Some("nvd".into()),
            tags: vec!["Upgrade".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn vendor_advisory_reference_without_remediation_tag_stays_unmatched() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-44445",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/vendor-advisory".into(),
            source: Some("nvd".into()),
            tags: vec!["Vendor Advisory".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(!outcome.reasons[0].contains("mitigation guidance available"));
        assert!(!outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn vendor_mitigation_guidance_marks_reason_when_reference_has_vendor_and_remediation_tags() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-44446",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/vendor-advisory".into(),
            source: Some("nvd".into()),
            tags: vec!["Vendor Advisory".into(), "Mitigation".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn vendor_fix_reference_tag_marks_vendor_guidance_without_advisory_word() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-44447",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/vendor-fix".into(),
            source: Some("nvd".into()),
            tags: vec!["Vendor Fix".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn vendor_update_reference_tag_marks_vendor_guidance_without_advisory_word() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-44448",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/vendor-update".into(),
            source: Some("nvd".into()),
            tags: vec!["Vendor Update".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn vendor_upgrade_reference_tag_marks_vendor_guidance_without_advisory_word() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let mut advisory = record(
            "CVE-2026-44449",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        advisory.references = vec![VulnerabilityReference {
            url: "https://example.test/vendor-upgrade".into(),
            source: Some("nvd".into()),
            tags: vec!["Vendor Upgrade".into()],
        }];
        let cache = cache(vec![advisory]);

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
        assert!(outcome.reasons[0].contains("mitigation guidance available"));
        assert!(outcome.reasons[0].contains("vendor guidance available"));
    }

    #[test]
    fn equally_ranked_matches_keep_multiple_reason_markers_visible() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let missing_fix = record(
            "CVE-2026-10000",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                Some("124.0.0"),
                None,
            )],
        );
        let mut with_guidance = record(
            "CVE-2026-99999",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                None,
                None,
            )],
        );
        with_guidance.mitigations = vec!["https://example.test/vendor-guidance".into()];
        let cache = cache(vec![missing_fix, with_guidance]);

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
        assert_eq!(outcome.reasons.len(), 2);
        assert!(outcome.reasons.iter().any(|reason| {
            reason.contains("CVE-2026-10000") && reason.contains("no fixed-version bound")
        }));
        assert!(outcome.reasons.iter().any(|reason| {
            reason.contains("CVE-2026-99999") && reason.contains("mitigation guidance available")
        }));
    }

    #[test]
    fn open_ended_range_marks_reason_as_missing_fix_version_bound() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let cache = cache(vec![record(
            "CVE-2026-44444",
            true,
            "CRITICAL",
            9.8,
            vec![affected(
                "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                None,
                Some("124.0.0"),
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
        assert!(outcome.reasons[0].contains("no fixed-version bound"));
    }

    #[test]
    fn bounded_range_does_not_mark_reason_as_missing_fix_version_bound() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::WindowsUninstallRegistry,
        )];
        let cache = cache(vec![record(
            "CVE-2026-55555",
            true,
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

        assert_eq!(outcome.score_delta, 3);
        assert!(!outcome.reasons[0].contains("no fixed-version bound"));
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
