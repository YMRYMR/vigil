use crate::advisory::{AdvisoryCache, AffectedProduct, VulnerabilityRecord};
use crate::advisory_match::{
    evaluate_cpe23_product_match, AffectedProductRef, InstalledProductRef, MatchBasis,
    MatchConfidence, VersionMatchStatus,
};
use crate::software_inventory::{InstalledSoftware, InventorySource};
use crate::storage::{InventoryStore, ProtectedJsonInventoryStore};
use crate::version_compare::VersionSource;
use std::path::PathBuf;

const ADVISORY_CACHE_FILE: &str = "vigil-advisory-cache.json";
const ADVISORY_CACHE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProductAdvisoryMatch {
    installed: InstalledSoftware,
    matches: Vec<RecordAdvisoryMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordAdvisoryMatch {
    primary_id: String,
    summary: String,
    source_kind: String,
    known_exploited: bool,
    cpe_uri: String,
    match_criteria_id: Option<String>,
    part: String,
    vendor: String,
    product: String,
    matched_alias: String,
    match_basis: MatchBasis,
    confidence: MatchConfidence,
    version_status: VersionMatchStatus,
    applies: bool,
}

pub fn run_cli() -> Result<(), String> {
    let inventory = ProtectedJsonInventoryStore::new_default().load_inventory()?;
    if inventory.is_empty() {
        println!(
            "Advisory match status: unavailable (no protected software inventory snapshot found)."
        );
        return Ok(());
    }

    let Some(cache) = load_advisory_cache()? else {
        println!("Advisory match status: unavailable (no protected advisory cache found).");
        return Ok(());
    };

    let product_matches = collect_product_matches(&inventory, &cache);
    let matched_records = product_matches
        .iter()
        .map(|product| product.matches.len())
        .sum::<usize>();
    let applicable_records = product_matches
        .iter()
        .flat_map(|product| product.matches.iter())
        .filter(|record| record.applies)
        .count();

    println!(
        "Advisory match status: {} installed products, {} advisory records, {} matched products, {} matched advisories ({} applicable).",
        inventory.len(),
        cache.records.len(),
        product_matches.len(),
        matched_records,
        applicable_records
    );

    for product in &product_matches {
        let applicable = product
            .matches
            .iter()
            .filter(|record| record.applies)
            .count();
        let version = product
            .installed
            .version_hint
            .as_deref()
            .unwrap_or("unknown");
        println!(
            "- {} [{}] version={} matches={} applicable={}",
            product.installed.display_name,
            inventory_source_label(product.installed.source),
            version,
            product.matches.len(),
            applicable
        );
        println!(
            "  product_key={} aliases={}",
            product.installed.product_key,
            product.installed.product_aliases.join(", ")
        );
        for record in &product.matches {
            println!(
                "  - {} [{}] confidence={} version={} applies={} alias={}",
                record.primary_id,
                record.source_kind,
                confidence_label(record.confidence),
                version_status_label(record.version_status),
                yes_no(record.applies),
                record.matched_alias
            );
            if record.known_exploited {
                println!("    known_exploited=yes");
            }
            println!("    cpe={}", record.cpe_uri);
            println!(
                "    source_product={}:{}:{}",
                part_label(&record.part),
                record.vendor,
                record.product
            );
            println!("    match_basis={}", match_basis_label(record.match_basis));
            if let Some(match_criteria_id) = &record.match_criteria_id {
                println!("    match_criteria_id={match_criteria_id}");
            }
            println!("    summary={}", condense_summary(&record.summary));
        }
    }

    Ok(())
}

fn collect_product_matches(
    inventory: &[InstalledSoftware],
    cache: &AdvisoryCache,
) -> Vec<ProductAdvisoryMatch> {
    let mut product_matches = inventory
        .iter()
        .filter_map(|installed| {
            let matches = cache
                .records
                .iter()
                .filter_map(|record| best_record_match(installed, record))
                .collect::<Vec<_>>();
            if matches.is_empty() {
                None
            } else {
                Some(ProductAdvisoryMatch {
                    installed: installed.clone(),
                    matches: sort_record_matches(matches),
                })
            }
        })
        .collect::<Vec<_>>();

    product_matches.sort_by(|left, right| {
        right
            .matches
            .iter()
            .filter(|record| record.applies)
            .count()
            .cmp(&left.matches.iter().filter(|record| record.applies).count())
            .then_with(|| right.matches.len().cmp(&left.matches.len()))
            .then_with(|| {
                left.installed
                    .display_name
                    .cmp(&right.installed.display_name)
            })
            .then_with(|| left.installed.product_key.cmp(&right.installed.product_key))
    });
    product_matches
}

fn sort_record_matches(mut matches: Vec<RecordAdvisoryMatch>) -> Vec<RecordAdvisoryMatch> {
    matches.sort_by(|left, right| {
        right
            .known_exploited
            .cmp(&left.known_exploited)
            .then_with(|| right.applies.cmp(&left.applies))
            .then_with(|| {
                match_rank(right.confidence, right.version_status)
                    .cmp(&match_rank(left.confidence, left.version_status))
            })
            .then_with(|| left.primary_id.cmp(&right.primary_id))
    });
    matches
}

fn best_record_match(
    installed: &InstalledSoftware,
    record: &VulnerabilityRecord,
) -> Option<RecordAdvisoryMatch> {
    let installed_ref = InstalledProductRef {
        product_key: &installed.product_key,
        product_aliases: &installed.product_aliases,
        vendor_key: installed.vendor_key.as_deref(),
        version_hint: installed.version_hint.as_deref(),
        version_source: version_source_for_inventory(installed.source),
    };

    let best = record
        .affected_products
        .iter()
        .filter_map(|affected| {
            evaluate_cpe23_product_match(&installed_ref, &affected_product_ref(affected))
        })
        .max_by_key(|matched| match_rank(matched.confidence, matched.version_status))?;

    Some(RecordAdvisoryMatch {
        primary_id: record.primary_id.clone(),
        summary: record.summary.clone(),
        source_kind: record.provenance.source_kind.clone(),
        known_exploited: record.known_exploited,
        cpe_uri: best.cpe_uri,
        match_criteria_id: best.match_criteria_id,
        part: best.part,
        vendor: best.vendor,
        product: best.product,
        matched_alias: best.matched_alias,
        match_basis: best.match_basis,
        confidence: best.confidence,
        version_status: best.version_status,
        applies: best.applies,
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

fn match_rank(confidence: MatchConfidence, version_status: VersionMatchStatus) -> (u8, u8, u8) {
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
    let path = advisory_cache_path();
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

fn advisory_cache_path() -> PathBuf {
    crate::config::data_dir().join(ADVISORY_CACHE_FILE)
}

fn inventory_source_label(source: InventorySource) -> &'static str {
    match source {
        InventorySource::RunningProcess => "running-process",
        InventorySource::LinuxDpkgStatus => "linux-dpkg-status",
        InventorySource::LinuxRpmDatabase => "linux-rpm-database",
        InventorySource::LinuxApkInstalled => "linux-apk-installed",
        InventorySource::WindowsUninstallRegistry => "windows-uninstall-registry",
        InventorySource::RunningService => "running-service",
    }
}

fn confidence_label(confidence: MatchConfidence) -> &'static str {
    match confidence {
        MatchConfidence::High => "high",
        MatchConfidence::Medium => "medium",
    }
}

fn match_basis_label(match_basis: MatchBasis) -> &'static str {
    match match_basis {
        MatchBasis::VendorQualifiedAlias => "vendor_qualified_alias",
        MatchBasis::ProductAliasWithVendorConfirmation => {
            "product_alias_with_vendor_confirmation"
        }
        MatchBasis::ProductAliasOnly => "product_alias_only",
    }
}

fn version_status_label(status: VersionMatchStatus) -> &'static str {
    match status {
        VersionMatchStatus::Exact => "exact",
        VersionMatchStatus::InRange => "in_range",
        VersionMatchStatus::NoConstraint => "no_constraint",
        VersionMatchStatus::MissingInstalledVersion => "missing_installed_version",
        VersionMatchStatus::OutOfRange => "out_of_range",
        VersionMatchStatus::Unknown => "unknown",
    }
}

fn part_label(part: &str) -> &'static str {
    match part {
        "a" => "application",
        "o" => "operating-system",
        "h" => "hardware",
        _ => "unknown",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn condense_summary(summary: &str) -> String {
    summary.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::{AffectedProduct, VulnerabilityProvenance};

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

    fn record(
        primary_id: &str,
        summary: &str,
        known_exploited: bool,
        affected_products: Vec<AffectedProduct>,
    ) -> VulnerabilityRecord {
        VulnerabilityRecord {
            primary_id: primary_id.into(),
            summary: summary.into(),
            known_exploited,
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

    fn affected(criteria: &str, cpe_name: Option<&str>) -> AffectedProduct {
        AffectedProduct {
            criteria: criteria.into(),
            cpe_name: cpe_name.map(str::to_string),
            vulnerable: true,
            ..AffectedProduct::default()
        }
    }

    #[test]
    fn collect_product_matches_prefers_higher_confidence_match_for_same_record() {
        let inventory = vec![installed(
            "google-chrome",
            "Google Chrome",
            Some("google"),
            Some("124.0.6367.91"),
            &["chrome", "google-chrome"],
            InventorySource::RunningProcess,
        )];
        let cache = AdvisoryCache {
            schema_version: 1,
            generated_unix: 0,
            sources: vec![],
            records: vec![record(
                "CVE-2026-12345",
                "Example Chrome issue",
                false,
                vec![
                    affected("cpe:2.3:a:haxx:chrome:*:*:*:*:*:*:*:*", None),
                    AffectedProduct {
                        criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*".into(),
                        match_criteria_id: Some("nvd-match-1".into()),
                        cpe_name: Some(
                            "cpe:2.3:a:google:chrome:124.0.6367.91:*:*:*:*:*:*:*".into(),
                        ),
                        vulnerable: true,
                        ..AffectedProduct::default()
                    },
                ],
            )],
        };

        let matches = collect_product_matches(&inventory, &cache);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matches.len(), 1);
        assert_eq!(matches[0].matches[0].matched_alias, "google-chrome");
        assert_eq!(
            matches[0].matches[0].match_basis,
            MatchBasis::VendorQualifiedAlias
        );
        assert_eq!(
            matches[0].matches[0].match_criteria_id.as_deref(),
            Some("nvd-match-1")
        );
        assert_eq!(matches[0].matches[0].part, "a");
        assert_eq!(matches[0].matches[0].vendor, "google");
        assert_eq!(matches[0].matches[0].product, "chrome");
        assert_eq!(matches[0].matches[0].confidence, MatchConfidence::High);
        assert_eq!(
            matches[0].matches[0].version_status,
            VersionMatchStatus::Exact
        );
        assert!(matches[0].matches[0].applies);
    }

    #[test]
    fn collect_product_matches_keeps_non_applicable_matches_explainable() {
        let inventory = vec![installed(
            "curl",
            "curl",
            Some("fedora"),
            Some("8.8.0-1.fc40"),
            &["curl", "fedora-curl"],
            InventorySource::LinuxRpmDatabase,
        )];
        let cache = AdvisoryCache {
            schema_version: 1,
            generated_unix: 0,
            sources: vec![],
            records: vec![record(
                "CVE-2026-9999",
                "Out of range curl issue",
                true,
                vec![AffectedProduct {
                    criteria: "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*".into(),
                    vulnerable: true,
                    version_start_including: Some("9.0.0-1.fc40".into()),
                    version_end_excluding: Some("9.1.0-1.fc40".into()),
                    ..AffectedProduct::default()
                }],
            )],
        };

        let matches = collect_product_matches(&inventory, &cache);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matches[0].primary_id, "CVE-2026-9999");
        assert_eq!(
            matches[0].matches[0].match_basis,
            MatchBasis::ProductAliasOnly
        );
        assert_eq!(
            matches[0].matches[0].version_status,
            VersionMatchStatus::OutOfRange
        );
        assert!(!matches[0].matches[0].applies);
    }

    #[test]
    fn match_basis_label_maps_known_match_bases() {
        assert_eq!(
            match_basis_label(MatchBasis::VendorQualifiedAlias),
            "vendor_qualified_alias"
        );
        assert_eq!(
            match_basis_label(MatchBasis::ProductAliasWithVendorConfirmation),
            "product_alias_with_vendor_confirmation"
        );
        assert_eq!(
            match_basis_label(MatchBasis::ProductAliasOnly),
            "product_alias_only"
        );
    }

    #[test]
    fn part_label_maps_known_cpe_parts() {
        assert_eq!(part_label("a"), "application");
        assert_eq!(part_label("o"), "operating-system");
        assert_eq!(part_label("h"), "hardware");
        assert_eq!(part_label("?"), "unknown");
    }

    #[test]
    fn version_source_for_inventory_maps_package_formats() {
        assert_eq!(
            version_source_for_inventory(InventorySource::LinuxDpkgStatus),
            VersionSource::DebianPackage
        );
        assert_eq!(
            version_source_for_inventory(InventorySource::LinuxRpmDatabase),
            VersionSource::RpmPackage
        );
        assert_eq!(
            version_source_for_inventory(InventorySource::LinuxApkInstalled),
            VersionSource::AlpinePackage
        );
        assert_eq!(
            version_source_for_inventory(InventorySource::RunningProcess),
            VersionSource::Default
        );
    }
}
