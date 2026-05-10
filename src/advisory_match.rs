use crate::version_compare::{
    extract_cpe23_version, version_in_range, VersionRange, VersionSource,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledProductRef<'a> {
    pub product_key: &'a str,
    pub product_aliases: &'a [String],
    pub vendor_key: Option<&'a str>,
    pub version_hint: Option<&'a str>,
    pub version_source: VersionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AffectedProductRef<'a> {
    pub criteria: &'a str,
    pub cpe_name: Option<&'a str>,
    pub vulnerable: bool,
    pub version_start_including: Option<&'a str>,
    pub version_start_excluding: Option<&'a str>,
    pub version_end_including: Option<&'a str>,
    pub version_end_excluding: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeProductMatch {
    pub cpe_uri: String,
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub matched_alias: String,
    pub confidence: MatchConfidence,
    pub version_status: VersionMatchStatus,
    pub applies: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchConfidence {
    High,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionMatchStatus {
    Exact,
    InRange,
    NoConstraint,
    MissingInstalledVersion,
    OutOfRange,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCpe23 {
    uri: String,
    part: String,
    vendor: String,
    product: String,
}

pub fn evaluate_cpe23_product_match(
    installed: &InstalledProductRef<'_>,
    affected: &AffectedProductRef<'_>,
) -> Option<CpeProductMatch> {
    if !affected.vulnerable {
        return None;
    }

    let cpe = parse_cpe23_uri(affected.criteria)
        .or_else(|| affected.cpe_name.and_then(parse_cpe23_uri))?;
    if matches!(cpe.part.as_str(), "h" | "") {
        return None;
    }

    let product = normalize_identity(&cpe.product);
    let vendor = normalize_identity(&cpe.vendor);
    if product.is_empty() || vendor.is_empty() {
        return None;
    }

    let aliases = installed_identity_aliases(installed);
    let vendor_qualified = format!("{vendor}-{product}");
    let vendor_matches = installed
        .vendor_key
        .map(normalize_identity)
        .as_deref()
        .is_some_and(|installed_vendor| installed_vendor == vendor);

    let (matched_alias, confidence) = if aliases.contains(&vendor_qualified) {
        (vendor_qualified, MatchConfidence::High)
    } else if vendor_matches && aliases.contains(&product) {
        (product.clone(), MatchConfidence::High)
    } else if aliases.contains(&product) {
        (product.clone(), MatchConfidence::Medium)
    } else {
        return None;
    };

    let version_status = evaluate_version_status(installed, affected);
    let applies = matches!(
        version_status,
        VersionMatchStatus::Exact
            | VersionMatchStatus::InRange
            | VersionMatchStatus::NoConstraint
    );

    Some(CpeProductMatch {
        cpe_uri: cpe.uri,
        part: cpe.part,
        vendor: vendor.clone(),
        product,
        matched_alias,
        confidence,
        version_status,
        applies,
    })
}

fn evaluate_version_status(
    installed: &InstalledProductRef<'_>,
    affected: &AffectedProductRef<'_>,
) -> VersionMatchStatus {
    let exact_version = if has_range_constraints(affected) {
        None
    } else {
        affected
            .cpe_name
            .and_then(extract_cpe23_version)
            .or_else(|| extract_cpe23_version(affected.criteria))
    };
    let range = VersionRange {
        exact: exact_version,
        start_including: affected.version_start_including,
        start_excluding: affected.version_start_excluding,
        end_including: affected.version_end_including,
        end_excluding: affected.version_end_excluding,
    };

    if range.is_empty() {
        return VersionMatchStatus::NoConstraint;
    }

    let Some(installed_version) = installed.version_hint.map(str::trim).filter(|v| !v.is_empty()) else {
        return VersionMatchStatus::MissingInstalledVersion;
    };

    match version_in_range(installed_version, range, installed.version_source) {
        Some(true) if exact_version.is_some() => VersionMatchStatus::Exact,
        Some(true) => VersionMatchStatus::InRange,
        Some(false) => VersionMatchStatus::OutOfRange,
        None => VersionMatchStatus::Unknown,
    }
}

fn has_range_constraints(affected: &AffectedProductRef<'_>) -> bool {
    affected.version_start_including.is_some()
        || affected.version_start_excluding.is_some()
        || affected.version_end_including.is_some()
        || affected.version_end_excluding.is_some()
}

fn installed_identity_aliases(installed: &InstalledProductRef<'_>) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    let normalized_key = normalize_identity(installed.product_key);
    if !normalized_key.is_empty() {
        aliases.insert(normalized_key);
    }
    for alias in installed.product_aliases {
        let normalized = normalize_identity(alias);
        if !normalized.is_empty() {
            aliases.insert(normalized);
        }
    }
    aliases
}

fn parse_cpe23_uri(input: &str) -> Option<ParsedCpe23> {
    let mut parts = input.split(':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("cpe"), Some("2.3"), Some(part), Some(vendor), Some(product)) => {
            let part = decode_cpe23_component(part);
            let vendor = decode_cpe23_component(vendor);
            let product = decode_cpe23_component(product);
            if part.is_empty() || vendor.is_empty() || product.is_empty() {
                None
            } else {
                Some(ParsedCpe23 {
                    uri: input.trim().to_string(),
                    part,
                    vendor,
                    product,
                })
            }
        }
        _ => None,
    }
}

fn decode_cpe23_component(input: &str) -> String {
    if matches!(input.trim(), "" | "*" | "-") {
        return String::new();
    }

    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(escaped) = chars.next() {
                decoded.push(escaped);
            }
        } else {
            decoded.push(ch);
        }
    }
    decoded
}

fn normalize_identity(input: &str) -> String {
    let lower = input.trim().to_lowercase();
    let no_ext = lower.strip_suffix(".exe").unwrap_or(&lower);
    no_ext
        .chars()
        .map(|ch| if ch.is_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_vendor_qualified_alias_with_exact_cpe_version() {
        let aliases = vec!["chrome".to_string(), "google-chrome".to_string()];
        let installed = InstalledProductRef {
            product_key: "google-chrome",
            product_aliases: &aliases,
            vendor_key: Some("google"),
            version_hint: Some("124.0.6367.91"),
            version_source: VersionSource::Default,
        };
        let affected = AffectedProductRef {
            criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
            cpe_name: Some("cpe:2.3:a:google:chrome:124.0.6367.91:*:*:*:*:*:*:*"),
            vulnerable: true,
            ..AffectedProductRef::default()
        };

        let matched = evaluate_cpe23_product_match(&installed, &affected).unwrap();
        assert_eq!(matched.vendor, "google");
        assert_eq!(matched.product, "chrome");
        assert_eq!(matched.matched_alias, "google-chrome");
        assert_eq!(matched.confidence, MatchConfidence::High);
        assert_eq!(matched.version_status, VersionMatchStatus::Exact);
        assert!(matched.applies);
    }

    #[test]
    fn matches_product_alias_without_vendor_confirmation_at_medium_confidence() {
        let aliases = vec!["curl".to_string()];
        let installed = InstalledProductRef {
            product_key: "curl",
            product_aliases: &aliases,
            vendor_key: Some("fedora"),
            version_hint: Some("8.8.0-1.fc40"),
            version_source: VersionSource::RpmPackage,
        };
        let affected = AffectedProductRef {
            criteria: "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
            cpe_name: None,
            vulnerable: true,
            version_start_including: Some("8.8.0-1.fc39"),
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some("8.8.0-1.fc41"),
        };

        let matched = evaluate_cpe23_product_match(&installed, &affected).unwrap();
        assert_eq!(matched.matched_alias, "curl");
        assert_eq!(matched.confidence, MatchConfidence::Medium);
        assert_eq!(matched.version_status, VersionMatchStatus::InRange);
        assert!(matched.applies);
    }

    #[test]
    fn out_of_range_version_stays_explainable_but_not_applicable() {
        let aliases = vec!["google-chrome".to_string()];
        let installed = InstalledProductRef {
            product_key: "google-chrome",
            product_aliases: &aliases,
            vendor_key: Some("google"),
            version_hint: Some("123.0.0"),
            version_source: VersionSource::Default,
        };
        let affected = AffectedProductRef {
            criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
            cpe_name: None,
            vulnerable: true,
            version_start_including: Some("124.0.0"),
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some("125.0.0"),
        };

        let matched = evaluate_cpe23_product_match(&installed, &affected).unwrap();
        assert_eq!(matched.confidence, MatchConfidence::High);
        assert_eq!(matched.version_status, VersionMatchStatus::OutOfRange);
        assert!(!matched.applies);
    }

    #[test]
    fn skips_non_vulnerable_and_hardware_cpes() {
        let aliases = vec!["example-agent".to_string()];
        let installed = InstalledProductRef {
            product_key: "example-agent",
            product_aliases: &aliases,
            vendor_key: Some("example"),
            version_hint: Some("2.4.1"),
            version_source: VersionSource::Default,
        };

        let non_vulnerable = AffectedProductRef {
            criteria: "cpe:2.3:a:example:agent:*:*:*:*:*:*:*:*",
            cpe_name: None,
            vulnerable: false,
            ..AffectedProductRef::default()
        };
        assert!(evaluate_cpe23_product_match(&installed, &non_vulnerable).is_none());

        let hardware = AffectedProductRef {
            criteria: "cpe:2.3:h:example:appliance:*:*:*:*:*:*:*:*",
            cpe_name: None,
            vulnerable: true,
            ..AffectedProductRef::default()
        };
        assert!(evaluate_cpe23_product_match(&installed, &hardware).is_none());
    }

    #[test]
    fn missing_installed_version_is_conservative() {
        let aliases = vec!["example-agent".to_string()];
        let installed = InstalledProductRef {
            product_key: "example-agent",
            product_aliases: &aliases,
            vendor_key: Some("example"),
            version_hint: None,
            version_source: VersionSource::Default,
        };
        let affected = AffectedProductRef {
            criteria: "cpe:2.3:a:example:agent:*:*:*:*:*:*:*:*",
            cpe_name: None,
            vulnerable: true,
            version_start_including: Some("2.4.0"),
            version_start_excluding: None,
            version_end_including: Some("2.4.9"),
            version_end_excluding: None,
        };

        let matched = evaluate_cpe23_product_match(&installed, &affected).unwrap();
        assert_eq!(matched.version_status, VersionMatchStatus::MissingInstalledVersion);
        assert!(!matched.applies);
    }

    #[test]
    fn decodes_escaped_cpe_components_before_matching() {
        let aliases = vec!["microsoft-edge-update".to_string()];
        let installed = InstalledProductRef {
            product_key: "microsoft-edge-update",
            product_aliases: &aliases,
            vendor_key: Some("microsoft"),
            version_hint: Some("1.3.191.37"),
            version_source: VersionSource::Default,
        };
        let affected = AffectedProductRef {
            criteria: r"cpe:2.3:a:microsoft:edge\_update:*:*:*:*:*:*:*:*",
            cpe_name: Some(r"cpe:2.3:a:microsoft:edge\_update:1.3.191.37:*:*:*:*:*:*:*"),
            vulnerable: true,
            ..AffectedProductRef::default()
        };

        let matched = evaluate_cpe23_product_match(&installed, &affected).unwrap();
        assert_eq!(matched.matched_alias, "microsoft-edge-update");
        assert_eq!(matched.version_status, VersionMatchStatus::Exact);
        assert!(matched.applies);
    }
}
