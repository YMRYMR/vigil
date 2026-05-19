//! Extract indicators of compromise (IOCs) from advisory records.
//!
//! Parses advisory reference URLs, summaries, and metadata for embedded IPs,
//! domains, and file hashes. The extracted IOCs can be fed into the blocklist
//! engine for automated, source-derived network protection.

use crate::advisory::VulnerabilityRecord;
use std::net::IpAddr;

pub struct IoCBundle {
    pub ips: Vec<IpAddr>,
    pub domains: Vec<String>,
    pub hashes: Vec<String>,
}

impl IoCBundle {
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.domains.is_empty() && self.hashes.is_empty()
    }

    pub fn total(&self) -> usize {
        self.ips.len() + self.domains.len() + self.hashes.len()
    }
}

/// Extract IOCs from advisory records, using reference URLs and CVE metadata.
/// Returns a bundle of discovered indicators across all records.
pub fn extract_iocs(records: &[VulnerabilityRecord]) -> IoCBundle {
    let mut ips = Vec::new();
    let mut domains = Vec::new();
    let mut hashes = Vec::new();

    for record in records {
        // Extract from reference URLs.
        for reference in &record.references {
            if let Some(host) = extract_domain_from_url(&reference.url) {
                domains.push(host);
            }
            if let Some(ip) = extract_ip_from_url(&reference.url) {
                ips.push(ip);
            }
        }

        // Extract hashes from summary text.
        for word in record.summary.split_whitespace() {
            let clean = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            if is_hash_candidate(clean) {
                hashes.push(clean.to_lowercase());
            }
        }
    }

    // Deduplicate.
    ips.sort();
    ips.dedup();
    domains.sort();
    domains.dedup();
    hashes.sort();
    hashes.dedup();

    IoCBundle {
        ips,
        domains,
        hashes,
    }
}

fn extract_domain_from_url(url: &str) -> Option<String> {
    let url_str = url.trim();
    // Extract hostname from URL using simple parsing.
    let after_scheme = if let Some(rest) = url_str.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url_str.strip_prefix("http://") {
        rest
    } else {
        return None;
    };

    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host.split(':').next().unwrap_or(host);

    if host.contains('.') && !host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        Some(host.to_lowercase())
    } else {
        None
    }
}

fn extract_ip_from_url(url: &str) -> Option<IpAddr> {
    let url_str = url.trim();
    let after_scheme = if let Some(rest) = url_str.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url_str.strip_prefix("http://") {
        rest
    } else {
        return None;
    };

    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host.split(':').next().unwrap_or(host);

    host.parse::<IpAddr>().ok()
}

fn is_hash_candidate(s: &str) -> bool {
    let bytes = s.as_bytes();
    (bytes.len() == 64 || bytes.len() == 40 || bytes.len() == 32)
        && bytes.iter().all(|&b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::{VulnerabilityRecord, VulnerabilityReference};

    fn make_record(
        primary_id: &str,
        summary: &str,
        refs: Vec<(&str, &str)>,
    ) -> VulnerabilityRecord {
        VulnerabilityRecord {
            primary_id: primary_id.into(),
            summary: summary.into(),
            references: refs
                .into_iter()
                .map(|(url, tag)| VulnerabilityReference {
                    url: url.into(),
                    source: Some(tag.into()),
                    tags: vec![],
                })
                .collect(),
            ..VulnerabilityRecord::default()
        }
    }

    #[test]
    fn extracts_domain_from_url() {
        let url = "https://malware.example.com/payload";
        assert_eq!(
            extract_domain_from_url(url),
            Some("malware.example.com".into())
        );
    }

    #[test]
    fn extracts_ip_from_url() {
        let url = "http://192.168.1.1/exploit";
        assert!(extract_ip_from_url(url).is_some());
    }

    #[test]
    fn extracts_hashes_from_summary() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let records = vec![make_record(
            "CVE-2026-0001",
            &format!("hash {sha256} found"),
            vec![],
        )];
        let bundle = extract_iocs(&records);
        assert!(bundle.hashes.contains(&sha256.to_string()));
    }

    #[test]
    fn extracts_from_multiple_records() {
        let records = vec![
            make_record(
                "CVE-2026-0001",
                &"sample hash a".repeat(64),
                vec![("https://badhost.example/c2", "source")],
            ),
            make_record(
                "CVE-2026-0002",
                "related activity",
                vec![("http://10.0.0.1/drop", "source")],
            ),
        ];
        let bundle = extract_iocs(&records);
        assert!(bundle.domains.iter().any(|d| d.contains("badhost")));
        assert!(bundle.ips.iter().any(|ip| ip.to_string() == "10.0.0.1"));
    }
}
