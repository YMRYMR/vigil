use crate::advisory::{AdvisorySourceCache, SourceHealth};
const NVD_API_ATTRIBUTION_NOTICE: &str =
    "This product uses the NVD API but is not endorsed or certified by the NVD.";

pub fn run_cli() -> Result<(), String> {
    let db = crate::storage::db::StorageDb::global()?;
    let sources = db.load_advisory_sources()?;
    let record_count = db.count_advisory_records()?;
    if sources.is_empty() && record_count == 0 {
        println!("Advisory database: empty.");
        return Ok(());
    }

    let now = unix_now();
    let attention_sources = sources
        .iter()
        .filter(|source| source_needs_attention(source, now))
        .count();

    println!(
        "Advisory database: {} records, {} sources ({} stale/error)",
        record_count,
        sources.len(),
        attention_sources
    );

    for source in &sources {
        println!(
            "- {} ({}) [{}] results={} fetched={} expires={} sha256={}",
            source.source_key,
            source.source_kind,
            source_state(source, now),
            source.total_results,
            source.fetched_unix,
            source.expires_unix,
            source.snapshot_sha256
        );
        if let Some(imported_from) = &source.imported_from {
            println!("  imported_from={imported_from}");
        }
        if source.imported_from_batch.len() > 1 {
            println!(
                "  imported_from_batch={}",
                source.imported_from_batch.join(", ")
            );
        }
        if !source.source_url.trim().is_empty() {
            println!("  source_url={}", source.source_url);
        }
        if let Some(attribution) = source_attribution(source) {
            println!("  attribution={attribution}");
        }
        if source.last_attempt_unix > 0 {
            println!("  last_attempt={}", source.last_attempt_unix);
        }
        if let Some(last_error) = source.last_error.as_deref() {
            if !last_error.trim().is_empty() {
                println!("  last_error={last_error}");
            }
        }
    }

    Ok(())
}

fn source_state(source: &AdvisorySourceCache, now: u64) -> &'static str {
    if is_source_stale(source.expires_unix, now) {
        return "stale";
    }
    match source.status {
        SourceHealth::Fresh => "fresh",
        SourceHealth::Stale => "stale",
        SourceHealth::Error => "error",
    }
}

fn source_needs_attention(source: &AdvisorySourceCache, now: u64) -> bool {
    is_source_stale(source.expires_unix, now)
        || matches!(source.status, SourceHealth::Stale | SourceHealth::Error)
}

fn source_attribution(source: &AdvisorySourceCache) -> Option<&'static str> {
    if source.source_kind == "nvd" && source.source_key == "nvd-cve" {
        Some(NVD_API_ATTRIBUTION_NOTICE)
    } else {
        None
    }
}

fn is_source_stale(expires_unix: u64, now: u64) -> bool {
    expires_unix > 0 && expires_unix < now
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

    #[test]
    fn source_state_reports_expired_sources_as_stale() {
        let source = AdvisorySourceCache {
            source_key: "nvd-cve".into(),
            source_kind: "nvd".into(),
            source_url: String::new(),
            imported_from: None,
            imported_from_batch: vec![],
            fetched_unix: 10,
            expires_unix: 20,
            snapshot_sha256: String::new(),
            total_results: 1,
            status: SourceHealth::Fresh,
            last_attempt_unix: 0,
            last_error: None,
            retry_after_unix: 0,
        };

        assert_eq!(source_state(&source, 30), "stale");
    }

    #[test]
    fn source_state_uses_recorded_health_before_expiry() {
        let source = AdvisorySourceCache {
            source_key: "nvd-cve".into(),
            source_kind: "nvd".into(),
            source_url: String::new(),
            imported_from: None,
            imported_from_batch: vec![],
            fetched_unix: 10,
            expires_unix: 100,
            snapshot_sha256: String::new(),
            total_results: 1,
            status: SourceHealth::Error,
            last_attempt_unix: 0,
            last_error: None,
            retry_after_unix: 0,
        };

        assert_eq!(source_state(&source, 30), "error");
    }

    #[test]
    fn source_needs_attention_for_error_sources_before_expiry() {
        let source = AdvisorySourceCache {
            source_key: "nvd-cve".into(),
            source_kind: "nvd".into(),
            source_url: String::new(),
            imported_from: None,
            imported_from_batch: vec![],
            fetched_unix: 10,
            expires_unix: 100,
            snapshot_sha256: String::new(),
            total_results: 1,
            status: SourceHealth::Error,
            last_attempt_unix: 0,
            last_error: Some("rate limit".into()),
            retry_after_unix: 0,
        };

        assert!(source_needs_attention(&source, 30));
    }

    #[test]
    fn source_attribution_reports_nvd_notice() {
        let source = AdvisorySourceCache {
            source_key: "nvd-cve".into(),
            source_kind: "nvd".into(),
            source_url: String::new(),
            imported_from: None,
            imported_from_batch: vec![],
            fetched_unix: 10,
            expires_unix: 100,
            snapshot_sha256: String::new(),
            total_results: 1,
            status: SourceHealth::Fresh,
            last_attempt_unix: 0,
            last_error: None,
            retry_after_unix: 0,
        };

        assert_eq!(
            source_attribution(&source),
            Some(NVD_API_ATTRIBUTION_NOTICE)
        );
    }

    #[test]
    fn source_attribution_is_empty_for_non_nvd_sources() {
        let source = AdvisorySourceCache {
            source_key: "euvd".into(),
            source_kind: "euvd".into(),
            source_url: String::new(),
            imported_from: None,
            imported_from_batch: vec![],
            fetched_unix: 10,
            expires_unix: 100,
            snapshot_sha256: String::new(),
            total_results: 1,
            status: SourceHealth::Fresh,
            last_attempt_unix: 0,
            last_error: None,
            retry_after_unix: 0,
        };

        assert_eq!(source_attribution(&source), None);
    }
}
