use crate::advisory::{AdvisoryCache, SourceHealth};
use std::path::PathBuf;

const CACHE_FILE: &str = "vigil-advisory-cache.json";
const CACHE_SCHEMA_VERSION: u32 = 1;

pub fn run_cli() -> Result<(), String> {
    let path = cache_path();
    if !path.exists() {
        println!("Advisory cache: empty (no protected cache found).");
        return Ok(());
    }

    let loaded: Option<AdvisoryCache> =
        crate::security::policy::load_struct_with_integrity(&path).map_err(|e| {
            format!(
                "failed to load protected advisory cache {}: {e}",
                path.display()
            )
        })?;
    let Some(cache) = loaded else {
        println!(
            "Advisory cache: unavailable (protected cache could not be verified or restored)."
        );
        return Ok(());
    };
    if cache.schema_version != CACHE_SCHEMA_VERSION {
        return Err(format!(
            "protected advisory cache {} used unsupported schema version {}",
            path.display(),
            cache.schema_version
        ));
    }

    let now = unix_now();
    let stale_sources = cache
        .sources
        .iter()
        .filter(|source| {
            is_source_stale(source.expires_unix, now)
                || matches!(source.status, SourceHealth::Stale)
        })
        .count();

    println!(
        "Advisory cache: {} records, {} sources ({} stale)",
        cache.records.len(),
        cache.sources.len(),
        stale_sources
    );

    for source in &cache.sources {
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
        if !source.source_url.trim().is_empty() {
            println!("  source_url={}", source.source_url);
        }
    }

    Ok(())
}

fn cache_path() -> PathBuf {
    crate::config::data_dir().join(CACHE_FILE)
}

fn source_state(source: &crate::advisory::AdvisorySourceCache, now: u64) -> &'static str {
    if is_source_stale(source.expires_unix, now) {
        return "stale";
    }
    match source.status {
        SourceHealth::Fresh => "fresh",
        SourceHealth::Stale => "stale",
        SourceHealth::Error => "error",
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
    use crate::advisory::AdvisorySourceCache;

    #[test]
    fn source_state_reports_expired_sources_as_stale() {
        let source = AdvisorySourceCache {
            source_key: "nvd-cve".into(),
            source_kind: "nvd".into(),
            source_url: String::new(),
            imported_from: None,
            fetched_unix: 10,
            expires_unix: 20,
            snapshot_sha256: String::new(),
            total_results: 1,
            status: SourceHealth::Fresh,
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
            fetched_unix: 10,
            expires_unix: 100,
            snapshot_sha256: String::new(),
            total_results: 1,
            status: SourceHealth::Error,
        };

        assert_eq!(source_state(&source, 30), "error");
    }
}
