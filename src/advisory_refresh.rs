//! Coordinated advisory refresh.
//!
//! Keeps network fetches and advisory DB writes serialized so startup cannot
//! launch multiple advisory writers against the same SQLite database.

use std::time::Instant;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdvisoryRefreshSummary {
    pub updated_sources: usize,
    pub skipped_groups: usize,
    pub requested_feeds: usize,
    pub imported_records: usize,
    pub failed_sources: usize,
    pub total_records: usize,
    pub total_sources: usize,
}

pub fn run_sync_all_cli(force: bool) -> Result<(), String> {
    let summary = sync_all_sources(force)?;
    println!(
        "Refreshed advisory sources: {} updated group(s), {} skipped group(s), {} feed/page request(s), {} imported record(s), {} source failure(s). Database now holds {} records across {} sources.",
        summary.updated_sources,
        summary.skipped_groups,
        summary.requested_feeds,
        summary.imported_records,
        summary.failed_sources,
        summary.total_records,
        summary.total_sources,
    );
    Ok(())
}

pub fn refresh_all_in_background_if_due() {
    match sync_all_sources(false) {
        Ok(summary) => {
            tracing::info!(
                updated_sources = summary.updated_sources,
                skipped_groups = summary.skipped_groups,
                requested_feeds = summary.requested_feeds,
                imported_records = summary.imported_records,
                failed_sources = summary.failed_sources,
                total_records = summary.total_records,
                total_sources = summary.total_sources,
                "coordinated advisory refresh completed"
            );
        }
        Err(err) => {
            tracing::warn!(%err, "coordinated advisory refresh failed");
        }
    }
}

pub fn sync_all_sources(force: bool) -> Result<AdvisoryRefreshSummary, String> {
    let started = Instant::now();
    let mut summary = AdvisoryRefreshSummary::default();
    let mut errors = Vec::new();

    match crate::advisory::sync_nvd(force) {
        Ok(crate::advisory::SyncOutcome::Updated(nvd)) => {
            summary.updated_sources += 1;
            summary.requested_feeds += nvd.requested_pages;
            summary.imported_records += nvd.imported_records;
            summary.total_records = nvd.total_records;
            summary.total_sources = nvd.total_sources;
        }
        Ok(crate::advisory::SyncOutcome::SkippedRateLimit { remaining_secs }) => {
            summary.skipped_groups += 1;
            tracing::debug!(
                remaining_secs,
                "skipped NVD advisory refresh in coordinated run"
            );
        }
        Err(err) => {
            summary.failed_sources += 1;
            errors.push(format!("NVD: {err}"));
        }
    }

    match crate::advisory_public_sources::sync_public_sources(force) {
        Ok(crate::advisory_public_sources::PublicSourceSyncOutcome::Updated(public)) => {
            summary.updated_sources += public.requested_sources;
            summary.requested_feeds += public.requested_feeds;
            summary.imported_records += public.imported_records;
            summary.failed_sources += public.failed_sources;
            summary.total_records = public.total_records;
            summary.total_sources = public.total_sources;
        }
        Ok(crate::advisory_public_sources::PublicSourceSyncOutcome::SkippedFresh {
            remaining_secs,
        }) => {
            summary.skipped_groups += 1;
            tracing::debug!(
                remaining_secs,
                "skipped EUVD/JVN advisory refresh in coordinated run"
            );
        }
        Err(err) => {
            summary.failed_sources += 2;
            errors.push(format!("EUVD/JVN: {err}"));
        }
    }

    match crate::advisory_ncsc_bsi::sync_national_sources(force) {
        Ok(crate::advisory_ncsc_bsi::NationalAdvisorySyncOutcome::Updated(national)) => {
            summary.updated_sources += national.requested_sources;
            summary.requested_feeds += national.requested_feeds;
            summary.imported_records += national.imported_records;
            summary.failed_sources += national.failed_sources;
            summary.total_records = national.total_records;
            summary.total_sources = national.total_sources;
        }
        Ok(crate::advisory_ncsc_bsi::NationalAdvisorySyncOutcome::SkippedFresh {
            remaining_secs,
        }) => {
            summary.skipped_groups += 1;
            tracing::debug!(
                remaining_secs,
                "skipped NCSC/BSI advisory refresh in coordinated run"
            );
        }
        Err(err) => {
            summary.failed_sources += 2;
            errors.push(format!("NCSC/BSI: {err}"));
        }
    }

    if summary.total_records == 0 && summary.total_sources == 0 {
        if let Ok(db) = crate::storage::db::StorageDb::global() {
            summary.total_records = db.count_advisory_records().unwrap_or_default();
            summary.total_sources = db
                .load_advisory_sources()
                .map(|s| s.len())
                .unwrap_or_default();
        }
    }

    tracing::info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        updated_sources = summary.updated_sources,
        skipped_groups = summary.skipped_groups,
        requested_feeds = summary.requested_feeds,
        imported_records = summary.imported_records,
        failed_sources = summary.failed_sources,
        "coordinated advisory refresh timing"
    );

    if summary.updated_sources == 0 && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    if !errors.is_empty() {
        tracing::warn!(errors = %errors.join("; "), "some advisory sources failed to refresh");
    }
    Ok(summary)
}
