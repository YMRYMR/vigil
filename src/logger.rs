//! Logging initialisation.
//!
//! Sets up a `tracing-subscriber` with a rolling daily file appender.
//! Log files land in the per-user data directory under `logs/`.
//!
//! Returns the log directory path (for the "Open Logs Folder" tray item)
//! and a `WorkerGuard` that must be kept alive for the lifetime of the
//! process — dropping it flushes and closes the background writer thread.

use std::path::PathBuf;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{fmt, EnvFilter};

// ── Custom timer ──────────────────────────────────────────────────────────────

struct LocalTimer;

impl FormatTime for LocalTimer {
    fn format_time(&self, w: &mut fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = chrono::Local::now();
        write!(w, "{}", now.format("%Y-%m-%d %H:%M:%S%.3f"))
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Opaque guard — drop at process exit to flush pending log records.
pub struct LogGuard {
    _inner: tracing_appender::non_blocking::WorkerGuard,
}

/// Initialise the global tracing subscriber.
///
/// Returns `(log_dir, guard)`.  Keep `guard` alive until the process exits.
pub fn init() -> (PathBuf, LogGuard) {
    let log_dir = crate::config::data_dir().join("logs");
    let _ = std::fs::create_dir_all(&log_dir);

    let appender = tracing_appender::rolling::daily(&log_dir, "vigil");
    let (writer, guard) = tracing_appender::non_blocking(appender);

    fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_writer(writer)
        .with_ansi(false)
        .with_target(false)
        .with_timer(LocalTimer)
        .init();

    (log_dir, LogGuard { _inner: guard })
}

// ── Helpers ───────────────────────────────────────────────────────────────────
