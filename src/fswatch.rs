//! File-system watcher for new-executable drops.
//!
//! A classic dropper / staged-payload chain looks like:
//!   1. User runs a macro or opens a phish attachment.
//!   2. A new `.exe` / `.dll` / `.scr` appears in `%TEMP%`, `%APPDATA%\Roaming`,
//!      or `Downloads`.
//!   3. That new file immediately makes an outbound connection.
//!
//! Vigil already has signals for steps 1 and 3; this module adds step 2.
//! The watcher records every new PE-like file seen in the watched directories
//! along with the wall-clock instant it appeared.  When the monitor scores a
//! new connection, it checks whether the process's executable path matches a
//! file that was dropped within the last `fswatch_window_secs` seconds — if
//! so, it's almost certainly a dropper.
//!
//! The watcher is entirely best-effort: if `notify` can't watch a given path
//! (for example the `Downloads` folder doesn't exist on a headless Linux box),
//! we log a warning and skip it.  Vigil never fails to start because the
//! watcher can't attach.

use dashmap::DashMap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

// ── What counts as "executable-like" ──────────────────────────────────────────

const INTERESTING_EXTS: &[&str] = &[
    "exe", "dll", "scr", "com", // Windows PE
    "bat", "cmd", "ps1", "vbs", "js", "wsf", "hta", // scripts
    "msi", "msix", // installers
    "jar",  // cross-platform Java
    "sh", "py", // Unix scripts
    "dylib", "so",  // Unix shared libs
    "app", // macOS bundles (rare for droppers but…)
];

fn is_interesting(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => INTERESTING_EXTS.iter().any(|i| ext.eq_ignore_ascii_case(i)),
        None => false,
    }
}

// ── Watched directory list ────────────────────────────────────────────────────

fn watched_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Some(tmp) = std::env::var_os("TEMP").map(PathBuf::from) {
        out.push(tmp);
    }
    if let Some(lad) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        out.push(lad.join("Temp"));
    }
    if let Some(appd) = std::env::var_os("APPDATA").map(PathBuf::from) {
        out.push(appd); // %APPDATA% == Roaming
    }

    // USERPROFILE\Downloads on Windows; $HOME/Downloads on Unix.
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    if let Some(h) = home.as_ref() {
        out.push(h.join("Downloads"));
    }

    // Unix temp
    #[cfg(not(windows))]
    {
        out.push(PathBuf::from("/tmp"));
        out.push(PathBuf::from("/var/tmp"));
    }

    // Dedup + filter to existing dirs only
    out.sort();
    out.dedup();
    out.retain(|p| p.is_dir());
    out
}

// ── Global state ──────────────────────────────────────────────────────────────

/// Map from **lowercased** full path → the Instant it was created / modified.
static DROPPED: OnceLock<DashMap<String, Instant>> = OnceLock::new();

/// Returned-path canonicalisation for comparison.
fn canon(p: &str) -> String {
    // Don't hit the filesystem — just lowercase on Windows, leave as-is on Unix.
    // Process paths arrive from sysinfo already in the canonical form we store.
    #[cfg(windows)]
    {
        p.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        p.to_string()
    }
}

fn record_drop(path: &Path) {
    if !is_interesting(path) {
        return;
    }
    let Some(s) = path.to_str() else {
        return;
    };
    let map = DROPPED.get_or_init(DashMap::new);
    map.insert(canon(s), Instant::now());

    // Keep the map bounded: if it grows past 4096 entries, drop the oldest.
    if map.len() > 4096 {
        let now = Instant::now();
        map.retain(|_, t| now.saturating_duration_since(*t).as_secs() < 86_400);
    }
}

/// Return `Some(age)` when `exe_path` was dropped into a watched directory
/// within the last `window` seconds.  `None` otherwise.
pub fn dropped_within(exe_path: &str, window: std::time::Duration) -> Option<std::time::Duration> {
    let map = DROPPED.get()?;
    let entry = map.get(&canon(exe_path))?;
    let age = Instant::now().saturating_duration_since(*entry);
    if age <= window {
        Some(age)
    } else {
        None
    }
}

// ── Startup ───────────────────────────────────────────────────────────────────

/// Start the watcher on a background thread.  The `RecommendedWatcher` is
/// leaked intentionally — Vigil runs for the process lifetime and dropping
/// the watcher would stop events from arriving.
pub fn start() {
    DROPPED.get_or_init(DashMap::new);

    let dirs = watched_dirs();
    if dirs.is_empty() {
        tracing::info!("fswatch: no eligible directories found; watcher disabled");
        return;
    }

    let mut watcher: RecommendedWatcher = match notify::recommended_watcher(handle) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("fswatch: failed to create watcher: {e}");
            return;
        }
    };

    let mut watching = 0usize;
    for dir in &dirs {
        match watcher.watch(dir, RecursiveMode::Recursive) {
            Ok(()) => watching += 1,
            Err(e) => tracing::warn!("fswatch: could not watch {}: {e}", dir.display()),
        }
    }

    if watching == 0 {
        tracing::warn!("fswatch: failed to attach to any directory");
        return;
    }

    tracing::info!(
        "fswatch: watching {watching} director{}",
        if watching == 1 { "y" } else { "ies" }
    );

    // Leak so the watcher lives for the process lifetime.
    Box::leak(Box::new(watcher));
}

fn handle(res: notify::Result<Event>) {
    let Ok(ev) = res else {
        return;
    };
    let is_drop = matches!(
        ev.kind,
        EventKind::Create(_) | EventKind::Modify(notify::event::ModifyKind::Data(_))
    );
    if !is_drop {
        return;
    }
    for p in &ev.paths {
        record_drop(p);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn interesting_extensions() {
        assert!(is_interesting(Path::new("foo.exe")));
        assert!(is_interesting(Path::new("FOO.EXE")));
        assert!(is_interesting(Path::new("x/y/z.dll")));
        assert!(is_interesting(Path::new("p.ps1")));
        assert!(!is_interesting(Path::new("readme.txt")));
        assert!(!is_interesting(Path::new("noext")));
    }

    #[test]
    fn record_and_lookup() {
        let p = PathBuf::from(if cfg!(windows) {
            r"C:\vigil_test\fswatch_hit.exe"
        } else {
            "/tmp/vigil_test_fswatch_hit.exe"
        });
        record_drop(&p);
        let hit = dropped_within(p.to_str().unwrap(), Duration::from_secs(60));
        assert!(hit.is_some());
    }

    #[test]
    fn lookup_miss_for_uninteresting_ext() {
        let p = PathBuf::from("/tmp/not_executable.txt");
        record_drop(&p);
        assert!(dropped_within(p.to_str().unwrap(), Duration::from_secs(60)).is_none());
    }
}
