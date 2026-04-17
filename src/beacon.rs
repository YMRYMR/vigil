//! Beaconing detector.
//!
//! Tracks the timing of repeated outbound connections from a given
//! `(pid, remote_ip)` pair and flags behaviour consistent with C2 beacon
//! callbacks: many connections at very regular intervals (low stddev).
//!
//! ## Decision thresholds
//!
//! | Constant          | Value | Meaning                                    |
//! |-------------------|-------|--------------------------------------------|
//! | `MIN_SAMPLES`     | 10    | Min observations before a verdict          |
//! | `MAX_HISTORY`     | 30    | Rolling window size                        |
//! | `MIN_MEAN_SECS`   | 1.0   | Ignore sub-second bursts                   |
//! | `MAX_MEAN_SECS`   | 600.0 | Ignore very slow beacons (> 10 min)        |
//! | `MAX_STDDEV_SECS` | 5.0   | Intervals this regular → suspected beaconing |

use std::collections::HashMap;
use std::time::Instant;

const MIN_SAMPLES: usize = 10;
const MAX_HISTORY: usize = 30;
const MIN_MEAN_SECS: f64 = 1.0;
const MAX_MEAN_SECS: f64 = 600.0;
const MAX_STDDEV_SECS: f64 = 5.0;

/// Tracks repeated connection attempts per `(pid, remote_ip)` and detects
/// beaconing patterns.  Designed to live inside the monitor loop — no I/O,
/// no allocator pressure beyond the initial HashMap grow.
pub struct BeaconTracker {
    // (pid, remote_ip_without_port) → ordered arrival times
    history: HashMap<(u32, String), Vec<Instant>>,
}

impl BeaconTracker {
    pub fn new() -> Self {
        Self {
            history: HashMap::new(),
        }
    }

    /// Record one connection from `pid` to `remote_ip` (may include port).
    ///
    /// Returns `true` if the accumulated pattern looks like C2 beaconing
    /// (≥ `MIN_SAMPLES` connections at suspiciously regular intervals).
    pub fn record(&mut self, pid: u32, remote_ip: &str) -> bool {
        // Strip port suffix so "1.2.3.4:80" and "1.2.3.4:443" map to the same IP.
        let ip = remote_ip.split(':').next().unwrap_or(remote_ip).to_string();
        let key = (pid, ip);

        let times = self.history.entry(key).or_default();
        times.push(Instant::now());

        // Rolling window — drop oldest entries beyond MAX_HISTORY
        if times.len() > MAX_HISTORY {
            let excess = times.len() - MAX_HISTORY;
            times.drain(0..excess);
        }

        if times.len() < MIN_SAMPLES {
            return false;
        }

        // Compute inter-arrival intervals in seconds
        let intervals: Vec<f64> = times
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect();

        let n = intervals.len() as f64;
        let mean: f64 = intervals.iter().sum::<f64>() / n;

        // Outside the "interesting" mean interval range → not regular C2 beaconing
        if !(MIN_MEAN_SECS..=MAX_MEAN_SECS).contains(&mean) {
            return false;
        }

        // Population standard deviation
        let variance: f64 = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();

        stddev < MAX_STDDEV_SECS
    }

    /// Remove stale entries for PIDs that no longer exist.
    /// Call this on every full poll cycle to bound memory growth.
    pub fn prune(&mut self, active_pids: &std::collections::HashSet<u32>) {
        self.history.retain(|(pid, _), _| active_pids.contains(pid));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_few_samples_never_beaconing() {
        let mut t = BeaconTracker::new();
        for _ in 0..9 {
            assert!(!t.record(1, "1.2.3.4"));
        }
    }

    #[test]
    fn different_pids_are_independent() {
        let mut t = BeaconTracker::new();
        // Fill up to MIN_SAMPLES - 1 for pid=1
        for _ in 0..9 {
            t.record(1, "1.2.3.4");
        }
        // pid=2 starts fresh — must not trigger
        assert!(!t.record(2, "1.2.3.4"));
    }

    #[test]
    fn prune_removes_inactive_pids() {
        let mut t = BeaconTracker::new();
        for _ in 0..9 {
            t.record(42, "5.6.7.8");
        }
        assert!(t.history.contains_key(&(42, "5.6.7.8".into())));
        // pid 42 not active → should be pruned
        t.prune(&std::collections::HashSet::new());
        assert!(t.history.is_empty());
    }
}
