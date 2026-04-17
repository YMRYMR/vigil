//! Long-lived outbound connection tracker.
//!
//! Malware C2 channels, reverse shells, and data-exfil sessions tend to stay
//! open for hours.  Legitimate user-driven traffic (browsers, chat) typically
//! churns connections on the order of minutes.  By tracking the first time
//! we saw each `(pid, remote_ip)` pair, we can flag connections that have
//! been held open past a configurable threshold.
//!
//! State is small: one `Instant` per unique `(pid, remote_ip)`.  Entries are
//! pruned opportunistically by the monitor loop when a connection goes away.

use dashmap::DashMap;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct LongLivedTracker {
    seen: DashMap<(u32, String), Instant>,
}

impl LongLivedTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the first-seen time for `(pid, remote_ip)` if not already known.
    /// Returns the `Duration` since first-seen.
    pub fn touch(&self, pid: u32, remote_ip: &str) -> Duration {
        let key = (pid, remote_ip.to_string());
        let now = Instant::now();
        let first = *self.seen.entry(key).or_insert(now);
        now.saturating_duration_since(first)
    }

    /// True when the connection's age exceeds `threshold`.
    pub fn is_long_lived(&self, pid: u32, remote_ip: &str, threshold: Duration) -> bool {
        self.touch(pid, remote_ip) >= threshold
    }

    /// Remove entries for connections that are no longer active.
    pub fn retain_active<F: Fn(u32, &str) -> bool>(&self, keep: F) {
        self.seen.retain(|(pid, ip), _| keep(*pid, ip));
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn first_touch_returns_zero() {
        let t = LongLivedTracker::new();
        let d = t.touch(123, "1.2.3.4");
        assert!(d.as_millis() < 50);
    }

    #[test]
    fn second_touch_returns_elapsed() {
        let t = LongLivedTracker::new();
        t.touch(42, "8.8.8.8");
        sleep(Duration::from_millis(30));
        let d = t.touch(42, "8.8.8.8");
        assert!(d >= Duration::from_millis(25));
    }

    #[test]
    fn is_long_lived_threshold() {
        let t = LongLivedTracker::new();
        t.touch(1, "1.1.1.1");
        assert!(!t.is_long_lived(1, "1.1.1.1", Duration::from_secs(10)));
        assert!(t.is_long_lived(1, "1.1.1.1", Duration::from_millis(0)));
    }

    #[test]
    fn retain_active_drops_stale() {
        let t = LongLivedTracker::new();
        t.touch(1, "a");
        t.touch(2, "b");
        t.retain_active(|pid, _| pid == 1);
        assert_eq!(t.len(), 1);
    }
}
