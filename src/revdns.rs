//! Reverse-DNS lookup with a background worker and in-memory cache.
//!
//! Calling `getnameinfo()` inline from the monitor would block the event loop
//! on every new connection (100 ms – 30 s depending on resolver health).
//! Instead we keep a cache and submit misses to a worker thread over a channel.
//!
//! Callers get:
//!   - Immediate cache hit → `Some(hostname)` or `Some("".into())` for confirmed
//!     misses.  (Empty string is a distinct sentinel from "not yet resolved".)
//!   - Cache miss → `None`, and the IP is queued for background resolution.
//!     The next time the same IP shows up in a connection event, the hostname
//!     will be available.
//!
//! The worker is only started when `reverse_dns_enabled` is `true` in the
//! config.  By default Vigil does **not** do reverse DNS because the OS
//! resolver emits a DNS query for each reverse lookup, which can leak
//! intel to an adversary who controls the authoritative server for the
//! `.in-addr.arpa` zone.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::Instant;

/// Cache entry.  Empty string means "looked up, no PTR record".
static CACHE: OnceLock<DashMap<String, (String, Instant)>> = OnceLock::new();
static TX: OnceLock<mpsc::SyncSender<String>> = OnceLock::new();

const TTL_SECS: u64 = 3600;

/// Start the background resolver thread.  Idempotent — calling multiple times
/// is a no-op.
pub fn start() {
    if TX.get().is_some() {
        return;
    }

    CACHE.get_or_init(DashMap::new);
    let (tx, rx) = mpsc::sync_channel::<String>(1024);
    TX.set(tx).ok();

    std::thread::Builder::new()
        .name("vigil-revdns".into())
        .spawn(move || worker(rx))
        .expect("failed to spawn revdns worker");

    tracing::info!("reverse-DNS resolver started");
}

fn worker(rx: mpsc::Receiver<String>) {
    while let Ok(ip_str) = rx.recv() {
        let Ok(ip): Result<IpAddr, _> = ip_str.parse() else {
            continue;
        };
        let host = dns_lookup::lookup_addr(&ip).unwrap_or_default();
        // An unresolvable address returns the IP string back — treat that as no PTR.
        let host = if host == ip_str { String::new() } else { host };
        if let Some(cache) = CACHE.get() {
            cache.insert(ip_str, (host, Instant::now()));
        }
    }
}

/// Returns `Some(hostname)` on cache hit (possibly empty string = confirmed
/// no PTR record), or `None` if the lookup has not completed yet.  On a miss
/// the IP is queued for background resolution.
pub fn lookup(ip: &str) -> Option<String> {
    let cache = CACHE.get()?;
    if let Some(entry) = cache.get(ip) {
        let (host, seen) = entry.value();
        if seen.elapsed().as_secs() < TTL_SECS {
            return Some(host.clone());
        }
    }
    // Miss or stale — queue for resolution.
    if let Some(tx) = TX.get() {
        let _ = tx.try_send(ip.to_string());
    }
    None
}

#[allow(dead_code)]
pub fn cache_size() -> usize {
    CACHE.get().map(|c| c.len()).unwrap_or(0)
}
