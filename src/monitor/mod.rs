//! Connection monitor: polls for new connections and emits `ConnEvent`s.
//!
//! ## Architecture
//!
//! `Monitor::start()` spawns a background task.  New events are broadcast over
//! a `tokio::sync::broadcast` channel so any number of receivers (UI, logger)
//! can subscribe independently.
//!
//! ### ETW fast path (Windows, admin required)
//! When the process has Administrator rights, `etw::start()` opens the
//! NT Kernel Logger and feeds `RawConn` events into an unbounded mpsc channel.
//! The poll loop wakes immediately on each ETW event (sub-millisecond latency).
//!
//! ### Polling fallback
//! When ETW is unavailable, or on non-Windows platforms, the poll loop calls
//! `poll::poll()` every `config.poll_interval_secs` seconds.
//!
//! Either way, a periodic full poll is always run (at a longer interval when
//! ETW is active) to detect closed connections and catch any events ETW missed.

pub mod etw;
pub mod poll;

use crate::beacon::BeaconTracker;
use crate::config::Config;
use crate::process;
use crate::registry;
use crate::score::{score, ScoreInput};
use crate::session;
use crate::types::{ConnEvent, ConnInfo, MonitorCmd};
use chrono::Local;
use poll::RawConn;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, Duration};

// ── Connection key ─────────────────────────────────────────────────────────────

/// Uniquely identifies a connection for change-tracking.
#[derive(PartialEq, Eq, Hash, Clone)]
struct ConnKey {
    pid: u32,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
}

impl From<&RawConn> for ConnKey {
    fn from(c: &RawConn) -> Self {
        Self {
            pid: c.pid,
            local_ip: c.local_ip.clone(),
            local_port: c.local_port,
            remote_ip: c.remote_ip.clone(),
            remote_port: c.remote_port,
        }
    }
}

// ── Monitor ───────────────────────────────────────────────────────────────────

pub struct Monitor {
    config: Arc<RwLock<Config>>,
    tx: broadcast::Sender<ConnEvent>,
    /// Kept for future use (Phase 4: tray stop/resume commands).
    _cmd_tx: mpsc::Sender<MonitorCmd>,
}

impl Monitor {
    /// Create a new monitor.  Subscribe to events via `subscribe()` **before**
    /// calling `start()` or events emitted during startup may be missed.
    pub fn new(config: Arc<RwLock<Config>>) -> Self {
        let (tx, _) = broadcast::channel(512);
        let (cmd_tx, _) = mpsc::channel(32);
        Self {
            config,
            tx,
            _cmd_tx: cmd_tx,
        }
    }

    /// Subscribe to connection events.
    pub fn subscribe(&self) -> broadcast::Receiver<ConnEvent> {
        self.tx.subscribe()
    }

    /// Spawn the polling / ETW loop as a Tokio task.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let tx = self.tx.clone();

        // Attempt to start the ETW kernel session (Windows + admin only).
        // On success, RawConn events arrive in real time via etw_rx.
        let (etw_tx, etw_rx) = mpsc::unbounded_channel::<RawConn>();
        let using_etw = etw::start(etw_tx);
        let etw_rx = if using_etw { Some(etw_rx) } else { None };

        if using_etw {
            tracing::info!("ETW kernel session started — real-time TCP monitoring active");
        } else {
            tracing::info!("ETW unavailable — falling back to polling");
        }

        // Spawn the registry persistence watcher (Windows only; no-op elsewhere).
        let threshold = config.read().unwrap().alert_threshold;
        registry::win::spawn(tx.clone(), threshold);

        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(poll_loop(config, tx, etw_rx))
        })
    }
}

// ── Async helpers ─────────────────────────────────────────────────────────────

/// Await the next ETW connection event, or return `pending` (never resolves)
/// when ETW is not active — makes `tokio::select!` work cleanly.
async fn recv_etw(
    rx: &mut Option<mpsc::UnboundedReceiver<RawConn>>,
) -> Option<RawConn> {
    match rx.as_mut() {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

// ── Main poll loop ────────────────────────────────────────────────────────────

async fn poll_loop(
    config: Arc<RwLock<Config>>,
    tx: broadcast::Sender<ConnEvent>,
    mut etw_rx: Option<mpsc::UnboundedReceiver<RawConn>>,
) {
    let using_etw = etw_rx.is_some();
    let mut known: HashMap<ConnKey, ConnInfo> = HashMap::new();

    // Beaconing detector: tracks inter-connection timing per (pid, remote_ip).
    let mut beacon = BeaconTracker::new();

    // Build service map once; refresh it on every full poll cycle.
    let mut svc_map = process::build_service_map();

    loop {
        let (interval, threshold, log_all) = {
            let cfg = config.read().unwrap();
            (cfg.poll_interval_secs, cfg.alert_threshold, cfg.log_all_connections)
        };

        // When ETW is active we run full polls less frequently — only for
        // cleanup (closed connections) and catching anything ETW missed.
        let poll_secs = if using_etw {
            (interval * 6).max(30).min(60)
        } else {
            interval.max(1)
        };

        tokio::select! {
            // ── ETW fast path ─────────────────────────────────────────────────
            // Wake immediately on each kernel TCP event.
            raw = recv_etw(&mut etw_rx) => {
                match raw {
                    Some(raw_conn) => {
                        let key = ConnKey::from(&raw_conn);
                        if !known.contains_key(&key) {
                            let beaconing = beacon.record(raw_conn.pid, &raw_conn.remote_ip);
                            process_conn(
                                &raw_conn, beaconing, &mut known, &svc_map,
                                &config, &tx, threshold, log_all,
                            );
                        }
                    }
                    None => {
                        // All ETW senders dropped — ETW crashed or process exited.
                        tracing::warn!("ETW channel closed; falling back to polling");
                        etw_rx = None;
                    }
                }
            }

            // ── Periodic full poll ────────────────────────────────────────────
            // Handles closed connections, catch-up for any missed ETW events,
            // and is the sole path when ETW is not available.
            _ = sleep(Duration::from_secs(poll_secs)) => {
                // Refresh the pid → service-name map every cycle
                svc_map = process::build_service_map();

                let raw = poll::poll();
                let current_keys: HashSet<ConnKey> =
                    raw.iter().map(ConnKey::from).collect();

                // Emit Closed events for connections that disappeared
                let stale: Vec<ConnKey> = known
                    .keys()
                    .filter(|k| !current_keys.contains(*k))
                    .cloned()
                    .collect();
                for key in stale {
                    if let Some(info) = known.remove(&key) {
                        let _ = tx.send(ConnEvent::Closed {
                            pid: info.pid,
                            local: info.local_addr.clone(),
                            remote: info.remote_addr.clone(),
                        });
                    }
                }

                // Prune the beacon tracker: drop entries for pids no longer seen.
                let active_pids: HashSet<u32> = known.keys().map(|k| k.pid).collect();
                beacon.prune(&active_pids);

                // Process any new connections the poll found
                // (ETW may already have them in `known`; skip those)
                for raw_conn in &raw {
                    let key = ConnKey::from(raw_conn);
                    if known.contains_key(&key) {
                        continue;
                    }
                    let beaconing = beacon.record(raw_conn.pid, &raw_conn.remote_ip);
                    process_conn(
                        raw_conn, beaconing, &mut known, &svc_map,
                        &config, &tx, threshold, log_all,
                    );
                }
            }
        }
    }
}

// ── Connection processor ──────────────────────────────────────────────────────

/// Enrich a single `RawConn`, score it, record it in `known`, and emit the
/// appropriate `ConnEvent` over the broadcast channel.
fn process_conn(
    raw_conn: &RawConn,
    beaconing: bool,
    known: &mut HashMap<ConnKey, ConnInfo>,
    svc_map: &HashMap<u32, String>,
    config: &Arc<RwLock<Config>>,
    tx: &broadcast::Sender<ConnEvent>,
    threshold: u8,
    log_all: bool,
) {
    let proc = process::collect(raw_conn.pid, svc_map);

    // Normalise ancestor names the same way as the process name
    let ancestors_norm: Vec<(String, u32)> = proc.ancestors
        .iter()
        .map(|(n, pid)| (crate::config::normalise_name(n), *pid))
        .collect();

    // Capture the interactive-session state at the moment we observed the
    // connection.  Once a user logs in this becomes false and stays false
    // for the rest of the process lifetime, so the check is effectively
    // "has a user ever logged in since we started monitoring?".
    let pre_login = session::is_pre_login();

    let (s, reasons) = {
        let cfg = config.read().unwrap();
        score(
            &ScoreInput {
                name:        &proc.name_key,
                path:        &proc.path,
                publisher:   &proc.publisher,
                remote_ip:   &raw_conn.remote_ip,
                remote_port: raw_conn.remote_port,
                status:      &raw_conn.status,
                ancestors:   &ancestors_norm,
                beaconing,
                pre_login,
            },
            &cfg,
        )
    };

    let local_addr = format!("{}:{}", raw_conn.local_ip, raw_conn.local_port);
    let remote_addr = if raw_conn.remote_ip.is_empty() {
        "LISTEN".to_string()
    } else {
        format!("{}:{}", raw_conn.remote_ip, raw_conn.remote_port)
    };

    let info = ConnInfo {
        timestamp: Local::now().format("%H:%M:%S").to_string(),
        proc_name: proc.name.clone(),
        pid: raw_conn.pid,
        proc_path: proc.path.clone(),
        proc_user: proc.user.clone(),
        parent_name: proc.parent_name.clone(),
        parent_pid: proc.parent_pid,
        ancestor_chain: proc.ancestors.clone(),
        service_name: proc.service_name.clone(),
        publisher: proc.publisher.clone(),
        local_addr,
        remote_addr,
        status: raw_conn.status.clone(),
        score: s,
        reasons: reasons.clone(),
        pre_login,
    };

    let key = ConnKey::from(raw_conn);
    known.insert(key, info.clone());

    let event = if s >= threshold {
        tracing::warn!(
            "{} ({}) | {} → {} | score={}",
            info.proc_name, raw_conn.pid, info.local_addr, info.remote_addr, s
        );
        ConnEvent::Alert(info)
    } else if s > 0 || log_all {
        tracing::info!(
            "{} ({}) | {} → {} | score={}",
            info.proc_name, raw_conn.pid, info.local_addr, info.remote_addr, s
        );
        ConnEvent::New(info)
    } else {
        return; // score 0, not logging all → silent
    };

    let _ = tx.send(event);
}

