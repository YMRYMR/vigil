//! Connection monitor: polls for new connections and emits `ConnEvent`s.
//!
//! ## Architecture
//!
//! `Monitor::start()` spawns a background task. New events are broadcast over
//! a `tokio::sync::broadcast` channel so any number of receivers can subscribe.

pub mod etw;
pub mod poll;

use crate::baseline;
use crate::beacon::BeaconTracker;
use crate::blocklist;
use crate::config::Config;
use crate::detection_depth;
use crate::forensics;
use crate::fswatch;
use crate::geoip;
use crate::honeypot;
use crate::longlived::LongLivedTracker;
use crate::pcap;
use crate::process;
use crate::registry;
use crate::revdns;
use crate::score::{score, ScoreInput};
use crate::session;
use crate::types::{ConnEvent, ConnInfo, MonitorCmd};
use chrono::Local;
use poll::RawConn;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, Duration};

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

pub struct Monitor {
    config: Arc<RwLock<Config>>,
    tx: broadcast::Sender<ConnEvent>,
    _cmd_tx: mpsc::Sender<MonitorCmd>,
}

impl Monitor {
    pub fn new(config: Arc<RwLock<Config>>) -> Self {
        let (tx, _) = broadcast::channel(4096);
        let (cmd_tx, _) = mpsc::channel(32);
        Self {
            config,
            tx,
            _cmd_tx: cmd_tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConnEvent> {
        self.tx.subscribe()
    }

    pub fn start(self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let tx = self.tx.clone();
        let (etw_tx, etw_rx) = mpsc::unbounded_channel::<RawConn>();
        let using_etw = etw::start(etw_tx);
        let etw_rx = if using_etw { Some(etw_rx) } else { None };
        if using_etw {
            tracing::info!("ETW kernel session started — real-time TCP monitoring active");
        } else {
            tracing::info!("ETW unavailable — falling back to polling");
        }
        let threshold = config.read().unwrap().alert_threshold;
        registry::win::spawn(tx.clone(), threshold);
        honeypot::start(config.clone(), tx.clone(), threshold);
        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(poll_loop(config, tx, etw_rx))
        })
    }
}

async fn recv_etw(rx: &mut Option<mpsc::UnboundedReceiver<RawConn>>) -> Option<RawConn> {
    match rx.as_mut() {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

async fn poll_loop(
    config: Arc<RwLock<Config>>,
    tx: broadcast::Sender<ConnEvent>,
    mut etw_rx: Option<mpsc::UnboundedReceiver<RawConn>>,
) {
    let using_etw = etw_rx.is_some();
    let mut known: HashMap<ConnKey, ConnInfo> = HashMap::new();
    let mut beacon = BeaconTracker::new();
    let long_lived = std::sync::Arc::new(LongLivedTracker::new());
    let mut svc_map = process::build_service_map();

    loop {
        let (interval, threshold, log_all) = {
            let cfg = config.read().unwrap();
            (
                cfg.poll_interval_secs,
                cfg.alert_threshold,
                cfg.log_all_connections,
            )
        };
        let poll_secs = if using_etw {
            (interval * 6).clamp(30, 60)
        } else {
            interval.max(1)
        };

        tokio::select! {
            raw = recv_etw(&mut etw_rx) => {
                match raw {
                    Some(raw_conn) => {
                        let key = ConnKey::from(&raw_conn);
                        if !known.contains_key(&key) {
                            let beaconing = beacon.record(raw_conn.pid, &raw_conn.remote_ip);
                            process_conn(&raw_conn, beaconing, &mut known, &svc_map, &config, &tx, threshold, log_all, &long_lived);
                        }
                    }
                    None => {
                        tracing::warn!("ETW channel closed; falling back to polling");
                        etw_rx = None;
                    }
                }
            }
            _ = sleep(Duration::from_secs(poll_secs)) => {
                svc_map = process::build_service_map();
                let raw = poll::poll();
                let current_keys: HashSet<ConnKey> = raw.iter().map(ConnKey::from).collect();
                let stale: Vec<ConnKey> = known.keys().filter(|k| !current_keys.contains(*k)).cloned().collect();
                for key in stale {
                    if let Some(info) = known.remove(&key) {
                        let _ = tx.send(ConnEvent::Closed {
                            pid: info.pid,
                            local: info.local_addr.clone(),
                            remote: info.remote_addr.clone(),
                        });
                    }
                }
                let active_pids: HashSet<u32> = known.keys().map(|k| k.pid).collect();
                beacon.prune(&active_pids);
                for raw_conn in &raw {
                    let key = ConnKey::from(raw_conn);
                    if known.contains_key(&key) {
                        continue;
                    }
                    let beaconing = beacon.record(raw_conn.pid, &raw_conn.remote_ip);
                    process_conn(raw_conn, beaconing, &mut known, &svc_map, &config, &tx, threshold, log_all, &long_lived);
                }
                let active: HashSet<(u32, String)> = known.keys().map(|k| (k.pid, k.remote_ip.clone())).collect();
                long_lived.retain_active(|pid, ip| active.contains(&(pid, ip.to_string())));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_conn(
    raw_conn: &RawConn,
    beaconing: bool,
    known: &mut HashMap<ConnKey, ConnInfo>,
    svc_map: &HashMap<u32, String>,
    config: &Arc<RwLock<Config>>,
    tx: &broadcast::Sender<ConnEvent>,
    threshold: u8,
    log_all: bool,
    long_lived: &LongLivedTracker,
) {
    let proc = process::collect(raw_conn.pid, svc_map);
    let ancestors_norm: Vec<(String, u32)> = proc
        .ancestors
        .iter()
        .map(|(n, pid)| (crate::config::normalise_name(n), *pid))
        .collect();
    let pre_login = session::is_pre_login();
    let (fs_window, long_threshold, rev_enabled, reputation_enabled, forensic_cfg) = {
        let cfg = config.read().unwrap();
        (
            std::time::Duration::from_secs(cfg.fswatch_window_secs),
            std::time::Duration::from_secs(cfg.long_lived_secs),
            cfg.reverse_dns_enabled,
            !cfg.blocklist_paths.is_empty(),
            cfg.clone(),
        )
    };

    let reputation_hit: Option<String> = if reputation_enabled {
        blocklist::lookup(&raw_conn.remote_ip)
    } else {
        None
    };
    let geo = if !raw_conn.remote_ip.is_empty() {
        geoip::lookup(&raw_conn.remote_ip)
    } else {
        crate::geoip::GeoInfo::default()
    };
    let hostname: Option<String> = if rev_enabled && !raw_conn.remote_ip.is_empty() {
        revdns::lookup(&raw_conn.remote_ip).filter(|s| !s.is_empty())
    } else {
        None
    };
    let recently_dropped =
        !proc.path.is_empty() && fswatch::dropped_within(&proc.path, fs_window).is_some();
    let ll_flag = !raw_conn.remote_ip.is_empty()
        && long_lived.is_long_lived(raw_conn.pid, &raw_conn.remote_ip, long_threshold);
    let baseline_signal = baseline::observe(
        &proc.name_key,
        &proc.publisher,
        &proc.path,
        &raw_conn.remote_ip,
        raw_conn.remote_port,
        geo.country.as_deref(),
    );
    let tls_sni: Option<String> = None;
    let tls_ja3: Option<String> = None;

    let (score_value, reasons, attack_tags) = {
        let cfg = config.read().unwrap();
        score(
            &ScoreInput {
                name: &proc.name_key,
                path: &proc.path,
                publisher: &proc.publisher,
                proc_user: &proc.user,
                parent_user: &proc.parent_user,
                command_line: &proc.command_line,
                remote_ip: &raw_conn.remote_ip,
                remote_port: raw_conn.remote_port,
                status: &raw_conn.status,
                ancestors: &ancestors_norm,
                beaconing,
                pre_login,
                reputation_hit: reputation_hit.as_deref(),
                country: geo.country.as_deref(),
                hostname: hostname.as_deref(),
                tls_sni: tls_sni.as_deref(),
                tls_ja3: tls_ja3.as_deref(),
                recently_dropped,
                long_lived: ll_flag,
                baseline_signal,
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
    let dga_like = {
        let cfg = config.read().unwrap();
        hostname
            .as_deref()
            .or(tls_sni.as_deref())
            .map(|h| crate::entropy::is_dga_like(h, cfg.dga_entropy_threshold))
            .unwrap_or(false)
    };
    let script_host_suspicious =
        detection_depth::inspect_script_host(&proc.name_key, &proc.command_line).triggered();
    let baseline_deviation = baseline_signal.mature
        && (baseline_signal.new_remote
            || baseline_signal.new_port
            || baseline_signal.new_country);

    let info = ConnInfo {
        timestamp: Local::now().format("%H:%M:%S").to_string(),
        proc_name: proc.name.clone(),
        pid: raw_conn.pid,
        proc_path: proc.path.clone(),
        proc_user: proc.user.clone(),
        parent_user: proc.parent_user.clone(),
        parent_name: proc.parent_name.clone(),
        parent_pid: proc.parent_pid,
        service_name: proc.service_name.clone(),
        publisher: proc.publisher.clone(),
        command_line: proc.command_line.clone(),
        local_addr,
        remote_addr,
        status: raw_conn.status.clone(),
        score: score_value,
        reasons: reasons.clone(),
        attack_tags,
        ancestor_chain: proc.ancestors.clone(),
        pre_login,
        hostname,
        country: geo.country,
        asn: geo.asn,
        asn_org: geo.asn_org,
        reputation_hit,
        recently_dropped,
        long_lived: ll_flag,
        dga_like,
        baseline_deviation,
        script_host_suspicious,
        tls_sni,
        tls_ja3,
    };

    let key = ConnKey::from(raw_conn);
    known.insert(key, info.clone());

    let event = if score_value >= threshold {
        forensics::maybe_capture_process_dump(&info, &forensic_cfg);
        pcap::maybe_capture_pcap(&info, &forensic_cfg);
        ConnEvent::Alert(info)
    } else if score_value > 0 || log_all {
        ConnEvent::New(info)
    } else {
        return;
    };
    let _ = tx.send(event);
}
