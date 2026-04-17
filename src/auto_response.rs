//! Optional, UI-layer auto-response policy engine.
//!
//! This module intentionally starts conservative:
//! - disabled by default
//! - dry-run by default
//! - automation is suppressed for trusted processes
//! - actions require strong corroborating signals, not just a high score
//! - actions are cooldown-limited per target to avoid thrashing
//! - repeated offences can escalate from connection kill to remote or process block
//! - allowlist-only mode can optionally force-block newly observed traffic from
//!   processes outside the trusted list / operator allowlist.

use crate::{active_response, audit, config::{normalise_name, Config}, types::ConnInfo};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct EngineState {
    cooldowns: HashMap<String, Instant>,
    offences: HashMap<String, OffenceState>,
}

#[derive(Debug, Clone, Copy)]
struct OffenceState { count: u8, last_seen: Instant }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedAction {
    KillConnection,
    BlockRemote { target: String, preset: active_response::DurationPreset },
    BlockProcess { pid: u32, path: String, preset: active_response::DurationPreset },
}

pub fn maybe_apply(conn: &ConnInfo, cfg: &Config, state: &mut EngineState) -> Option<String> {
    let action = plan(conn, cfg, state)?;
    let cooldown = Duration::from_secs(cfg.auto_response_cooldown_secs.max(1));
    if !state.try_acquire(cooldown_key(&action, conn), cooldown) { return None; }
    let summary = describe_action(&action, conn);

    let dry_run = cfg.auto_response_dry_run || (cfg.allowlist_mode_enabled && cfg.allowlist_mode_dry_run && is_allowlist_enforcement(&action, conn, cfg));
    if dry_run {
        audit::record("auto_response", "dry_run", json!({"summary": summary, "pid": conn.pid, "proc_name": conn.proc_name, "local_addr": conn.local_addr, "remote_addr": conn.remote_addr, "score": conn.score }));
        return Some(format!("Auto-response dry run: {summary}."));
    }

    let result = execute(&action, conn);
    match &result {
        Ok(message) => { audit::record("auto_response", "success", json!({"summary": summary, "message": message, "pid": conn.pid, "proc_name": conn.proc_name, "local_addr": conn.local_addr, "remote_addr": conn.remote_addr, "score": conn.score })); Some(format!("Auto-response: {message}")) }
        Err(err) => { audit::record("auto_response", "failure", json!({"summary": summary, "error": err, "pid": conn.pid, "proc_name": conn.proc_name, "local_addr": conn.local_addr, "remote_addr": conn.remote_addr, "score": conn.score })); Some(format!("Auto-response failed: {summary} ({err})")) }
    }
}

pub fn plan(conn: &ConnInfo, cfg: &Config, state: &mut EngineState) -> Option<PlannedAction> {
    if cfg.allowlist_mode_enabled && !is_allowlisted_process(conn, cfg) && !conn.proc_path.trim().is_empty() {
        return Some(PlannedAction::BlockProcess { pid: conn.pid, path: conn.proc_path.clone(), preset: active_response::DurationPreset::Permanent });
    }
    if !cfg.auto_response_enabled || conn.score < cfg.auto_response_min_score || is_trusted_process(conn, cfg) { return None; }

    let signal_strength = signal_strength(conn);
    if signal_strength < 2 { return None; }
    let offence_level = state.record_offence(conn, offence_window(cfg));

    if cfg.auto_block_process && offence_level >= 3 && signal_strength >= 3 && !conn.proc_path.trim().is_empty() {
        return Some(PlannedAction::BlockProcess { pid: conn.pid, path: conn.proc_path.clone(), preset: active_response::DurationPreset::OneHour });
    }
    if cfg.auto_block_remote && offence_level >= 2 {
        if let Some(target) = active_response::extract_remote_target(&conn.remote_addr) { return Some(PlannedAction::BlockRemote { target, preset: active_response::DurationPreset::OneHour }); }
    }
    if cfg.auto_kill_connection && active_response::can_kill_connection(conn) { return Some(PlannedAction::KillConnection); }
    if cfg.auto_block_remote {
        if let Some(target) = active_response::extract_remote_target(&conn.remote_addr) { return Some(PlannedAction::BlockRemote { target, preset: active_response::DurationPreset::OneHour }); }
    }
    if cfg.auto_block_process && signal_strength >= 3 && !conn.proc_path.trim().is_empty() {
        return Some(PlannedAction::BlockProcess { pid: conn.pid, path: conn.proc_path.clone(), preset: active_response::DurationPreset::OneHour });
    }
    None
}

fn execute(action: &PlannedAction, conn: &ConnInfo) -> Result<String, String> {
    match action {
        PlannedAction::KillConnection => active_response::kill_connection(conn).map_err(|err| err.to_string()),
        PlannedAction::BlockRemote { target, preset } => active_response::block_remote(target, *preset),
        PlannedAction::BlockProcess { pid, path, preset } => active_response::block_process(*pid, path, *preset),
    }
}

fn describe_action(action: &PlannedAction, conn: &ConnInfo) -> String {
    match action {
        PlannedAction::KillConnection => format!("kill connection {} -> {}", conn.local_addr, conn.remote_addr),
        PlannedAction::BlockRemote { target, preset } => format!("block remote {target} for {}", describe_preset(*preset)),
        PlannedAction::BlockProcess { path, preset, .. } => format!("block process traffic for {path} for {}", describe_preset(*preset)),
    }
}

fn describe_preset(preset: active_response::DurationPreset) -> &'static str {
    match preset { active_response::DurationPreset::OneHour => "1 hour", active_response::DurationPreset::OneDay => "24 hours", active_response::DurationPreset::Permanent => "an unlimited duration" }
}

fn is_trusted_process(conn: &ConnInfo, cfg: &Config) -> bool {
    let key = normalise_name(&conn.proc_name);
    cfg.trusted_processes.iter().any(|trusted| trusted.eq_ignore_ascii_case(&key))
}
fn is_allowlisted_process(conn: &ConnInfo, cfg: &Config) -> bool {
    if is_trusted_process(conn, cfg) { return true; }
    let key = normalise_name(&conn.proc_name);
    cfg.allowlist_processes.iter().any(|entry| {
        let entry_norm = normalise_name(entry);
        entry.eq_ignore_ascii_case(&conn.proc_path) || entry_norm == key
    }) || conn.publisher.to_ascii_lowercase().contains("microsoft")
}
fn is_allowlist_enforcement(action: &PlannedAction, conn: &ConnInfo, cfg: &Config) -> bool {
    cfg.allowlist_mode_enabled && !is_allowlisted_process(conn, cfg) && matches!(action, PlannedAction::BlockProcess { preset: active_response::DurationPreset::Permanent, .. })
}

fn signal_strength(conn: &ConnInfo) -> u8 {
    let mut strength = 0u8; let mut has_primary_signal = false;
    if conn.reputation_hit.is_some() { strength += 2; has_primary_signal = true; }
    if conn.recently_dropped { strength += 1; has_primary_signal = true; }
    if conn.dga_like { strength += 1; has_primary_signal = true; }
    if conn.pre_login { strength += 1; }
    if conn.publisher.trim().is_empty() { strength += 1; }
    if conn.reasons.iter().any(|reason| reason.to_ascii_lowercase().contains("beacon")) { strength += 1; has_primary_signal = true; }
    if conn.reasons.iter().any(|reason| reason.to_ascii_lowercase().contains("malware port")) { strength += 1; }
    if has_primary_signal { strength } else { 0 }
}

fn cooldown_key(action: &PlannedAction, conn: &ConnInfo) -> String {
    match action {
        PlannedAction::KillConnection => format!("kill-connection:{}:{}", conn.local_addr, conn.remote_addr),
        PlannedAction::BlockRemote { target, .. } => format!("block-remote:{target}"),
        PlannedAction::BlockProcess { path, .. } => format!("block-process:{path}"),
    }
}
fn offence_key(conn: &ConnInfo) -> String { let remote = active_response::extract_remote_target(&conn.remote_addr).unwrap_or_else(|| conn.remote_addr.clone()); format!("{}:{}:{}", conn.pid, normalise_name(&conn.proc_name), remote) }
fn offence_window(cfg: &Config) -> Duration { Duration::from_secs(cfg.auto_response_cooldown_secs.max(30).saturating_mul(3)) }

impl EngineState {
    fn try_acquire(&mut self, key: String, cooldown: Duration) -> bool { let now = Instant::now(); self.cooldowns.retain(|_, at| now.duration_since(*at) < cooldown.saturating_mul(2)); if let Some(previous) = self.cooldowns.get(&key) { if now.duration_since(*previous) < cooldown { return false; } } self.cooldowns.insert(key, now); true }
    fn record_offence(&mut self, conn: &ConnInfo, offence_window: Duration) -> u8 { let now = Instant::now(); self.offences.retain(|_, state| now.duration_since(state.last_seen) < offence_window.saturating_mul(2)); let key = offence_key(conn); let entry = self.offences.entry(key).or_insert(OffenceState { count: 0, last_seen: now }); if now.duration_since(entry.last_seen) > offence_window { entry.count = 0; } entry.count = entry.count.saturating_add(1); entry.last_seen = now; entry.count }
}
