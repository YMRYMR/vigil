//! Optional, UI-layer auto-response policy engine.
//!
//! This module intentionally starts conservative:
//! - disabled by default
//! - dry-run by default
//! - automation is suppressed for trusted processes
//! - actions require strong corroborating signals, not just a high score
//! - actions are cooldown-limited per target to avoid thrashing

use crate::{
    active_response,
    config::{normalise_name, Config},
    types::ConnInfo,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct EngineState {
    cooldowns: HashMap<String, Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedAction {
    KillConnection,
    BlockRemote {
        target: String,
        preset: active_response::DurationPreset,
    },
    BlockProcess {
        pid: u32,
        path: String,
        preset: active_response::DurationPreset,
    },
}

pub fn maybe_apply(conn: &ConnInfo, cfg: &Config, state: &mut EngineState) -> Option<String> {
    let action = plan(conn, cfg)?;
    let cooldown = Duration::from_secs(cfg.auto_response_cooldown_secs.max(1));
    if !state.try_acquire(cooldown_key(&action), cooldown) {
        return None;
    }

    let summary = describe_action(&action, conn);
    if cfg.auto_response_dry_run {
        tracing::warn!(
            pid = conn.pid,
            proc_name = %conn.proc_name,
            score = conn.score,
            local_addr = %conn.local_addr,
            remote_addr = %conn.remote_addr,
            action = %summary,
            "auto-response dry run"
        );
        return Some(format!("Auto-response dry run: {summary}."));
    }

    let result = execute(&action, conn);
    match &result {
        Ok(message) => {
            tracing::warn!(
                pid = conn.pid,
                proc_name = %conn.proc_name,
                score = conn.score,
                local_addr = %conn.local_addr,
                remote_addr = %conn.remote_addr,
                action = %summary,
                result = %message,
                "auto-response executed"
            );
            Some(format!("Auto-response: {message}"))
        }
        Err(err) => {
            tracing::warn!(
                pid = conn.pid,
                proc_name = %conn.proc_name,
                score = conn.score,
                local_addr = %conn.local_addr,
                remote_addr = %conn.remote_addr,
                action = %summary,
                error = %err,
                "auto-response failed"
            );
            Some(format!("Auto-response failed: {summary} ({err})"))
        }
    }
}

pub fn plan(conn: &ConnInfo, cfg: &Config) -> Option<PlannedAction> {
    if !cfg.auto_response_enabled || conn.score < cfg.auto_response_min_score {
        return None;
    }
    if is_trusted_process(conn, cfg) {
        return None;
    }

    let signal_strength = signal_strength(conn);
    if signal_strength < 2 {
        return None;
    }

    if cfg.auto_kill_connection && active_response::can_kill_connection(conn) {
        return Some(PlannedAction::KillConnection);
    }

    if cfg.auto_block_remote {
        if let Some(target) = active_response::extract_remote_target(&conn.remote_addr) {
            return Some(PlannedAction::BlockRemote {
                target,
                preset: active_response::DurationPreset::OneHour,
            });
        }
    }

    if cfg.auto_block_process && signal_strength >= 3 && !conn.proc_path.trim().is_empty() {
        return Some(PlannedAction::BlockProcess {
            pid: conn.pid,
            path: conn.proc_path.clone(),
            preset: active_response::DurationPreset::OneHour,
        });
    }

    None
}

fn execute(action: &PlannedAction, conn: &ConnInfo) -> Result<String, String> {
    match action {
        PlannedAction::KillConnection => active_response::kill_connection(conn)
            .map_err(|err| err.to_string()),
        PlannedAction::BlockRemote { target, preset } => {
            active_response::block_remote(target, *preset)
        }
        PlannedAction::BlockProcess { pid, path, preset } => {
            active_response::block_process(*pid, path, *preset)
        }
    }
}

fn describe_action(action: &PlannedAction, conn: &ConnInfo) -> String {
    match action {
        PlannedAction::KillConnection => {
            format!("would kill connection {} -> {}", conn.local_addr, conn.remote_addr)
        }
        PlannedAction::BlockRemote { target, .. } => {
            format!("would block remote {target} for 1 hour")
        }
        PlannedAction::BlockProcess { path, .. } => {
            format!("would block process traffic for {path} for 1 hour")
        }
    }
}

fn is_trusted_process(conn: &ConnInfo, cfg: &Config) -> bool {
    let key = normalise_name(&conn.proc_name);
    cfg.trusted_processes
        .iter()
        .any(|trusted| trusted.eq_ignore_ascii_case(&key))
}

fn signal_strength(conn: &ConnInfo) -> u8 {
    let mut strength = 0u8;
    let mut has_primary_signal = false;

    if conn.reputation_hit.is_some() {
        strength += 2;
        has_primary_signal = true;
    }
    if conn.recently_dropped {
        strength += 1;
        has_primary_signal = true;
    }
    if conn.dga_like {
        strength += 1;
        has_primary_signal = true;
    }
    if conn.pre_login {
        strength += 1;
    }
    if conn.publisher.trim().is_empty() {
        strength += 1;
    }
    if conn
        .reasons
        .iter()
        .any(|reason| reason.to_ascii_lowercase().contains("beacon"))
    {
        strength += 1;
        has_primary_signal = true;
    }
    if conn
        .reasons
        .iter()
        .any(|reason| reason.to_ascii_lowercase().contains("malware port"))
    {
        strength += 1;
    }

    if has_primary_signal {
        strength
    } else {
        0
    }
}

fn cooldown_key(action: &PlannedAction) -> String {
    match action {
        PlannedAction::KillConnection => "kill-connection".to_string(),
        PlannedAction::BlockRemote { target, .. } => format!("block-remote:{target}"),
        PlannedAction::BlockProcess { path, .. } => format!("block-process:{path}"),
    }
}

impl EngineState {
    fn try_acquire(&mut self, key: String, cooldown: Duration) -> bool {
        let now = Instant::now();
        self.cooldowns
            .retain(|_, at| now.duration_since(*at) < cooldown.saturating_mul(2));
        if let Some(previous) = self.cooldowns.get(&key) {
            if now.duration_since(*previous) < cooldown {
                return false;
            }
        }
        self.cooldowns.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_conn() -> ConnInfo {
        ConnInfo {
            timestamp: "12:00:00".into(),
            proc_name: "evil.exe".into(),
            pid: 4242,
            proc_path: "C:/Temp/evil.exe".into(),
            proc_user: "user".into(),
            parent_name: "cmd.exe".into(),
            parent_pid: 123,
            service_name: String::new(),
            publisher: String::new(),
            local_addr: "192.168.1.10:50000".into(),
            remote_addr: "8.8.8.8:443".into(),
            status: "ESTABLISHED".into(),
            score: 12,
            reasons: vec!["beaconing cadence".into()],
            ancestor_chain: vec![("cmd.exe".into(), 123)],
            pre_login: false,
            hostname: Some("abcd1234.bad.example".into()),
            country: None,
            asn: None,
            asn_org: None,
            reputation_hit: Some("feed.txt".into()),
            recently_dropped: false,
            long_lived: false,
            dga_like: true,
        }
    }

    #[test]
    fn disabled_config_never_plans() {
        let cfg = Config::default();
        assert_eq!(plan(&sample_conn(), &cfg), None);
    }

    #[test]
    fn trusted_process_suppresses_automation() {
        let mut cfg = Config::default();
        cfg.auto_response_enabled = true;
        cfg.auto_block_remote = true;
        cfg.trusted_processes.push("evil".into());
        assert_eq!(plan(&sample_conn(), &cfg), None);
    }

    #[test]
    fn plans_remote_block_when_enabled_and_signals_are_strong() {
        let mut cfg = Config::default();
        cfg.auto_response_enabled = true;
        cfg.auto_block_remote = true;
        let planned = plan(&sample_conn(), &cfg).unwrap();
        assert!(matches!(
            planned,
            PlannedAction::BlockRemote {
                target,
                preset: active_response::DurationPreset::OneHour,
            } if target == "8.8.8.8"
        ));
    }

    #[test]
    fn process_block_requires_stronger_signal_and_known_path() {
        let mut cfg = Config::default();
        cfg.auto_response_enabled = true;
        cfg.auto_block_process = true;
        let planned = plan(&sample_conn(), &cfg).unwrap();
        assert!(matches!(
            planned,
            PlannedAction::BlockProcess {
                pid: 4242,
                ref path,
                preset: active_response::DurationPreset::OneHour,
            } if path == "C:/Temp/evil.exe"
        ));
    }

    #[test]
    fn cooldown_suppresses_duplicate_actions() {
        let mut state = EngineState::default();
        assert!(state.try_acquire("k".into(), Duration::from_secs(60)));
        assert!(!state.try_acquire("k".into(), Duration::from_secs(60)));
    }
}
