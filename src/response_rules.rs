//! User-defined response rules loaded from YAML.
//!
//! The rule file is optional and operator-controlled. Rules are evaluated in
//! order; the first matching rule wins. Current actions intentionally reuse the
//! existing active-response primitives so every action stays reversible and
//! audited in the same way as the built-in controls.

use crate::{active_response, audit, config::{normalise_name, Config}, types::ConnInfo};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct EngineState {
    cooldowns: HashMap<String, Instant>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<ResponseRule>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseRule {
    pub name: String,
    #[serde(default)] pub min_score: Option<u8>,
    #[serde(default)] pub process_name_contains: Option<String>,
    #[serde(default)] pub remote_contains: Option<String>,
    #[serde(default)] pub require_unsigned: bool,
    #[serde(default)] pub require_pre_login: bool,
    #[serde(default)] pub require_reputation_hit: bool,
    #[serde(default)] pub require_dga: bool,
    #[serde(default)] pub require_recently_dropped: bool,
    #[serde(default)] pub require_long_lived: bool,
    #[serde(default)] pub action: RuleAction,
    #[serde(default)] pub duration: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    #[default]
    KillConnection,
    BlockRemote,
    BlockProcess,
    Quarantine,
}

pub fn maybe_apply(conn: &ConnInfo, cfg: &Config, state: &mut EngineState) -> Option<String> {
    if !cfg.response_rules_enabled || cfg.response_rules_path.trim().is_empty() || is_trusted_process(conn, cfg) {
        return None;
    }
    let rules = load_rules(&cfg.response_rules_path).ok()?;
    let rule = rules.into_iter().find(|rule| matches_rule(rule, conn))?;
    let action = plan_action(&rule, conn)?;
    let cooldown = Duration::from_secs(cfg.auto_response_cooldown_secs.max(30));
    let key = format!("{}:{}", rule.name, cooldown_key(&action, conn));
    if !state.try_acquire(key, cooldown) {
        return None;
    }
    let summary = describe_action(&rule.name, &action, conn);
    if cfg.response_rules_dry_run {
        audit::record("response_rule", "dry_run", json!({"rule": rule.name, "summary": summary, "pid": conn.pid, "proc_name": conn.proc_name, "remote_addr": conn.remote_addr, "score": conn.score }));
        return Some(format!("Response-rule dry run: {summary}."));
    }
    let result = execute(&action, conn);
    match result {
        Ok(message) => {
            audit::record("response_rule", "success", json!({"rule": rule.name, "message": message, "pid": conn.pid, "proc_name": conn.proc_name, "remote_addr": conn.remote_addr, "score": conn.score }));
            Some(format!("Response rule: {message}"))
        }
        Err(err) => {
            audit::record("response_rule", "failure", json!({"rule": rule.name, "error": err, "pid": conn.pid, "proc_name": conn.proc_name, "remote_addr": conn.remote_addr, "score": conn.score }));
            Some(format!("Response rule failed: {summary} ({err})"))
        }
    }
}

fn load_rules(path: &str) -> Result<Vec<ResponseRule>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("failed to read rule file {path}: {e}"))?;
    let file: RuleFile = serde_yaml::from_str(&text).map_err(|e| format!("failed to parse YAML rule file {path}: {e}"))?;
    Ok(file.rules)
}

fn matches_rule(rule: &ResponseRule, conn: &ConnInfo) -> bool {
    if rule.min_score.is_some_and(|min| conn.score < min) { return false; }
    if rule.require_unsigned && !conn.publisher.trim().is_empty() { return false; }
    if rule.require_pre_login && !conn.pre_login { return false; }
    if rule.require_reputation_hit && conn.reputation_hit.is_none() { return false; }
    if rule.require_dga && !conn.dga_like { return false; }
    if rule.require_recently_dropped && !conn.recently_dropped { return false; }
    if rule.require_long_lived && !conn.long_lived { return false; }
    if let Some(text) = rule.process_name_contains.as_ref() {
        if !normalise_name(&conn.proc_name).contains(&normalise_name(text)) { return false; }
    }
    if let Some(text) = rule.remote_contains.as_ref() {
        let text = text.to_ascii_lowercase();
        if !conn.remote_addr.to_ascii_lowercase().contains(&text) && !conn.hostname.as_deref().unwrap_or_default().to_ascii_lowercase().contains(&text) { return false; }
    }
    true
}

#[derive(Debug, Clone)]
enum PlannedAction {
    KillConnection,
    BlockRemote { target: String, preset: active_response::DurationPreset },
    BlockProcess { pid: u32, path: String, preset: active_response::DurationPreset },
    Quarantine { pid: u32, path: String, proc_name: String },
}

fn plan_action(rule: &ResponseRule, conn: &ConnInfo) -> Option<PlannedAction> {
    let preset = parse_duration(rule.duration.as_deref());
    match rule.action {
        RuleAction::KillConnection if active_response::can_kill_connection(conn) => Some(PlannedAction::KillConnection),
        RuleAction::BlockRemote => active_response::extract_remote_target(&conn.remote_addr).map(|target| PlannedAction::BlockRemote { target, preset }),
        RuleAction::BlockProcess if !conn.proc_path.trim().is_empty() => Some(PlannedAction::BlockProcess { pid: conn.pid, path: conn.proc_path.clone(), preset }),
        RuleAction::Quarantine => Some(PlannedAction::Quarantine { pid: conn.pid, path: conn.proc_path.clone(), proc_name: conn.proc_name.clone() }),
        _ => None,
    }
}

fn parse_duration(text: Option<&str>) -> active_response::DurationPreset {
    match text.unwrap_or("1h").trim().to_ascii_lowercase().as_str() {
        "24h" | "1d" | "day" => active_response::DurationPreset::OneDay,
        "permanent" | "forever" => active_response::DurationPreset::Permanent,
        _ => active_response::DurationPreset::OneHour,
    }
}

fn execute(action: &PlannedAction, conn: &ConnInfo) -> Result<String, String> {
    match action {
        PlannedAction::KillConnection => active_response::kill_connection(conn).map_err(|e| e.to_string()),
        PlannedAction::BlockRemote { target, preset } => active_response::block_remote(target, *preset),
        PlannedAction::BlockProcess { pid, path, preset } => active_response::block_process(*pid, path, *preset),
        PlannedAction::Quarantine { pid, path, proc_name } => active_response::apply_quarantine_profile(*pid, path, proc_name),
    }
}

fn describe_action(rule_name: &str, action: &PlannedAction, conn: &ConnInfo) -> String {
    match action {
        PlannedAction::KillConnection => format!("rule {rule_name} kills {} -> {}", conn.local_addr, conn.remote_addr),
        PlannedAction::BlockRemote { target, .. } => format!("rule {rule_name} blocks remote {target}"),
        PlannedAction::BlockProcess { path, .. } => format!("rule {rule_name} blocks process {path}"),
        PlannedAction::Quarantine { pid, .. } => format!("rule {rule_name} quarantines pid {pid}"),
    }
}

fn cooldown_key(action: &PlannedAction, conn: &ConnInfo) -> String {
    match action {
        PlannedAction::KillConnection => format!("kill:{}:{}", conn.local_addr, conn.remote_addr),
        PlannedAction::BlockRemote { target, .. } => format!("remote:{target}"),
        PlannedAction::BlockProcess { path, .. } => format!("proc:{path}"),
        PlannedAction::Quarantine { pid, .. } => format!("quarantine:{pid}"),
    }
}

fn is_trusted_process(conn: &ConnInfo, cfg: &Config) -> bool {
    let key = normalise_name(&conn.proc_name);
    cfg.trusted_processes.iter().any(|trusted| trusted.eq_ignore_ascii_case(&key))
}

impl EngineState {
    fn try_acquire(&mut self, key: String, cooldown: Duration) -> bool {
        let now = Instant::now();
        self.cooldowns.retain(|_, at| now.duration_since(*at) < cooldown.saturating_mul(2));
        if self.cooldowns.get(&key).is_some_and(|previous| now.duration_since(*previous) < cooldown) { return false; }
        self.cooldowns.insert(key, now);
        true
    }
}
