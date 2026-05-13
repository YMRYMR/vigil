//! User-defined response rules loaded from YAML.
//!
//! The rule file is optional and operator-controlled. Rules are evaluated in
//! order; the first matching rule wins. Current actions intentionally reuse the
//! existing active-response primitives so every action stays reversible and
//! audited in the same way as the built-in controls. `<rules-file>.sha256`
//! is required beside the YAML file; Vigil verifies the SHA-256 digest before
//! parsing and refuses missing or tampered rule files.
//!
//! Advisory-aware predicates intentionally consume only the normalized,
//! high-confidence advisory reason strings already attached to a connection.
//! This keeps the Phase 16 rule slice conservative: no extra live cache
//! lookups happen in the rule engine, and a missing or unparsable advisory
//! reason simply leaves the advisory predicates unmatched instead of guessing.

use crate::{
    active_response, audit,
    config::{normalise_name, Config},
    security::integrity,
    types::ConnInfo,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct EngineState {
    cooldowns: HashMap<String, Instant>,
    last_rule_load_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<ResponseRule>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseRule {
    pub name: String,
    #[serde(default)]
    pub min_score: Option<u8>,
    #[serde(default)]
    pub process_name_contains: Option<String>,
    #[serde(default)]
    pub remote_contains: Option<String>,
    #[serde(default)]
    pub require_unsigned: bool,
    #[serde(default)]
    pub require_pre_login: bool,
    #[serde(default)]
    pub require_reputation_hit: bool,
    #[serde(default)]
    pub require_dga: bool,
    #[serde(default)]
    pub require_recently_dropped: bool,
    #[serde(default)]
    pub require_long_lived: bool,
    #[serde(default)]
    pub require_advisory_match: bool,
    #[serde(default)]
    pub require_known_exploited_advisory: bool,
    #[serde(default)]
    pub require_advisory_mitigation_guidance: bool,
    #[serde(default)]
    pub require_missing_advisory_fix_version: bool,
    #[serde(default)]
    pub advisory_id_contains: Option<String>,
    #[serde(default)]
    pub advisory_product_contains: Option<String>,
    #[serde(default)]
    pub min_advisory_severity: Option<AdvisorySeverity>,
    #[serde(default)]
    pub action: RuleAction,
    #[serde(default)]
    pub duration: Option<String>,
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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedAdvisoryReason<'a> {
    primary_id: &'a str,
    product_name: &'a str,
    severity: Option<AdvisorySeverity>,
    known_exploited: bool,
    mitigation_guidance: bool,
    missing_fix_version: bool,
}

pub fn maybe_apply(conn: &ConnInfo, cfg: &Config, state: &mut EngineState) -> Option<String> {
    if !cfg.response_rules_enabled
        || cfg.response_rules_path.trim().is_empty()
        || is_trusted_process(conn, cfg)
    {
        return None;
    }
    let rules = match load_rules(&cfg.response_rules_path) {
        Ok(rules) => {
            state.clear_rule_load_error();
            rules
        }
        Err(err) => {
            if !state.note_rule_load_error(&cfg.response_rules_path, &err) {
                return None;
            }
            audit::record(
                "response_rule",
                "integrity_failure",
                json!({"path": cfg.response_rules_path, "error": err}),
            );
            return Some(format!("Response rules unavailable: {err}"));
        }
    };
    let rule = rules.into_iter().find(|rule| matches_rule(rule, conn))?;
    let action = plan_action(&rule, conn)?;
    let cooldown = Duration::from_secs(cfg.auto_response_cooldown_secs.max(30));
    let key = format!("{}:{}", rule.name, cooldown_key(&action, conn));
    if !state.try_acquire(key, cooldown) {
        return None;
    }
    let summary = describe_action(&rule.name, &action, conn);
    if cfg.response_rules_dry_run {
        audit::record(
            "response_rule",
            "dry_run",
            json!({"rule": rule.name, "summary": summary, "pid": conn.pid, "proc_name": conn.proc_name, "remote_addr": conn.remote_addr, "score": conn.score }),
        );
        return Some(format!("Response-rule dry run: {summary}."));
    }
    let result = execute(&action, conn);
    match result {
        Ok(message) => {
            audit::record(
                "response_rule",
                "success",
                json!({"rule": rule.name, "message": message, "pid": conn.pid, "proc_name": conn.proc_name, "remote_addr": conn.remote_addr, "score": conn.score }),
            );
            Some(format!("Response rule: {message}"))
        }
        Err(err) => {
            audit::record(
                "response_rule",
                "failure",
                json!({"rule": rule.name, "error": err, "pid": conn.pid, "proc_name": conn.proc_name, "remote_addr": conn.remote_addr, "score": conn.score }),
            );
            Some(format!("Response rule failed: {summary} ({err})"))
        }
    }
}

fn load_rules(path: &str) -> Result<Vec<ResponseRule>, String> {
    let path_ref = Path::new(path);
    load_rules_with_post_verify_hook(path_ref, |_path_ref| {
        #[cfg(not(test))]
        let _observation = crate::security::operator_provenance::observe_operator_file(
            "response_rules",
            _path_ref,
        );
    })
}

fn load_rules_with_post_verify_hook<F>(
    path_ref: &Path,
    mut post_verify: F,
) -> Result<Vec<ResponseRule>, String>
where
    F: FnMut(&Path),
{
    let (text, status) = integrity::read_verified_to_string(path_ref, "response rules")?;
    post_verify(path_ref);
    match status {
        integrity::VerificationStatus::Verified { sidecar } => {
            info_verified_rules_once(path_ref, &sidecar)
        }
    }
    let path = path_ref.display();
    let file: RuleFile = serde_yaml::from_str(&text)
        .map_err(|e| format!("failed to parse YAML rule file {path}: {e}"))?;
    Ok(file.rules)
}

fn info_verified_rules_once(path: &Path, sidecar: &Path) {
    if note_logged_rule_path(&VERIFIED_RULE_PATHS, path) {
        tracing::info!(
            "verified response rules {} with sidecar {}",
            path.display(),
            sidecar.display()
        );
    }
}

static VERIFIED_RULE_PATHS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn note_logged_rule_path(paths: &'static OnceLock<Mutex<HashSet<String>>>, path: &Path) -> bool {
    let paths = paths.get_or_init(|| Mutex::new(HashSet::new()));
    let Ok(mut paths) = paths.lock() else {
        tracing::debug!(
            "response rules logging cache unavailable for {}",
            path.display()
        );
        return false;
    };
    let path = path.display().to_string();
    paths.insert(path)
}

fn matches_rule(rule: &ResponseRule, conn: &ConnInfo) -> bool {
    if rule.min_score.is_some_and(|min| conn.score < min) {
        return false;
    }
    if rule.require_unsigned && !conn.publisher.trim().is_empty() {
        return false;
    }
    if rule.require_pre_login && !conn.pre_login {
        return false;
    }
    if rule.require_reputation_hit && conn.reputation_hit.is_none() {
        return false;
    }
    if rule.require_dga && !conn.dga_like {
        return false;
    }
    if rule.require_recently_dropped && !conn.recently_dropped {
        return false;
    }
    if rule.require_long_lived && !conn.long_lived {
        return false;
    }

    let advisory_reasons = parse_advisory_reasons(&conn.reasons);
    if !matches_advisory_filters(rule, &advisory_reasons) {
        return false;
    }

    if let Some(text) = rule.process_name_contains.as_ref() {
        if !normalise_name(&conn.proc_name).contains(&normalise_name(text)) {
            return false;
        }
    }
    if let Some(text) = rule.remote_contains.as_ref() {
        let text = text.to_ascii_lowercase();
        if !conn.remote_addr.to_ascii_lowercase().contains(&text)
            && !conn
                .hostname
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains(&text)
        {
            return false;
        }
    }
    true
}

fn matches_advisory_filters(
    rule: &ResponseRule,
    advisory_reasons: &[ParsedAdvisoryReason<'_>],
) -> bool {
    let has_advisory_filter = rule.require_advisory_match
        || rule.require_known_exploited_advisory
        || rule.require_advisory_mitigation_guidance
        || rule.require_missing_advisory_fix_version
        || rule.advisory_id_contains.is_some()
        || rule.advisory_product_contains.is_some()
        || rule.min_advisory_severity.is_some();
    if !has_advisory_filter {
        return true;
    }
    if advisory_reasons.is_empty() {
        return false;
    }

    let advisory_id_contains = rule
        .advisory_id_contains
        .as_ref()
        .map(|text| text.trim().to_ascii_lowercase())
        .filter(|text| !text.is_empty());
    if rule.advisory_id_contains.is_some() && advisory_id_contains.is_none() {
        return false;
    }

    let advisory_product_contains = rule
        .advisory_product_contains
        .as_ref()
        .map(|text| normalise_name(text))
        .filter(|text| !text.is_empty());
    if rule.advisory_product_contains.is_some() && advisory_product_contains.is_none() {
        return false;
    }

    advisory_reasons.iter().any(|reason| {
        (!rule.require_known_exploited_advisory || reason.known_exploited)
            && (!rule.require_advisory_mitigation_guidance || reason.mitigation_guidance)
            && (!rule.require_missing_advisory_fix_version || reason.missing_fix_version)
            && advisory_id_contains
                .as_ref()
                .is_none_or(|text| reason.primary_id.to_ascii_lowercase().contains(text))
            && advisory_product_contains
                .as_ref()
                .is_none_or(|text| normalise_name(reason.product_name).contains(text))
            && rule
                .min_advisory_severity
                .is_none_or(|min| reason.severity.is_some_and(|severity| severity >= min))
    })
}

fn parse_advisory_reasons<'a>(reasons: &'a [String]) -> Vec<ParsedAdvisoryReason<'a>> {
    reasons
        .iter()
        .filter_map(|reason| parse_advisory_reason(reason))
        .collect()
}

fn parse_advisory_reason(reason: &str) -> Option<ParsedAdvisoryReason<'_>> {
    const PREFIX: &str = "High-confidence advisory match: ";

    let body = reason.strip_prefix(PREFIX)?;
    let (left, product_name) = body.split_once(" applies to ")?;
    let product_name = product_name.trim();
    if product_name.is_empty() {
        return None;
    }

    let (primary_id, detail_block) = if let Some((primary_id, details)) = left.split_once(" (") {
        let details = details.strip_suffix(')')?;
        (primary_id.trim(), Some(details.trim()))
    } else {
        (left.trim(), None)
    };
    if primary_id.is_empty() {
        return None;
    }

    let mut severity = None;
    let mut known_exploited = false;
    let mut mitigation_guidance = false;
    let mut missing_fix_version = false;
    if let Some(detail_block) = detail_block {
        for detail in detail_block
            .split(',')
            .map(str::trim)
            .filter(|detail| !detail.is_empty())
        {
            if detail.eq_ignore_ascii_case("known exploited") {
                known_exploited = true;
                continue;
            }
            if detail.eq_ignore_ascii_case("mitigation guidance available") {
                mitigation_guidance = true;
                continue;
            }
            if detail.eq_ignore_ascii_case("no fixed-version bound") {
                missing_fix_version = true;
                continue;
            }
            if severity.is_none() {
                severity = parse_advisory_severity(detail);
            }
        }
    }

    Some(ParsedAdvisoryReason {
        primary_id,
        product_name,
        severity,
        known_exploited,
        mitigation_guidance,
        missing_fix_version,
    })
}

fn parse_advisory_severity(text: &str) -> Option<AdvisorySeverity> {
    let token = text.split_whitespace().next()?.trim().to_ascii_lowercase();
    match token.as_str() {
        "low" => Some(AdvisorySeverity::Low),
        "medium" => Some(AdvisorySeverity::Medium),
        "high" => Some(AdvisorySeverity::High),
        "critical" => Some(AdvisorySeverity::Critical),
        _ => None,
    }
}

#[derive(Debug, Clone)]
enum PlannedAction {
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
    Quarantine {
        pid: u32,
        path: String,
        proc_name: String,
    },
}

fn plan_action(rule: &ResponseRule, conn: &ConnInfo) -> Option<PlannedAction> {
    let preset = parse_duration(rule.duration.as_deref());
    match rule.action {
        RuleAction::KillConnection if active_response::can_kill_connection(conn) => {
            Some(PlannedAction::KillConnection)
        }
        RuleAction::BlockRemote => active_response::extract_remote_target(&conn.remote_addr)
            .map(|target| PlannedAction::BlockRemote { target, preset }),
        RuleAction::BlockProcess if !conn.proc_path.trim().is_empty() => {
            Some(PlannedAction::BlockProcess {
                pid: conn.pid,
                path: conn.proc_path.clone(),
                preset,
            })
        }
        RuleAction::Quarantine => Some(PlannedAction::Quarantine {
            pid: conn.pid,
            path: conn.proc_path.clone(),
            proc_name: conn.proc_name.clone(),
        }),
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
        PlannedAction::KillConnection => {
            active_response::kill_connection(conn).map_err(|e| e.to_string())
        }
        PlannedAction::BlockRemote { target, preset } => {
            active_response::block_remote(target, *preset)
        }
        PlannedAction::BlockProcess { pid, path, preset } => {
            active_response::block_process(*pid, path, *preset)
        }
        PlannedAction::Quarantine {
            pid,
            path,
            proc_name,
        } => active_response::apply_quarantine_profile(*pid, path, proc_name),
    }
}

fn describe_action(rule_name: &str, action: &PlannedAction, conn: &ConnInfo) -> String {
    match action {
        PlannedAction::KillConnection => format!(
            "rule {rule_name} kills {} -> {}",
            conn.local_addr, conn.remote_addr
        ),
        PlannedAction::BlockRemote { target, .. } => {
            format!("rule {rule_name} blocks remote {target}")
        }
        PlannedAction::BlockProcess { path, .. } => {
            format!("rule {rule_name} blocks process {path}")
        }
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
    cfg.trusted_processes
        .iter()
        .any(|trusted| trusted.eq_ignore_ascii_case(&key))
}

impl EngineState {
    fn try_acquire(&mut self, key: String, cooldown: Duration) -> bool {
        let now = Instant::now();
        self.cooldowns
            .retain(|_, at| now.duration_since(*at) < cooldown.saturating_mul(2));
        if self
            .cooldowns
            .get(&key)
            .is_some_and(|previous| now.duration_since(*previous) < cooldown)
        {
            return false;
        }
        self.cooldowns.insert(key, now);
        true
    }

    fn note_rule_load_error(&mut self, path: &str, err: &str) -> bool {
        let key = format!("{path}:{err}");
        if self.last_rule_load_error.as_deref() == Some(key.as_str()) {
            return false;
        }
        self.last_rule_load_error = Some(key);
        true
    }

    fn clear_rule_load_error(&mut self) {
        self.last_rule_load_error = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn signed_rule_file_loads() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        let yaml = "rules:\n  - name: high score\n    min_score: 9\n    action: block_remote\n";
        fs::write(&path, yaml).unwrap();
        write_sidecar(&path, yaml);

        let rules = load_rules(&path.to_string_lossy()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "high score");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tampered_signed_rule_file_is_rejected() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        let original = "rules: []\n";
        fs::write(&path, original).unwrap();
        write_sidecar(&path, original);
        fs::write(&path, "rules:\n  - name: tampered\n").unwrap();

        let err = load_rules(&path.to_string_lossy()).unwrap_err();
        assert!(err.contains("failed SHA-256 verification"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_sidecar_rule_file_is_rejected() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        fs::write(&path, "rules: []\n").unwrap();

        let err = load_rules(&path.to_string_lossy()).unwrap_err();
        assert!(err.contains("missing required SHA-256 sidecar"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn provenance_hook_runs_only_after_verified_rule_read() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        fs::write(&path, "rules: []\n").unwrap();

        let mut observed = false;
        let err = load_rules_with_post_verify_hook(&path, |_| observed = true).unwrap_err();
        assert!(err.contains("missing required SHA-256 sidecar"));
        assert!(!observed);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn repeated_rule_paths_only_log_once() {
        let path = Path::new("rules.yaml");
        assert!(note_logged_rule_path(&VERIFIED_RULE_PATHS, path));
        assert!(!note_logged_rule_path(&VERIFIED_RULE_PATHS, path));
    }

    #[test]
    fn repeated_rule_load_failures_are_reported_once_until_success() {
        let mut state = EngineState::default();

        assert!(state.note_rule_load_error("/tmp/rules.yaml", "signature mismatch"));
        assert!(!state.note_rule_load_error("/tmp/rules.yaml", "signature mismatch"));
        assert!(state.note_rule_load_error("/tmp/rules.yaml", "yaml parse failed"));

        state.clear_rule_load_error();

        assert!(state.note_rule_load_error("/tmp/rules.yaml", "signature mismatch"));
    }

    #[test]
    fn parses_advisory_reason_with_known_exploited_guidance_severity_and_fix_bound_marker() {
        let parsed = parse_advisory_reason(
            "High-confidence advisory match: CVE-2026-12345 (critical 9.8, known exploited, mitigation guidance available, no fixed-version bound) applies to Google Chrome",
        )
        .unwrap();

        assert_eq!(parsed.primary_id, "CVE-2026-12345");
        assert_eq!(parsed.product_name, "Google Chrome");
        assert_eq!(parsed.severity, Some(AdvisorySeverity::Critical));
        assert!(parsed.known_exploited);
        assert!(parsed.mitigation_guidance);
        assert!(parsed.missing_fix_version);
    }

    #[test]
    fn advisory_filters_match_high_confidence_reason() {
        let mut conn = sample_conn();
        conn.reasons = vec![
            "High-confidence advisory match: CVE-2026-12345 (critical 9.8, known exploited, mitigation guidance available, no fixed-version bound) applies to Google Chrome".into(),
        ];

        let rule = ResponseRule {
            name: "exploited browser advisory".into(),
            min_score: None,
            process_name_contains: None,
            remote_contains: None,
            require_unsigned: false,
            require_pre_login: false,
            require_reputation_hit: false,
            require_dga: false,
            require_recently_dropped: false,
            require_long_lived: false,
            require_advisory_match: true,
            require_known_exploited_advisory: true,
            require_advisory_mitigation_guidance: true,
            require_missing_advisory_fix_version: true,
            advisory_id_contains: Some("CVE-2026-12345".into()),
            advisory_product_contains: Some("chrome".into()),
            min_advisory_severity: Some(AdvisorySeverity::Critical),
            action: RuleAction::BlockRemote,
            duration: None,
        };

        assert!(matches_rule(&rule, &conn));
    }

    #[test]
    fn advisory_filters_do_not_mix_signals_from_different_reasons() {
        let mut conn = sample_conn();
        conn.reasons = vec![
            "High-confidence advisory match: CVE-2026-12345 (critical 9.8, known exploited) applies to Google Chrome".into(),
            "High-confidence advisory match: CVE-2026-99999 (medium 5.4, mitigation guidance available, no fixed-version bound) applies to Example Agent".into(),
        ];

        let rule = ResponseRule {
            require_advisory_match: true,
            require_known_exploited_advisory: true,
            require_advisory_mitigation_guidance: true,
            require_missing_advisory_fix_version: true,
            advisory_id_contains: Some("CVE-2026-12345".into()),
            advisory_product_contains: Some("chrome".into()),
            min_advisory_severity: Some(AdvisorySeverity::Critical),
            ..sample_rule()
        };

        assert!(!matches_rule(&rule, &conn));
    }

    #[test]
    fn advisory_filters_reject_missing_or_weaker_matches() {
        let mut conn = sample_conn();
        conn.reasons = vec![
            "High-confidence advisory match: CVE-2026-54321 (medium 5.4) applies to Example Agent"
                .into(),
        ];

        let exploited_rule = ResponseRule {
            require_advisory_match: true,
            require_known_exploited_advisory: true,
            require_advisory_mitigation_guidance: true,
            require_missing_advisory_fix_version: true,
            min_advisory_severity: Some(AdvisorySeverity::High),
            advisory_product_contains: Some("chrome".into()),
            ..sample_rule()
        };
        assert!(!matches_rule(&exploited_rule, &conn));

        let mut no_advisory_conn = sample_conn();
        no_advisory_conn.reasons = vec!["Unusual destination port 4444".into()];
        let advisory_rule = ResponseRule {
            require_advisory_match: true,
            ..sample_rule()
        };
        assert!(!matches_rule(&advisory_rule, &no_advisory_conn));
    }

    fn write_sidecar(path: &Path, content: &str) {
        let digest = Sha256::digest(content.as_bytes());
        fs::write(
            integrity::sidecar_path(path),
            format!(
                "{}  {}\n",
                hex(&digest),
                path.file_name().unwrap().to_string_lossy()
            ),
        )
        .unwrap();
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-response-rules-test-{nanos}"))
    }

    fn sample_rule() -> ResponseRule {
        ResponseRule {
            name: "sample".into(),
            min_score: None,
            process_name_contains: None,
            remote_contains: None,
            require_unsigned: false,
            require_pre_login: false,
            require_reputation_hit: false,
            require_dga: false,
            require_recently_dropped: false,
            require_long_lived: false,
            require_advisory_match: false,
            require_known_exploited_advisory: false,
            require_advisory_mitigation_guidance: false,
            require_missing_advisory_fix_version: false,
            advisory_id_contains: None,
            advisory_product_contains: None,
            min_advisory_severity: None,
            action: RuleAction::KillConnection,
            duration: None,
        }
    }

    fn sample_conn() -> ConnInfo {
        ConnInfo {
            timestamp: "12:00:00".into(),
            proc_name: "chrome.exe".into(),
            pid: 4242,
            proc_path: "C:/Program Files/Google/Chrome/chrome.exe".into(),
            proc_user: "user".into(),
            parent_user: "user".into(),
            parent_name: "explorer.exe".into(),
            parent_pid: 1337,
            service_name: String::new(),
            publisher: "Google LLC".into(),
            command_line: String::new(),
            local_addr: "10.0.0.2:51234".into(),
            remote_addr: "198.51.100.20:443".into(),
            status: "ESTABLISHED".into(),
            score: 10,
            reasons: vec![],
            attack_tags: vec![],
            ancestor_chain: vec![],
            pre_login: false,
            hostname: Some("example.test".into()),
            country: None,
            asn: None,
            asn_org: None,
            reputation_hit: None,
            recently_dropped: false,
            long_lived: false,
            dga_like: false,
            baseline_deviation: false,
            script_host_suspicious: false,
            tls_sni: None,
            tls_ja3: None,
        }
    }
}
