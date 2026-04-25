use crate::config::Config;

pub struct SettingsDraft {
    pub alert_threshold: u8,
    pub poll_interval_secs: u64,
    pub log_all_connections: bool,
    pub autostart: bool,
    pub trusted_processes: Vec<String>,
    pub new_trusted_input: String,
    pub trusted_filter: String,
    pub auto_response_enabled: bool,
    pub auto_response_dry_run: bool,
    pub auto_kill_connection: bool,
    pub auto_block_remote: bool,
    pub auto_block_process: bool,
    pub auto_isolate_machine: bool,
    pub auto_response_min_score: u8,
    pub auto_response_cooldown_secs: u64,
    pub allowlist_mode_enabled: bool,
    pub allowlist_mode_dry_run: bool,
    pub allowlist_processes_text: String,
    pub response_rules_enabled: bool,
    pub response_rules_dry_run: bool,
    pub response_rules_path: String,
    pub scheduled_lockdown_enabled: bool,
    pub scheduled_lockdown_start_hour: u8,
    pub scheduled_lockdown_start_minute: u8,
    pub scheduled_lockdown_end_hour: u8,
    pub scheduled_lockdown_end_minute: u8,
    pub process_dump_on_alert: bool,
    pub process_dump_min_score: u8,
    pub process_dump_cooldown_secs: u64,
    pub process_dump_dir: String,
    pub pcap_on_alert: bool,
    pub pcap_min_score: u8,
    pub pcap_duration_secs: u64,
    pub pcap_cooldown_secs: u64,
    pub pcap_packet_size_bytes: u32,
    pub pcap_dir: String,
    pub honeypot_decoys_enabled: bool,
    pub honeypot_auto_isolate: bool,
    pub honeypot_poll_secs: u64,
    pub honeypot_decoy_names_text: String,
    pub break_glass_timeout_mins: u64,
    pub break_glass_heartbeat_secs: u64,
    pub ui_scale: f32,
    pub status_msg: Option<(String, std::time::Instant)>,
    pub grant_capabilities_requested: bool,
    pub uninstall_confirm_requested: bool,
    pub uninstall_requested: bool,
}

impl SettingsDraft {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            alert_threshold: cfg.alert_threshold,
            poll_interval_secs: cfg.poll_interval_secs,
            log_all_connections: cfg.log_all_connections,
            autostart: cfg.autostart,
            trusted_processes: cfg.trusted_processes.clone(),
            new_trusted_input: String::new(),
            trusted_filter: String::new(),
            auto_response_enabled: cfg.auto_response_enabled,
            auto_response_dry_run: cfg.auto_response_dry_run,
            auto_kill_connection: cfg.auto_kill_connection,
            auto_block_remote: cfg.auto_block_remote,
            auto_block_process: cfg.auto_block_process,
            auto_isolate_machine: cfg.auto_isolate_machine,
            auto_response_min_score: cfg.auto_response_min_score,
            auto_response_cooldown_secs: cfg.auto_response_cooldown_secs,
            allowlist_mode_enabled: cfg.allowlist_mode_enabled,
            allowlist_mode_dry_run: cfg.allowlist_mode_dry_run,
            allowlist_processes_text: cfg.allowlist_processes.join("\n"),
            response_rules_enabled: cfg.response_rules_enabled,
            response_rules_dry_run: cfg.response_rules_dry_run,
            response_rules_path: cfg.response_rules_path.clone(),
            scheduled_lockdown_enabled: cfg.scheduled_lockdown_enabled,
            scheduled_lockdown_start_hour: cfg.scheduled_lockdown_start_hour,
            scheduled_lockdown_start_minute: cfg.scheduled_lockdown_start_minute,
            scheduled_lockdown_end_hour: cfg.scheduled_lockdown_end_hour,
            scheduled_lockdown_end_minute: cfg.scheduled_lockdown_end_minute,
            process_dump_on_alert: cfg.process_dump_on_alert,
            process_dump_min_score: cfg.process_dump_min_score,
            process_dump_cooldown_secs: cfg.process_dump_cooldown_secs,
            process_dump_dir: cfg.process_dump_dir.clone(),
            pcap_on_alert: cfg.pcap_on_alert,
            pcap_min_score: cfg.pcap_min_score,
            pcap_duration_secs: cfg.pcap_duration_secs,
            pcap_cooldown_secs: cfg.pcap_cooldown_secs,
            pcap_packet_size_bytes: cfg.pcap_packet_size_bytes,
            pcap_dir: cfg.pcap_dir.clone(),
            honeypot_decoys_enabled: cfg.honeypot_decoys_enabled,
            honeypot_auto_isolate: cfg.honeypot_auto_isolate,
            honeypot_poll_secs: cfg.honeypot_poll_secs,
            honeypot_decoy_names_text: cfg.honeypot_decoy_names.join("\n"),
            break_glass_timeout_mins: cfg.break_glass_timeout_mins,
            break_glass_heartbeat_secs: cfg.break_glass_heartbeat_secs,
            ui_scale: cfg.sanitised_ui_scale(),
            status_msg: None,
            grant_capabilities_requested: false,
            uninstall_confirm_requested: false,
            uninstall_requested: false,
        }
    }

    pub fn apply_to(&self, cfg: &mut Config, allow_policy_edits: bool) {
        macro_rules! set_if_changed {
            ($field:ident, $value:expr) => {{
                let value = $value;
                if cfg.$field != value {
                    cfg.$field = value;
                }
            }};
        }

        // Non-sensitive preferences can always be persisted.
        set_if_changed!(alert_threshold, self.alert_threshold);
        set_if_changed!(poll_interval_secs, self.poll_interval_secs);
        set_if_changed!(log_all_connections, self.log_all_connections);
        set_if_changed!(ui_scale, self.ui_scale.clamp(0.8, 1.8));

        if allow_policy_edits {
            set_if_changed!(autostart, self.autostart);
            set_if_changed!(trusted_processes, self.trusted_processes.clone());
            set_if_changed!(auto_response_enabled, self.auto_response_enabled);
            set_if_changed!(auto_response_dry_run, self.auto_response_dry_run);
            set_if_changed!(auto_kill_connection, self.auto_kill_connection);
            set_if_changed!(auto_block_remote, self.auto_block_remote);
            set_if_changed!(auto_block_process, self.auto_block_process);
            set_if_changed!(auto_isolate_machine, self.auto_isolate_machine);
            set_if_changed!(auto_response_min_score, self.auto_response_min_score);
            set_if_changed!(
                auto_response_cooldown_secs,
                self.auto_response_cooldown_secs
            );
            set_if_changed!(allowlist_mode_enabled, self.allowlist_mode_enabled);
            set_if_changed!(allowlist_mode_dry_run, self.allowlist_mode_dry_run);
            set_if_changed!(
                allowlist_processes,
                split_lines(&self.allowlist_processes_text)
            );
            set_if_changed!(response_rules_enabled, self.response_rules_enabled);
            set_if_changed!(response_rules_dry_run, self.response_rules_dry_run);
            set_if_changed!(
                response_rules_path,
                self.response_rules_path.trim().to_string()
            );
            set_if_changed!(scheduled_lockdown_enabled, self.scheduled_lockdown_enabled);
            set_if_changed!(
                scheduled_lockdown_start_hour,
                self.scheduled_lockdown_start_hour.min(23)
            );
            set_if_changed!(
                scheduled_lockdown_start_minute,
                self.scheduled_lockdown_start_minute.min(59)
            );
            set_if_changed!(
                scheduled_lockdown_end_hour,
                self.scheduled_lockdown_end_hour.min(23)
            );
            set_if_changed!(
                scheduled_lockdown_end_minute,
                self.scheduled_lockdown_end_minute.min(59)
            );
            set_if_changed!(process_dump_on_alert, self.process_dump_on_alert);
            set_if_changed!(process_dump_min_score, self.process_dump_min_score);
            set_if_changed!(process_dump_cooldown_secs, self.process_dump_cooldown_secs);
            set_if_changed!(process_dump_dir, self.process_dump_dir.trim().to_string());
            set_if_changed!(pcap_on_alert, self.pcap_on_alert);
            set_if_changed!(pcap_min_score, self.pcap_min_score);
            set_if_changed!(pcap_duration_secs, self.pcap_duration_secs);
            set_if_changed!(pcap_cooldown_secs, self.pcap_cooldown_secs);
            set_if_changed!(pcap_packet_size_bytes, self.pcap_packet_size_bytes);
            set_if_changed!(pcap_dir, self.pcap_dir.trim().to_string());
            set_if_changed!(honeypot_decoys_enabled, self.honeypot_decoys_enabled);
            set_if_changed!(honeypot_auto_isolate, self.honeypot_auto_isolate);
            set_if_changed!(honeypot_poll_secs, self.honeypot_poll_secs.clamp(5, 300));
            set_if_changed!(
                honeypot_decoy_names,
                split_lines(&self.honeypot_decoy_names_text)
            );
            cfg.break_glass_enabled = true;
            set_if_changed!(
                break_glass_timeout_mins,
                self.break_glass_timeout_mins.clamp(1, 240)
            );
            set_if_changed!(
                break_glass_heartbeat_secs,
                self.break_glass_heartbeat_secs.clamp(5, 300)
            );
        }
    }

    pub fn policy_edits_pending(&self, cfg: &Config) -> bool {
        self.autostart != cfg.autostart
            || self.trusted_processes != cfg.trusted_processes
            || self.auto_response_enabled != cfg.auto_response_enabled
            || self.auto_response_dry_run != cfg.auto_response_dry_run
            || self.auto_kill_connection != cfg.auto_kill_connection
            || self.auto_block_remote != cfg.auto_block_remote
            || self.auto_block_process != cfg.auto_block_process
            || self.auto_isolate_machine != cfg.auto_isolate_machine
            || self.auto_response_min_score != cfg.auto_response_min_score
            || self.auto_response_cooldown_secs != cfg.auto_response_cooldown_secs
            || self.allowlist_mode_enabled != cfg.allowlist_mode_enabled
            || self.allowlist_mode_dry_run != cfg.allowlist_mode_dry_run
            || split_lines(&self.allowlist_processes_text) != cfg.allowlist_processes
            || self.response_rules_enabled != cfg.response_rules_enabled
            || self.response_rules_dry_run != cfg.response_rules_dry_run
            || self.response_rules_path.trim() != cfg.response_rules_path
            || self.scheduled_lockdown_enabled != cfg.scheduled_lockdown_enabled
            || self.scheduled_lockdown_start_hour.min(23) != cfg.scheduled_lockdown_start_hour
            || self.scheduled_lockdown_start_minute.min(59) != cfg.scheduled_lockdown_start_minute
            || self.scheduled_lockdown_end_hour.min(23) != cfg.scheduled_lockdown_end_hour
            || self.scheduled_lockdown_end_minute.min(59) != cfg.scheduled_lockdown_end_minute
            || self.process_dump_on_alert != cfg.process_dump_on_alert
            || self.process_dump_min_score != cfg.process_dump_min_score
            || self.process_dump_cooldown_secs != cfg.process_dump_cooldown_secs
            || self.process_dump_dir.trim() != cfg.process_dump_dir
            || self.pcap_on_alert != cfg.pcap_on_alert
            || self.pcap_min_score != cfg.pcap_min_score
            || self.pcap_duration_secs != cfg.pcap_duration_secs
            || self.pcap_cooldown_secs != cfg.pcap_cooldown_secs
            || self.pcap_packet_size_bytes != cfg.pcap_packet_size_bytes
            || self.pcap_dir.trim() != cfg.pcap_dir
            || self.honeypot_decoys_enabled != cfg.honeypot_decoys_enabled
            || self.honeypot_auto_isolate != cfg.honeypot_auto_isolate
            || self.honeypot_poll_secs != cfg.honeypot_poll_secs
            || split_lines(&self.honeypot_decoy_names_text) != cfg.honeypot_decoy_names
            || self.break_glass_timeout_mins != cfg.break_glass_timeout_mins
            || self.break_glass_heartbeat_secs != cfg.break_glass_heartbeat_secs
    }
}

fn split_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty()
            && !out
                .iter()
                .any(|item: &String| item.eq_ignore_ascii_case(trimmed))
        {
            out.push(trimmed.to_string());
        }
    }
    out
}
