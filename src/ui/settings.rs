//! Settings tab — edits a live `Config` with auto-save on change.
//!
//! Changes are buffered in `SettingsDraft` and written to disk as soon as any
//! control changes. Returns `true` when the draft changed.
//!
//! Layout is responsive and fills the available width, so the trusted list can
//! breathe instead of collapsing into a narrow column.

use crate::config::{normalise_name, Config};
use crate::ui::theme;
use egui::RichText;

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

pub fn show(ui: &mut egui::Ui, draft: &mut SettingsDraft, elevated: bool) -> bool {
    let mut changed = false;
    egui::ScrollArea::vertical()
        .id_salt("settings_scroll")
        .show(ui, |ui| {
            ui.add_space(16.0);
            ui.vertical(|ui| {
                let content_w = ui.available_width();
                ui.set_max_width(content_w);
                ui.set_width(content_w);
                if !elevated {
                    ui.label(
                        RichText::new("Policy edits are locked until Admin Mode is active. Detection, display, and other non-sensitive preferences can still be adjusted.")
                            .color(theme::WARN)
                            .size(11.0),
                    );
                    ui.add_space(10.0);
                }
                inner(ui, draft, &mut changed);
            });
            ui.add_space(18.0);
        });
    changed
}

fn inner(ui: &mut egui::Ui, draft: &mut SettingsDraft, changed: &mut bool) {
    let label_w = 185.0f32;

    section_header(ui, "Display");
    setting_row(ui, label_w, "Font size", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::Slider::new(&mut draft.ui_scale, 0.8_f32..=1.8_f32)
                    .fixed_decimals(2)
                    .clamping(egui::SliderClamping::Always),
            );
            *changed |= resp.changed();
            ui.label(
                RichText::new(format!("  {}%", (draft.ui_scale * 100.0).round() as i32))
                    .color(theme::TEXT3)
                    .size(11.0),
            );
        });
    });
    ui.label(
        RichText::new(
            "Tip: hold Ctrl and use the mouse wheel anywhere in the app to adjust font size.",
        )
        .color(theme::TEXT3)
        .size(10.6),
    );
    ui.add_space(12.0);

    section_header(ui, "Detection");
    setting_row(ui, label_w, "Alert threshold", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::Slider::new(&mut draft.alert_threshold, 1_u8..=10_u8)
                    .clamping(egui::SliderClamping::Always),
            );
            *changed |= resp.changed();
            ui.label(
                RichText::new(format!("  score >= {} => alert", draft.alert_threshold))
                    .color(theme::TEXT3)
                    .size(11.0),
            );
        });
    });
    setting_row(ui, label_w, "Poll interval", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::Slider::new(&mut draft.poll_interval_secs, 2_u64..=60_u64)
                    .suffix(" s")
                    .clamping(egui::SliderClamping::Always),
            );
            *changed |= resp.changed();
            ui.label(
                RichText::new("  (ETW uses longer interval)")
                    .color(theme::TEXT3)
                    .size(11.0),
            );
        });
    });
    setting_row(ui, label_w, "Log all connections", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.log_all_connections,
                RichText::new("include score-0 connections in the log and activity table")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });

    ui.add_space(16.0);
    section_header(ui, "Auto response");
    ui.label(RichText::new("Optional and disabled by default. Vigil only auto-acts when this is enabled, the selected action type is enabled, the process is not trusted, and strong corroborating signals are present.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable auto response", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.auto_response_enabled,
                RichText::new("allow Vigil to take automated containment actions")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    setting_row(ui, label_w, "Dry run", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.auto_response_dry_run,
                RichText::new("log and surface planned actions without executing them")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    ui.add_enabled_ui(draft.auto_response_enabled, |ui| {
        setting_row(ui, label_w, "Minimum score", |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(egui::Slider::new(&mut draft.auto_response_min_score, 6_u8..=20_u8).clamping(egui::SliderClamping::Always));
                *changed |= resp.changed();
                ui.label(RichText::new(format!("  auto-response threshold: {}", draft.auto_response_min_score)).color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "Cooldown", |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(egui::Slider::new(&mut draft.auto_response_cooldown_secs, 30_u64..=3600_u64).suffix(" s").clamping(egui::SliderClamping::Always));
                *changed |= resp.changed();
                ui.label(RichText::new("  suppress duplicate actions for the same target").color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "Auto kill connection", |ui| {
            *changed |= ui.checkbox(&mut draft.auto_kill_connection, RichText::new("terminate a live IPv4 TCP connection when high-confidence signals match").color(theme::TEXT2).size(11.5)).changed();
        });
        setting_row(ui, label_w, "Auto block remote", |ui| {
            *changed |= ui.checkbox(&mut draft.auto_block_remote, RichText::new("optionally add a temporary 1-hour firewall rule for a suspicious remote IP").color(theme::TEXT2).size(11.5)).changed();
        });
        setting_row(ui, label_w, "Auto block process", |ui| {
            *changed |= ui.checkbox(&mut draft.auto_block_process, RichText::new("optionally add temporary process firewall rules for stronger high-confidence matches").color(theme::TEXT2).size(11.5)).changed();
        });
        setting_row(ui, label_w, "Auto isolate machine", |ui| {
            ui.label(RichText::new("reserved for future policy expansion; kept disabled in the current release").color(theme::TEXT3).size(11.0));
        });
    });
    if !draft.auto_response_enabled {
        ui.label(RichText::new("Auto response is currently disabled, so Vigil will only surface recommendations and manual actions.").color(theme::TEXT3).size(10.8));
    }

    ui.add_space(16.0);
    section_header(ui, "Allowlist-only mode");
    ui.label(RichText::new("Optional restrictive policy. When enabled, Vigil treats traffic from processes outside the trusted list, the custom allowlist, and Microsoft-signed system processes as containment candidates.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable allowlist mode", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.allowlist_mode_enabled,
                RichText::new("enforce network allowlisting for processes")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    setting_row(ui, label_w, "Allowlist dry run", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.allowlist_mode_dry_run,
                RichText::new("log planned allowlist containment without executing it")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    setting_row(ui, label_w, "Allowed processes", |ui| {
        let resp = ui.add(
            egui::TextEdit::multiline(&mut draft.allowlist_processes_text)
                .hint_text("one process name or full executable path per line")
                .desired_width(420.0)
                .desired_rows(5),
        );
        *changed |= resp.changed();
    });
    ui.label(RichText::new("Trusted processes are always treated as allowed. One entry per line; names are matched case-insensitively and .exe is ignored.").color(theme::TEXT3).size(10.8));

    ui.add_space(16.0);
    section_header(ui, "User-defined response rules");
    ui.label(RichText::new("Optional YAML rule engine. Rules are evaluated in order, first match wins, and can dry-run or execute the same containment actions used elsewhere in Vigil.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable rules", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.response_rules_enabled,
                RichText::new("load and evaluate a YAML response-rules file")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    setting_row(ui, label_w, "Rules dry run", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.response_rules_dry_run,
                RichText::new("log matching rules without executing their actions")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    setting_row(ui, label_w, "Rules file", |ui| {
        let resp = ui.add(
            egui::TextEdit::singleline(&mut draft.response_rules_path)
                .hint_text("path to response-rules.yaml")
                .desired_width(420.0),
        );
        *changed |= resp.changed();
    });
    ui.label(RichText::new("Supported rule actions currently include kill_connection, block_remote, block_process, and quarantine.").color(theme::TEXT3).size(10.8));

    ui.add_space(16.0);
    section_header(ui, "Scheduled lockdown");
    ui.label(RichText::new("Optionally isolate the machine automatically during a fixed time window. This reuses the same reversible firewall rules as the panic button and is currently implemented on Windows.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable schedule", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.scheduled_lockdown_enabled,
                RichText::new("automatically isolate the network during the selected hours")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    ui.add_enabled_ui(draft.scheduled_lockdown_enabled, |ui| {
        setting_row(ui, label_w, "Start time", |ui| {
            ui.horizontal(|ui| {
                let hour = ui.add(egui::Slider::new(&mut draft.scheduled_lockdown_start_hour, 0_u8..=23_u8).text("hour").clamping(egui::SliderClamping::Always));
                let minute = ui.add(egui::Slider::new(&mut draft.scheduled_lockdown_start_minute, 0_u8..=59_u8).text("minute").clamping(egui::SliderClamping::Always));
                *changed |= hour.changed() || minute.changed();
                ui.label(RichText::new(format!("  starts at {:02}:{:02}", draft.scheduled_lockdown_start_hour, draft.scheduled_lockdown_start_minute)).color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "End time", |ui| {
            ui.horizontal(|ui| {
                let hour = ui.add(egui::Slider::new(&mut draft.scheduled_lockdown_end_hour, 0_u8..=23_u8).text("hour").clamping(egui::SliderClamping::Always));
                let minute = ui.add(egui::Slider::new(&mut draft.scheduled_lockdown_end_minute, 0_u8..=59_u8).text("minute").clamping(egui::SliderClamping::Always));
                *changed |= hour.changed() || minute.changed();
                ui.label(RichText::new(format!("  ends at {:02}:{:02}", draft.scheduled_lockdown_end_hour, draft.scheduled_lockdown_end_minute)).color(theme::TEXT3).size(11.0));
            });
        });
        ui.label(RichText::new("Overnight windows are supported. Example: 23:00 to 06:00 isolates overnight and restores in the morning.").color(theme::TEXT3).size(10.8));
    });
    if !draft.scheduled_lockdown_enabled {
        ui.label(
            RichText::new("Scheduled lockdown is currently disabled.")
                .color(theme::TEXT3)
                .size(10.8),
        );
    }

    ui.add_space(16.0);
    section_header(ui, "Break-glass recovery");
    ui.label(RichText::new("When machine isolation is active, Vigil always arms a recovery watchdog. It keeps touching a heartbeat file while the app is alive, and a scheduled watchdog task restores the network if the heartbeat goes stale past the timeout.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Fail-safe mode", |ui| {
        ui.label(
            RichText::new("always on during isolation (safety override)")
                .color(theme::TEXT2)
                .size(11.5),
        );
    });
    setting_row(ui, label_w, "Recovery timeout", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::Slider::new(&mut draft.break_glass_timeout_mins, 1_u64..=240_u64)
                    .suffix(" min")
                    .clamping(egui::SliderClamping::Always),
            );
            *changed |= resp.changed();
            ui.label(
                RichText::new("  restores networking after this timeout if the heartbeat is stale")
                    .color(theme::TEXT3)
                    .size(11.0),
            );
        });
    });
    setting_row(ui, label_w, "Heartbeat interval", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::Slider::new(&mut draft.break_glass_heartbeat_secs, 5_u64..=300_u64)
                    .suffix(" s")
                    .clamping(egui::SliderClamping::Always),
            );
            *changed |= resp.changed();
            ui.label(
                RichText::new("  Vigil refreshes the heartbeat at this cadence while running")
                    .color(theme::TEXT3)
                    .size(11.0),
            );
        });
    });
    ui.label(RichText::new("Watchdog implementation uses the local OS scheduler (Windows Task Scheduler, Linux cron, macOS launchd) and runs the same Vigil binary with --break-glass-recover.").color(theme::TEXT3).size(10.8));

    ui.add_space(16.0);
    section_header(ui, "Forensics on alert");
    ui.label(RichText::new("Optional forensic capture for high-confidence alerts. Current implementation is Windows-only and can write process memory dumps and short packet captures when enabled.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable process dump", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.process_dump_on_alert,
                RichText::new("capture a process memory dump on sufficiently high-score alerts")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    ui.add_enabled_ui(draft.process_dump_on_alert, |ui| {
        setting_row(ui, label_w, "Dump minimum score", |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(egui::Slider::new(&mut draft.process_dump_min_score, 8_u8..=20_u8).clamping(egui::SliderClamping::Always));
                *changed |= resp.changed();
                ui.label(RichText::new(format!("  dump when score >= {}", draft.process_dump_min_score)).color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "Dump cooldown", |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(egui::Slider::new(&mut draft.process_dump_cooldown_secs, 60_u64..=7200_u64).suffix(" s").clamping(egui::SliderClamping::Always));
                *changed |= resp.changed();
                ui.label(RichText::new("  suppress repeated dumps for the same PID").color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "Dump directory", |ui| {
            let resp = ui.add(egui::TextEdit::singleline(&mut draft.process_dump_dir).hint_text("default: <data-dir>/artifacts/process-dumps").desired_width(420.0));
            *changed |= resp.changed();
        });
        ui.label(RichText::new("Windows implementation uses the built-in comsvcs MiniDump helper. Empty dump directory uses Vigil's per-user data folder.").color(theme::TEXT3).size(10.8));
    });
    if !draft.process_dump_on_alert {
        ui.label(
            RichText::new("Process dump on alert is currently disabled.")
                .color(theme::TEXT3)
                .size(10.8),
        );
    }

    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable PCAP capture", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.pcap_on_alert,
                RichText::new("capture a short packet window on sufficiently high-score alerts")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    ui.add_enabled_ui(draft.pcap_on_alert, |ui| {
        setting_row(ui, label_w, "PCAP minimum score", |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(egui::Slider::new(&mut draft.pcap_min_score, 8_u8..=20_u8).clamping(egui::SliderClamping::Always));
                *changed |= resp.changed();
                ui.label(RichText::new(format!("  capture when score >= {}", draft.pcap_min_score)).color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "Capture seconds", |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(egui::Slider::new(&mut draft.pcap_duration_secs, 5_u64..=120_u64).suffix(" s").clamping(egui::SliderClamping::Always));
                *changed |= resp.changed();
                ui.label(RichText::new("  short host-wide pktmon capture window").color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "PCAP cooldown", |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(egui::Slider::new(&mut draft.pcap_cooldown_secs, 60_u64..=7200_u64).suffix(" s").clamping(egui::SliderClamping::Always));
                *changed |= resp.changed();
                ui.label(RichText::new("  suppress repeated packet captures for the same PID").color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "Packet bytes", |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(egui::Slider::new(&mut draft.pcap_packet_size_bytes, 0_u32..=512_u32).clamping(egui::SliderClamping::Always));
                *changed |= resp.changed();
                ui.label(RichText::new("  0 = full packet, larger values truncate less").color(theme::TEXT3).size(11.0));
            });
        });
        setting_row(ui, label_w, "PCAP directory", |ui| {
            let resp = ui.add(egui::TextEdit::singleline(&mut draft.pcap_dir).hint_text("default: <data-dir>/artifacts/pcap").desired_width(420.0));
            *changed |= resp.changed();
        });
        ui.label(RichText::new("Windows implementation uses pktmon and converts the ETL trace to pcapng. Only one packet capture runs at a time.").color(theme::TEXT3).size(10.8));
    });
    if !draft.pcap_on_alert {
        ui.label(
            RichText::new("PCAP capture on alert is currently disabled.")
                .color(theme::TEXT3)
                .size(10.8),
        );
    }

    ui.add_space(16.0);
    section_header(ui, "Honeypot decoy files");
    ui.label(RichText::new("Optional canary documents. Vigil plants decoy files in common user folders, watches for touches, raises a synthetic alert, and can optionally isolate the machine.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable decoys", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.honeypot_decoys_enabled,
                RichText::new("create and monitor honeypot decoy files")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    setting_row(ui, label_w, "Auto isolate on touch", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.honeypot_auto_isolate,
                RichText::new("automatically isolate the machine when a decoy is touched")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });
    setting_row(ui, label_w, "Poll interval", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::Slider::new(&mut draft.honeypot_poll_secs, 5_u64..=300_u64)
                    .suffix(" s")
                    .clamping(egui::SliderClamping::Always),
            );
            *changed |= resp.changed();
            ui.label(
                RichText::new("  how often Vigil checks decoy timestamps")
                    .color(theme::TEXT3)
                    .size(11.0),
            );
        });
    });
    setting_row(ui, label_w, "Decoy names", |ui| {
        let resp = ui.add(
            egui::TextEdit::multiline(&mut draft.honeypot_decoy_names_text)
                .hint_text("one decoy filename per line")
                .desired_width(420.0)
                .desired_rows(4),
        );
        *changed |= resp.changed();
    });
    ui.label(
        RichText::new(
            "Desktop, Documents, Downloads, and Public Documents are used when available.",
        )
        .color(theme::TEXT3)
        .size(10.8),
    );

    ui.add_space(16.0);
    section_header(ui, "Startup");
    setting_row(ui, label_w, "Run at login", |ui| {
        ui.vertical(|ui| {
            *changed |= ui
                .checkbox(
                    &mut draft.autostart,
                    RichText::new("start Vigil automatically when you log in")
                        .color(theme::TEXT2)
                        .size(11.5),
                )
                .changed();
            ui.add_space(2.0);
            ui.label(
                RichText::new("On Windows, elevated runs use a highest-privilege scheduled task.")
                    .color(theme::TEXT3)
                    .size(10.2),
            );
        });
    });

    ui.add_space(16.0);
    section_header(ui, "Uninstall");
    ui.label(
        RichText::new(
            "Remove Vigil from startup/service registration and close this running instance. This does not delete evidence, logs, or exported artifacts from disk.",
        )
        .color(theme::TEXT2)
        .size(12.0),
    );
    ui.add_space(8.0);
    setting_row(ui, label_w, "Uninstall Vigil", |ui| {
        ui.vertical(|ui| {
            let uninstall = ui
                .add(
                    egui::Button::new(
                        RichText::new("Uninstall Vigil")
                            .color(theme::DANGER)
                            .size(11.5),
                    )
                    .fill(theme::DANGER_BG)
                    .stroke(egui::Stroke::new(1.0, theme::DANGER))
                    .corner_radius(6.0),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("Ask for confirmation before uninstalling Vigil and closing the app.");
            if uninstall.clicked() {
                draft.uninstall_confirm_requested = true;
            }
            ui.add_space(2.0);
            ui.label(
                RichText::new(
                    "Requires Admin Mode when service or elevated startup entries are installed.",
                )
                .color(theme::TEXT3)
                .size(10.2),
            );
        });
    });
    if draft.uninstall_confirm_requested {
        egui::Frame::NONE
            .fill(theme::DANGER_BG)
            .stroke(egui::Stroke::new(1.0, theme::DANGER))
            .corner_radius(10.0)
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Confirm uninstall? Vigil will disable its login/startup registration, remove the OS service/daemon when present, and then close.",
                    )
                    .color(theme::TEXT)
                    .size(11.5),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Yes, uninstall and close")
                                    .color(theme::DANGER)
                                    .size(11.0),
                            )
                            .fill(theme::SURFACE2)
                            .stroke(egui::Stroke::new(1.0, theme::DANGER))
                            .corner_radius(6.0),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        draft.uninstall_requested = true;
                        draft.uninstall_confirm_requested = false;
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Cancel")
                                    .color(theme::TEXT2)
                                    .size(11.0),
                            )
                            .fill(theme::SURFACE3)
                            .stroke(egui::Stroke::new(1.0, theme::BORDER))
                            .corner_radius(6.0),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        draft.uninstall_confirm_requested = false;
                    }
                });
            });
    }

    #[cfg(target_os = "linux")]
    {
        ui.add_space(16.0);
        section_header(ui, "Privileges");
        let elevated = crate::autostart::is_elevated();
        let (status_text, status_color) = if elevated {
            ("Elevated privileges: active", theme::ACCENT)
        } else {
            ("Elevated privileges: not active", theme::DANGER)
        };
        setting_row(ui, label_w, "Status", |ui| {
            ui.label(RichText::new(status_text).color(status_color).size(11.5));
        });
        if !elevated {
            setting_row(ui, label_w, "", |ui| {
                ui.vertical(|ui| {
                    if ui
                        .button(
                            RichText::new("Run as Admin")
                                .color(theme::ACCENT)
                                .size(11.5),
                        )
                        .clicked()
                    {
                        draft.grant_capabilities_requested = true;
                    }
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(
                            "Uses pkexec (polkit) to relaunch Vigil with elevated privileges.",
                        )
                        .color(theme::TEXT3)
                        .size(10.2),
                    );
                });
            });
        }
    }

    ui.add_space(16.0);
    section_header(ui, "Trusted Processes");
    ui.add_space(6.0);
    ui.label(RichText::new("Trusted processes are exempt from routine penalties and automatic response. They still alert on severe signals such as malware ports or suspicious ancestry. Matching is case-insensitive and ignores .exe.").color(theme::TEXT2).size(12.0));
    ui.add_space(10.0);

    ui.horizontal(|ui| {
        let te = egui::TextEdit::singleline(&mut draft.new_trusted_input)
            .hint_text("process name…")
            .desired_width(280.0);
        let resp = ui.add(te);
        let add_clicked = ui
            .add(
                egui::Button::new(RichText::new("  Add  ").color(theme::TEXT).size(12.0))
                    .fill(theme::ACCENT)
                    .stroke(egui::Stroke::new(1.0, theme::ACCENT))
                    .corner_radius(4.0),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text("Add this process name to the trusted list.")
            .clicked();
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (add_clicked || enter) && !draft.new_trusted_input.trim().is_empty() {
            let key = normalise_name(draft.new_trusted_input.trim());
            if !key.is_empty()
                && !draft
                    .trusted_processes
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(&key))
            {
                draft.trusted_processes.push(key);
                draft.trusted_processes.sort_unstable();
                *changed = true;
            }
            draft.new_trusted_input.clear();
        }
        ui.add_space(10.0);
        if ui
            .add(
                egui::Button::new(
                    RichText::new("Reset shipped defaults")
                        .color(theme::TEXT2)
                        .size(11.0),
                )
                .fill(theme::SURFACE2)
                .stroke(egui::Stroke::new(1.0, theme::BORDER))
                .corner_radius(4.0),
            )
            .on_hover_text("Restore the trusted list that ships with Vigil")
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            draft.trusted_processes = Config::default().trusted_processes;
            draft.trusted_filter.clear();
            draft.new_trusted_input.clear();
            draft.status_msg = Some((
                "Restored shipped trusted defaults.".into(),
                std::time::Instant::now(),
            ));
            *changed = true;
        }
    });

    ui.add_space(10.0);
    if let Some((msg, at)) = &draft.status_msg {
        if at.elapsed().as_secs() < 3 {
            ui.label(RichText::new(msg).color(theme::ACCENT).size(11.5));
            ui.add_space(8.0);
        } else {
            draft.status_msg = None;
        }
    }

    let mut remove_idx: Option<usize> = None;
    if draft.trusted_processes.is_empty() {
        ui.label(
            RichText::new("No trusted processes yet.")
                .color(theme::TEXT3)
                .size(11.5),
        );
    } else {
        let total = draft.trusted_processes.len();
        if total > 4 {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut draft.trusted_filter)
                        .hint_text("filter…")
                        .desired_width(180.0),
                );
                if !draft.trusted_filter.is_empty()
                    && ui
                        .add(
                            egui::Button::new(RichText::new("x").color(theme::TEXT2).size(11.0))
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::NONE),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("Clear trusted-processes filter.")
                        .clicked()
                {
                    draft.trusted_filter.clear();
                }
            });
            ui.add_space(6.0);
        }
        let filter_lower = draft.trusted_filter.to_lowercase();
        let filtered: Vec<usize> = draft
            .trusted_processes
            .iter()
            .enumerate()
            .filter(|(_, name)| {
                filter_lower.is_empty() || name.to_lowercase().contains(&filter_lower)
            })
            .map(|(i, _)| i)
            .collect();
        let visible = filtered.len();
        let count_label = if filter_lower.is_empty() || visible == total {
            format!("{} process{}", total, if total == 1 { "" } else { "es" })
        } else {
            format!("{} / {} processes", visible, total)
        };
        ui.label(RichText::new(&count_label).color(theme::TEXT3).size(11.5));
        ui.add_space(8.0);
        egui::Frame::NONE.fill(theme::SURFACE3).stroke(egui::Stroke::new(1.0, theme::BORDER)).corner_radius(12.0).inner_margin(egui::Margin::symmetric(12, 10)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Process").color(theme::TEXT3).size(11.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new("Action").color(theme::TEXT3).size(11.0).strong());
                });
            });
            ui.add_space(8.0);
            let viewport_h = ui.ctx().content_rect().height();
            // Reserve a large, stable viewport for trusted processes so this section
            // is usable when it appears near the bottom of the Settings page.
            let min_view_h = (viewport_h * 0.58).clamp(320.0, 640.0);
            let rows_hint_h = (visible.clamp(8, 14) as f32 * 40.0).max(320.0);
            let list_h = min_view_h.max(rows_hint_h);
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), list_h),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                        for orig_idx in filtered {
                            let name = draft.trusted_processes[orig_idx].clone();
                            egui::Frame::NONE.fill(theme::SURFACE2).stroke(egui::Stroke::new(1.0, theme::BORDER)).corner_radius(12.0).inner_margin(egui::Margin::symmetric(10, 5)).show(ui, |ui| {
                                ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), 38.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                    let (bar_rect, _) = ui.allocate_exact_size(egui::vec2(3.0, 16.0), egui::Sense::hover());
                                    ui.painter().rect_filled(bar_rect, 2.0, theme::ACCENT);
                                    ui.add_space(8.0);
                                    ui.vertical(|ui| {
                                        ui.label(RichText::new(&name).color(theme::TEXT).size(12.2));
                                        ui.label(RichText::new("Trusted for routine connections and automation suppression").color(theme::TEXT3).size(9.6));
                                    });
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        let remove_btn = egui::Button::new(RichText::new("Remove").color(theme::DANGER).size(11.0)).fill(theme::DANGER_BG).stroke(egui::Stroke::new(1.0, theme::DANGER)).corner_radius(7.0);
                                        if ui
                                            .add(remove_btn)
                                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                                            .on_hover_text("Remove this process from the trusted list.")
                                            .clicked()
                                        {
                                            remove_idx = Some(orig_idx);
                                        }
                                    });
                                });
                            });
                            ui.add_space(6.0);
                        }
                    });
                },
            );
        });
    }

    if let Some(idx) = remove_idx {
        draft.trusted_processes.remove(idx);
        *changed = true;
    }
}

fn section_header(ui: &mut egui::Ui, title: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(3.0, 16.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 2.0, theme::ACCENT);
        ui.add_space(8.0);
        ui.label(RichText::new(title).color(theme::TEXT).size(13.5).strong());
    });
    ui.add_space(10.0);
}

fn setting_row(ui: &mut egui::Ui, label_w: f32, label: &str, ctrl: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [label_w, 20.0],
            egui::Label::new(RichText::new(label).color(theme::TEXT).size(12.0)),
        );
        ui.add_space(8.0);
        ctrl(ui);
    });
    ui.add_space(8.0);
}
