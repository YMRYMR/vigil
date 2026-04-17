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
    pub scheduled_lockdown_enabled: bool,
    pub scheduled_lockdown_start_hour: u8,
    pub scheduled_lockdown_start_minute: u8,
    pub scheduled_lockdown_end_hour: u8,
    pub scheduled_lockdown_end_minute: u8,
    pub process_dump_on_alert: bool,
    pub process_dump_min_score: u8,
    pub process_dump_cooldown_secs: u64,
    pub process_dump_dir: String,
    pub status_msg: Option<(String, std::time::Instant)>,
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
            scheduled_lockdown_enabled: cfg.scheduled_lockdown_enabled,
            scheduled_lockdown_start_hour: cfg.scheduled_lockdown_start_hour,
            scheduled_lockdown_start_minute: cfg.scheduled_lockdown_start_minute,
            scheduled_lockdown_end_hour: cfg.scheduled_lockdown_end_hour,
            scheduled_lockdown_end_minute: cfg.scheduled_lockdown_end_minute,
            process_dump_on_alert: cfg.process_dump_on_alert,
            process_dump_min_score: cfg.process_dump_min_score,
            process_dump_cooldown_secs: cfg.process_dump_cooldown_secs,
            process_dump_dir: cfg.process_dump_dir.clone(),
            status_msg: None,
        }
    }

    pub fn apply_to(&self, cfg: &mut Config) {
        cfg.alert_threshold = self.alert_threshold;
        cfg.poll_interval_secs = self.poll_interval_secs;
        cfg.log_all_connections = self.log_all_connections;
        cfg.autostart = self.autostart;
        cfg.trusted_processes = self.trusted_processes.clone();
        cfg.auto_response_enabled = self.auto_response_enabled;
        cfg.auto_response_dry_run = self.auto_response_dry_run;
        cfg.auto_kill_connection = self.auto_kill_connection;
        cfg.auto_block_remote = self.auto_block_remote;
        cfg.auto_block_process = self.auto_block_process;
        cfg.auto_isolate_machine = self.auto_isolate_machine;
        cfg.auto_response_min_score = self.auto_response_min_score;
        cfg.auto_response_cooldown_secs = self.auto_response_cooldown_secs;
        cfg.scheduled_lockdown_enabled = self.scheduled_lockdown_enabled;
        cfg.scheduled_lockdown_start_hour = self.scheduled_lockdown_start_hour.min(23);
        cfg.scheduled_lockdown_start_minute = self.scheduled_lockdown_start_minute.min(59);
        cfg.scheduled_lockdown_end_hour = self.scheduled_lockdown_end_hour.min(23);
        cfg.scheduled_lockdown_end_minute = self.scheduled_lockdown_end_minute.min(59);
        cfg.process_dump_on_alert = self.process_dump_on_alert;
        cfg.process_dump_min_score = self.process_dump_min_score;
        cfg.process_dump_cooldown_secs = self.process_dump_cooldown_secs;
        cfg.process_dump_dir = self.process_dump_dir.trim().to_string();
    }
}

pub fn show(ui: &mut egui::Ui, draft: &mut SettingsDraft) -> bool {
    let mut changed = false;
    egui::ScrollArea::vertical().id_salt("settings_scroll").show(ui, |ui| {
        ui.add_space(16.0);
        ui.vertical(|ui| {
            let content_w = ui.available_width();
            ui.set_max_width(content_w);
            ui.set_width(content_w);
            inner(ui, draft, &mut changed);
        });
        ui.add_space(18.0);
    });
    changed
}

fn inner(ui: &mut egui::Ui, draft: &mut SettingsDraft, changed: &mut bool) {
    let label_w = 185.0f32;

    section_header(ui, "Detection");
    setting_row(ui, label_w, "Alert threshold", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(egui::Slider::new(&mut draft.alert_threshold, 1_u8..=10_u8).clamping(egui::SliderClamping::Always));
            *changed |= resp.changed();
            ui.label(RichText::new(format!("  score >= {} => alert", draft.alert_threshold)).color(theme::TEXT3).size(11.0));
        });
    });
    setting_row(ui, label_w, "Poll interval", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(egui::Slider::new(&mut draft.poll_interval_secs, 2_u64..=60_u64).suffix(" s").clamping(egui::SliderClamping::Always));
            *changed |= resp.changed();
            ui.label(RichText::new("  (ETW uses longer interval)").color(theme::TEXT3).size(11.0));
        });
    });
    setting_row(ui, label_w, "Log all connections", |ui| {
        *changed |= ui.checkbox(&mut draft.log_all_connections, RichText::new("include score-0 connections in the log and activity table").color(theme::TEXT2).size(11.5)).changed();
    });

    ui.add_space(16.0);
    section_header(ui, "Auto response");
    ui.label(RichText::new("Optional and disabled by default. Vigil only auto-acts when this is enabled, the selected action type is enabled, the process is not trusted, and strong corroborating signals are present.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable auto response", |ui| {
        *changed |= ui.checkbox(&mut draft.auto_response_enabled, RichText::new("allow Vigil to take automated containment actions").color(theme::TEXT2).size(11.5)).changed();
    });
    setting_row(ui, label_w, "Dry run", |ui| {
        *changed |= ui.checkbox(&mut draft.auto_response_dry_run, RichText::new("log and surface planned actions without executing them").color(theme::TEXT2).size(11.5)).changed();
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
    section_header(ui, "Scheduled lockdown");
    ui.label(RichText::new("Optionally isolate the machine automatically during a fixed time window. This reuses the same reversible firewall rules as the panic button and is currently implemented on Windows.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable schedule", |ui| {
        *changed |= ui.checkbox(&mut draft.scheduled_lockdown_enabled, RichText::new("automatically isolate the network during the selected hours").color(theme::TEXT2).size(11.5)).changed();
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
        ui.label(RichText::new("Scheduled lockdown is currently disabled.").color(theme::TEXT3).size(10.8));
    }

    ui.add_space(16.0);
    section_header(ui, "Forensics on alert");
    ui.label(RichText::new("Optional forensic capture for high-confidence alerts. Current implementation is Windows-only and writes process memory dumps to disk when enabled.").color(theme::TEXT2).size(12.0));
    ui.add_space(8.0);
    setting_row(ui, label_w, "Enable process dump", |ui| {
        *changed |= ui.checkbox(&mut draft.process_dump_on_alert, RichText::new("capture a process memory dump on sufficiently high-score alerts").color(theme::TEXT2).size(11.5)).changed();
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
        ui.label(RichText::new("Process dump on alert is currently disabled.").color(theme::TEXT3).size(10.8));
    }

    ui.add_space(16.0);
    section_header(ui, "Startup");
    setting_row(ui, label_w, "Run at login", |ui| {
        ui.vertical(|ui| {
            *changed |= ui.checkbox(&mut draft.autostart, RichText::new("start Vigil automatically when you log in").color(theme::TEXT2).size(11.5)).changed();
            ui.add_space(2.0);
            ui.label(RichText::new("On Windows, elevated runs use a highest-privilege scheduled task.").color(theme::TEXT3).size(10.2));
        });
    });

    ui.add_space(16.0);
    section_header(ui, "Trusted Processes");
    ui.add_space(6.0);
    ui.label(RichText::new("Trusted processes are exempt from routine penalties and automatic response. They still alert on severe signals such as malware ports or suspicious ancestry. Matching is case-insensitive and ignores .exe.").color(theme::TEXT2).size(12.0));
    ui.add_space(10.0);

    ui.horizontal(|ui| {
        let te = egui::TextEdit::singleline(&mut draft.new_trusted_input).hint_text("process name…").desired_width(280.0);
        let resp = ui.add(te);
        let add_clicked = ui.add(egui::Button::new(RichText::new("  Add  ").color(theme::TEXT).size(12.0)).fill(theme::ACCENT).stroke(egui::Stroke::new(1.0, theme::ACCENT)).corner_radius(4.0)).on_hover_cursor(egui::CursorIcon::PointingHand).clicked();
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (add_clicked || enter) && !draft.new_trusted_input.trim().is_empty() {
            let key = normalise_name(draft.new_trusted_input.trim());
            if !key.is_empty() && !draft.trusted_processes.iter().any(|t| t.eq_ignore_ascii_case(&key)) {
                draft.trusted_processes.push(key);
                draft.trusted_processes.sort_unstable();
                *changed = true;
            }
            draft.new_trusted_input.clear();
        }
        ui.add_space(10.0);
        if ui.add(egui::Button::new(RichText::new("Reset shipped defaults").color(theme::TEXT2).size(11.0)).fill(theme::SURFACE2).stroke(egui::Stroke::new(1.0, theme::BORDER)).corner_radius(4.0)).on_hover_text("Restore the trusted list that ships with Vigil").on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            draft.trusted_processes = Config::default().trusted_processes;
            draft.trusted_filter.clear();
            draft.new_trusted_input.clear();
            draft.status_msg = Some(("Restored shipped trusted defaults.".into(), std::time::Instant::now()));
            *changed = true;
        }
    });

    ui.add_space(10.0);
    if let Some((msg, at)) = &draft.status_msg {
        if at.elapsed().as_secs() < 3 { ui.label(RichText::new(msg).color(theme::ACCENT).size(11.5)); ui.add_space(8.0); } else { draft.status_msg = None; }
    }

    let mut remove_idx: Option<usize> = None;
    if draft.trusted_processes.is_empty() {
        ui.label(RichText::new("No trusted processes yet.").color(theme::TEXT3).size(11.5));
    } else {
        let total = draft.trusted_processes.len();
        if total > 4 {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut draft.trusted_filter).hint_text("filter…").desired_width(180.0));
                if !draft.trusted_filter.is_empty() && ui.add(egui::Button::new(RichText::new("x").color(theme::TEXT2).size(11.0)).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE)).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    draft.trusted_filter.clear();
                }
            });
            ui.add_space(6.0);
        }
        let filter_lower = draft.trusted_filter.to_lowercase();
        let filtered: Vec<usize> = draft.trusted_processes.iter().enumerate().filter(|(_, name)| filter_lower.is_empty() || name.to_lowercase().contains(&filter_lower)).map(|(i, _)| i).collect();
        let visible = filtered.len();
        let count_label = if filter_lower.is_empty() || visible == total { format!("{} process{}", total, if total == 1 { "" } else { "es" }) } else { format!("{} / {} processes", visible, total) };
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
            let list_h = (visible.max(4) as f32 * 42.0).clamp(210.0, 520.0);
            egui::ScrollArea::vertical().max_height(list_h).auto_shrink([false, false]).show(ui, |ui| {
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
                                if ui.add(remove_btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { remove_idx = Some(orig_idx); }
                            });
                        });
                    });
                    ui.add_space(6.0);
                }
            });
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
        ui.add_sized([label_w, 20.0], egui::Label::new(RichText::new(label).color(theme::TEXT).size(12.0)));
        ui.add_space(8.0);
        ctrl(ui);
    });
    ui.add_space(8.0);
}
