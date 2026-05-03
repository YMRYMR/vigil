//! Right-side inspector panel.
//!
//! The inspector is process-first. A process summary is always shown; when the
//! user clicks a specific stacked connection row, the selected connection is
//! shown underneath the process summary.

use crate::{
    active_response,
    ui::{has_known_location, is_ghost_process_name, theme, ProcessSelection},
};
use egui::{RichText, Ui};
use std::collections::BTreeSet;

const MAX_REASON_SCAN: usize = 1_200;
const MAX_REASON_PLAIN_ROWS: usize = 40;
const MAX_REASON_PORT_ROWS: usize = 24;
const MAX_INSPECTOR_VALUE_CHARS: usize = 600;

#[derive(Debug, Clone)]
pub enum Action {
    Trust,
    OpenLocation,
    Kill,
    SuspendProcess,
    ResumeProcess,
    FreezeAutoruns,
    RevertAutoruns,
    QuarantineProfile,
    ClearQuarantineProfile,
    RequestAdmin,
    BlockRemote(active_response::DurationPreset),
    BlockDomain,
    BlockProcess(active_response::DurationPreset),
    KillConnection,
    UnblockRemote,
    UnblockDomain,
    UnblockProcess,
    IsolateMachine,
    RestoreNetwork,
    KillConfirmed,
    KillCancelled,
}

pub fn show(
    ui: &mut Ui,
    selection: Option<&ProcessSelection>,
    kill_confirm: bool,
    inspector_state: &active_response::InspectorSnapshot,
) -> Option<Action> {
    match selection {
        Some(selection) => show_detail(ui, selection, kill_confirm, inspector_state),
        None => {
            show_placeholder(ui);
            None
        }
    }
}

fn show_placeholder(ui: &mut Ui) {
    let rect = ui.available_rect_before_wrap();
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "Select a process\nto inspect",
        egui::FontId::proportional(12.0),
        theme::TEXT3,
    );
}

fn show_detail(
    ui: &mut Ui,
    sel: &ProcessSelection,
    kill_confirm: bool,
    inspector_state: &active_response::InspectorSnapshot,
) -> Option<Action> {
    let mut action: Option<Action> = None;
    let ghost = is_ghost_process_name(&sel.proc_name);
    let known_location = has_known_location(sel);
    let trust_enabled = known_location;
    let open_location_enabled = known_location;
    let kill_enabled = !ghost;
    let suspend_enabled = inspector_state.suspend_enabled && !ghost;
    let response_enabled = inspector_state.firewall_modifiable;
    let isolation_enabled = inspector_state.network_isolation_modifiable;
    let domain_enabled = inspector_state.domain_modifiable;
    let response_status = inspector_state.status;
    let remote_target = inspector_state.remote_target.as_ref();
    let remote_blocked = inspector_state.remote_blocked;
    let remote_remaining = inspector_state.remote_remaining;
    let domain_target = inspector_state.domain_target.as_ref();
    let domain_blocked = inspector_state.domain_blocked;
    let process_blocked = inspector_state.process_blocked;
    let process_remaining = inspector_state.process_remaining;
    let process_suspended = inspector_state.process_suspended;
    let connection_kill_enabled = inspector_state.connection_kill_enabled;
    let isolated = response_status.isolated;
    let quarantine_ready = inspector_state.quarantine_ready && !ghost;
    let quarantine_active = isolated || process_blocked || process_suspended;
    let autoruns_frozen = response_status.frozen_autoruns;

    egui::ScrollArea::vertical().id_salt("help_scroll").show(ui, |ui| {
        ui.add_space(8.0);
        process_hero(ui, sel);
        ui.add_space(10.0);
        separator(ui);
        ui.add_space(8.0);

        section_header(ui, "Process");
        kv(ui, "PID", &sel.pid.to_string());
        kv(ui, "User", nonempty(&sel.proc_user));
        kv(ui, "Parent", &format!("{} ({})", nonempty(&sel.parent_name), sel.parent_pid));
        kv(ui, "Parent usr", nonempty(&sel.parent_user));
        kv(ui, "Service", nonempty(&sel.service_name));
        kv(ui, "Publisher", nonempty(&sel.publisher));
        if !sel.command_line.is_empty() {
            kv(ui, "Cmdline", &sel.command_line);
        }

        ui.add_space(8.0);
        separator(ui);
        ui.add_space(8.0);

        section_header(ui, "Connections");
        kv(ui, "Count", &format!("{}", sel.connection_count));
        kv(ui, "Distinct ports", &format!("{}", sel.distinct_ports));
        kv(ui, "Distinct remotes", &format!("{}", sel.distinct_remotes));
        let statuses = if sel.statuses.is_empty() { "n/a".to_string() } else { sel.statuses.join(", ") };
        kv(ui, "Statuses", statuses.as_str());

        ui.add_space(8.0);
        separator(ui);
        ui.add_space(8.0);

        section_header(ui, "Phase 12 heuristics");
        ui.horizontal_wrapped(|ui| {
            if sel.script_host_suspicious {
                chip(ui, "Script-host abuse");
            }
            if sel.baseline_deviation {
                chip(ui, "Behaviour drift");
            }
            if !sel.attack_tags.is_empty() {
                chip(ui, &format!("{} ATT&CK tag{}", sel.attack_tags.len(), if sel.attack_tags.len() == 1 { "" } else { "s" }));
            }
        });
        if !sel.attack_tags.is_empty() {
            ui.add_space(4.0);
            for tag in &sel.attack_tags {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("> ").color(theme::ACCENT).size(10.0));
                    ui.add(egui::Label::new(RichText::new(tag).color(theme::TEXT2).size(10.8)).wrap());
                });
            }
        } else {
            ui.label(RichText::new("No ATT&CK mappings recorded for this process group.").color(theme::TEXT3).size(10.6));
        }

        ui.add_space(8.0);
        separator(ui);
        ui.add_space(8.0);

        section_header(ui, "Active response");
        if response_enabled {
            let mut action_cells = Vec::new();
            if autoruns_frozen {
                action_cells.push(ActionCell {
                    action: Action::RevertAutoruns,
                    label: "Revert autoruns".into(),
                    hover: "Remove autorun entries added after the baseline and restore baseline values.".into(),
                    tone: ActionTone::Accent,
                });
            } else {
                action_cells.push(ActionCell {
                    action: Action::FreezeAutoruns,
                    label: "Freeze autoruns".into(),
                    hover: "Capture the current Run and RunOnce keys as a baseline so later additions can be reverted.".into(),
                    tone: ActionTone::Warn,
                });
            }

            if quarantine_active {
                action_cells.push(ActionCell {
                    action: Action::ClearQuarantineProfile,
                    label: "Clear quarantine".into(),
                    hover: "Restore the network and undo the selected process containment steps where possible.".into(),
                    tone: ActionTone::Accent,
                });
            } else if quarantine_ready {
                action_cells.push(ActionCell {
                    action: Action::QuarantineProfile,
                    label: "Quarantine profile".into(),
                    hover: "Initial quarantine preset: isolate the network, block the executable path, and suspend the process when available.".into(),
                    tone: ActionTone::Danger,
                });
            }

            if process_blocked {
                let label = match process_remaining {
                    Some(duration) => format!("Unban process ({})", format_remaining(duration)),
                    None => "Unban process".to_string(),
                };
                action_cells.push(ActionCell {
                    action: Action::UnblockProcess,
                    label,
                    hover: "Remove temporary firewall rules for this executable path.".into(),
                    tone: ActionTone::Accent,
                });
            } else if known_location {
                action_cells.push(ActionCell {
                    action: Action::BlockProcess(active_response::DurationPreset::OneDay),
                    label: "Ban process 24h".into(),
                    hover: "Temporarily block inbound and outbound traffic for this executable path for 24 hours.".into(),
                    tone: ActionTone::Block(active_response::DurationPreset::OneDay),
                });
                action_cells.push(ActionCell {
                    action: Action::BlockProcess(active_response::DurationPreset::Permanent),
                    label: "Ban process permanent".into(),
                    hover: "Block inbound and outbound traffic for this executable path until removed.".into(),
                    tone: ActionTone::Block(active_response::DurationPreset::Permanent),
                });
            }

            if let Some(target) = remote_target.as_ref() {
                if remote_blocked {
                    let label = match remote_remaining {
                        Some(duration) => format!("Unban remote ({})", format_remaining(duration)),
                        None => "Unban remote".to_string(),
                    };
                    action_cells.push(ActionCell {
                        action: Action::UnblockRemote,
                        label,
                        hover: format!("Remove temporary firewall rule for {target}."),
                        tone: ActionTone::Accent,
                    });
                } else {
                    action_cells.push(ActionCell {
                        action: Action::BlockRemote(active_response::DurationPreset::OneHour),
                        label: "Ban remote 1h".into(),
                        hover: format!("Temporarily block outbound traffic to {target} for 1 hour."),
                        tone: ActionTone::Block(active_response::DurationPreset::OneHour),
                    });
                }
            }

            if domain_enabled {
                if let Some(domain) = domain_target.as_ref() {
                    if domain_blocked {
                        action_cells.push(ActionCell {
                            action: Action::UnblockDomain,
                            label: "Unban domain".into(),
                            hover: format!("Remove local hosts-file block for {domain}."),
                            tone: ActionTone::Accent,
                        });
                    } else {
                        action_cells.push(ActionCell {
                            action: Action::BlockDomain,
                            label: "Ban domain".into(),
                            hover: format!("Redirect {domain} to localhost through the hosts file."),
                            tone: ActionTone::Warn,
                        });
                    }
                }
            }

            if connection_kill_enabled {
                action_cells.push(ActionCell {
                    action: Action::KillConnection,
                    label: "Kill connection".into(),
                    hover: "Immediately terminate the selected live TCP connection.".into(),
                    tone: ActionTone::Danger,
                });
            }

            if process_suspended {
                action_cells.push(ActionCell {
                    action: Action::ResumeProcess,
                    label: "Resume process".into(),
                    hover: "Resume every suspended thread in this process.".into(),
                    tone: ActionTone::Accent,
                });
            } else if suspend_enabled {
                action_cells.push(ActionCell {
                    action: Action::SuspendProcess,
                    label: "Suspend process".into(),
                    hover: "Freeze the process while you investigate.".into(),
                    tone: ActionTone::Warn,
                });
            }

            if kill_enabled {
                action_cells.push(ActionCell {
                    action: Action::Kill,
                    label: "Kill process".into(),
                    hover: "Terminate this process after confirmation.".into(),
                    tone: ActionTone::Danger,
                });
            }

            if isolation_enabled {
                let restoring = isolated;
                action_cells.push(ActionCell {
                    action: if isolated {
                        Action::RestoreNetwork
                    } else {
                        Action::IsolateMachine
                    },
                    label: if isolated {
                        "Restore network".into()
                    } else {
                        "Isolate network".into()
                    },
                    hover: if isolated {
                        "Restore saved firewall and adapter state from before isolation.".into()
                    } else {
                        "Immediately isolate the machine network.".into()
                    },
                    tone: if restoring {
                        ActionTone::Accent
                    } else {
                        ActionTone::Danger
                    },
                });
            }

            render_action_grid(ui, "active_response_actions", &action_cells, &mut action);

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                chip(ui, &format!("{} blocked target{}", response_status.blocked_rules, if response_status.blocked_rules == 1 { "" } else { "s" }));
                chip(ui, &format!("{} blocked domain{}", response_status.blocked_domains, if response_status.blocked_domains == 1 { "" } else { "s" }));
                chip(ui, if response_status.isolated { "Network isolated" } else { "Network open" });
                chip(ui, &format!("{} process block{}", response_status.blocked_processes, if response_status.blocked_processes == 1 { "" } else { "s" }));
                chip(ui, &format!("{} suspended", response_status.suspended_processes));
                if response_status.frozen_autoruns { chip(ui, "Autorun baseline"); }
            });
        } else {
            ui.label(
                RichText::new("Active response actions are hidden until Vigil runs in Admin Mode.")
                    .color(theme::TEXT3)
                    .size(10.5),
            );
        }

        ui.add_space(8.0);
        separator(ui);
        ui.add_space(8.0);

        section_header(ui, "Why it scored");
        if sel.reason_summary.is_empty() {
            ui.label(RichText::new("No score reasons recorded.").color(theme::TEXT3).size(11.0));
        } else {
            render_reason_block(
                ui,
                "process",
                &sel.reason_summary,
                ">",
                theme::WARN,
                theme::TEXT2,
                11.0,
                2.0,
            );
        }

        if let Some(conn) = sel.selected_connection.as_ref() {
            ui.add_space(8.0);
            separator(ui);
            ui.add_space(8.0);
            section_header(ui, "Selected connection");
            kv_mono(ui, "Local", &conn.local_addr);
            kv_mono(ui, "Remote", &conn.remote_addr);
            if let Some(host) = domain_target {
                kv(ui, "Hostname", host);
            }
            if let Some(sni) = conn.tls_sni.as_deref() {
                kv(ui, "TLS SNI", sni);
            }
            if let Some(ja3) = conn.tls_ja3.as_deref() {
                kv_mono(ui, "TLS JA3", ja3);
            }
            kv(ui, "Status", &conn.status);
            kv(ui, "Time", &conn.timestamp);
            if !conn.attack_tags.is_empty() {
                kv(ui, "ATT&CK", &conn.attack_tags.join(", "));
            }
            if let Some(summary) = sel
                .selected_connection_reason_summary
                .as_ref()
                .filter(|summary| !summary.is_empty())
            {
                ui.add_space(4.0);
                render_reason_block(
                    ui,
                    "connection",
                    summary,
                    "-",
                    theme::TEXT3,
                    theme::TEXT2,
                    10.6,
                    0.0,
                );
            }
        }

        if kill_confirm {
            ui.label(RichText::new("Really kill this process?").color(theme::DANGER).size(11.0));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let kill_resp = ui.add_enabled(kill_enabled, danger_btn("Kill"));
                let kill_resp = if kill_enabled {
                    kill_resp
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("Terminate this process immediately.")
                } else {
                    kill_resp.on_hover_text("This row is unresolved, so Vigil cannot verify that a process is still running.")
                };
                if kill_resp.clicked() { action = Some(Action::KillConfirmed); }
                if ui
                    .add(muted_btn("Cancel"))
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text("Cancel process termination.")
                    .clicked()
                {
                    action = Some(Action::KillCancelled);
                }
            });
        } else {
            ui.horizontal_wrapped(|ui| {
                if trust_enabled {
                    let trust_resp = ui
                        .add(accent_btn("Trust"))
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("Add this process name to the trusted list.");
                    if trust_resp.clicked() {
                        action = Some(Action::Trust);
                    }
                }
                if open_location_enabled {
                    let open_resp = ui
                        .add(muted_btn("Open Loc"))
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("Open this executable's folder in the file explorer.");
                    if open_resp.clicked() {
                        action = Some(Action::OpenLocation);
                    }
                }
            });
        }

        ui.add_space(12.0);
    });

    action
}

fn process_hero(ui: &mut Ui, sel: &ProcessSelection) {
    let ghost = is_ghost_process_name(&sel.proc_name);
    egui::Frame::NONE
        .fill(theme::SURFACE2)
        .stroke(egui::Stroke::new(1.0, theme::ACCENT_BG))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                score_badge(ui, sel.score);
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(&sel.proc_name)
                            .color(theme::TEXT)
                            .size(14.5)
                            .strong(),
                    );
                    ui.label(
                        RichText::new(format!("PID {} | {}", sel.pid, sel.timestamp))
                            .color(theme::TEXT2)
                            .size(10.5),
                    );
                    ui.label(
                        RichText::new(format!("Latest: {} to {}", sel.status, sel.remote_addr))
                            .color(theme::TEXT3)
                            .size(10.0),
                    );
                });
            });
            ui.add_space(8.0);
            ui.label(
                RichText::new(if sel.proc_path.is_empty() {
                    "No executable path available"
                } else {
                    sel.proc_path.as_str()
                })
                .color(theme::TEXT2)
                .size(10.5),
            );
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                chip(ui, &format!("{} connections", sel.connection_count));
                chip(ui, &format!("{} ports", sel.distinct_ports));
                chip(ui, &format!("{} remotes", sel.distinct_remotes));
                if ghost {
                    chip(ui, "Unresolved PID");
                }
                if sel.proc_path.is_empty() {
                    chip(ui, "No location");
                }
                if sel.script_host_suspicious {
                    chip(ui, "Script host");
                }
                if sel.baseline_deviation {
                    chip(ui, "Baseline drift");
                }
                if sel.selected_connection.is_some() {
                    chip(ui, "Connection selected");
                } else {
                    chip(ui, "Process summary");
                }
            });
        });
}

fn separator(ui: &mut Ui) {
    let rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 1.0));
    ui.painter().rect_filled(rect, 0.0, theme::BORDER);
    ui.advance_cursor_after_rect(rect);
}
fn section_header(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).color(theme::TEXT2).size(10.5).strong());
    ui.add_space(4.0);
}

#[derive(Debug, Clone, Default)]
pub struct ReasonSummary {
    plain: Vec<String>,
    unusual_ports: Vec<u16>,
    truncated_input: usize,
}

impl ReasonSummary {
    pub fn is_empty(&self) -> bool {
        self.plain.is_empty() && self.unusual_ports.is_empty() && self.truncated_input == 0
    }
}

pub fn summarize_reasons(reasons: &[String]) -> ReasonSummary {
    let mut summary = ReasonSummary::default();
    let mut ports = BTreeSet::new();
    for reason in reasons.iter().take(MAX_REASON_SCAN) {
        if let Some(port) = parse_unusual_destination_port(reason) {
            ports.insert(port);
        } else {
            summary.plain.push(reason.clone());
        }
    }
    summary.unusual_ports = ports.into_iter().collect();
    summary.truncated_input = reasons.len().saturating_sub(MAX_REASON_SCAN);
    summary
}

fn parse_unusual_destination_port(reason: &str) -> Option<u16> {
    let tail = reason.strip_prefix("Unusual destination port ")?;
    let token = tail.split_whitespace().next()?;
    token.parse::<u16>().ok()
}

fn render_reason_row(
    ui: &mut Ui,
    marker: &str,
    marker_color: egui::Color32,
    text_color: egui::Color32,
    text_size: f32,
    reason: &str,
    row_gap: f32,
) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(marker).color(marker_color).size(10.0));
        ui.add(egui::Label::new(RichText::new(reason).color(text_color).size(text_size)).wrap());
    });
    if row_gap > 0.0 {
        ui.add_space(row_gap);
    }
}

#[allow(clippy::too_many_arguments)]
fn render_reason_block(
    ui: &mut Ui,
    id_prefix: &str,
    summary: &ReasonSummary,
    marker: &str,
    marker_color: egui::Color32,
    text_color: egui::Color32,
    text_size: f32,
    row_gap: f32,
) {
    for reason in summary.plain.iter().take(MAX_REASON_PLAIN_ROWS) {
        render_reason_row(
            ui,
            marker,
            marker_color,
            text_color,
            text_size,
            reason,
            row_gap,
        );
    }
    let extra_plain = summary.plain.len().saturating_sub(MAX_REASON_PLAIN_ROWS);
    if extra_plain > 0 {
        ui.label(
            RichText::new(format!(
                "{} additional reason entries hidden for readability.",
                extra_plain
            ))
            .color(theme::TEXT3)
            .size(10.2),
        );
    }
    if !summary.unusual_ports.is_empty() {
        let count = summary.unusual_ports.len();
        egui::CollapsingHeader::new(format!("Unusual destination ports ({count})"))
            .id_salt((id_prefix, "unusual_ports"))
            .default_open(count <= 6)
            .show(ui, |ui| {
                for port in summary.unusual_ports.iter().take(MAX_REASON_PORT_ROWS) {
                    render_reason_row(
                        ui,
                        marker,
                        marker_color,
                        text_color,
                        text_size,
                        &format!("Unusual destination port {port}"),
                        row_gap,
                    );
                }
                let extra_ports = summary
                    .unusual_ports
                    .len()
                    .saturating_sub(MAX_REASON_PORT_ROWS);
                if extra_ports > 0 {
                    ui.label(
                        RichText::new(format!("{} additional unusual ports hidden.", extra_ports))
                            .color(theme::TEXT3)
                            .size(10.2),
                    );
                }
            });
    }
    if summary.truncated_input > 0 {
        ui.label(
            RichText::new(format!(
                "Input capped at {MAX_REASON_SCAN} reasons ({} hidden) to protect UI responsiveness.",
                summary.truncated_input
            ))
            .color(theme::WARN)
            .size(10.2),
        );
    }
}

fn kv(ui: &mut Ui, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [88.0, 16.0],
            egui::Label::new(RichText::new(key).color(theme::TEXT3).size(11.0)),
        );
        let display = bounded_display(val);
        ui.add(egui::Label::new(RichText::new(display).color(theme::TEXT).size(11.0)).wrap());
    });
    ui.add_space(2.0);
}
fn kv_mono(ui: &mut Ui, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [88.0, 16.0],
            egui::Label::new(RichText::new(key).color(theme::TEXT3).size(11.0)),
        );
        let display = bounded_display(val);
        ui.add(
            egui::Label::new(
                RichText::new(display)
                    .color(theme::TEXT)
                    .monospace()
                    .size(10.5),
            )
            .wrap(),
        );
    });
    ui.add_space(2.0);
}

fn bounded_display(value: &str) -> std::borrow::Cow<'_, str> {
    if value.len() <= MAX_INSPECTOR_VALUE_CHARS {
        std::borrow::Cow::Borrowed(value)
    } else {
        let truncated: String = value.chars().take(MAX_INSPECTOR_VALUE_CHARS).collect();
        std::borrow::Cow::Owned(format!("{truncated} ..."))
    }
}
fn score_badge(ui: &mut Ui, score: u8) {
    let (fg, bg) = theme::score_colors(score);
    ui.label(
        RichText::new(format!(" {score:>2} "))
            .color(fg)
            .background_color(bg)
            .monospace()
            .size(12.0)
            .strong(),
    );
}
fn chip(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(format!(" {text} "))
            .color(theme::TEXT2)
            .background_color(theme::SURFACE3)
            .size(10.0)
            .strong(),
    );
}
#[derive(Clone, Copy)]
enum ActionTone {
    Danger,
    Warn,
    Accent,
    Block(active_response::DurationPreset),
}

struct ActionCell {
    action: Action,
    label: String,
    hover: String,
    tone: ActionTone,
}

fn render_action_grid(ui: &mut Ui, id: &str, cells: &[ActionCell], action: &mut Option<Action>) {
    if cells.is_empty() {
        return;
    }
    let col_w = ((ui.available_width() - 8.0).max(220.0)) * 0.5;
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([8.0, 8.0])
        .show(ui, |ui| {
            for (idx, cell) in cells.iter().enumerate() {
                let button = match cell.tone {
                    ActionTone::Danger => danger_btn(&cell.label),
                    ActionTone::Warn => warn_btn(&cell.label),
                    ActionTone::Accent => accent_btn(&cell.label),
                    ActionTone::Block(preset) => block_btn(preset, &cell.label),
                };
                let resp = ui
                    .add_sized([col_w, 28.0], button)
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text(&cell.hover);
                if resp.clicked() {
                    *action = Some(cell.action.clone());
                }
                if idx % 2 == 1 {
                    ui.end_row();
                }
            }
            if cells.len() % 2 == 1 {
                ui.add_space(0.0);
                ui.end_row();
            }
        });
}
fn nonempty(text: &str) -> &str {
    if text.is_empty() {
        "n/a"
    } else {
        text
    }
}
fn accent_btn(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(theme::ACCENT).size(11.5))
        .fill(theme::ACCENT_BG)
        .stroke(egui::Stroke::new(1.0, theme::ACCENT))
        .corner_radius(6.0)
}
fn block_btn(preset: active_response::DurationPreset, text: &str) -> egui::Button<'_> {
    let (fg, bg, border) = match preset {
        active_response::DurationPreset::OneHour => (theme::WARN, theme::WARN_BG, theme::WARN),
        active_response::DurationPreset::OneDay => (theme::WARN, theme::WARN_BG, theme::WARN),
        active_response::DurationPreset::Permanent => {
            (theme::DANGER, theme::DANGER_BG, theme::DANGER)
        }
    };
    egui::Button::new(RichText::new(text).color(fg).size(11.5))
        .fill(bg)
        .stroke(egui::Stroke::new(1.0, border))
        .corner_radius(6.0)
}
fn muted_btn(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(theme::TEXT2).size(11.5))
        .fill(theme::SURFACE2)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(6.0)
}
fn danger_btn(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(theme::DANGER).size(11.5))
        .fill(theme::DANGER_BG)
        .stroke(egui::Stroke::new(1.0, theme::DANGER))
        .corner_radius(6.0)
}
fn warn_btn(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(theme::WARN).size(11.5))
        .fill(theme::WARN_BG)
        .stroke(egui::Stroke::new(1.0, theme::WARN))
        .corner_radius(6.0)
}
fn format_remaining(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    let hours = secs / 3_600;
    let mins = (secs % 3_600) / 60;
    let secs = secs % 60;
    if hours > 0 {
        format!("{hours:02}:{mins:02}:{secs:02}")
    } else {
        format!("{mins:02}:{secs:02}")
    }
}
