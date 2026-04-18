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

#[derive(Debug)]
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
) -> Option<Action> {
    match selection {
        Some(selection) => show_detail(ui, selection, kill_confirm),
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

fn show_detail(ui: &mut Ui, sel: &ProcessSelection, kill_confirm: bool) -> Option<Action> {
    let mut action: Option<Action> = None;
    let ghost = is_ghost_process_name(&sel.proc_name);
    let known_location = has_known_location(sel);
    let trust_enabled = known_location;
    let open_location_enabled = known_location;
    let kill_enabled = !ghost;
    let suspend_enabled = active_response::can_suspend_process(sel.pid) && !ghost;
    let response_enabled = active_response::can_modify_firewall();
    let isolation_enabled = active_response::can_isolate_network();
    let domain_enabled = active_response::can_block_domain();
    let response_status = active_response::status();
    let remote_target = sel
        .selected_connection
        .as_ref()
        .and_then(|conn| active_response::extract_remote_target(&conn.remote_addr));
    let remote_blocked = remote_target
        .as_deref()
        .is_some_and(active_response::is_blocked);
    let remote_remaining = remote_target
        .as_deref()
        .and_then(active_response::remote_block_remaining);
    let domain_target = sel
        .selected_connection
        .as_ref()
        .and_then(active_response::extract_domain_target);
    let domain_blocked = domain_target
        .as_deref()
        .is_some_and(active_response::is_domain_blocked);
    let process_blocked = active_response::is_process_blocked(sel.pid, &sel.proc_path);
    let process_remaining = active_response::process_block_remaining(sel.pid, &sel.proc_path);
    let process_suspended = active_response::is_process_suspended(sel.pid, &sel.proc_path);
    let connection_kill_enabled = sel
        .selected_connection
        .as_ref()
        .is_some_and(active_response::can_kill_connection);
    let isolated = response_status.isolated;
    let quarantine_ready =
        active_response::can_apply_quarantine_profile(sel.pid, &sel.proc_path) && !ghost;
    let quarantine_active = isolated || process_blocked || process_suspended;
    let autoruns_frozen = active_response::has_frozen_autoruns();

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
            ui.horizontal_wrapped(|ui| {
                if autoruns_frozen {
                    chip(ui, "Autoruns frozen");
                    let revert = ui.add(accent_btn("Revert autoruns"));
                    let revert = revert.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Remove autorun entries added after the baseline and restore baseline values.");
                    if revert.clicked() { action = Some(Action::RevertAutoruns); }
                } else {
                    let freeze = ui.add(danger_btn("Freeze autoruns"));
                    let freeze = freeze.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Capture the current Run and RunOnce keys as a baseline so later additions can be reverted.");
                    if freeze.clicked() { action = Some(Action::FreezeAutoruns); }
                }

                if quarantine_active {
                    let clear_btn = ui.add(accent_btn("Clear quarantine"));
                    let clear_btn = clear_btn.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Restore the network and undo the selected process containment steps where possible.");
                    if clear_btn.clicked() { action = Some(Action::ClearQuarantineProfile); }
                } else {
                    let quarantine_btn = ui.add_enabled(quarantine_ready, danger_btn("Quarantine profile"));
                    let quarantine_btn = if quarantine_ready { quarantine_btn.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Initial quarantine preset: isolate the network, block the executable path, and suspend the process when available.") } else { quarantine_btn.on_hover_text("Quarantine profile requires administrator privileges and a real PID or known executable path.") };
                    if quarantine_btn.clicked() { action = Some(Action::QuarantineProfile); }
                }
            });

            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                if let Some(target) = remote_target.as_ref() {
                    if remote_blocked {
                        blocked_status_row(ui, "Remote blocked", remote_remaining, &format!("Temporary firewall rule for {target}"), Action::UnblockRemote, &mut action);
                    } else {
                        for preset in [active_response::DurationPreset::OneHour, active_response::DurationPreset::OneDay, active_response::DurationPreset::Permanent] {
                            let (label, hover) = match preset {
                                active_response::DurationPreset::OneHour => ("Block 1h", format!("Temporarily block outbound traffic to {target} for 1 hour.")),
                                active_response::DurationPreset::OneDay => ("Block 24h", format!("Temporarily block outbound traffic to {target} for 24 hours.")),
                                active_response::DurationPreset::Permanent => ("Block permanent", format!("Block outbound traffic to {target} until you remove the rule.")),
                            };
                            let resp = ui.add_enabled(true, block_btn(preset, label));
                            let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(hover);
                            if resp.clicked() { action = Some(Action::BlockRemote(preset)); }
                        }
                    }
                } else {
                    ui.add_enabled(false, accent_btn("Block 1h")).on_hover_text("Select a concrete connection row to block its remote IP.");
                }

                if process_blocked {
                    blocked_status_row(ui, "Process blocked", process_remaining, "Temporary firewall rules for this executable path", Action::UnblockProcess, &mut action);
                } else {
                    for preset in [active_response::DurationPreset::OneHour, active_response::DurationPreset::OneDay, active_response::DurationPreset::Permanent] {
                        let (label, hover) = match preset {
                            active_response::DurationPreset::OneHour => ("Block process 1h", "Temporarily block inbound and outbound traffic for this executable path for 1 hour."),
                            active_response::DurationPreset::OneDay => ("Block process 24h", "Temporarily block inbound and outbound traffic for this executable path for 24 hours."),
                            active_response::DurationPreset::Permanent => ("Block process permanent", "Block inbound and outbound traffic for this executable path until you remove the rule."),
                        };
                        let resp = ui.add_enabled(known_location, block_btn(preset, label));
                        let resp = if known_location { resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(hover) } else { resp.on_hover_text("Block process is disabled because Vigil does not know the executable location.") };
                        if resp.clicked() { action = Some(Action::BlockProcess(preset)); }
                    }
                }

            });
        }
        if isolation_enabled {
            ui.add_space(6.0);
            let isolate_label = if isolated {
                "Restore network"
            } else {
                "Isolate network"
            };
            let iso_resp = ui
                .add_enabled(true, danger_btn(isolate_label))
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(if isolated {
                    "Restore the saved firewall profile state and any adapter snapshot from before isolation."
                } else {
                    "Immediately isolate the machine. Vigil hardens firewall policy first and falls back to emergency adapter cutoff if connectivity is still reachable."
                });
            if iso_resp.clicked() {
                action = Some(if isolated {
                    Action::RestoreNetwork
                } else {
                    Action::IsolateMachine
                });
            }
        } else if !response_enabled {
            ui.label(
                RichText::new("Administrator privileges are required for active response.")
                    .color(theme::TEXT3)
                    .size(10.5),
            );
        }

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            if domain_blocked {
                chip(ui, "Domain blocked");
                let unblock_domain = ui.add(accent_btn("Unblock domain"));
                let unblock_domain = unblock_domain.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Remove the local hosts-file block for this hostname.");
                if unblock_domain.clicked() { action = Some(Action::UnblockDomain); }
            } else {
                let domain_btn = ui.add_enabled(domain_enabled && domain_target.is_some(), danger_btn("Block domain"));
                let domain_btn = if domain_enabled && domain_target.is_some() { let host = domain_target.as_deref().unwrap_or_default(); domain_btn.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(format!("Redirect {host} to the local machine through the Windows hosts file.")) } else { domain_btn.on_hover_text("Block domain requires administrator privileges and a selected connection with a resolved hostname.") };
                if domain_btn.clicked() { action = Some(Action::BlockDomain); }
            }
            let kill_conn_resp = ui.add_enabled(connection_kill_enabled, danger_btn("Kill connection"));
            let kill_conn_resp = if connection_kill_enabled { kill_conn_resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Immediately terminate the selected live TCP connection.") } else { kill_conn_resp.on_hover_text("Select an IPv4 TCP connection with a killable state while Vigil is running as administrator.") };
            if kill_conn_resp.clicked() { action = Some(Action::KillConnection); }
            if process_suspended {
                chip(ui, "Process suspended");
                let resume = ui.add(accent_btn("Resume process"));
                let resume = resume.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Resume every suspended thread in this process.");
                if resume.clicked() { action = Some(Action::ResumeProcess); }
            } else {
                let suspend = ui.add_enabled(suspend_enabled, danger_btn("Suspend process"));
                let suspend = if suspend_enabled { suspend.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Freeze the process while you investigate. Use Resume process to continue it later.") } else { suspend.on_hover_text("Suspension requires a real PID, administrator privileges, and the Windows active-response backend.") };
                if suspend.clicked() { action = Some(Action::SuspendProcess); }
            }
        });

        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            chip(ui, &format!("{} blocked target{}", response_status.blocked_rules, if response_status.blocked_rules == 1 { "" } else { "s" }));
            chip(ui, &format!("{} blocked domain{}", response_status.blocked_domains, if response_status.blocked_domains == 1 { "" } else { "s" }));
            chip(ui, if response_status.isolated { "Network isolated" } else { "Network open" });
            chip(ui, &format!("{} process block{}", response_status.blocked_processes, if response_status.blocked_processes == 1 { "" } else { "s" }));
            chip(ui, &format!("{} suspended", response_status.suspended_processes));
            if response_status.frozen_autoruns { chip(ui, "Autorun baseline"); }
        });

        ui.add_space(8.0);
        separator(ui);
        ui.add_space(8.0);

        section_header(ui, "Why it scored");
        if sel.reasons.is_empty() {
            ui.label(RichText::new("No score reasons recorded.").color(theme::TEXT3).size(11.0));
        } else {
            for reason in &sel.reasons {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(">").color(theme::WARN).size(10.0));
                    ui.add(egui::Label::new(RichText::new(reason).color(theme::TEXT2).size(11.0)).wrap());
                });
                ui.add_space(2.0);
            }
        }

        if let Some(conn) = sel.selected_connection.as_ref() {
            ui.add_space(8.0);
            separator(ui);
            ui.add_space(8.0);
            section_header(ui, "Selected connection");
            kv_mono(ui, "Local", &conn.local_addr);
            kv_mono(ui, "Remote", &conn.remote_addr);
            if let Some(host) = domain_target.as_deref() { kv(ui, "Hostname", host); }
            if let Some(sni) = conn.tls_sni.as_deref() { kv(ui, "TLS SNI", sni); }
            if let Some(ja3) = conn.tls_ja3.as_deref() { kv_mono(ui, "TLS JA3", ja3); }
            kv(ui, "Status", &conn.status);
            kv(ui, "Time", &conn.timestamp);
            if !conn.attack_tags.is_empty() {
                kv(ui, "ATT&CK", &conn.attack_tags.join(", "));
            }
            if !conn.reasons.is_empty() {
                ui.add_space(4.0);
                for reason in &conn.reasons {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("-").color(theme::TEXT3).size(10.0));
                        ui.add(egui::Label::new(RichText::new(reason).color(theme::TEXT2).size(10.6)).wrap());
                    });
                }
            }
        }

        if kill_confirm {
            ui.label(RichText::new("Really kill this process?").color(theme::DANGER).size(11.0));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let kill_resp = ui.add_enabled(kill_enabled, accent_btn("Kill"));
                let kill_resp = if kill_enabled { kill_resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { kill_resp.on_hover_text("This row is unresolved, so Vigil cannot verify that a process is still running.") };
                if kill_resp.clicked() { action = Some(Action::KillConfirmed); }
                if ui.add(muted_btn("Cancel")).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { action = Some(Action::KillCancelled); }
            });
        } else {
            ui.horizontal_wrapped(|ui| {
                let trust_resp = ui.add_enabled(trust_enabled, accent_btn("Trust"));
                let trust_resp = if trust_enabled { trust_resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { trust_resp.on_hover_text("Trust is disabled because Vigil does not know this process's executable location.") };
                if trust_resp.clicked() { action = Some(Action::Trust); }
                let open_resp = ui.add_enabled(open_location_enabled, muted_btn("Open Loc"));
                let open_resp = if open_location_enabled { open_resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { open_resp.on_hover_text("No executable path is known for this process.") };
                if open_resp.clicked() { action = Some(Action::OpenLocation); }
                let kill_resp = ui.add_enabled(kill_enabled, danger_btn("Kill"));
                let kill_resp = if kill_enabled { kill_resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { kill_resp.on_hover_text("This is an unresolved PID row, so it cannot be killed from the UI.") };
                if kill_resp.clicked() { action = Some(Action::Kill); }
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
fn kv(ui: &mut Ui, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [88.0, 16.0],
            egui::Label::new(RichText::new(key).color(theme::TEXT3).size(11.0)),
        );
        ui.add(egui::Label::new(RichText::new(val).color(theme::TEXT).size(11.0)).wrap());
    });
    ui.add_space(2.0);
}
fn kv_mono(ui: &mut Ui, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [88.0, 16.0],
            egui::Label::new(RichText::new(key).color(theme::TEXT3).size(11.0)),
        );
        ui.add(
            egui::Label::new(RichText::new(val).color(theme::TEXT).monospace().size(10.5)).wrap(),
        );
    });
    ui.add_space(2.0);
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
fn blocked_status_row(
    ui: &mut Ui,
    label: &str,
    remaining: Option<std::time::Duration>,
    hover_prefix: &str,
    unblock_action: Action,
    action: &mut Option<Action>,
) {
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        let status = match remaining {
            Some(duration) => format!("{label} {}", format_remaining(duration)),
            None => format!("{label} permanently"),
        };
        chip(ui, &status);
        let unblock = ui.add(accent_btn("Unblock"));
        let unblock = unblock
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text(format!("{}.", hover_prefix));
        if unblock.clicked() {
            *action = Some(unblock_action);
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
        active_response::DurationPreset::OneHour => {
            (theme::ACCENT, theme::ACCENT_BG, theme::ACCENT)
        }
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
