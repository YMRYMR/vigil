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

// ── Actions ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Action {
    Trust,
    OpenLocation,
    Kill,
    BlockRemote,
    UnblockRemote,
    IsolateMachine,
    RestoreNetwork,
    KillConfirmed,
    KillCancelled,
}

// ── Public entry point ────────────────────────────────────────────────────────

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
    let firewall_enabled = active_response::can_modify_firewall();
    let remote_target = sel
        .selected_connection
        .as_ref()
        .and_then(|conn| active_response::extract_remote_target(&conn.remote_addr));
    let remote_blocked = remote_target
        .as_deref()
        .is_some_and(active_response::is_blocked);
    let isolated = active_response::status().isolated;

    egui::ScrollArea::vertical()
        .id_salt("inspector_scroll")
        .show(ui, |ui| {
            ui.add_space(8.0);

            process_hero(ui, sel);
            ui.add_space(10.0);
            separator(ui);
            ui.add_space(8.0);

            section_header(ui, "Process");
            kv(ui, "PID", &sel.pid.to_string());
            kv(ui, "User", nonempty(&sel.proc_user));
            kv(ui, "Parent", &format!("{} ({})", nonempty(&sel.parent_name), sel.parent_pid));
            kv(ui, "Service", nonempty(&sel.service_name));
            kv(ui, "Publisher", nonempty(&sel.publisher));

            ui.add_space(8.0);
            separator(ui);
            ui.add_space(8.0);

            section_header(ui, "Connections");
            kv(ui, "Count", &format!("{}", sel.connection_count));
            kv(ui, "Distinct ports", &format!("{}", sel.distinct_ports));
            kv(ui, "Distinct remotes", &format!("{}", sel.distinct_remotes));
            let statuses = if sel.statuses.is_empty() {
                "—".to_string()
            } else {
                sel.statuses.join(" · ")
            };
            kv(
                ui,
                "Statuses",
                statuses.as_str(),
            );

            ui.add_space(8.0);
            separator(ui);
            ui.add_space(8.0);

            section_header(ui, "Why it scored");
            if sel.reasons.is_empty() {
                ui.label(RichText::new("No score reasons recorded.").color(theme::TEXT3).size(11.0));
            } else {
                for reason in &sel.reasons {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("▸").color(theme::WARN).size(10.0));
                        ui.add(
                            egui::Label::new(RichText::new(reason).color(theme::TEXT2).size(11.0))
                                .wrap(),
                        );
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
                kv(ui, "Status", &conn.status);
                kv(ui, "Time", &conn.timestamp);
                if !conn.reasons.is_empty() {
                    ui.add_space(4.0);
                    for reason in &conn.reasons {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("•").color(theme::TEXT3).size(10.0));
                            ui.add(
                                egui::Label::new(
                                    RichText::new(reason).color(theme::TEXT2).size(10.6),
                                )
                                .wrap(),
                            );
                        });
                    }
                }
            }

            ui.add_space(12.0);
            separator(ui);
            ui.add_space(8.0);

            section_header(ui, "Active response");
            if firewall_enabled {
                ui.horizontal_wrapped(|ui| {
                    if let Some(target) = remote_target.as_ref() {
                        let label = if remote_blocked {
                            "Unblock remote"
                        } else {
                            "Block remote 1h"
                        };
                        let resp = ui.add_enabled(remote_target.is_some(), accent_btn(label));
                        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(
                            if remote_blocked {
                                format!("Remove the temporary firewall rule for {target}.")
                            } else {
                                format!("Temporarily block outbound traffic to {target}.")
                            },
                        );
                        if resp.clicked() {
                            action = Some(if remote_blocked {
                                Action::UnblockRemote
                            } else {
                                Action::BlockRemote
                            });
                        }
                    } else {
                        ui.add_enabled(false, accent_btn("Block remote 1h"))
                            .on_hover_text("Select a concrete connection row to block its remote IP.");
                    }

                    let isolate_label = if isolated {
                        "Restore network"
                    } else {
                        "Isolate network"
                    };
                    let iso_resp = ui.add_enabled(true, danger_btn(isolate_label));
                    let iso_resp = iso_resp
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text(if isolated {
                            "Remove the temporary network-isolation firewall rules."
                        } else {
                            "Temporarily block inbound and outbound traffic with reversible firewall rules."
                        });
                    if iso_resp.clicked() {
                        action = Some(if isolated {
                            Action::RestoreNetwork
                        } else {
                            Action::IsolateMachine
                        });
                    }
                });
            } else {
                ui.label(
                    RichText::new("Administrator privileges are required for active response.")
                        .color(theme::TEXT3)
                        .size(10.5),
                );
            }

            if kill_confirm {
                ui.label(
                    RichText::new("Really kill this process?")
                        .color(theme::DANGER)
                        .size(11.0),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let kill_resp = ui.add_enabled(kill_enabled, accent_btn("✕  Kill"));
                    let kill_resp = if kill_enabled {
                        kill_resp.on_hover_cursor(egui::CursorIcon::PointingHand)
                    } else {
                        kill_resp.on_hover_text(
                            "This row is unresolved, so Vigil cannot verify that a process is still running.",
                        )
                    };
                    if kill_resp.clicked() {
                        action = Some(Action::KillConfirmed);
                    }
                    if ui
                        .add(muted_btn("Cancel"))
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        action = Some(Action::KillCancelled);
                    }
                });
            } else {
                ui.horizontal_wrapped(|ui| {
                    let trust_resp = ui.add_enabled(trust_enabled, accent_btn("✓  Trust"));
                    let trust_resp = if trust_enabled {
                        trust_resp.on_hover_cursor(egui::CursorIcon::PointingHand)
                    } else {
                        trust_resp.on_hover_text(
                            "Trust is disabled because Vigil does not know this process's executable location.",
                        )
                    };
                    if trust_resp.clicked() {
                        action = Some(Action::Trust);
                    }
                    let open_resp =
                        ui.add_enabled(open_location_enabled, muted_btn("Open Loc"));
                    let open_resp = if open_location_enabled {
                        open_resp.on_hover_cursor(egui::CursorIcon::PointingHand)
                    } else {
                        open_resp.on_hover_text("No executable path is known for this process.")
                    };
                    if open_resp.clicked() {
                        action = Some(Action::OpenLocation);
                    }
                    let kill_resp = ui.add_enabled(kill_enabled, danger_btn("Kill"));
                    let kill_resp = if kill_enabled {
                        kill_resp.on_hover_cursor(egui::CursorIcon::PointingHand)
                    } else {
                        kill_resp.on_hover_text(
                            "This is an unresolved PID row, so it cannot be killed from the UI.",
                        )
                    };
                    if kill_resp.clicked() {
                        action = Some(Action::Kill);
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
                        RichText::new(format!("PID {}  ·  {}", sel.pid, sel.timestamp))
                            .color(theme::TEXT2)
                            .size(10.5),
                    );
                    ui.label(
                        RichText::new(format!("Latest: {}  →  {}", sel.status, sel.remote_addr))
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

fn nonempty(text: &str) -> &str {
    if text.is_empty() {
        "—"
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
