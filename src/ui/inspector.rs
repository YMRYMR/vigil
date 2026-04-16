//! Right-side inspector panel.
//!
//! Shows full detail for the currently-selected connection.
//! Returns an `Action` if the user clicked a button.

use crate::types::ConnInfo;
use crate::ui::theme;
use egui::{RichText, Ui};

// ── Actions ───────────────────────────────────────────────────────────────────

/// Returned when the user presses one of the inspector action buttons.
#[derive(Debug)]
pub enum Action {
    Trust,
    OpenLocation,
    Kill,
    KillConfirmed,
    KillCancelled,
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Show the inspector panel.
///
/// `kill_confirm` — when `true`, the kill-confirmation UI is shown instead of
/// the normal action buttons.
///
/// Returns `Some(Action)` if the user triggered an action, `None` otherwise.
pub fn show(ui: &mut Ui, info: Option<&ConnInfo>, kill_confirm: bool) -> Option<Action> {
    match info {
        Some(info) => show_detail(ui, info, kill_confirm),
        None => {
            show_placeholder(ui);
            None
        }
    }
}

// ── Placeholder ───────────────────────────────────────────────────────────────

fn show_placeholder(ui: &mut Ui) {
    let rect = ui.available_rect_before_wrap();
    let center = rect.center();
    ui.painter().text(
        center,
        egui::Align2::CENTER_CENTER,
        "Select a connection\nto inspect",
        egui::FontId::proportional(12.0),
        theme::TEXT3,
    );
}

// ── Detail view ───────────────────────────────────────────────────────────────

fn show_detail(ui: &mut Ui, info: &ConnInfo, kill_confirm: bool) -> Option<Action> {
    let mut action: Option<Action> = None;

    egui::ScrollArea::vertical()
        .id_salt("inspector_scroll")
        .show(ui, |ui| {
            ui.add_space(8.0);

            // ── Score badge + timestamp ───────────────────────────────────────
            ui.horizontal(|ui| {
                score_badge(ui, info.score);
                ui.add_space(6.0);
                ui.label(
                    RichText::new(&info.timestamp)
                        .color(theme::TEXT2)
                        .size(11.0),
                );
            });

            ui.add_space(6.0);

            // ── Process name + path ───────────────────────────────────────────
            ui.label(
                RichText::new(&info.proc_name)
                    .color(theme::TEXT)
                    .size(14.0)
                    .strong(),
            );
            if !info.proc_path.is_empty() {
                ui.add(
                    egui::Label::new(
                        RichText::new(&info.proc_path)
                            .color(theme::TEXT2)
                            .size(10.5),
                    )
                    .wrap(),
                );
            }

            ui.add_space(10.0);
            separator(ui);
            ui.add_space(6.0);

            // ── Process section ───────────────────────────────────────────────
            section_header(ui, "Process");
            kv(ui, "PID", &info.pid.to_string());
            kv(ui, "User", if info.proc_user.is_empty() { "—" } else { &info.proc_user });

            // Ancestor tree (replaces the single "Parent" kv row)
            ancestor_tree(ui, info);

            kv(
                ui,
                "Service",
                if info.service_name.is_empty() { "—" } else { &info.service_name },
            );
            kv(
                ui,
                "Publisher",
                if info.publisher.is_empty() { "—" } else { &info.publisher },
            );

            ui.add_space(8.0);
            separator(ui);
            ui.add_space(6.0);

            // ── Connection section ────────────────────────────────────────────
            section_header(ui, "Connection");
            kv_mono(ui, "Remote", &info.remote_addr);
            kv_mono(ui, "Local", &info.local_addr);
            kv(ui, "Status", &info.status);

            // ── Reasons section ───────────────────────────────────────────────
            if !info.reasons.is_empty() {
                ui.add_space(8.0);
                separator(ui);
                ui.add_space(6.0);
                section_header(ui, "Why it scored");
                for reason in &info.reasons {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("▸").color(theme::WARN).size(10.0));
                        ui.add(
                            egui::Label::new(
                                RichText::new(reason).color(theme::TEXT2).size(11.0),
                            )
                            .wrap(),
                        );
                    });
                    ui.add_space(1.0);
                }
            }

            ui.add_space(12.0);
            separator(ui);
            ui.add_space(8.0);

            // ── Action buttons ────────────────────────────────────────────────
            if kill_confirm {
                ui.label(
                    RichText::new("Really kill this process?")
                        .color(theme::DANGER)
                        .size(11.0),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if accent_btn(ui, "✕  Kill").clicked() {
                        action = Some(Action::KillConfirmed);
                    }
                    if muted_btn(ui, "Cancel").clicked() {
                        action = Some(Action::KillCancelled);
                    }
                });
            } else {
                ui.horizontal_wrapped(|ui| {
                    if accent_btn(ui, "✓  Trust").clicked() {
                        action = Some(Action::Trust);
                    }
                    if muted_btn(ui, "Open Loc").clicked() {
                        action = Some(Action::OpenLocation);
                    }
                    if danger_btn(ui, "Kill").clicked() {
                        action = Some(Action::Kill);
                    }
                });
            }

            ui.add_space(16.0);
        });

    action
}

// ── Ancestor tree ─────────────────────────────────────────────────────────────

/// Renders the process ancestor tree in the "Process" section.
///
/// If `ancestor_chain` is non-empty, shows a "Process tree" section label
/// followed by each node indented at its depth level.  Level 0 is the current
/// process; levels 1..n are successive ancestors from `ancestor_chain`.
///
/// Falls back to a plain `kv` row when there is no ancestry information.
fn ancestor_tree(ui: &mut Ui, info: &ConnInfo) {
    if info.ancestor_chain.is_empty() {
        // No ancestor data — show a plain parent row.
        kv(
            ui,
            "Parent",
            &if info.parent_name.is_empty() {
                "—".to_string()
            } else {
                format!("{} ({})", info.parent_name, info.parent_pid)
            },
        );
        return;
    }

    // Section label, styled like section_header but without the gap that
    // section_header adds — we keep the same spacing rhythm as other kv rows.
    ui.horizontal(|ui| {
        ui.add_sized(
            [80.0, 16.0],
            egui::Label::new(RichText::new("Process tree").color(theme::TEXT3).size(11.0)),
        );
    });
    ui.add_space(1.0);

    // Level 0 — the current process itself (no branch prefix).
    let root_line = format!("{} ({})", info.proc_name, info.pid);
    ui.add(
        egui::Label::new(
            RichText::new(&root_line)
                .color(theme::TEXT2)
                .size(11.0)
                .monospace(),
        )
        .wrap(),
    );

    // Levels 1..n — one entry per ancestor.
    for (i, (name, pid)) in info.ancestor_chain.iter().enumerate() {
        let indent = "  ".repeat(i + 1);
        let line = format!("{}└─ {} ({})", indent, name, pid);
        ui.add(
            egui::Label::new(
                RichText::new(&line)
                    .color(theme::TEXT2)
                    .size(11.0)
                    .monospace(),
            )
            .wrap(),
        );
    }

    ui.add_space(1.0);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn separator(ui: &mut Ui) {
    let rect = egui::Rect::from_min_size(
        ui.cursor().min,
        egui::vec2(ui.available_width(), 1.0),
    );
    ui.painter().rect_filled(rect, 0.0, theme::BORDER);
    ui.advance_cursor_after_rect(rect);
}

fn section_header(ui: &mut Ui, title: &str) {
    ui.label(
        RichText::new(title)
            .color(theme::TEXT2)
            .size(10.5)
            .strong(),
    );
    ui.add_space(4.0);
}

fn kv(ui: &mut Ui, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [80.0, 16.0],
            egui::Label::new(RichText::new(key).color(theme::TEXT3).size(11.0)),
        );
        ui.add(egui::Label::new(RichText::new(val).color(theme::TEXT).size(11.0)).wrap());
    });
    ui.add_space(1.0);
}

fn kv_mono(ui: &mut Ui, key: &str, val: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [80.0, 16.0],
            egui::Label::new(RichText::new(key).color(theme::TEXT3).size(11.0)),
        );
        ui.add(
            egui::Label::new(RichText::new(val).color(theme::TEXT).monospace().size(10.5))
                .wrap(),
        );
    });
    ui.add_space(1.0);
}

fn score_badge(ui: &mut Ui, score: u8) {
    let (fg, bg) = theme::score_colors(score);
    let text = RichText::new(format!(" {score:>2} "))
        .color(fg)
        .monospace()
        .size(12.0)
        .background_color(bg);
    ui.label(text);
}

fn accent_btn(ui: &mut Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(label).color(theme::ACCENT).size(11.5))
        .fill(theme::ACCENT_BG)
        .stroke(egui::Stroke::new(1.0, theme::ACCENT))
        .corner_radius(4.0);
    ui.add(btn)
}

fn muted_btn(ui: &mut Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(label).color(theme::TEXT2).size(11.5))
        .fill(theme::SURFACE2)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(4.0);
    ui.add(btn)
}

fn danger_btn(ui: &mut Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(label).color(theme::DANGER).size(11.5))
        .fill(theme::DANGER_BG)
        .stroke(egui::Stroke::new(1.0, theme::DANGER))
        .corner_radius(4.0);
    ui.add(btn)
}
