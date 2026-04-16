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

// ── Draft state ───────────────────────────────────────────────────────────────

pub struct SettingsDraft {
    pub alert_threshold: u8,
    pub poll_interval_secs: u64,
    pub log_all_connections: bool,
    pub autostart: bool,
    pub trusted_processes: Vec<String>,
    pub new_trusted_input: String,
    /// UI-only filter string for the trusted processes table; never persisted.
    pub trusted_filter: String,
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
            status_msg: None,
        }
    }

    pub fn apply_to(&self, cfg: &mut Config) {
        cfg.alert_threshold = self.alert_threshold;
        cfg.poll_interval_secs = self.poll_interval_secs;
        cfg.log_all_connections = self.log_all_connections;
        cfg.autostart = self.autostart;
        cfg.trusted_processes = self.trusted_processes.clone();
        // trusted_filter is intentionally not persisted
    }
}

// ── Panel ─────────────────────────────────────────────────────────────────────

pub fn show(ui: &mut egui::Ui, draft: &mut SettingsDraft) -> bool {
    let mut changed = false;

    egui::ScrollArea::vertical()
        .id_salt("settings_scroll")
        .show(ui, |ui| {
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

/// All settings content — rendered full width with live auto-save.
fn inner(ui: &mut egui::Ui, draft: &mut SettingsDraft, changed: &mut bool) {
    let label_w = 185.0f32;

    // ── Detection ─────────────────────────────────────────────────────────────
    section_header(ui, "Detection");

    setting_row(ui, label_w, "Alert threshold", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::Slider::new(&mut draft.alert_threshold, 1_u8..=10_u8)
                    .clamping(egui::SliderClamping::Always),
            );
            *changed |= resp.changed();
            ui.label(
                RichText::new(format!("  score ≥ {} → alert", draft.alert_threshold))
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

    // ── Startup ───────────────────────────────────────────────────────────────
    ui.add_space(16.0);
    section_header(ui, "Startup");

    setting_row(ui, label_w, "Run at login", |ui| {
        *changed |= ui
            .checkbox(
                &mut draft.autostart,
                RichText::new("start Vigil automatically when you log in")
                    .color(theme::TEXT2)
                    .size(11.5),
            )
            .changed();
    });

    // ── Trusted Processes ─────────────────────────────────────────────────────
    ui.add_space(16.0);
    section_header(ui, "Trusted Processes");
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "Trusted processes are exempt from routine penalties. They still alert on severe signals such as malware ports or suspicious ancestry. Matching is case-insensitive and ignores .exe.",
        )
        .color(theme::TEXT2)
        .size(12.0),
    );
    ui.add_space(10.0);

    // ── Add / reset row ────────────────────────────────────────────────────────
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

    // ── Trusted list ──────────────────────────────────────────────────────────
    let mut remove_idx: Option<usize> = None;

    if draft.trusted_processes.is_empty() {
        ui.label(
            RichText::new("No trusted processes yet.")
                .color(theme::TEXT3)
                .size(11.5),
        );
    } else {
        let total = draft.trusted_processes.len();

        // Filter bar — only shown when there are more than 4 entries.
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
                            egui::Button::new(RichText::new("✕").color(theme::TEXT2).size(11.0))
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::NONE),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                {
                    draft.trusted_filter.clear();
                }
            });
            ui.add_space(6.0);
        }

        // Build the filtered index: (display_position → original_index).
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

        // Count label above the table.
        let count_label = if filter_lower.is_empty() || visible == total {
            format!("{} process{}", total, if total == 1 { "" } else { "es" })
        } else {
            format!("{} / {} processes", visible, total)
        };
        ui.label(RichText::new(&count_label).color(theme::TEXT3).size(11.5));
        ui.add_space(8.0);

        // Framed list.
        egui::Frame::NONE
            .fill(theme::SURFACE3)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .corner_radius(12.0)
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Process")
                            .color(theme::TEXT3)
                            .size(11.0)
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new("Action")
                                .color(theme::TEXT3)
                                .size(11.0)
                                .strong(),
                        );
                    });
                });

                ui.add_space(8.0);

                let list_h = (visible.max(4) as f32 * 42.0).clamp(210.0, 520.0);
                egui::ScrollArea::vertical()
                    .max_height(list_h)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for orig_idx in filtered {
                            let name = draft.trusted_processes[orig_idx].clone();

                            egui::Frame::NONE
                                .fill(theme::SURFACE2)
                                .stroke(egui::Stroke::new(1.0, theme::BORDER))
                                .corner_radius(12.0)
                                .inner_margin(egui::Margin::symmetric(10, 5))
                                .show(ui, |ui| {
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(ui.available_width(), 38.0),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            let (bar_rect, _) = ui.allocate_exact_size(
                                                egui::vec2(3.0, 16.0),
                                                egui::Sense::hover(),
                                            );
                                            ui.painter().rect_filled(bar_rect, 2.0, theme::ACCENT);
                                            ui.add_space(8.0);
                                            ui.vertical(|ui| {
                                                ui.label(
                                                    RichText::new(&name)
                                                        .color(theme::TEXT)
                                                        .size(12.2),
                                                );
                                                ui.label(
                                                    RichText::new(
                                                        "Trusted for routine connections",
                                                    )
                                                    .color(theme::TEXT3)
                                                    .size(9.6),
                                                );
                                            });
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    let remove_btn = egui::Button::new(
                                                        RichText::new("Remove")
                                                            .color(theme::DANGER)
                                                            .size(11.0),
                                                    )
                                                    .fill(theme::DANGER_BG)
                                                    .stroke(egui::Stroke::new(1.0, theme::DANGER))
                                                    .corner_radius(7.0);
                                                    if ui
                                                        .add(remove_btn)
                                                        .on_hover_cursor(
                                                            egui::CursorIcon::PointingHand,
                                                        )
                                                        .clicked()
                                                    {
                                                        remove_idx = Some(orig_idx);
                                                    }
                                                },
                                            );
                                        },
                                    );
                                });
                            ui.add_space(6.0);
                        }
                    });
            });
    }

    if let Some(idx) = remove_idx {
        draft.trusted_processes.remove(idx);
        // Keep filter valid; no index fixup needed since we remove by original index.
        *changed = true;
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Section header: 3 px accent bar + bold label.
fn section_header(ui: &mut egui::Ui, title: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(3.0, 16.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 2.0, theme::ACCENT);
        ui.add_space(8.0);
        ui.label(RichText::new(title).color(theme::TEXT).size(13.5).strong());
    });
    ui.add_space(10.0);
}

/// Two-column row: fixed-width label on the left, control closure on the right.
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
