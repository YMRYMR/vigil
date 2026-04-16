//! Alerts tab — scored threats, sortable and filterable.
//!
//! Columns (all resizable): Time · Process · Parent · Score · Remote · Reasons
//! Default sort: Score descending (highest threat first).

use crate::types::ConnInfo;
use crate::ui::{theme, TableState};
use egui::{Color32, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use std::collections::VecDeque;

const W_TIME:   f32 = 80.0;
const W_PROC:   f32 = 185.0;
const W_PARENT: f32 = 140.0;
const W_SCORE:  f32 = 58.0;
const W_REMOTE: f32 = 175.0;
const ROW_H:    f32 = 26.0;
const HDR_H:    f32 = 28.0;

const COL_TIME:    usize = 0;
const COL_PROC:    usize = 1;
const COL_PARENT:  usize = 2;
const COL_SCORE:   usize = 3;
const COL_REMOTE:  usize = 4;
const COL_REASONS: usize = 5;

pub fn show(
    ui: &mut egui::Ui,
    rows: &VecDeque<ConnInfo>,
    selected: &mut Option<usize>,
    state: &mut TableState,
) -> bool {
    let mut clear_requested = false;

    if rows.is_empty() {
        show_empty(ui);
        return clear_requested;
    }

    // ── Filter bar ────────────────────────────────────────────────────────────
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("⌕").size(14.0).color(theme::TEXT3));
                let te = egui::TextEdit::singleline(&mut state.filter)
                    .hint_text("filter alerts…")
                    .desired_width(ui.available_width() - 120.0)
                    .font(egui::TextStyle::Body);
                ui.add(te);
                if !state.filter.is_empty()
                    && ui
                        .add(
                            egui::Button::new(RichText::new("✕").color(theme::TEXT3).size(11.0))
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::NONE),
                        )
                        .clicked()
                {
                    state.filter.clear();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let total = rows.len();
                    let shown = visible_count(rows, &state.filter);
                    let label = if total != shown {
                        format!("{shown} / {total} alerts")
                    } else {
                        format!("{total} alert{}", if total == 1 { "" } else { "s" })
                    };
                    ui.label(RichText::new(label).color(theme::DANGER).size(10.5));
                });
            });
        });

    let view = sorted_view(rows, &state.filter, state.sort_col, state.sort_asc);
    let mut clicked_idx: Option<usize> = None;

    TableBuilder::new(ui)
        .id_salt("alerts_table_v2")
        .striped(true)
        .resizable(true)
        // sense(Sense::click()) makes every cell's response carry click/hover info.
        // Use the (Rect, Response) return value of row.col() for interaction.
        .sense(Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(W_TIME).at_least(54.0))
        .column(Column::initial(W_PROC).at_least(80.0))
        .column(Column::initial(W_PARENT).at_least(70.0))
        .column(Column::initial(W_SCORE).at_least(44.0))
        .column(Column::initial(W_REMOTE).at_least(90.0))
        .column(Column::remainder().at_least(60.0))
        .header(HDR_H, |mut hdr| {
            sort_header(&mut hdr, "Time",    COL_TIME,    state);
            sort_header(&mut hdr, "Process", COL_PROC,    state);
            sort_header(&mut hdr, "Parent",  COL_PARENT,  state);
            sort_header(&mut hdr, "Score",   COL_SCORE,   state);
            sort_header(&mut hdr, "Remote",  COL_REMOTE,  state);
            sort_header(&mut hdr, "Reasons", COL_REASONS, state);
        })
        .body(|mut body| {
            for (orig_idx, info) in &view {
                let is_selected = *selected == Some(*orig_idx);
                body.row(ROW_H, |mut row| {
                    row.set_selected(is_selected);
                    let mut row_clicked = false;

                    // Each row.col() call returns (Rect, Response).
                    // The Response has clicked/hovered because sense(Sense::click())
                    // was set on the builder.

                    // Time
                    let (_, r) = row.col(|ui| {
                        ui.label(RichText::new(&info.timestamp).color(theme::TEXT2).size(11.0));
                    });
                    if r.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { row_clicked = true; }

                    // Process
                    let (_, r) = row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&info.proc_name)
                                    .color(alert_color(info.score))
                                    .size(11.5),
                            )
                            .truncate(),
                        );
                    });
                    if r.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { row_clicked = true; }

                    // Parent
                    let (_, r) = row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&info.parent_name)
                                    .color(theme::TEXT2)
                                    .size(11.0),
                            )
                            .truncate(),
                        );
                    });
                    if r.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { row_clicked = true; }

                    // Score
                    let (_, r) = row.col(|ui| {
                        let (fg, bg) = theme::score_colors(info.score);
                        ui.label(
                            RichText::new(format!("{:>2}", info.score))
                                .color(fg)
                                .background_color(bg)
                                .monospace()
                                .size(11.0),
                        );
                    });
                    if r.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { row_clicked = true; }

                    // Remote
                    let (_, r) = row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&info.remote_addr)
                                    .color(theme::TEXT2)
                                    .monospace()
                                    .size(10.5),
                            )
                            .truncate(),
                        );
                    });
                    if r.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { row_clicked = true; }

                    // Reasons
                    let (_, r) = row.col(|ui| {
                        let reason = info.reasons.first().map(|s| s.as_str()).unwrap_or("—");
                        ui.add(
                            egui::Label::new(
                                RichText::new(reason).color(theme::TEXT2).size(11.0),
                            )
                            .truncate(),
                        );
                    });
                    if r.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { row_clicked = true; }

                    if row_clicked { clicked_idx = Some(*orig_idx); }
                });
            }
        });

    if let Some(idx) = clicked_idx {
        *selected = if *selected == Some(idx) { None } else { Some(idx) };
    }

    let table_response = ui.interact(
        ui.min_rect(),
        ui.id().with("ctx_menu"),
        egui::Sense::click(),
    );
    table_response.context_menu(|ui| {
        if ui.button("Clear all").clicked() {
            clear_requested = true;
            ui.close();
        }
    });

    clear_requested
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn sort_header(
    hdr: &mut egui_extras::TableRow<'_, '_>,
    label: &str,
    col: usize,
    state: &mut TableState,
) {
    hdr.col(|ui| {
        let active = state.sort_col == col;
        let arrow  = state.arrow(col);
        let text   = format!("{label}{arrow}");
        let color  = if active { theme::TEXT } else { theme::TEXT2 };
        let rich   = RichText::new(&text).color(color).size(10.5).strong();
        if ui
            .add(egui::Label::new(rich).sense(Sense::click()))
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            state.toggle(col);
        }
    });
}

fn visible_count(rows: &VecDeque<ConnInfo>, filter: &str) -> usize {
    if filter.is_empty() { return rows.len(); }
    let f = filter.to_lowercase();
    rows.iter().filter(|r| matches_filter(r, &f)).count()
}

fn sorted_view<'a>(
    rows: &'a VecDeque<ConnInfo>,
    filter: &str,
    sort_col: usize,
    sort_asc: bool,
) -> Vec<(usize, &'a ConnInfo)> {
    let f = filter.to_lowercase();
    let mut view: Vec<(usize, &ConnInfo)> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| f.is_empty() || matches_filter(r, &f))
        .collect();

    view.sort_by(|(ai, a), (bi, b)| {
        let ord = match sort_col {
            COL_TIME    => bi.cmp(ai),   // descending index = newest first
            COL_PROC    => a.proc_name.to_lowercase().cmp(&b.proc_name.to_lowercase()),
            COL_PARENT  => a.parent_name.to_lowercase().cmp(&b.parent_name.to_lowercase()),
            COL_SCORE   => a.score.cmp(&b.score),
            COL_REMOTE  => a.remote_addr.cmp(&b.remote_addr),
            COL_REASONS => a.reasons.first().map(|s| s.as_str()).unwrap_or("")
                .cmp(b.reasons.first().map(|s| s.as_str()).unwrap_or("")),
            _           => bi.cmp(ai),
        };
        if sort_asc { ord } else { ord.reverse() }
    });

    view
}

fn matches_filter(r: &ConnInfo, lower: &str) -> bool {
    r.proc_name.to_lowercase().contains(lower)
        || r.parent_name.to_lowercase().contains(lower)
        || r.remote_addr.to_lowercase().contains(lower)
        || r.reasons.iter().any(|s| s.to_lowercase().contains(lower))
}

fn alert_color(score: u8) -> Color32 {
    if score >= 5 { theme::DANGER } else { theme::WARN }
}

fn show_empty(ui: &mut egui::Ui) {
    let rect = ui.available_rect_before_wrap();
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "No alerts  ✓",
        egui::FontId::proportional(14.0),
        theme::TEXT3,
    );
}
