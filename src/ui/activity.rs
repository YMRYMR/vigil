//! Activity tab — scrollable, sortable, filterable table of all connections.
//!
//! Columns (all resizable): Time · Process · Parent · Remote · Status · Score
//! Rows are sorted by the active column; newest-first by default.
//! Click any column header to sort; click again to flip direction.
//! Click a row anywhere to select it for the inspector.
//! Right-click the table body to get a context menu with "Clear all".

use crate::types::ConnInfo;
use crate::ui::{theme, TableState};
use egui::{Color32, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use std::collections::VecDeque;

const W_TIME:   f32 = 80.0;
const W_PARENT: f32 = 140.0;
const W_REMOTE: f32 = 175.0;
const W_STATUS: f32 = 115.0;
const W_SCORE:  f32 = 58.0;
const ROW_H:    f32 = 26.0;
const HDR_H:    f32 = 28.0;

const COL_TIME:   usize = 0;
const COL_PROC:   usize = 1;
const COL_PARENT: usize = 2;
const COL_REMOTE: usize = 3;
const COL_STATUS: usize = 4;
const COL_SCORE:  usize = 5;

pub fn show(
    ui: &mut egui::Ui,
    rows: &VecDeque<ConnInfo>,
    selected: &mut Option<usize>,
    state: &mut TableState,
) -> bool {
    let mut clear_requested = false;

    // ── Filter bar ────────────────────────────────────────────────────────────
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("⌕").size(14.0).color(theme::TEXT3));
                let te = egui::TextEdit::singleline(&mut state.filter)
                    .hint_text("filter by process, remote, or status…")
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
                        format!("{shown} / {total}")
                    } else {
                        format!("{total} connections")
                    };
                    ui.label(RichText::new(label).color(theme::TEXT3).size(10.5));
                });
            });
        });

    // ── Build sorted + filtered view ──────────────────────────────────────────
    let view = sorted_view(rows, &state.filter, state.sort_col, state.sort_asc);

    // ── Table ─────────────────────────────────────────────────────────────────
    let mut clicked_idx: Option<usize> = None;

    TableBuilder::new(ui)
        .id_salt("activity_table_v2")
        .striped(true)
        .resizable(true)
        .sense(Sense::hover())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(W_TIME).at_least(54.0))
        .column(Column::remainder().at_least(80.0))
        .column(Column::initial(W_PARENT).at_least(70.0))
        .column(Column::initial(W_REMOTE).at_least(90.0))
        .column(Column::initial(W_STATUS).at_least(70.0))
        .column(Column::initial(W_SCORE).at_least(44.0))
        .header(HDR_H, |mut hdr| {
            sort_header(&mut hdr, "Time",    COL_TIME,   state);
            sort_header(&mut hdr, "Process", COL_PROC,   state);
            sort_header(&mut hdr, "Parent",  COL_PARENT, state);
            sort_header(&mut hdr, "Remote",  COL_REMOTE, state);
            sort_header(&mut hdr, "Status",  COL_STATUS, state);
            sort_header(&mut hdr, "Score",   COL_SCORE,  state);
        })
        .body(|mut body| {
            for (orig_idx, info) in &view {
                let is_selected = *selected == Some(*orig_idx);
                body.row(ROW_H, |mut row| {
                    row.set_selected(is_selected);
                    let mut row_clicked = false;

                    // Time
                    row.col(|ui| {
                        let r = ui
                            .interact(ui.max_rect(), ui.id().with("ri"), Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand);
                        ui.label(RichText::new(&info.timestamp).color(theme::TEXT2).size(11.0));
                        if r.clicked() { row_clicked = true; }
                    });

                    // Process + pid
                    row.col(|ui| {
                        let r = ui
                            .interact(ui.max_rect(), ui.id().with("ri"), Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand);
                        let text = format!("{}  {}", info.proc_name, info.pid);
                        ui.add(
                            egui::Label::new(
                                RichText::new(&text).color(score_color(info.score)).size(11.5),
                            )
                            .truncate(),
                        );
                        if r.clicked() { row_clicked = true; }
                    });

                    // Parent
                    row.col(|ui| {
                        let r = ui
                            .interact(ui.max_rect(), ui.id().with("ri"), Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand);
                        ui.add(
                            egui::Label::new(
                                RichText::new(&info.parent_name)
                                    .color(theme::TEXT2)
                                    .size(11.0),
                            )
                            .truncate(),
                        );
                        if r.clicked() { row_clicked = true; }
                    });

                    // Remote
                    row.col(|ui| {
                        let r = ui
                            .interact(ui.max_rect(), ui.id().with("ri"), Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand);
                        ui.add(
                            egui::Label::new(
                                RichText::new(&info.remote_addr)
                                    .color(theme::TEXT2)
                                    .monospace()
                                    .size(10.5),
                            )
                            .truncate(),
                        );
                        if r.clicked() { row_clicked = true; }
                    });

                    // Status
                    row.col(|ui| {
                        let r = ui
                            .interact(ui.max_rect(), ui.id().with("ri"), Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand);
                        ui.label(
                            RichText::new(&info.status)
                                .color(status_color(&info.status))
                                .size(11.0),
                        );
                        if r.clicked() { row_clicked = true; }
                    });

                    // Score badge
                    row.col(|ui| {
                        let r = ui
                            .interact(ui.max_rect(), ui.id().with("ri"), Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand);
                        let (fg, bg) = theme::score_colors(info.score);
                        score_badge(ui, info.score, fg, bg);
                        if r.clicked() { row_clicked = true; }
                    });

                    if row_clicked { clicked_idx = Some(*orig_idx); }
                });
            }
        });

    // ── Context menu (right-click on table area) ──────────────────────────────
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

    if let Some(idx) = clicked_idx {
        *selected = if *selected == Some(idx) { None } else { Some(idx) };
    }

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
        // Claim the full cell rect first — same pattern used for body-row clicks.
        // Label::sense(click()) stopped working once the table sense was set to
        // Sense::hover(); ui.interact on max_rect is reliable in egui_extras 0.34.
        let r = ui
            .interact(ui.max_rect(), ui.id().with("sh"), Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        ui.label(rich);
        if r.clicked() {
            state.toggle(col);
        }
    });
}

fn score_badge(ui: &mut egui::Ui, score: u8, fg: egui::Color32, bg: egui::Color32) {
    ui.label(
        RichText::new(format!("{score:>2}"))
            .color(fg)
            .background_color(bg)
            .monospace()
            .size(11.0),
    );
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
            COL_TIME   => bi.cmp(ai),
            COL_PROC   => a.proc_name.to_lowercase().cmp(&b.proc_name.to_lowercase()),
            COL_PARENT => a.parent_name.to_lowercase().cmp(&b.parent_name.to_lowercase()),
            COL_REMOTE => a.remote_addr.cmp(&b.remote_addr),
            COL_STATUS => a.status.cmp(&b.status),
            COL_SCORE  => a.score.cmp(&b.score),
            _          => bi.cmp(ai),
        };
        if sort_asc { ord } else { ord.reverse() }
    });

    view
}

fn matches_filter(r: &ConnInfo, lower: &str) -> bool {
    r.proc_name.to_lowercase().contains(lower)
        || r.remote_addr.to_lowercase().contains(lower)
        || r.status.to_lowercase().contains(lower)
        || r.local_addr.to_lowercase().contains(lower)
}

fn score_color(score: u8) -> Color32 {
    if score >= 5 { theme::DANGER } else if score >= 3 { theme::WARN } else { theme::TEXT }
}

fn status_color(status: &str) -> Color32 {
    match status {
        "ESTABLISHED"                                            => theme::ACCENT,
        "LISTEN"                                                 => theme::TEXT2,
        "SYN_SENT" | "SYN_RECV"                                 => theme::WARN,
        "CLOSE_WAIT" | "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" => theme::TEXT3,
        _                                                        => theme::TEXT2,
    }
}
