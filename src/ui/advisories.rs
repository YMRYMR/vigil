//! Advisory browser tab.
//!
//! The tab intentionally uses a small async snapshot instead of querying
//! SQLite on the UI thread. Advisory imports can be busy, and browsing should
//! never stall rendering.

use crate::advisory::{AffectedProduct, VulnerabilityRecord};
use crate::advisory_match::{
    evaluate_affected_product_match, AffectedProductRef, InstalledProductRef, VersionMatchStatus,
};
use crate::software_inventory::{InstalledSoftware, InventorySource};
use crate::storage::db::StorageDb;
use crate::ui::theme;
use crate::version_compare::VersionSource;
use egui::{Align2, FontId, RichText, Ui};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const QUERY_LIMIT: usize = 300;
const RELOAD_AFTER: Duration = Duration::from_secs(300);
const FILTER_DEBOUNCE: Duration = Duration::from_millis(350);
const HEADER_H: f32 = 28.0;
const ROW_H: f32 = 58.0;

pub struct AdvisoriesState {
    pub filter: String,
    records: Vec<VulnerabilityRecord>,
    selected: Option<AdvisorySelection>,
    local_status: HashMap<AdvisorySelection, LocalExposureStatus>,
    source_counts: Vec<(String, usize)>,
    total_records: usize,
    sort_col: usize,
    sort_asc: bool,
    error: Option<String>,
    requested_filter: Option<String>,
    query_rx: Option<mpsc::Receiver<Result<AdvisoryQueryResult, String>>>,
    loading_since: Option<Instant>,
    last_loaded: Option<Instant>,
    filter_changed_at: Option<Instant>,
}

impl Default for AdvisoriesState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            records: Vec::new(),
            selected: None,
            local_status: HashMap::new(),
            source_counts: Vec::new(),
            total_records: 0,
            sort_col: 3,
            sort_asc: false,
            error: None,
            requested_filter: None,
            query_rx: None,
            loading_since: None,
            last_loaded: None,
            filter_changed_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AdvisorySelection {
    primary_id: String,
    source_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalExposureStatus {
    Applies,
    InstalledUnknown,
    InstalledNotAffected,
    NotDetected,
    NoInventory,
}

struct AdvisoryQueryResult {
    filter: String,
    records: Vec<VulnerabilityRecord>,
    local_status: HashMap<AdvisorySelection, LocalExposureStatus>,
    source_counts: Vec<(String, usize)>,
    total_records: usize,
    elapsed: Duration,
}

pub fn show(ui: &mut Ui, state: &mut AdvisoriesState) {
    state.poll_query();
    state.ensure_query();

    if state.query_rx.is_some() {
        ui.ctx().request_repaint_after(Duration::from_millis(100));
    } else if state.filter_changed_at.is_some() {
        ui.ctx().request_repaint_after(FILTER_DEBOUNCE);
    }

    ui.add_space(4.0);
    filter_row(ui, state);
    source_summary(ui, state);
    ui.add_space(8.0);

    let available_width = ui.available_width();
    let available_height = ui.available_height().max(220.0);
    let list_width = available_width.max(360.0);

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(list_width);
            ui.set_height(available_height);
            table_header(ui, state, list_width);
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .id_salt("advisories-records-scroll")
                .auto_shrink([false, false])
                .max_height((available_height - HEADER_H - 8.0).max(160.0))
                .show(ui, |ui| {
                    ui.set_width(list_width);
                    advisory_rows(ui, state, list_width);
                });
        });
    });
}

pub fn show_detail(ui: &mut Ui, state: &AdvisoriesState) {
    ui.add_space(12.0);
    if let Some(record) = state.selected_record() {
        egui::ScrollArea::vertical()
            .id_salt("advisory-detail-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| detail_panel(ui, record));
    } else {
        ui.label(
            RichText::new("Select an advisory")
                .color(theme::TEXT2)
                .size(12.5)
                .strong(),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("Details will appear here.")
                .color(theme::TEXT3)
                .size(11.0),
        );
    }
}

impl AdvisoriesState {
    fn selected_record(&self) -> Option<&VulnerabilityRecord> {
        let selected = self.selected.as_ref()?;
        self.records.iter().find(|record| {
            record.primary_id == selected.primary_id
                && record.provenance.source_key == selected.source_key
        })
    }

    fn ensure_query(&mut self) {
        let filter = self.filter.trim().to_string();
        let filter_changed = self.requested_filter.as_deref() != Some(filter.as_str());
        if filter_changed
            && !self.records.is_empty()
            && self
                .filter_changed_at
                .map(|changed| changed.elapsed() < FILTER_DEBOUNCE)
                .unwrap_or(false)
        {
            return;
        }
        let stale = self
            .last_loaded
            .map(|loaded| loaded.elapsed() >= RELOAD_AFTER)
            .unwrap_or(true);

        if self.query_rx.is_none() && (filter_changed || stale) {
            self.start_query(filter);
        }
    }

    fn start_query(&mut self, filter: String) {
        let (tx, rx) = mpsc::channel();
        self.requested_filter = Some(filter.clone());
        self.query_rx = Some(rx);
        self.loading_since = Some(Instant::now());
        self.filter_changed_at = None;
        self.error = None;

        let spawned = std::thread::Builder::new()
            .name("vigil-advisories-query".into())
            .spawn(move || {
                let started = Instant::now();
                let result = (|| -> Result<AdvisoryQueryResult, String> {
                    let db = StorageDb::global()?;
                    let total_records = db.count_advisory_records()?;
                    let source_counts = db.count_advisory_records_by_source()?;
                    let records = db.search_advisory_records(&filter, QUERY_LIMIT)?;
                    let inventory = db.load_software_inventory()?;
                    let local_status = local_status_for_records(&records, &inventory);
                    Ok(AdvisoryQueryResult {
                        filter,
                        records,
                        local_status,
                        source_counts,
                        total_records,
                        elapsed: started.elapsed(),
                    })
                })();
                let _ = tx.send(result);
            });

        if let Err(err) = spawned {
            self.query_rx = None;
            self.loading_since = None;
            self.error = Some(format!("Could not start advisory query worker: {err}"));
        }
    }

    fn poll_query(&mut self) {
        let Some(rx) = self.query_rx.as_ref() else {
            return;
        };

        match rx.try_recv() {
            Ok(Ok(result)) => {
                if self.requested_filter.as_deref() == Some(result.filter.as_str()) {
                    tracing::info!(
                        "advisory tab query completed in {} ms (filter='{}', records={}/{})",
                        result.elapsed.as_millis(),
                        result.filter,
                        result.records.len(),
                        result.total_records
                    );
                    self.records = result.records;
                    self.local_status = result.local_status;
                    sort_records(
                        &mut self.records,
                        &self.local_status,
                        self.sort_col,
                        self.sort_asc,
                    );
                    self.source_counts = result.source_counts;
                    self.total_records = result.total_records;
                    self.error = None;
                    if let Some(selected) = self.selected.as_ref() {
                        let still_visible = self.records.iter().any(|record| {
                            record.primary_id == selected.primary_id
                                && record.provenance.source_key == selected.source_key
                        });
                        if !still_visible {
                            self.selected = None;
                        }
                    }
                }
                self.query_rx = None;
                self.loading_since = None;
                self.last_loaded = Some(Instant::now());
            }
            Ok(Err(err)) => {
                self.error = Some(err);
                self.query_rx = None;
                self.loading_since = None;
                self.last_loaded = Some(Instant::now());
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.error = Some("Advisory query worker stopped before returning data.".into());
                self.query_rx = None;
                self.loading_since = None;
                self.last_loaded = Some(Instant::now());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
    }

    fn toggle_sort(&mut self, col: usize) {
        if self.sort_col == col {
            self.sort_asc = !self.sort_asc;
        } else {
            self.sort_col = col;
            self.sort_asc = !matches!(col, 3 | 4);
        }
        sort_records(
            &mut self.records,
            &self.local_status,
            self.sort_col,
            self.sort_asc,
        );
    }

    fn sort_arrow(&self, col: usize) -> &'static str {
        if self.sort_col != col {
            ""
        } else if self.sort_asc {
            " ^"
        } else {
            " v"
        }
    }
}

fn filter_row(ui: &mut Ui, state: &mut AdvisoriesState) {
    let row_width = ui.available_width();
    egui::Frame::NONE
        .fill(theme::SURFACE2)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width((row_width - 24.0).max(320.0));
            ui.horizontal(|ui| {
                ui.label(RichText::new("Search").size(11.5).color(theme::TEXT3));
                let fixed_width = if state.filter.is_empty() {
                    204.0
                } else {
                    232.0
                };
                let search_width = (ui.available_width() - fixed_width).max(180.0);
                let search_response = ui
                    .add_sized(
                        [search_width, 24.0],
                        egui::TextEdit::singleline(&mut state.filter).hint_text(
                            "filter by CVE, source, severity, product, summary, or reference...",
                        ),
                    )
                    .on_hover_text("Search the local advisory database.");
                if search_response.changed() {
                    state.last_loaded = None;
                    state.filter_changed_at = Some(Instant::now());
                }
                if !state.filter.is_empty()
                    && ui
                        .add(
                            egui::Button::new(RichText::new("x").color(theme::TEXT3).size(11.0))
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::NONE),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("Clear search filter.")
                        .clicked()
                {
                    state.filter.clear();
                    state.last_loaded = None;
                    state.filter_changed_at = Some(Instant::now());
                }
                if state.query_rx.is_some() {
                    ui.add(egui::Spinner::new().size(14.0));
                }
                ui.label(
                    RichText::new(advisory_count_label(state))
                        .color(theme::TEXT3)
                        .size(11.0),
                );
                if ui
                    .add(
                        egui::Button::new(RichText::new("Refresh").color(theme::TEXT2).size(11.0))
                            .fill(egui::Color32::TRANSPARENT)
                            .stroke(egui::Stroke::NONE),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text("Reload advisories from the local database.")
                    .clicked()
                {
                    state.last_loaded = None;
                    state.filter_changed_at = None;
                    state.requested_filter = None;
                }
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(status_label(state))
                    .color(theme::TEXT3)
                    .size(10.5),
            );
        });
}

fn advisory_count_label(state: &AdvisoriesState) -> String {
    match state.total_records {
        1 => "1 record".to_string(),
        total => format!("{total} records"),
    }
}

fn status_label(state: &AdvisoriesState) -> String {
    if state.query_rx.is_some() {
        let seconds = state
            .loading_since
            .map(|started| started.elapsed().as_secs())
            .unwrap_or_default();
        format!("Loading local advisory database ({seconds}s)")
    } else if state.filter.trim().is_empty() {
        format!("Showing up to {QUERY_LIMIT} highest-signal records")
    } else {
        format!("Showing up to {QUERY_LIMIT} records matching the filter")
    }
}

fn source_summary(ui: &mut Ui, state: &AdvisoriesState) {
    if let Some(error) = state.error.as_ref() {
        ui.label(RichText::new(error).color(theme::DANGER).size(11.0));
        return;
    }

    if state.source_counts.is_empty() {
        ui.label(
            RichText::new("No advisory source counts are available yet.")
                .color(theme::TEXT3)
                .size(10.5),
        );
        return;
    }

    let row_width = ui.available_width();
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.set_width((row_width - 20.0).max(320.0));
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Sources").color(theme::TEXT3).size(10.5));
                for (source, count) in state.source_counts.iter().take(8) {
                    ui.label(
                        RichText::new(format!(" {source}: {count} "))
                            .color(theme::TEXT2)
                            .background_color(theme::SURFACE2)
                            .size(10.5)
                            .monospace(),
                    );
                }
                if state.source_counts.len() > 8 {
                    ui.label(
                        RichText::new(format!("+{} sources", state.source_counts.len() - 8))
                            .color(theme::TEXT3)
                            .size(10.5),
                    );
                }
            });
        });
}

fn advisory_rows(ui: &mut Ui, state: &mut AdvisoriesState, width: f32) {
    if state.query_rx.is_some() && state.records.is_empty() {
        loading_placeholder(ui);
        return;
    }

    if state.records.is_empty() {
        ui.label(
            RichText::new("No advisory records match the current filter.")
                .color(theme::TEXT2)
                .size(12.0),
        );
        return;
    }

    let mut clicked_selection = None;
    for record in &state.records {
        let local_status = local_status_for_record(&state.local_status, record);
        let selected = state
            .selected
            .as_ref()
            .map(|sel| {
                sel.primary_id == record.primary_id
                    && sel.source_key == record.provenance.source_key
            })
            .unwrap_or(false);
        if advisory_row(ui, record, local_status, selected, width).clicked() {
            clicked_selection = Some(AdvisorySelection {
                primary_id: record.primary_id.clone(),
                source_key: record.provenance.source_key.clone(),
            });
        }
    }
    if clicked_selection.is_some() {
        state.selected = clicked_selection;
    }
}

fn loading_placeholder(ui: &mut Ui) {
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(12, 12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(
                    RichText::new("Loading advisories from the local database...")
                        .color(theme::TEXT2)
                        .size(12.0),
                );
            });
        });
}

#[derive(Clone, Copy)]
struct AdvisoryColumns {
    id_x: f32,
    source_x: f32,
    severity_x: f32,
    updated_x: f32,
    local_x: f32,
    local_w: f32,
}

fn advisory_columns(width: f32) -> AdvisoryColumns {
    let id_w = 138.0;
    let source_w = 126.0;
    let severity_w = 120.0;
    let updated_w = 108.0;
    let gap = 8.0;
    let local_x = 12.0 + id_w + source_w + severity_w + updated_w + gap * 4.0;
    AdvisoryColumns {
        id_x: 12.0,
        source_x: 12.0 + id_w + gap,
        severity_x: 12.0 + id_w + source_w + gap * 2.0,
        updated_x: 12.0 + id_w + source_w + severity_w + gap * 3.0,
        local_x,
        local_w: (width - local_x - 12.0).max(120.0),
    }
}

fn table_header(ui: &mut Ui, state: &mut AdvisoriesState, width: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, HEADER_H), egui::Sense::hover());
    let columns = advisory_columns(width);
    let headers = [
        (0, "ID", columns.id_x, 130.0, true),
        (1, "Source", columns.source_x, 118.0, true),
        (2, "Severity", columns.severity_x, 112.0, true),
        (3, "Updated", columns.updated_x, 100.0, true),
        (4, "Machine", columns.local_x, columns.local_w, false),
    ];

    for (col, label, x, w, monospace) in headers {
        let cell = egui::Rect::from_min_size(
            egui::pos2(rect.min.x + x - 4.0, rect.min.y),
            egui::vec2(w, HEADER_H),
        );
        let active = state.sort_col == col;
        let response = ui
            .interact(
                cell,
                ui.id().with(("advisory-header", col)),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text(if col == 4 {
                "Sort by whether the advisory appears applicable to this machine.".to_string()
            } else {
                format!("Sort by {label}. Click again to reverse order.")
            });
        if response.clicked() {
            state.toggle_sort(col);
        }
        ui.painter().rect_filled(cell, 6.0, theme::SURFACE2);
        ui.painter().rect_stroke(
            cell,
            6.0,
            egui::Stroke::new(1.0, if active { theme::ACCENT } else { theme::BORDER }),
            egui::StrokeKind::Outside,
        );
        let text = format!("{label}{}", state.sort_arrow(col));
        paint_cell(
            ui,
            rect.min.x + x + 4.0,
            rect.center().y,
            &text,
            if active { theme::TEXT } else { theme::TEXT2 },
            monospace,
        );
    }
}

fn advisory_row(
    ui: &mut Ui,
    record: &VulnerabilityRecord,
    local_status: LocalExposureStatus,
    selected: bool,
    width: f32,
) -> egui::Response {
    let severity = top_severity(record);
    let severity_color = severity_color(&severity);
    let fill = if selected {
        theme::SURFACE3
    } else {
        theme::SURFACE2
    };
    let stroke_color = if selected {
        theme::ACCENT
    } else {
        theme::BORDER
    };

    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, ROW_H), egui::Sense::click());
    let columns = advisory_columns(width);
    let painter = ui.painter();
    painter.rect_filled(rect, 8.0, fill);
    painter.rect_stroke(
        rect,
        8.0,
        egui::Stroke::new(1.0, stroke_color),
        egui::StrokeKind::Outside,
    );

    let top_y = rect.min.y + 18.0;
    let sub_y = rect.min.y + 39.0;
    paint_cell(
        ui,
        rect.min.x + columns.id_x,
        top_y,
        &compact_summary(&record.primary_id, 18),
        theme::TEXT,
        true,
    );
    paint_cell(
        ui,
        rect.min.x + columns.source_x,
        top_y,
        &compact_summary(&source_label(record), 17),
        theme::TEXT2,
        true,
    );
    paint_cell(
        ui,
        rect.min.x + columns.severity_x,
        top_y,
        &severity,
        severity_color,
        true,
    );
    paint_cell(
        ui,
        rect.min.x + columns.updated_x,
        top_y,
        &updated_short_label(record),
        theme::TEXT2,
        true,
    );

    let local_x = rect.min.x + columns.local_x;
    let local_chars = (columns.local_w / 6.2).max(12.0) as usize;
    paint_text(
        ui,
        local_x,
        top_y,
        local_status.label(),
        local_status.color(),
        false,
        11.0,
    );

    let meta = local_status.detail(record);
    paint_text(
        ui,
        local_x,
        sub_y,
        &compact_summary(&meta, local_chars),
        theme::TEXT3,
        false,
        10.0,
    );

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn paint_cell(ui: &Ui, x: f32, y: f32, text: &str, color: egui::Color32, monospace: bool) {
    paint_text(ui, x, y, text, color, monospace, 10.8);
}

fn paint_text(
    ui: &Ui,
    x: f32,
    y: f32,
    text: &str,
    color: egui::Color32,
    monospace: bool,
    size: f32,
) {
    let font = if monospace {
        FontId::monospace(size)
    } else {
        FontId::proportional(size)
    };
    ui.painter()
        .text(egui::pos2(x, y), Align2::LEFT_CENTER, text, font, color);
}

fn sort_records(
    records: &mut [VulnerabilityRecord],
    local_status: &HashMap<AdvisorySelection, LocalExposureStatus>,
    sort_col: usize,
    sort_asc: bool,
) {
    records.sort_by(|left, right| {
        let ordering = match sort_col {
            0 => natural_text_cmp(&left.primary_id, &right.primary_id),
            1 => natural_text_cmp(&source_label(left), &source_label(right)),
            2 => severity_sort_key(left)
                .cmp(&severity_sort_key(right))
                .then_with(|| natural_text_cmp(&left.primary_id, &right.primary_id)),
            3 => updated_sort_key(left)
                .cmp(&updated_sort_key(right))
                .then_with(|| natural_text_cmp(&left.primary_id, &right.primary_id)),
            4 => local_status_for_record(local_status, left)
                .sort_rank()
                .cmp(&local_status_for_record(local_status, right).sort_rank())
                .then_with(|| natural_text_cmp(&left.primary_id, &right.primary_id)),
            _ => Ordering::Equal,
        };
        if sort_asc {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

fn natural_text_cmp(left: &str, right: &str) -> Ordering {
    left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
}

fn local_status_for_records(
    records: &[VulnerabilityRecord],
    inventory: &[InstalledSoftware],
) -> HashMap<AdvisorySelection, LocalExposureStatus> {
    records
        .iter()
        .map(|record| {
            (
                AdvisorySelection {
                    primary_id: record.primary_id.clone(),
                    source_key: record.provenance.source_key.clone(),
                },
                local_status_for_inventory(record, inventory),
            )
        })
        .collect()
}

fn local_status_for_record(
    statuses: &HashMap<AdvisorySelection, LocalExposureStatus>,
    record: &VulnerabilityRecord,
) -> LocalExposureStatus {
    statuses
        .get(&AdvisorySelection {
            primary_id: record.primary_id.clone(),
            source_key: record.provenance.source_key.clone(),
        })
        .copied()
        .unwrap_or(LocalExposureStatus::NoInventory)
}

fn local_status_for_inventory(
    record: &VulnerabilityRecord,
    inventory: &[InstalledSoftware],
) -> LocalExposureStatus {
    if inventory.is_empty() {
        return LocalExposureStatus::NoInventory;
    }

    let mut detected_unknown = false;
    let mut detected_not_affected = false;
    for installed in inventory {
        let installed_ref = installed_product_ref(installed);
        for affected in &record.affected_products {
            let Some(matched) =
                evaluate_affected_product_match(&installed_ref, &affected_product_ref(affected))
            else {
                continue;
            };
            if matched.applies {
                return LocalExposureStatus::Applies;
            }
            if matches!(
                matched.version_status,
                VersionMatchStatus::MissingInstalledVersion | VersionMatchStatus::Unknown
            ) {
                detected_unknown = true;
            } else {
                detected_not_affected = true;
            }
        }
    }

    if detected_unknown {
        LocalExposureStatus::InstalledUnknown
    } else if detected_not_affected {
        LocalExposureStatus::InstalledNotAffected
    } else {
        LocalExposureStatus::NotDetected
    }
}

fn installed_product_ref(installed: &InstalledSoftware) -> InstalledProductRef<'_> {
    InstalledProductRef {
        product_key: &installed.product_key,
        product_aliases: &installed.product_aliases,
        vendor_key: installed.vendor_key.as_deref(),
        version_hint: installed.version_hint.as_deref(),
        version_source: version_source_for_inventory(installed.source),
    }
}

fn affected_product_ref(affected: &AffectedProduct) -> AffectedProductRef<'_> {
    AffectedProductRef {
        criteria: &affected.criteria,
        match_criteria_id: affected.match_criteria_id.as_deref(),
        cpe_name: affected.cpe_name.as_deref(),
        vulnerable: affected.vulnerable,
        version_start_including: affected.version_start_including.as_deref(),
        version_start_excluding: affected.version_start_excluding.as_deref(),
        version_end_including: affected.version_end_including.as_deref(),
        version_end_excluding: affected.version_end_excluding.as_deref(),
    }
}

fn version_source_for_inventory(source: InventorySource) -> VersionSource {
    match source {
        InventorySource::LinuxDpkgStatus => VersionSource::DebianPackage,
        InventorySource::LinuxRpmDatabase => VersionSource::RpmPackage,
        InventorySource::LinuxApkInstalled => VersionSource::AlpinePackage,
        InventorySource::RunningProcess
        | InventorySource::WindowsUninstallRegistry
        | InventorySource::RunningService => VersionSource::Default,
    }
}

fn severity_sort_key(record: &VulnerabilityRecord) -> (u8, i32) {
    record
        .severities
        .iter()
        .map(|severity| {
            (
                severity_rank(&severity.severity),
                severity
                    .score
                    .map(|score| (score * 10.0) as i32)
                    .unwrap_or(0),
            )
        })
        .max()
        .unwrap_or((0, 0))
}

fn updated_sort_key(record: &VulnerabilityRecord) -> String {
    record
        .last_modified
        .as_ref()
        .or(record.published.as_ref())
        .cloned()
        .unwrap_or_default()
}

fn detail_panel(ui: &mut Ui, record: &VulnerabilityRecord) {
    ui.label(
        RichText::new(&record.primary_id)
            .color(theme::ACCENT)
            .strong()
            .size(14.0)
            .monospace(),
    );
    ui.label(
        RichText::new(source_label(record))
            .color(theme::TEXT2)
            .size(11.0)
            .monospace(),
    );
    ui.separator();
    ui.add_space(8.0);

    detail_kv(ui, "Severity", top_severity(record));
    detail_kv(
        ui,
        "Published",
        record.published.as_deref().unwrap_or("n/a"),
    );
    detail_kv(
        ui,
        "Updated",
        record.last_modified.as_deref().unwrap_or("n/a"),
    );
    detail_kv(
        ui,
        "Known exploited",
        if record.known_exploited { "yes" } else { "no" },
    );

    ui.add_space(8.0);
    section(ui, "Summary");
    detail_text(ui, &record.summary);

    if !record.aliases.is_empty() {
        ui.add_space(8.0);
        section(ui, "Aliases");
        detail_text_mono(
            ui,
            &record
                .aliases
                .iter()
                .take(12)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    if !record.affected_products.is_empty() {
        ui.add_space(8.0);
        section(ui, "Affected Products");
        for affected in record.affected_products.iter().take(8) {
            detail_text_mono(ui, &compact_summary(&affected.criteria, 120));
        }
        overflow_label(ui, record.affected_products.len(), 8, "products");
    }

    if !record.mitigations.is_empty() {
        ui.add_space(8.0);
        section(ui, "Mitigations");
        for mitigation in record.mitigations.iter().take(4) {
            detail_text(ui, &compact_summary(mitigation, 180));
        }
        overflow_label(ui, record.mitigations.len(), 4, "mitigations");
    }

    if !record.references.is_empty() {
        ui.add_space(8.0);
        section(ui, "References");
        for reference in record.references.iter().take(8) {
            ui.hyperlink_to(
                RichText::new(compact_summary(&reference.url, 90))
                    .color(theme::ACCENT)
                    .size(10.5),
                &reference.url,
            );
        }
        overflow_label(ui, record.references.len(), 8, "references");
    }
}

fn detail_kv(ui: &mut Ui, key: &str, value: impl AsRef<str>) {
    ui.label(RichText::new(key).color(theme::TEXT3).size(10.5));
    detail_text(ui, value.as_ref());
    ui.add_space(6.0);
}

fn section(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).color(theme::TEXT).strong().size(12.0));
}

fn detail_text(ui: &mut Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).color(theme::TEXT2).size(11.0)).wrap());
}

fn detail_text_mono(ui: &mut Ui, text: &str) {
    ui.add(
        egui::Label::new(
            RichText::new(text)
                .color(theme::TEXT2)
                .size(10.5)
                .monospace(),
        )
        .wrap(),
    );
}

fn overflow_label(ui: &mut Ui, total: usize, shown: usize, label: &str) {
    if total > shown {
        ui.label(
            RichText::new(format!("+{} more {label}", total - shown))
                .color(theme::TEXT3)
                .size(10.5),
        );
    }
}

fn source_label(record: &VulnerabilityRecord) -> String {
    format!(
        "{} / {}",
        record.provenance.source_kind, record.provenance.source_key
    )
}

fn updated_short_label(record: &VulnerabilityRecord) -> String {
    record
        .last_modified
        .as_ref()
        .or(record.published.as_ref())
        .map(|value| date_only_label(value))
        .unwrap_or_else(|| "n/a".into())
}

fn date_only_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 10 {
        let candidate = &trimmed[..10];
        if candidate.chars().all(|ch| ch.is_ascii_digit() || ch == '-') {
            return candidate.to_string();
        }
    }
    compact_summary(trimmed, 10)
}

impl LocalExposureStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Applies => "applies",
            Self::InstalledUnknown => "installed ?",
            Self::InstalledNotAffected => "not affected",
            Self::NotDetected => "not detected",
            Self::NoInventory => "no inventory",
        }
    }

    fn detail(self, record: &VulnerabilityRecord) -> String {
        let products = record.affected_products.len();
        match self {
            Self::Applies => format!("affected software detected | {products} products"),
            Self::InstalledUnknown => {
                format!("software detected, version unknown | {products} products")
            }
            Self::InstalledNotAffected => {
                format!("software detected, version out of range | {products} products")
            }
            Self::NotDetected => format!("no local product match | {products} products"),
            Self::NoInventory => format!("inventory unavailable | {products} products"),
        }
    }

    fn color(self) -> egui::Color32 {
        match self {
            Self::Applies => theme::DANGER,
            Self::InstalledUnknown => theme::WARN,
            Self::InstalledNotAffected => theme::ACCENT,
            Self::NotDetected | Self::NoInventory => theme::TEXT2,
        }
    }

    fn sort_rank(self) -> u8 {
        match self {
            Self::Applies => 4,
            Self::InstalledUnknown => 3,
            Self::InstalledNotAffected => 2,
            Self::NotDetected => 1,
            Self::NoInventory => 0,
        }
    }
}

fn top_severity(record: &VulnerabilityRecord) -> String {
    record
        .severities
        .iter()
        .filter_map(|severity| {
            let rank = severity_rank(&severity.severity);
            (rank > 0).then_some((rank, severity))
        })
        .max_by(|(left_rank, left), (right_rank, right)| {
            left_rank.cmp(right_rank).then_with(|| {
                left.score
                    .partial_cmp(&right.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        })
        .map(|(_, severity)| match severity.score {
            Some(score) => format!("{} {score:.1}", severity.severity.to_ascii_lowercase()),
            None => severity.severity.to_ascii_lowercase(),
        })
        .unwrap_or_else(|| "unknown".into())
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_color(severity: &str) -> egui::Color32 {
    match severity.split_whitespace().next().unwrap_or_default() {
        "critical" | "high" => theme::DANGER,
        "medium" => theme::WARN,
        "low" => theme::ACCENT,
        _ => theme::TEXT2,
    }
}

fn compact_summary(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    let mut compact = trimmed
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    compact.push_str("...");
    compact
}
