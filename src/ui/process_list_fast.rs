//! Faster cached renderer for the process-grouped Activity and Alerts tabs.
//!
//! The existing `process_list` module exposes the public cache metadata type that
//! the rest of the UI already stores. This module keeps the same cache contract
//! but adds an internal owned render-model cache so normal repaints reuse grouped
//! process and endpoint rows instead of rebuilding them every frame.

use crate::types::ConnInfo;
use crate::ui::{inspector::summarize_reasons, process_list, theme, ProcessSelection, TableState};
use egui::RichText;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

pub type CachedGroupView = process_list::CachedGroupView;

const CONN_TIME_W: f32 = 84.0;
const CONN_REMOTE_W: f32 = 216.0;
const CONN_STATUS_W: f32 = 132.0;
const CONN_SCORE_W: f32 = 44.0;
const CONN_BADGE_GAP: f32 = 8.0;
const SUMMARY_H: f32 = 60.0;
const MAX_RENDER_CACHE_ENTRIES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Activity,
    Alerts,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RenderKey {
    kind: Kind,
    data_version: u64,
    filter_hash: u64,
    sort_col: usize,
    sort_asc: bool,
}

#[derive(Debug, Clone)]
struct OwnedRenderView {
    total_connections: usize,
    total_groups: usize,
    total_endpoints: usize,
    process_count: usize,
    groups: Vec<OwnedProcessGroup>,
}

#[derive(Debug, Clone)]
struct OwnedProcessGroup {
    pid: u32,
    proc_name: String,
    proc_path: String,
    proc_user: String,
    parent_user: String,
    command_line: String,
    parent_name: String,
    parent_pid: u32,
    service_name: String,
    publisher: String,
    latest_timestamp: String,
    latest_status: String,
    latest_remote: String,
    score: u8,
    conn_count: usize,
    distinct_ports: usize,
    distinct_remotes: usize,
    statuses: Vec<String>,
    reason_summary: crate::ui::inspector::ReasonSummary,
    attack_tags: Vec<String>,
    baseline_deviation: bool,
    script_host_suspicious: bool,
    tls_enriched: bool,
    endpoint_rows: Vec<OwnedEndpointRow>,
}

#[derive(Debug, Clone)]
struct OwnedEndpointRow {
    representative: ConnInfo,
    latest_timestamp: String,
    remote_addr: String,
    conn_count: usize,
    local_port_count: usize,
    statuses: Vec<String>,
    status_summary: String,
    max_score: u8,
    pre_login: bool,
    reputation_hit: bool,
    recently_dropped: bool,
    long_lived: bool,
    dga_like: bool,
    script_host_suspicious: bool,
    baseline_deviation: bool,
    tls_enriched: bool,
}

#[derive(Default)]
struct ProcessAccumulator {
    pid: u32,
    proc_name: String,
    proc_path: String,
    proc_user: String,
    parent_user: String,
    command_line: String,
    parent_name: String,
    parent_pid: u32,
    service_name: String,
    publisher: String,
    latest_timestamp: String,
    latest_status: String,
    latest_remote: String,
    score: u8,
    conn_count: usize,
    distinct_ports: HashSet<u16>,
    distinct_remotes: HashSet<String>,
    statuses: Vec<String>,
    reasons: Vec<String>,
    attack_tags: Vec<String>,
    baseline_deviation: bool,
    script_host_suspicious: bool,
    tls_enriched: bool,
    endpoints: HashMap<String, EndpointAccumulator>,
}

#[derive(Default)]
struct EndpointAccumulator {
    representative: Option<ConnInfo>,
    latest_timestamp: String,
    remote_addr: String,
    conn_count: usize,
    local_ports: HashSet<String>,
    statuses: Vec<String>,
    max_score: u8,
    pre_login: bool,
    reputation_hit: bool,
    recently_dropped: bool,
    long_lived: bool,
    dga_like: bool,
    script_host_suspicious: bool,
    baseline_deviation: bool,
    tls_enriched: bool,
}

fn render_cache() -> &'static Mutex<HashMap<RenderKey, OwnedRenderView>> {
    static CACHE: OnceLock<Mutex<HashMap<RenderKey, OwnedRenderView>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[allow(deprecated)]
pub fn show(
    ui: &mut egui::Ui,
    rows: &VecDeque<ConnInfo>,
    selected: &mut Option<ProcessSelection>,
    state: &mut TableState,
    kind: Kind,
    data_version: u64,
    cache: &mut Option<CachedGroupView>,
) -> bool {
    ui.add_space(4.0);
    filter_bar(ui, rows.len(), state, kind);

    let filter_hash = calc_filter_hash(&state.filter);
    let key = RenderKey {
        kind,
        data_version,
        filter_hash,
        sort_col: state.sort_col,
        sort_asc: state.sort_asc,
    };

    let view = {
        let mut store = render_cache().lock().unwrap();
        if let Some(view) = store.get(&key).cloned() {
            *cache = Some(CachedGroupView {
                data_version,
                filter_hash,
                sort_col: state.sort_col,
                sort_asc: state.sort_asc,
                total_connections: view.total_connections,
                total_groups: view.total_groups,
                total_endpoints: view.total_endpoints,
                process_count: view.process_count,
            });
            view
        } else {
            let rebuilt = build_view(rows, &state.filter, kind, state.sort_col, state.sort_asc);
            *cache = Some(CachedGroupView {
                data_version,
                filter_hash,
                sort_col: state.sort_col,
                sort_asc: state.sort_asc,
                total_connections: rebuilt.total_connections,
                total_groups: rebuilt.total_groups,
                total_endpoints: rebuilt.total_endpoints,
                process_count: rebuilt.process_count,
            });
            if store.len() >= MAX_RENDER_CACHE_ENTRIES {
                store.clear();
            }
            store.insert(key, rebuilt.clone());
            rebuilt
        }
    };

    ui.add_space(8.0);
    header_row(ui, state);
    ui.add_space(8.0);

    egui::ScrollArea::vertical()
        .id_salt(match kind {
            Kind::Activity => "activity_groups_fast",
            Kind::Alerts => "alerts_groups_fast",
        })
        .show(ui, |ui| {
            if view.groups.is_empty() {
                empty_state(ui, kind);
                return;
            }

            for group in &view.groups {
                let selected_in_group = selected.as_ref().is_some_and(|sel| sel.pid == group.pid);
                let collapsed = state.is_collapsed(group.pid);
                let frame_fill = if selected_in_group {
                    theme::SURFACE3
                } else {
                    theme::SURFACE
                };

                egui::Frame::NONE
                    .fill(frame_fill)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER))
                    .corner_radius(12.0)
                    .inner_margin(egui::Margin::same(14))
                    .show(ui, |ui| {
                        let (summary_rect, summary_resp) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), SUMMARY_H),
                            egui::Sense::click(),
                        );
                        let summary_fill = if selected_in_group {
                            theme::SURFACE3
                        } else {
                            theme::SURFACE2
                        };
                        ui.painter().rect_filled(
                            summary_rect.shrink2(egui::vec2(0.0, 1.0)),
                            10.0,
                            summary_fill,
                        );
                        ui.painter().rect_stroke(
                            summary_rect.shrink2(egui::vec2(0.0, 1.0)),
                            10.0,
                            egui::Stroke::new(1.0, theme::BORDER),
                            egui::StrokeKind::Outside,
                        );

                        ui.allocate_ui_at_rect(summary_rect.shrink2(egui::vec2(12.0, 8.0)), |ui| {
                            ui.horizontal(|ui| {
                                let (bar_rect, bar_resp) = ui.allocate_exact_size(
                                    egui::vec2(4.0, 40.0),
                                    egui::Sense::click(),
                                );
                                ui.painter().rect_filled(
                                    bar_rect,
                                    2.0,
                                    if collapsed {
                                        theme::TEXT3
                                    } else {
                                        summary_bar_color(group.score, kind)
                                    },
                                );
                                if bar_resp
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text(if collapsed {
                                        "Expand this process card"
                                    } else {
                                        "Collapse this process card"
                                    })
                                    .clicked()
                                {
                                    state.toggle_collapsed(group.pid);
                                }
                                ui.add_space(12.0);

                                ui.vertical(|ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(
                                            RichText::new(&group.proc_name)
                                                .color(theme::TEXT)
                                                .size(14.0)
                                                .strong()
                                                .monospace(),
                                        );
                                        ui.label(
                                            RichText::new(format!("PID {}", group.pid))
                                                .color(theme::TEXT3)
                                                .size(10.0)
                                                .monospace(),
                                        );
                                        pill(
                                            ui,
                                            &format!(
                                                "{} socket{}",
                                                group.conn_count,
                                                plural(group.conn_count)
                                            ),
                                            theme::TEXT2,
                                            theme::SURFACE2,
                                        );
                                        pill(
                                            ui,
                                            &format!(
                                                "{} endpoint{}",
                                                group.endpoint_rows.len(),
                                                plural(group.endpoint_rows.len())
                                            ),
                                            theme::TEXT2,
                                            theme::SURFACE2,
                                        );
                                        if group.script_host_suspicious {
                                            pill(ui, "Script host", theme::WARN, theme::WARN_BG);
                                        }
                                        if group.baseline_deviation {
                                            pill(
                                                ui,
                                                "Baseline drift",
                                                theme::ACCENT,
                                                theme::ACCENT_BG,
                                            );
                                        }
                                        if group.tls_enriched {
                                            pill(ui, "TLS", theme::ACCENT, theme::ACCENT_BG);
                                        }
                                    });
                                    ui.add_space(2.0);
                                    ui.label(
                                        RichText::new(process_meta_line(group))
                                            .color(theme::TEXT2)
                                            .size(10.4),
                                    );
                                    if !group.statuses.is_empty() {
                                        ui.label(
                                            RichText::new(format!(
                                                "States seen: {}",
                                                group.statuses.join(", ")
                                            ))
                                            .color(theme::TEXT3)
                                            .size(10.0),
                                        );
                                    }
                                });

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Min),
                                    |ui| {
                                        let (fg, bg) = theme::score_colors(group.score);
                                        ui.label(
                                            RichText::new(format!("{:>2}", group.score))
                                                .color(fg)
                                                .background_color(bg)
                                                .monospace()
                                                .size(11.5),
                                        );
                                        ui.add_space(10.0);
                                        ui.label(
                                            RichText::new(&group.latest_timestamp)
                                                .color(theme::TEXT2)
                                                .size(10.2),
                                        );
                                    },
                                );
                            });
                        });

                        if summary_resp
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(
                                "Select this process card to inspect process-level details.",
                            )
                            .clicked()
                        {
                            *selected = Some(selection_from_group(group, None));
                        }

                        if !collapsed {
                            ui.add_space(10.0);
                            ui.separator();
                            ui.add_space(8.0);
                            for endpoint in &group.endpoint_rows {
                                let conn_selected = selected
                                    .as_ref()
                                    .and_then(|sel| sel.selected_connection.as_ref())
                                    .is_some_and(|sel_conn| {
                                        crate::ui::conn_matches_selection(
                                            &endpoint.representative,
                                            Some(sel_conn),
                                        )
                                    });
                                if let Some(clicked) =
                                    endpoint_line(ui, endpoint, kind, conn_selected)
                                {
                                    *selected = Some(selection_from_group(group, Some(clicked)));
                                }
                                ui.add_space(6.0);
                            }
                        } else {
                            ui.add_space(8.0);
                            ui.label(
                                RichText::new(format!(
                                    "{} endpoint row{} hidden",
                                    group.endpoint_rows.len(),
                                    plural(group.endpoint_rows.len())
                                ))
                                .color(theme::TEXT3)
                                .size(10.2),
                            );
                        }
                    });
                ui.add_space(10.0);
            }

            let footer = match kind {
                Kind::Activity => format!(
                    "{} processes / {} sockets / {} endpoint rows",
                    view.total_groups, view.total_connections, view.total_endpoints
                ),
                Kind::Alerts => format!(
                    "{} alerting processes / {} sockets / {} endpoint rows",
                    view.total_groups, view.total_connections, view.total_endpoints
                ),
            };
            ui.add_space(4.0);
            ui.label(RichText::new(footer).color(theme::TEXT3).size(10.5));
        });

    false
}

fn build_view(
    rows: &VecDeque<ConnInfo>,
    filter: &str,
    kind: Kind,
    sort_col: usize,
    sort_asc: bool,
) -> OwnedRenderView {
    let lower = filter.to_ascii_lowercase();
    let mut groups: HashMap<u32, ProcessAccumulator> = HashMap::new();
    let mut order = Vec::new();

    for info in rows.iter().filter(|r| matches_filter(r, &lower, kind)) {
        let entry = groups.entry(info.pid).or_insert_with(|| {
            order.push(info.pid);
            ProcessAccumulator {
                pid: info.pid,
                proc_name: info.proc_name.clone(),
                proc_path: info.proc_path.clone(),
                proc_user: info.proc_user.clone(),
                parent_user: info.parent_user.clone(),
                command_line: info.command_line.clone(),
                parent_name: info.parent_name.clone(),
                parent_pid: info.parent_pid,
                service_name: info.service_name.clone(),
                publisher: info.publisher.clone(),
                latest_timestamp: info.timestamp.clone(),
                latest_status: info.status.clone(),
                latest_remote: info.remote_addr.clone(),
                score: info.score,
                ..Default::default()
            }
        });
        entry.conn_count += 1;
        entry.score = entry.score.max(info.score);
        if info.timestamp >= entry.latest_timestamp {
            entry.latest_timestamp = info.timestamp.clone();
            entry.latest_status = info.status.clone();
            entry.latest_remote = info.remote_addr.clone();
        }
        if info.remote_addr != "LISTEN" {
            entry.distinct_remotes.insert(info.remote_addr.clone());
        }
        if let Some(port) = parse_port(&info.remote_addr) {
            entry.distinct_ports.insert(port);
        }
        push_unique(&mut entry.statuses, info.status.clone());
        entry.reasons.extend(info.reasons.iter().cloned());
        entry.attack_tags.extend(info.attack_tags.iter().cloned());
        entry.baseline_deviation |= info.baseline_deviation;
        entry.script_host_suspicious |= info.script_host_suspicious;
        entry.tls_enriched |= info.tls_sni.is_some() || info.tls_ja3.is_some();
        entry
            .endpoints
            .entry(endpoint_key(info))
            .or_default()
            .add(info);
    }

    let mut out_groups = Vec::new();
    for pid in order {
        if let Some(group) = groups.remove(&pid) {
            let mut endpoint_rows: Vec<OwnedEndpointRow> = group
                .endpoints
                .into_values()
                .map(EndpointAccumulator::finish)
                .collect();
            sort_endpoint_rows(&mut endpoint_rows, sort_col, sort_asc);
            let mut reasons = dedup_strings(group.reasons);
            let attack_tags = dedup_strings(group.attack_tags);
            if group.conn_count > 1 {
                reasons.push(format!(
                    "{} sockets from the same process",
                    group.conn_count
                ));
            }
            if endpoint_rows.len() < group.conn_count {
                reasons.push(format!(
                    "{} repeated sockets collapsed into {} endpoint rows",
                    group.conn_count,
                    endpoint_rows.len()
                ));
            }
            if group.distinct_ports.len() > 1 {
                reasons.push(format!(
                    "{} distinct remote ports",
                    group.distinct_ports.len()
                ));
            }
            if group.distinct_remotes.len() > 1 {
                reasons.push(format!(
                    "{} distinct remote targets",
                    group.distinct_remotes.len()
                ));
            }
            let reason_summary = summarize_reasons(&reasons);
            out_groups.push(OwnedProcessGroup {
                pid: group.pid,
                proc_name: group.proc_name,
                proc_path: group.proc_path,
                proc_user: group.proc_user,
                parent_user: group.parent_user,
                command_line: group.command_line,
                parent_name: group.parent_name,
                parent_pid: group.parent_pid,
                service_name: group.service_name,
                publisher: group.publisher,
                latest_timestamp: group.latest_timestamp,
                latest_status: group.latest_status,
                latest_remote: group.latest_remote,
                score: group.score.saturating_add(fanout_bonus(
                    group.conn_count,
                    group.distinct_ports.len(),
                    group.distinct_remotes.len(),
                    group.statuses.len(),
                )),
                conn_count: group.conn_count,
                distinct_ports: group.distinct_ports.len(),
                distinct_remotes: group.distinct_remotes.len(),
                statuses: group.statuses,
                reason_summary,
                attack_tags,
                baseline_deviation: group.baseline_deviation,
                script_host_suspicious: group.script_host_suspicious,
                tls_enriched: group.tls_enriched,
                endpoint_rows,
            });
        }
    }

    sort_groups(&mut out_groups, sort_col, sort_asc);
    OwnedRenderView {
        total_connections: out_groups.iter().map(|g| g.conn_count).sum(),
        total_groups: out_groups.len(),
        total_endpoints: out_groups.iter().map(|g| g.endpoint_rows.len()).sum(),
        process_count: out_groups.len(),
        groups: out_groups,
    }
}

impl EndpointAccumulator {
    fn add(&mut self, conn: &ConnInfo) {
        self.conn_count += 1;
        if conn.timestamp >= self.latest_timestamp {
            self.latest_timestamp = conn.timestamp.clone();
            self.representative = Some(conn.clone());
            self.remote_addr = conn.remote_addr.clone();
        }
        self.local_ports.insert(conn.local_addr.clone());
        push_unique(&mut self.statuses, conn.status.clone());
        self.max_score = self.max_score.max(conn.score);
        self.pre_login |= conn.pre_login;
        self.reputation_hit |= conn.reputation_hit.is_some();
        self.recently_dropped |= conn.recently_dropped;
        self.long_lived |= conn.long_lived;
        self.dga_like |= conn.dga_like;
        self.script_host_suspicious |= conn.script_host_suspicious;
        self.baseline_deviation |= conn.baseline_deviation;
        self.tls_enriched |= conn.tls_sni.is_some() || conn.tls_ja3.is_some();
    }

    fn finish(self) -> OwnedEndpointRow {
        let representative = self
            .representative
            .expect("endpoint accumulator finished without a representative");
        let statuses = self.statuses;
        OwnedEndpointRow {
            representative,
            latest_timestamp: self.latest_timestamp,
            remote_addr: self.remote_addr,
            conn_count: self.conn_count.max(1),
            local_port_count: self.local_ports.len().max(1),
            status_summary: statuses.join(" + "),
            statuses,
            max_score: self.max_score,
            pre_login: self.pre_login,
            reputation_hit: self.reputation_hit,
            recently_dropped: self.recently_dropped,
            long_lived: self.long_lived,
            dga_like: self.dga_like,
            script_host_suspicious: self.script_host_suspicious,
            baseline_deviation: self.baseline_deviation,
            tls_enriched: self.tls_enriched,
        }
    }
}

fn filter_bar(ui: &mut egui::Ui, total: usize, state: &mut TableState, kind: Kind) {
    egui::Frame::NONE
        .fill(theme::SURFACE2)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Search").size(11.5).color(theme::TEXT3));
                let hint = match kind {
                    Kind::Activity => "filter by process, endpoint, state, reason, or TLS…",
                    Kind::Alerts => "filter alerts by process, endpoint, state, reason, or TLS…",
                };
                ui.add(
                    egui::TextEdit::singleline(&mut state.filter)
                        .hint_text(hint)
                        .desired_width(ui.available_width() - 120.0),
                );
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
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = if total == 1 {
                        "1 process".to_string()
                    } else {
                        format!("{total} processes")
                    };
                    ui.label(RichText::new(label).color(theme::TEXT3).size(11.0));
                });
            });
        });
}

fn header_row(ui: &mut egui::Ui, state: &mut TableState) {
    ui.horizontal(|ui| {
        header_chip(ui, "Time", 0, state, 88.0);
        header_chip(ui, "Process", 1, state, 220.0);
        header_chip(ui, "Fan-out", 2, state, 120.0);
        header_chip(ui, "State", 3, state, 160.0);
        header_chip(ui, "Score", 4, state, 72.0);
    });
}

fn header_chip(ui: &mut egui::Ui, label: &str, col: usize, state: &mut TableState, width: f32) {
    let active = state.sort_col == col;
    let text = format!("{label}{}", state.arrow(col));
    let fg = if active { theme::TEXT } else { theme::TEXT2 };
    let resp = ui.add_sized(
        [width, 24.0],
        egui::Button::new(RichText::new(text).color(fg).size(11.0).strong())
            .fill(theme::SURFACE2)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .corner_radius(6.0),
    );
    if resp
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(format!("Sort by {label}. Click again to reverse order."))
        .clicked()
    {
        state.toggle(col);
    }
}

fn selection_from_group(
    group: &OwnedProcessGroup,
    selected_connection: Option<ConnInfo>,
) -> ProcessSelection {
    let selected_connection_reason_summary = selected_connection
        .as_ref()
        .map(|conn| summarize_reasons(&conn.reasons));
    ProcessSelection {
        pid: group.pid,
        proc_name: group.proc_name.clone(),
        proc_path: group.proc_path.clone(),
        proc_user: group.proc_user.clone(),
        parent_user: group.parent_user.clone(),
        command_line: group.command_line.clone(),
        parent_name: group.parent_name.clone(),
        parent_pid: group.parent_pid,
        service_name: group.service_name.clone(),
        publisher: group.publisher.clone(),
        score: group.score,
        reason_summary: group.reason_summary.clone(),
        attack_tags: group.attack_tags.clone(),
        baseline_deviation: group.baseline_deviation,
        script_host_suspicious: group.script_host_suspicious,
        timestamp: group.latest_timestamp.clone(),
        status: group.latest_status.clone(),
        remote_addr: selected_connection
            .as_ref()
            .map(|c| c.remote_addr.clone())
            .unwrap_or_else(|| group.latest_remote.clone()),
        connection_count: group.conn_count,
        distinct_ports: group.distinct_ports,
        distinct_remotes: group.distinct_remotes,
        statuses: group.statuses.clone(),
        selected_connection,
        selected_connection_reason_summary,
    }
}

#[allow(deprecated)]
fn endpoint_line(
    ui: &mut egui::Ui,
    endpoint: &OwnedEndpointRow,
    kind: Kind,
    selected: bool,
) -> Option<ConnInfo> {
    let h = 30.0;
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), h), egui::Sense::click());
    let fill = if selected {
        theme::SURFACE3
    } else {
        theme::SURFACE2
    };
    ui.painter()
        .rect_filled(rect.shrink2(egui::vec2(1.0, 0.5)), 8.0, fill);
    ui.painter().rect_stroke(
        rect.shrink2(egui::vec2(1.0, 0.5)),
        8.0,
        egui::Stroke::new(1.0, theme::BORDER),
        egui::StrokeKind::Outside,
    );

    ui.allocate_ui_at_rect(rect.shrink2(egui::vec2(10.0, 6.0)), |ui| {
        let avail = ui.available_width();
        let fixed = CONN_TIME_W + CONN_REMOTE_W + CONN_STATUS_W + CONN_SCORE_W;
        let badge_area = (avail - fixed - CONN_BADGE_GAP).max(0.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.add_sized(
                [CONN_TIME_W, 16.0],
                egui::Label::new(
                    RichText::new(&endpoint.latest_timestamp)
                        .color(theme::TEXT2)
                        .size(10.5),
                ),
            );
            ui.add_sized(
                [CONN_REMOTE_W, 16.0],
                egui::Label::new(
                    RichText::new(&endpoint.remote_addr)
                        .color(theme::TEXT)
                        .size(11.0),
                ),
            );
            ui.add_sized(
                [CONN_STATUS_W, 16.0],
                egui::Label::new(
                    RichText::new(&endpoint.status_summary)
                        .color(status_summary_color(&endpoint.statuses))
                        .size(10.5),
                ),
            );
            if let Kind::Alerts = kind {
                let (badge_rect, _) =
                    ui.allocate_exact_size(egui::vec2(badge_area, 16.0), egui::Sense::hover());
                ui.allocate_ui_at_rect(badge_rect, |ui| {
                    badge_row(ui, endpoint);
                    if endpoint.conn_count > 1 {
                        ui.label(
                            RichText::new(format!("x{}", endpoint.conn_count))
                                .color(theme::TEXT2)
                                .background_color(theme::SURFACE3)
                                .monospace()
                                .size(9.0),
                        );
                    }
                });
            } else {
                let (meta_rect, _) =
                    ui.allocate_exact_size(egui::vec2(badge_area, 16.0), egui::Sense::hover());
                ui.allocate_ui_at_rect(meta_rect, |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} socket{} / {} local port{}",
                            endpoint.conn_count,
                            plural(endpoint.conn_count),
                            endpoint.local_port_count,
                            plural(endpoint.local_port_count)
                        ))
                        .color(theme::TEXT3)
                        .size(9.4),
                    );
                });
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (fg, bg) = theme::score_colors(endpoint.max_score);
                ui.label(
                    RichText::new(format!("{:>2}", endpoint.max_score))
                        .color(fg)
                        .background_color(bg)
                        .monospace()
                        .size(10.5),
                );
            });
        });
    });

    if resp
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(if endpoint.conn_count > 1 {
            "Select the newest matching socket for this endpoint group."
        } else {
            "Select this connection to inspect connection-level details."
        })
        .clicked()
    {
        return Some(endpoint.representative.clone());
    }
    None
}

fn empty_state(ui: &mut egui::Ui, kind: Kind) {
    let text = match kind {
        Kind::Activity => "No connections yet",
        Kind::Alerts => "No alerts yet",
    };
    ui.add_space(20.0);
    ui.label(RichText::new(text).color(theme::TEXT3).size(12.0));
}

fn badge_row(ui: &mut egui::Ui, endpoint: &OwnedEndpointRow) {
    fn badge(ui: &mut egui::Ui, text: &str) {
        ui.label(
            RichText::new(text)
                .color(theme::DANGER)
                .background_color(theme::DANGER_BG)
                .monospace()
                .size(9.0),
        );
    }
    if endpoint.pre_login {
        badge(ui, "PL");
    }
    if endpoint.reputation_hit {
        badge(ui, "REP");
    }
    if endpoint.recently_dropped {
        badge(ui, "DRP");
    }
    if endpoint.long_lived {
        badge(ui, "LL");
    }
    if endpoint.dga_like {
        badge(ui, "DGA");
    }
    if endpoint.script_host_suspicious {
        badge(ui, "SCR");
    }
    if endpoint.baseline_deviation {
        badge(ui, "BASE");
    }
    if endpoint.tls_enriched {
        badge(ui, "TLS");
    }
}

fn matches_filter(info: &ConnInfo, lower: &str, kind: Kind) -> bool {
    if lower.is_empty() {
        return true;
    }
    let base = contains_lower(&info.proc_name, lower)
        || contains_lower(&info.parent_name, lower)
        || contains_lower(&info.remote_addr, lower)
        || contains_lower(&info.status, lower)
        || contains_lower(&info.proc_path, lower)
        || contains_lower(&info.local_addr, lower)
        || info
            .attack_tags
            .iter()
            .any(|tag| contains_lower(tag, lower))
        || info
            .reasons
            .iter()
            .any(|reason| contains_lower(reason, lower))
        || info
            .hostname
            .as_deref()
            .is_some_and(|h| contains_lower(h, lower))
        || info
            .country
            .as_deref()
            .is_some_and(|c| contains_lower(c, lower))
        || info
            .tls_sni
            .as_deref()
            .is_some_and(|s| contains_lower(s, lower))
        || info
            .tls_ja3
            .as_deref()
            .is_some_and(|s| contains_lower(s, lower));
    match kind {
        Kind::Activity | Kind::Alerts => base,
    }
}

fn contains_lower(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle_lower)
}

fn process_meta_line(group: &OwnedProcessGroup) -> String {
    let publisher = if group.publisher.is_empty() {
        if group.service_name.is_empty() {
            &group.parent_name
        } else {
            &group.service_name
        }
    } else {
        &group.publisher
    };
    format!(
        "{} | {} | {}",
        if group.proc_path.is_empty() {
            "No path"
        } else {
            &group.proc_path
        },
        if group.proc_user.is_empty() {
            "Unknown user"
        } else {
            &group.proc_user
        },
        publisher
    )
}

fn endpoint_key(conn: &ConnInfo) -> String {
    format!(
        "{}|{}",
        conn.remote_addr,
        conn.hostname.as_deref().unwrap_or_default()
    )
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn dedup_strings(mut values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .drain(..)
        .filter(|v| seen.insert(v.to_ascii_lowercase()))
        .collect()
}

fn sort_groups(groups: &mut [OwnedProcessGroup], sort_col: usize, sort_asc: bool) {
    groups.sort_by(|a, b| {
        let primary = match sort_col {
            0 => a.latest_timestamp.cmp(&b.latest_timestamp),
            1 => a
                .proc_name
                .to_ascii_lowercase()
                .cmp(&b.proc_name.to_ascii_lowercase()),
            2 => a
                .endpoint_rows
                .len()
                .cmp(&b.endpoint_rows.len())
                .then_with(|| a.conn_count.cmp(&b.conn_count)),
            3 => status_rank(&a.statuses).cmp(&status_rank(&b.statuses)),
            4 => a.score.cmp(&b.score),
            _ => a.latest_timestamp.cmp(&b.latest_timestamp),
        };
        let ord = primary.then_with(|| a.pid.cmp(&b.pid));
        if sort_asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn sort_endpoint_rows(rows: &mut [OwnedEndpointRow], sort_col: usize, sort_asc: bool) {
    rows.sort_by(|a, b| {
        let primary = match sort_col {
            0 => a.latest_timestamp.cmp(&b.latest_timestamp),
            1 => a.remote_addr.cmp(&b.remote_addr),
            2 => a
                .conn_count
                .cmp(&b.conn_count)
                .then_with(|| a.local_port_count.cmp(&b.local_port_count)),
            3 => status_rank(&a.statuses).cmp(&status_rank(&b.statuses)),
            4 => a.max_score.cmp(&b.max_score),
            _ => a.max_score.cmp(&b.max_score),
        };
        let ord = primary.then_with(|| a.remote_addr.cmp(&b.remote_addr));
        if sort_asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn status_rank(statuses: &[String]) -> u8 {
    if statuses.iter().any(|s| s == "SYN_SENT" || s == "SYN_RECV") {
        4
    } else if statuses.iter().any(|s| s == "ESTABLISHED") {
        3
    } else if statuses.iter().any(|s| {
        matches!(
            s.as_str(),
            "FIN_WAIT1"
                | "FIN_WAIT2"
                | "CLOSE_WAIT"
                | "TIME_WAIT"
                | "LAST_ACK"
                | "CLOSING"
                | "DELETE_TCB"
        )
    }) {
        2
    } else if statuses.iter().any(|s| s == "LISTEN") {
        1
    } else {
        0
    }
}

fn summary_bar_color(score: u8, kind: Kind) -> egui::Color32 {
    match kind {
        Kind::Activity => {
            if score >= 5 {
                theme::DANGER
            } else if score >= 3 {
                theme::WARN
            } else {
                theme::ACCENT
            }
        }
        Kind::Alerts => theme::DANGER,
    }
}

fn status_summary_color(statuses: &[String]) -> egui::Color32 {
    match status_rank(statuses) {
        4 => theme::WARN,
        3 => theme::ACCENT,
        2 => theme::TEXT3,
        _ => theme::TEXT2,
    }
}

fn parse_port(remote: &str) -> Option<u16> {
    remote
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
}

fn fanout_bonus(conns: usize, ports: usize, remotes: usize, statuses: usize) -> u8 {
    let mut bonus = 0;
    if conns >= 2 {
        bonus += 1;
    }
    if conns >= 4 {
        bonus += 1;
    }
    if ports >= 2 {
        bonus += 1;
    }
    if ports >= 4 {
        bonus += 1;
    }
    if remotes >= 3 {
        bonus += 1;
    }
    if statuses >= 3 {
        bonus += 1;
    }
    bonus.min(4)
}

fn calc_filter_hash(filter: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    filter.hash(&mut hasher);
    hasher.finish()
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn pill(ui: &mut egui::Ui, text: &str, fg: egui::Color32, bg: egui::Color32) {
    ui.label(
        RichText::new(format!(" {text} "))
            .color(fg)
            .background_color(bg)
            .size(10.0)
            .strong(),
    );
}
