//! Process-grouped connection list used by the Activity and Alerts tabs.
//!
//! One process becomes one card. Each card shows summary metadata up top and
//! then groups repeated sockets by remote endpoint so the UI stays useful even
//! when a process opens many connections to the same destination.

use crate::types::ConnInfo;
use crate::ui::{theme, ProcessSelection, TableState};
use egui::RichText;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

const CONN_TIME_W: f32 = 84.0;
const CONN_REMOTE_W: f32 = 216.0;
const CONN_STATUS_W: f32 = 132.0;
const CONN_SCORE_W: f32 = 44.0;
const CONN_BADGE_GAP: f32 = 8.0;

#[derive(Clone, Copy)]
pub enum Kind {
    Activity,
    Alerts,
}

struct ProcessGroup<'a> {
    pid: u32,
    proc_name: &'a str,
    proc_path: &'a str,
    proc_user: &'a str,
    parent_user: &'a str,
    command_line: &'a str,
    parent_name: &'a str,
    parent_pid: u32,
    service_name: &'a str,
    publisher: &'a str,
    latest_timestamp: &'a str,
    latest_status: &'a str,
    latest_remote: &'a str,
    connections: Vec<&'a ConnInfo>,
    endpoint_rows: Vec<EndpointRow<'a>>,
    score: u8,
    conn_count: usize,
    distinct_ports: usize,
    distinct_remotes: usize,
    statuses: Vec<String>,
    reasons: Vec<String>,
    attack_tags: Vec<String>,
    baseline_deviation: bool,
    script_host_suspicious: bool,
    tls_enriched: bool,
}

struct EndpointRow<'a> {
    representative: &'a ConnInfo,
    latest_timestamp: &'a str,
    remote_addr: &'a str,
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

#[allow(deprecated)]
pub fn show(
    ui: &mut egui::Ui,
    rows: &VecDeque<ConnInfo>,
    selected: &mut Option<ProcessSelection>,
    state: &mut TableState,
    kind: Kind,
) -> bool {
    ui.add_space(4.0);
    filter_bar(ui, rows.len(), state, kind);

    let mut groups = grouped_rows(rows, &state.filter, kind);
    sort_groups(&mut groups, state);
    for group in &mut groups {
        sort_endpoint_rows(group, state);
    }

    ui.add_space(8.0);
    header_row(ui, state);
    ui.add_space(8.0);

    let total_connections: usize = groups.iter().map(|g| g.conn_count).sum();
    let total_groups = groups.len();

    egui::ScrollArea::vertical()
        .id_salt(match kind {
            Kind::Activity => "activity_groups",
            Kind::Alerts => "alerts_groups",
        })
        .show(ui, |ui| {
            if groups.is_empty() {
                empty_state(ui, kind);
                return;
            }

            for group in &groups {
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
                        let summary_h = if collapsed { 48.0 } else { 56.0 };
                        let (summary_rect, summary_resp) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), summary_h),
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
                                    egui::vec2(4.0, if collapsed { 28.0 } else { 40.0 }),
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
                                            RichText::new(group.proc_name)
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
                                                if group.conn_count == 1 { "" } else { "s" }
                                            ),
                                            theme::TEXT2,
                                            theme::SURFACE2,
                                            theme::BORDER,
                                        );
                                        pill(
                                            ui,
                                            &format!(
                                                "{} endpoint{}",
                                                group.endpoint_rows.len(),
                                                if group.endpoint_rows.len() == 1 { "" } else { "s" }
                                            ),
                                            theme::TEXT2,
                                            theme::SURFACE2,
                                            theme::BORDER,
                                        );
                                        pill(
                                            ui,
                                            &format!("{} ports", group.distinct_ports),
                                            theme::TEXT2,
                                            theme::SURFACE2,
                                            theme::BORDER,
                                        );
                                        if group.distinct_remotes > 1 {
                                            pill(
                                                ui,
                                                &format!("{} remotes", group.distinct_remotes),
                                                theme::TEXT2,
                                                theme::SURFACE2,
                                                theme::BORDER,
                                            );
                                        }
                                        if group.script_host_suspicious {
                                            pill(ui, "Script host", theme::WARN, theme::WARN_BG, theme::WARN);
                                        }
                                        if group.baseline_deviation {
                                            pill(ui, "Baseline drift", theme::ACCENT, theme::ACCENT_BG, theme::ACCENT);
                                        }
                                        if group.tls_enriched {
                                            pill(ui, "TLS", theme::ACCENT, theme::ACCENT_BG, theme::ACCENT);
                                        }
                                    });

                                    ui.add_space(2.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "{} | {} | {}",
                                            if group.proc_path.is_empty() {
                                                "No path"
                                            } else {
                                                group.proc_path
                                            },
                                            if group.proc_user.is_empty() {
                                                "Unknown user"
                                            } else {
                                                group.proc_user
                                            },
                                            if group.publisher.is_empty() {
                                                if group.service_name.is_empty() {
                                                    group.parent_name
                                                } else {
                                                    group.service_name
                                                }
                                            } else {
                                                group.publisher
                                            }
                                        ))
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
                                    egui::Layout::right_to_left(egui::Align::Center),
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
                                            RichText::new(group.latest_timestamp)
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
                                            endpoint.representative,
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
                                    if group.endpoint_rows.len() == 1 { "" } else { "s" }
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
                    total_groups,
                    total_connections,
                    groups.iter().map(|g| g.endpoint_rows.len()).sum::<usize>()
                ),
                Kind::Alerts => format!(
                    "{} alerting processes / {} sockets / {} endpoint rows",
                    total_groups,
                    total_connections,
                    groups.iter().map(|g| g.endpoint_rows.len()).sum::<usize>()
                ),
            };
            ui.add_space(4.0);
            ui.label(RichText::new(footer).color(theme::TEXT3).size(10.5));
        });

    false
}

pub fn selection_for_pid(
    rows: &VecDeque<ConnInfo>,
    pid: u32,
    selected_connection: Option<&ConnInfo>,
    kind: Kind,
) -> Option<ProcessSelection> {
    let groups = grouped_rows(rows, "", kind);
    let group = groups.into_iter().find(|g| g.pid == pid)?;
    let selected = selected_connection.cloned();
    Some(selection_from_group(&group, selected))
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
                let te = egui::TextEdit::singleline(&mut state.filter)
                    .hint_text(hint)
                    .desired_width(ui.available_width() - 120.0)
                    .font(egui::TextStyle::Body);
                ui.add(te);
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
                    let shown = total;
                    let label = if shown == 1 {
                        "1 process".to_string()
                    } else {
                        format!("{shown} processes")
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

fn grouped_rows<'a>(
    rows: &'a VecDeque<ConnInfo>,
    filter: &str,
    kind: Kind,
) -> Vec<ProcessGroup<'a>> {
    let f = filter.to_lowercase();
    let mut groups: HashMap<u32, ProcessGroup<'a>> = HashMap::new();
    let mut order: Vec<u32> = Vec::new();

    for info in rows.iter().filter(|r| matches_filter(r, &f, kind)) {
        let entry = groups.entry(info.pid).or_insert_with(|| {
            order.push(info.pid);
            ProcessGroup {
                pid: info.pid,
                proc_name: &info.proc_name,
                proc_path: &info.proc_path,
                proc_user: &info.proc_user,
                parent_user: &info.parent_user,
                command_line: &info.command_line,
                parent_name: &info.parent_name,
                parent_pid: info.parent_pid,
                service_name: &info.service_name,
                publisher: &info.publisher,
                latest_timestamp: &info.timestamp,
                latest_status: &info.status,
                latest_remote: &info.remote_addr,
                connections: Vec::new(),
                endpoint_rows: Vec::new(),
                score: info.score,
                conn_count: 0,
                distinct_ports: 0,
                distinct_remotes: 0,
                statuses: Vec::new(),
                reasons: Vec::new(),
                attack_tags: Vec::new(),
                baseline_deviation: false,
                script_host_suspicious: false,
                tls_enriched: false,
            }
        });

        entry.connections.push(info);
        entry.conn_count += 1;
        if info.score > entry.score {
            entry.score = info.score;
        }
        if info.timestamp.as_str() > entry.latest_timestamp {
            entry.latest_timestamp = &info.timestamp;
            entry.latest_status = &info.status;
            entry.latest_remote = &info.remote_addr;
        }
    }

    let mut out = Vec::new();
    for pid in order {
        if let Some(mut group) = groups.remove(&pid) {
            let mut ports = HashSet::new();
            let mut remotes = HashSet::new();
            let mut statuses = Vec::new();
            let mut reasons = Vec::new();
            let mut attack_tags = Vec::new();
            let mut endpoint_map: HashMap<String, EndpointAccumulator<'a>> = HashMap::new();

            for conn in &group.connections {
                if conn.remote_addr != "LISTEN" {
                    remotes.insert(conn.remote_addr.clone());
                }
                if let Some(port) = parse_port(&conn.remote_addr) {
                    ports.insert(port);
                }
                if !statuses.iter().any(|s| s == &conn.status) {
                    statuses.push(conn.status.clone());
                }
                reasons.extend(conn.reasons.iter().cloned());
                attack_tags.extend(conn.attack_tags.iter().cloned());
                group.baseline_deviation |= conn.baseline_deviation;
                group.script_host_suspicious |= conn.script_host_suspicious;
                group.tls_enriched |= conn.tls_sni.is_some() || conn.tls_ja3.is_some();

                let key = endpoint_key(conn);
                endpoint_map
                    .entry(key)
                    .or_insert_with(|| EndpointAccumulator::new(conn))
                    .add(conn);
            }

            group.distinct_ports = ports.len();
            group.distinct_remotes = remotes.len();
            group.statuses = statuses;
            group.reasons = dedup_reasons(reasons);
            group.attack_tags = dedup_reasons(attack_tags);
            group.endpoint_rows = endpoint_map
                .into_values()
                .map(EndpointAccumulator::finish)
                .collect();
            if group.conn_count > 1 {
                group.reasons.push(format!(
                    "{} sockets from the same process",
                    group.conn_count
                ));
            }
            if group.endpoint_rows.len() < group.conn_count {
                group.reasons.push(format!(
                    "{} repeated sockets collapsed into {} endpoint rows",
                    group.conn_count,
                    group.endpoint_rows.len()
                ));
            }
            if group.distinct_ports > 1 {
                group
                    .reasons
                    .push(format!("{} distinct remote ports", group.distinct_ports));
            }
            if group.distinct_remotes > 1 {
                group.reasons.push(format!(
                    "{} distinct remote targets",
                    group.distinct_remotes
                ));
            }
            group.score = group.score.saturating_add(fanout_bonus(
                group.conn_count,
                group.distinct_ports,
                group.distinct_remotes,
                group.statuses.len(),
            ));
            out.push(group);
        }
    }
    out
}

struct EndpointAccumulator<'a> {
    representative: &'a ConnInfo,
    latest_timestamp: &'a str,
    conn_count: usize,
    local_ports: BTreeSet<String>,
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

impl<'a> EndpointAccumulator<'a> {
    fn new(conn: &'a ConnInfo) -> Self {
        let mut acc = Self {
            representative: conn,
            latest_timestamp: &conn.timestamp,
            conn_count: 0,
            local_ports: BTreeSet::new(),
            statuses: Vec::new(),
            max_score: 0,
            pre_login: false,
            reputation_hit: false,
            recently_dropped: false,
            long_lived: false,
            dga_like: false,
            script_host_suspicious: false,
            baseline_deviation: false,
            tls_enriched: false,
        };
        acc.add(conn);
        acc
    }

    fn add(&mut self, conn: &'a ConnInfo) {
        if self.conn_count > 0 {
            self.conn_count += 1;
        }
        if conn.timestamp.as_str() >= self.latest_timestamp {
            self.latest_timestamp = &conn.timestamp;
            self.representative = conn;
        }
        self.local_ports.insert(conn.local_addr.clone());
        if !self.statuses.iter().any(|s| s == &conn.status) {
            self.statuses.push(conn.status.clone());
        }
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

    fn finish(self) -> EndpointRow<'a> {
        EndpointRow {
            representative: self.representative,
            latest_timestamp: self.latest_timestamp,
            remote_addr: &self.representative.remote_addr,
            conn_count: self.conn_count.max(1),
            local_port_count: self.local_ports.len().max(1),
            status_summary: self.statuses.join(" + "),
            statuses: self.statuses,
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

fn endpoint_key(conn: &ConnInfo) -> String {
    format!("{}|{}", conn.remote_addr, conn.hostname.as_deref().unwrap_or_default())
}

fn dedup_reasons(mut reasons: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    reasons
        .drain(..)
        .filter(|r| seen.insert(r.to_lowercase()))
        .collect()
}

fn selection_from_group(
    group: &ProcessGroup<'_>,
    selected_connection: Option<ConnInfo>,
) -> ProcessSelection {
    ProcessSelection {
        pid: group.pid,
        proc_name: group.proc_name.to_string(),
        proc_path: group.proc_path.to_string(),
        proc_user: group.proc_user.to_string(),
        parent_user: group.parent_user.to_string(),
        command_line: group.command_line.to_string(),
        parent_name: group.parent_name.to_string(),
        parent_pid: group.parent_pid,
        service_name: group.service_name.to_string(),
        publisher: group.publisher.to_string(),
        score: group.score,
        reasons: group.reasons.clone(),
        attack_tags: group.attack_tags.clone(),
        baseline_deviation: group.baseline_deviation,
        script_host_suspicious: group.script_host_suspicious,
        timestamp: group.latest_timestamp.to_string(),
        status: group.latest_status.to_string(),
        remote_addr: selected_connection
            .as_ref()
            .map(|c| c.remote_addr.clone())
            .unwrap_or_else(|| group.latest_remote.to_string()),
        connection_count: group.conn_count,
        distinct_ports: group.distinct_ports,
        distinct_remotes: group.distinct_remotes,
        statuses: group.statuses.clone(),
        selected_connection,
    }
}

fn sort_groups(groups: &mut [ProcessGroup<'_>], state: &TableState) {
    groups.sort_by(|a, b| {
        let ord = match state.sort_col {
            0 => a.latest_timestamp.cmp(b.latest_timestamp),
            1 => a.proc_name.to_lowercase().cmp(&b.proc_name.to_lowercase()),
            2 => a
                .endpoint_rows
                .len()
                .cmp(&b.endpoint_rows.len())
                .then_with(|| a.conn_count.cmp(&b.conn_count)),
            3 => a.latest_status.cmp(b.latest_status),
            4 => a.score.cmp(&b.score),
            _ => a.latest_timestamp.cmp(b.latest_timestamp),
        };
        if state.sort_asc { ord } else { ord.reverse() }
    });
}

fn sort_endpoint_rows(group: &mut ProcessGroup<'_>, state: &TableState) {
    group.endpoint_rows.sort_by(|a, b| {
        let ord = match state.sort_col {
            0 => a.latest_timestamp.cmp(b.latest_timestamp),
            1 => a.remote_addr.cmp(b.remote_addr),
            2 => a.conn_count.cmp(&b.conn_count).then_with(|| a.local_port_count.cmp(&b.local_port_count)),
            3 => a.status_summary.cmp(&b.status_summary),
            4 => a.max_score.cmp(&b.max_score),
            _ => a.latest_timestamp.cmp(b.latest_timestamp),
        };
        if state.sort_asc { ord } else { ord.reverse() }
    });
}

#[allow(deprecated)]
fn endpoint_line(
    ui: &mut egui::Ui,
    endpoint: &EndpointRow<'_>,
    kind: Kind,
    selected: bool,
) -> Option<ConnInfo> {
    let h = 30.0;
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), h), egui::Sense::click());
    let fill = if selected { theme::SURFACE3 } else { theme::SURFACE2 };
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
                    RichText::new(endpoint.latest_timestamp)
                        .color(theme::TEXT2)
                        .size(10.5),
                ),
            );
            ui.add_sized(
                [CONN_REMOTE_W, 16.0],
                egui::Label::new(
                    RichText::new(remote_label(endpoint.remote_addr))
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
                let (badge_rect, _) = ui.allocate_exact_size(
                    egui::vec2(badge_area.max(0.0), 16.0),
                    egui::Sense::hover(),
                );
                ui.allocate_ui_at_rect(badge_rect, |ui| {
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
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
                });
            } else {
                let (meta_rect, _) = ui.allocate_exact_size(
                    egui::vec2(badge_area.max(0.0), 16.0),
                    egui::Sense::hover(),
                );
                ui.allocate_ui_at_rect(meta_rect, |ui| {
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} socket{} / {} local port{}",
                                endpoint.conn_count,
                                if endpoint.conn_count == 1 { "" } else { "s" },
                                endpoint.local_port_count,
                                if endpoint.local_port_count == 1 { "" } else { "s" }
                            ))
                            .color(theme::TEXT3)
                            .size(9.4),
                        );
                    });
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

    let clicked = resp
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(if endpoint.conn_count > 1 {
            "Select the newest matching socket for this endpoint group."
        } else {
            "Select this connection to inspect connection-level details."
        })
        .clicked();
    if clicked {
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

fn badge_row(ui: &mut egui::Ui, endpoint: &EndpointRow<'_>) {
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
    let base = info.proc_name.to_lowercase().contains(lower)
        || info.parent_name.to_lowercase().contains(lower)
        || info.remote_addr.to_lowercase().contains(lower)
        || info.status.to_lowercase().contains(lower)
        || info.proc_path.to_lowercase().contains(lower)
        || info.local_addr.to_lowercase().contains(lower)
        || info.attack_tags.iter().any(|tag| tag.to_lowercase().contains(lower))
        || info.tls_sni.as_deref().map(|s| s.to_lowercase().contains(lower)).unwrap_or(false)
        || info.tls_ja3.as_deref().map(|s| s.to_lowercase().contains(lower)).unwrap_or(false);

    if lower.is_empty() {
        return true;
    }
    if base {
        return true;
    }

    match kind {
        Kind::Activity | Kind::Alerts => {
            info.reasons.iter().any(|s| s.to_lowercase().contains(lower))
                || info.hostname.as_deref().map(|h| h.to_lowercase().contains(lower)).unwrap_or(false)
                || info.country.as_deref().map(|c| c.to_lowercase().contains(lower)).unwrap_or(false)
        }
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

fn status_color(status: &str) -> egui::Color32 {
    match status {
        "ESTABLISHED" => theme::ACCENT,
        "LISTEN" => theme::TEXT2,
        "SYN_SENT" | "SYN_RECV" => theme::WARN,
        "CLOSE_WAIT" | "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" | "LAST_ACK" | "CLOSING" => theme::TEXT3,
        _ => theme::TEXT2,
    }
}

fn status_summary_color(statuses: &[String]) -> egui::Color32 {
    if statuses.iter().any(|s| s == "SYN_SENT" || s == "SYN_RECV") {
        theme::WARN
    } else if statuses.iter().any(|s| s == "ESTABLISHED") {
        theme::ACCENT
    } else if statuses.iter().any(|s| matches!(s.as_str(), "FIN_WAIT1" | "FIN_WAIT2" | "CLOSE_WAIT" | "TIME_WAIT" | "LAST_ACK" | "CLOSING")) {
        theme::TEXT3
    } else {
        theme::TEXT2
    }
}

fn remote_label(remote: &str) -> String {
    if let Some((ip, port)) = remote.rsplit_once(':') {
        if !ip.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return format!("{ip}:{port}");
        }
    }
    remote.to_string()
}

fn parse_port(remote: &str) -> Option<u16> {
    remote.rsplit_once(':').and_then(|(_, port)| port.parse().ok())
}

fn fanout_bonus(conns: usize, ports: usize, remotes: usize, statuses: usize) -> u8 {
    let mut bonus = 0;
    if conns >= 2 { bonus += 1; }
    if conns >= 4 { bonus += 1; }
    if ports >= 2 { bonus += 1; }
    if ports >= 4 { bonus += 1; }
    if remotes >= 3 { bonus += 1; }
    if statuses >= 3 { bonus += 1; }
    bonus.min(4)
}

fn pill(
    ui: &mut egui::Ui,
    text: &str,
    fg: egui::Color32,
    bg: egui::Color32,
    stroke: egui::Color32,
) {
    ui.label(
        RichText::new(format!(" {text} "))
            .color(fg)
            .background_color(bg)
            .size(10.0)
            .strong(),
    );
    ui.painter().rect_stroke(
        ui.min_rect(),
        0.0,
        egui::Stroke::new(1.0, stroke),
        egui::StrokeKind::Outside,
    );
}
