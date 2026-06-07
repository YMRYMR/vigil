//! Firewall status and active-response rule browser.
//!
//! This tab is deliberately UI-only: it presents the current firewall backend
//! state and Vigil-managed response entries without expanding native firewall
//! behavior.

use super::{FirewallAction, FirewallSelection};
use crate::ui::theme;
use crate::{active_response, security::firewall};
use egui::{Align2, Color32, FontId, RichText, Ui};

const RIGHT_W: f32 = 320.0;
const GAP: f32 = 12.0;
const SUMMARY_H: f32 = 56.0;
const RULE_ROW_H: f32 = 54.0;

/// Render the firewall tab. Returns an action if the user clicked a button in
/// the right panel.
pub fn show(ui: &mut Ui, selected: &mut Option<FirewallSelection>) -> Option<FirewallAction> {
    let rules = active_response::list_rules();
    let model = firewall::state::build_firewall_status_model(
        firewall::state::FirewallBackendState::from_backend(firewall::get_backend()),
        firewall::state::ActiveResponseState::from(&rules),
    );
    refresh_selection(selected, &rules);

    let available_w = ui.available_width();
    let available_h = ui.available_height().max(260.0);
    let right_w = RIGHT_W.min((available_w * 0.34).clamp(240.0, RIGHT_W));
    let left_w = (available_w - right_w - GAP).max(260.0);
    let mut action = None;

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(left_w);
            ui.set_height(available_h);
            status_band(ui, &model, &rules, left_w);
            ui.add_space(8.0);
            warnings_band(ui, &model, left_w);
            ui.add_space(8.0);
            profiles_band(ui, &rules, left_w);
            ui.add_space(8.0);
            rules_header(ui, &rules);
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .id_salt("firewall-rules-scroll")
                .auto_shrink([false, false])
                .max_height((available_h - 220.0).max(160.0))
                .show(ui, |ui| {
                    ui.set_width(left_w);
                    rule_rows(ui, &rules, selected, left_w);
                });
        });

        ui.add_space(GAP);

        egui::Frame::NONE
            .fill(theme::SURFACE)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .inner_margin(egui::Margin::symmetric(12, 12))
            .show(ui, |ui| {
                ui.set_width((right_w - 24.0).max(220.0));
                ui.set_height(available_h - 24.0);
                egui::ScrollArea::vertical()
                    .id_salt("firewall-detail-scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        action = detail_panel(ui, selected.as_ref(), &rules, &model);
                    });
            });
    });

    action
}

/// Return true when a connection still matches the currently selected process row.
pub fn firewall_matches_selection(
    info: &crate::types::ConnInfo,
    selected: Option<&crate::types::ConnInfo>,
) -> bool {
    crate::ui::conn_matches_selection(info, selected)
}

/// Build the currently actionable firewall selections for selection refresh.
pub fn current_entries(
    _activity: &std::collections::VecDeque<crate::types::ConnInfo>,
    _selected_activity: Option<&super::ProcessSelection>,
    _selected_alert: Option<&super::ProcessSelection>,
    _status: &active_response::Status,
) -> Vec<FirewallSelection> {
    let rules = active_response::list_rules();
    selections_from_rules(&rules)
}

fn status_band(
    ui: &mut Ui,
    model: &firewall::state::FirewallStatusModel,
    rules: &active_response::FirewallRuleList,
    width: f32,
) {
    framed(ui, width, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Firewall").size(14.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                backend_badge(ui, model);
            });
        });
        ui.add_space(8.0);
        let tile_w = ((ui.available_width() - 20.0) / 5.0).max(80.0);
        ui.horizontal_wrapped(|ui| {
            metric_tile(
                ui,
                "Isolation",
                if model.isolation_active {
                    "active"
                } else {
                    "inactive"
                },
                if model.isolation_active {
                    theme::DANGER
                } else {
                    theme::ACCENT
                },
                tile_w,
            );
            metric_tile(
                ui,
                "IPs",
                &model.blocked_ip_count.to_string(),
                count_color(model.blocked_ip_count),
                tile_w,
            );
            metric_tile(
                ui,
                "Processes",
                &model.blocked_process_count.to_string(),
                count_color(model.blocked_process_count),
                tile_w,
            );
            metric_tile(
                ui,
                "Domains",
                &model.blocked_domain_count.to_string(),
                count_color(model.blocked_domain_count),
                tile_w,
            );
            metric_tile(
                ui,
                "Suspended",
                &rules.suspended_processes.len().to_string(),
                count_color(rules.suspended_processes.len()),
                tile_w,
            );
        });
    });
}

fn warnings_band(ui: &mut Ui, model: &firewall::state::FirewallStatusModel, width: f32) {
    if model.warnings.is_empty() {
        return;
    }

    framed(ui, width, |ui| {
        section_header(ui, "Warnings");
        ui.add_space(4.0);
        for warning in &model.warnings {
            ui.label(RichText::new(warning).color(theme::WARN).size(11.5));
        }
    });
}

fn profiles_band(ui: &mut Ui, rules: &active_response::FirewallRuleList, width: f32) {
    framed(ui, width, |ui| {
        section_header(ui, "OS Profiles");
        ui.add_space(6.0);
        if rules.profiles.is_empty() {
            muted(ui, "No OS firewall profile snapshot is available.");
            return;
        }

        for profile in &rules.profiles {
            let (status, color) = profile_status(profile);
            ui.horizontal(|ui| {
                ui.label(RichText::new(&profile.name).strong().size(12.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(status).color(color).size(10.5).monospace());
                });
            });
            ui.label(
                RichText::new(format!(
                    "inbound {} | outbound {}",
                    profile.inbound_action, profile.outbound_action
                ))
                .color(theme::TEXT2)
                .size(10.5),
            );
            ui.add_space(5.0);
        }
    });
}

fn rules_header(ui: &mut Ui, rules: &active_response::FirewallRuleList) {
    let total = total_rule_count(rules);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Managed Response Entries")
                .size(13.0)
                .strong(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(format!("{total} active"))
                    .color(theme::TEXT3)
                    .size(10.5),
            );
        });
    });
}

fn rule_rows(
    ui: &mut Ui,
    rules: &active_response::FirewallRuleList,
    selected: &mut Option<FirewallSelection>,
    width: f32,
) {
    let entries = selections_from_rules(rules);
    if entries.is_empty() {
        empty_rules(ui, width);
        return;
    }

    for entry in entries {
        let is_selected = selected
            .as_ref()
            .map(|sel| same_selection(sel, &entry))
            .unwrap_or(false);
        if rule_row(ui, &entry, rules, is_selected, width).clicked() {
            *selected = Some(entry);
        }
        ui.add_space(6.0);
    }
}

fn rule_row(
    ui: &mut Ui,
    entry: &FirewallSelection,
    rules: &active_response::FirewallRuleList,
    selected: bool,
    width: f32,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(width, RULE_ROW_H), egui::Sense::click());
    let fill = if selected {
        theme::SURFACE3
    } else {
        theme::SURFACE2
    };
    ui.painter().rect_filled(rect, 8.0, fill);
    ui.painter().rect_stroke(
        rect,
        8.0,
        egui::Stroke::new(
            1.0,
            if selected {
                theme::ACCENT
            } else {
                theme::BORDER
            },
        ),
        egui::StrokeKind::Outside,
    );

    let color = rule_color(entry);
    let type_label = rule_type_label(entry);
    let target = compact(&entry.target, ((width - 220.0) / 7.0).max(18.0) as usize);
    let detail = rule_detail(entry, rules);

    ui.painter().rect_filled(
        egui::Rect::from_min_size(rect.min + egui::vec2(14.0, 14.0), egui::vec2(4.0, 26.0)),
        2.0,
        color,
    );
    paint(
        ui,
        rect.min.x + 30.0,
        rect.min.y + 18.0,
        type_label,
        color,
        true,
        10.8,
    );
    paint(
        ui,
        rect.min.x + 130.0,
        rect.min.y + 18.0,
        &target,
        theme::TEXT,
        true,
        11.0,
    );
    paint(
        ui,
        rect.min.x + 30.0,
        rect.min.y + 38.0,
        &detail,
        theme::TEXT3,
        false,
        10.5,
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn detail_panel(
    ui: &mut Ui,
    selected: Option<&FirewallSelection>,
    rules: &active_response::FirewallRuleList,
    model: &firewall::state::FirewallStatusModel,
) -> Option<FirewallAction> {
    match selected {
        Some(sel) => selected_detail(ui, sel, rules),
        None => overview_detail(ui, rules, model),
    }
}

fn overview_detail(
    ui: &mut Ui,
    rules: &active_response::FirewallRuleList,
    model: &firewall::state::FirewallStatusModel,
) -> Option<FirewallAction> {
    ui.label(RichText::new("Firewall Summary").strong().size(14.0));
    ui.add_space(8.0);
    detail_kv(ui, "Backend", backend_label(model));
    detail_kv(
        ui,
        "Outbound blocking",
        match model.outbound_block_supported {
            Some(true) => "supported",
            Some(false) => "not supported",
            None => "unknown",
        },
    );
    detail_kv(
        ui,
        "Network isolation",
        if rules.isolated { "active" } else { "inactive" },
    );
    if let Some(secs) = rules.isolation_remaining_secs.filter(|secs| *secs > 0) {
        detail_kv(ui, "Isolation timeout", duration_label(secs));
    }
    if !model.warnings.is_empty() {
        ui.separator();
        ui.add_space(8.0);
        section_header(ui, "Warnings");
        for warning in &model.warnings {
            ui.label(
                RichText::new(warning)
                    .color(theme::WARN)
                    .size(11.0)
                    .monospace(),
            );
            ui.add_space(4.0);
        }
    }
    ui.separator();
    ui.add_space(8.0);
    section_header(ui, "Active Entries");
    detail_kv(ui, "Blocked IPs", rules.blocked_ips.len().to_string());
    detail_kv(
        ui,
        "Blocked processes",
        rules.blocked_processes.len().to_string(),
    );
    detail_kv(
        ui,
        "Blocked domains",
        rules.blocked_domains.len().to_string(),
    );
    detail_kv(
        ui,
        "Suspended processes",
        rules.suspended_processes.len().to_string(),
    );
    ui.add_space(8.0);
    if rules.isolated {
        return restore_button(ui);
    }
    muted(ui, "Select an entry to inspect actions.");
    None
}

fn selected_detail(
    ui: &mut Ui,
    sel: &FirewallSelection,
    rules: &active_response::FirewallRuleList,
) -> Option<FirewallAction> {
    ui.label(
        RichText::new(rule_type_label(sel))
            .color(rule_color(sel))
            .strong()
            .size(13.5),
    );
    ui.label(
        RichText::new(compact(&sel.target, 46))
            .color(theme::TEXT)
            .size(12.0)
            .monospace(),
    );
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);

    detail_kv(ui, "Direction", &sel.direction);
    if sel.pid != 0 {
        detail_kv(ui, "PID", sel.pid.to_string());
    }
    if !sel.path.is_empty() {
        detail_kv(ui, "Path", &sel.path);
    }
    if !sel.rule_name.is_empty() {
        detail_kv(ui, "Rule", &sel.rule_name);
    }
    detail_kv(ui, "State", rule_detail(sel, rules));
    ui.add_space(8.0);

    match sel.rule_type.as_str() {
        "ip" => {
            if let Some(entry) = rules
                .blocked_ips
                .iter()
                .find(|entry| entry.rule_name == sel.rule_name)
            {
                if let Some(expires) = entry.expires_at_unix {
                    detail_kv(ui, "Expires", expires_label(expires));
                }
            }
            danger_button(ui, "Unblock IP").then(|| FirewallAction::UnblockIp {
                rule_name: sel.rule_name.clone(),
                target: sel.target.clone(),
            })
        }
        "process" => {
            let is_blocked = rules
                .blocked_processes
                .iter()
                .any(|entry| entry.pid == sel.pid && entry.path == sel.path);
            let is_suspended = rules
                .suspended_processes
                .iter()
                .any(|entry| entry.pid == sel.pid && entry.path == sel.path);
            if is_blocked && danger_button(ui, "Unblock Process") {
                return Some(FirewallAction::UnblockProcess {
                    rule_name: sel.rule_name.clone(),
                    pid: sel.pid,
                    path: sel.path.clone(),
                });
            }
            if is_suspended && accent_button(ui, "Resume Process") {
                return Some(FirewallAction::RestoreProcess {
                    pid: sel.pid,
                    path: sel.path.clone(),
                });
            }
            None
        }
        "domain" => {
            danger_button(ui, "Clear Domain Block").then(|| FirewallAction::ClearDomainBlock {
                domain: sel.target.clone(),
            })
        }
        "isolation" => restore_button(ui),
        _ => None,
    }
}

fn selections_from_rules(rules: &active_response::FirewallRuleList) -> Vec<FirewallSelection> {
    let mut entries = Vec::new();

    if rules.isolated {
        entries.push(FirewallSelection {
            rule_name: "Network Isolation".into(),
            target: "Entire machine".into(),
            rule_type: "isolation".into(),
            direction: "both".into(),
            pid: 0,
            path: String::new(),
        });
    }

    entries.extend(rules.blocked_ips.iter().map(|entry| FirewallSelection {
        rule_name: entry.rule_name.clone(),
        target: entry.target.clone(),
        rule_type: "ip".into(),
        direction: "out".into(),
        pid: 0,
        path: String::new(),
    }));
    entries.extend(rules.blocked_processes.iter().map(|entry| {
        let target = if entry.path.is_empty() {
            format!("PID {}", entry.pid)
        } else {
            entry.path.clone()
        };
        FirewallSelection {
            rule_name: entry.outbound_rule_name.clone(),
            target,
            rule_type: "process".into(),
            direction: "out".into(),
            pid: entry.pid,
            path: entry.path.clone(),
        }
    }));
    entries.extend(rules.blocked_domains.iter().map(|entry| FirewallSelection {
        rule_name: format!("domain-{}", entry.domain),
        target: entry.domain.clone(),
        rule_type: "domain".into(),
        direction: "out".into(),
        pid: 0,
        path: String::new(),
    }));
    entries.extend(rules.suspended_processes.iter().map(|entry| {
        let target = if entry.proc_name.is_empty() {
            format!("PID {}", entry.pid)
        } else {
            format!("{} (PID {})", entry.proc_name, entry.pid)
        };
        FirewallSelection {
            rule_name: format!("suspend-{}", entry.pid),
            target,
            rule_type: "process".into(),
            direction: "both".into(),
            pid: entry.pid,
            path: entry.path.clone(),
        }
    }));

    entries
}

fn refresh_selection(
    selected: &mut Option<FirewallSelection>,
    rules: &active_response::FirewallRuleList,
) {
    let Some(current) = selected.as_ref() else {
        return;
    };
    if !selections_from_rules(rules)
        .iter()
        .any(|entry| same_selection(entry, current))
    {
        *selected = None;
    }
}

fn empty_rules(ui: &mut Ui, width: f32) {
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(12, 12))
        .show(ui, |ui| {
            ui.set_width((width - 24.0).max(220.0));
            ui.label(
                RichText::new("No Vigil-managed firewall or response entries are active.")
                    .color(theme::TEXT2)
                    .size(12.0),
            );
            ui.add_space(3.0);
            ui.label(
                RichText::new("Backend health and OS profile state remain visible above.")
                    .color(theme::TEXT3)
                    .size(10.5),
            );
        });
}

fn metric_tile(ui: &mut Ui, label: &str, value: &str, color: Color32, width: f32) {
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(7.0)
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.set_width(width - 20.0);
            ui.set_height(SUMMARY_H - 14.0);
            ui.label(RichText::new(label).color(theme::TEXT3).size(10.0));
            ui.label(RichText::new(value).color(color).size(13.0).strong());
        });
}

fn framed(ui: &mut Ui, width: f32, body: impl FnOnce(&mut Ui)) {
    egui::Frame::NONE
        .fill(theme::SURFACE2)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width((width - 24.0).max(260.0));
            body(ui);
        });
}

fn backend_badge(ui: &mut Ui, model: &firewall::state::FirewallStatusModel) {
    let (color, text): (Color32, String) = if model.backend_available {
        (theme::ACCENT, model.backend_label.clone())
    } else {
        (
            theme::DANGER,
            format!("{} unavailable", model.backend_label),
        )
    };
    ui.label(RichText::new(text).color(color).size(11.0).monospace())
        .on_hover_text("Native firewall backend selected for this platform.");
}

fn backend_label(model: &firewall::state::FirewallStatusModel) -> String {
    if model.backend_available {
        model.backend_label.clone()
    } else {
        format!("{} unavailable", model.backend_label)
    }
}

fn profile_status(profile: &active_response::FirewallProfileEntry) -> (&'static str, Color32) {
    if profile.enabled && profile.inbound_action == "Block" && profile.outbound_action == "Block" {
        ("isolated", theme::DANGER)
    } else if profile.enabled {
        ("enabled", theme::ACCENT)
    } else {
        ("disabled", theme::WARN)
    }
}

fn rule_type_label(sel: &FirewallSelection) -> &'static str {
    match sel.rule_type.as_str() {
        "ip" => "blocked ip",
        "process" if sel.direction == "both" => "suspended process",
        "process" => "blocked process",
        "domain" => "blocked domain",
        "isolation" => "network isolation",
        _ => "response entry",
    }
}

fn rule_color(sel: &FirewallSelection) -> Color32 {
    match sel.rule_type.as_str() {
        "isolation" => theme::DANGER,
        "ip" | "domain" => theme::WARN,
        "process" if sel.direction == "both" => theme::DANGER,
        "process" => theme::WARN,
        _ => theme::TEXT2,
    }
}

fn rule_detail(sel: &FirewallSelection, rules: &active_response::FirewallRuleList) -> String {
    match sel.rule_type.as_str() {
        "ip" => rules
            .blocked_ips
            .iter()
            .find(|entry| entry.rule_name == sel.rule_name)
            .and_then(|entry| entry.expires_at_unix)
            .map(expires_label)
            .unwrap_or_else(|| "permanent or unknown duration".into()),
        "process" if sel.direction == "both" => "process execution is suspended".into(),
        "process" => "outbound process firewall rule".into(),
        "domain" => "hosts-file domain block".into(),
        "isolation" => rules
            .isolation_remaining_secs
            .filter(|secs| *secs > 0)
            .map(|secs| format!("{} remaining", duration_label(secs)))
            .unwrap_or_else(|| "all network profiles contained".into()),
        _ => String::new(),
    }
}

fn detail_kv(ui: &mut Ui, key: &str, value: impl AsRef<str>) {
    ui.label(RichText::new(key).color(theme::TEXT3).size(10.5));
    ui.add(
        egui::Label::new(
            RichText::new(value.as_ref())
                .color(theme::TEXT2)
                .size(11.0)
                .monospace(),
        )
        .wrap(),
    );
    ui.add_space(6.0);
}

fn restore_button(ui: &mut Ui) -> Option<FirewallAction> {
    accent_button(ui, "Restore Network").then_some(FirewallAction::RestoreIsolation)
}

fn danger_button(ui: &mut Ui, label: &str) -> bool {
    ui.add(
        egui::Button::new(RichText::new(label).color(theme::DANGER).size(12.0))
            .fill(theme::SURFACE2)
            .stroke(egui::Stroke::new(1.0, theme::DANGER)),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .clicked()
}

fn accent_button(ui: &mut Ui, label: &str) -> bool {
    ui.add(
        egui::Button::new(RichText::new(label).color(theme::ACCENT).size(12.0))
            .fill(theme::SURFACE2)
            .stroke(egui::Stroke::new(1.0, theme::ACCENT)),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .clicked()
}

fn section_header(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).size(12.5).strong());
}

fn muted(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::TEXT2).size(11.5));
}

fn count_color(count: usize) -> Color32 {
    if count == 0 {
        theme::TEXT2
    } else {
        theme::WARN
    }
}

fn total_rule_count(rules: &active_response::FirewallRuleList) -> usize {
    usize::from(rules.isolated)
        + rules.blocked_ips.len()
        + rules.blocked_processes.len()
        + rules.blocked_domains.len()
        + rules.suspended_processes.len()
}

fn same_selection(left: &FirewallSelection, right: &FirewallSelection) -> bool {
    left.rule_type == right.rule_type
        && left.rule_name == right.rule_name
        && left.target == right.target
        && left.pid == right.pid
        && left.path == right.path
}

fn expires_label(expires_at_unix: u64) -> String {
    let now = unix_now();
    match expires_at_unix.checked_sub(now) {
        Some(remaining) if remaining > 0 => format!("expires in {}", duration_label(remaining)),
        Some(_) => "expired, pending reconciliation".into(),
        None => "expiration time is in the past".into(),
    }
}

fn duration_label(seconds: u64) -> String {
    if seconds >= 3600 {
        let hours = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        if mins == 0 {
            format!("{hours}h")
        } else {
            format!("{hours}h {mins}m")
        }
    } else if seconds >= 60 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn compact(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let keep = limit.saturating_sub(1);
    format!("{}...", text.chars().take(keep).collect::<String>())
}

fn paint(ui: &Ui, x: f32, y: f32, text: &str, color: Color32, monospace: bool, size: f32) {
    let font = if monospace {
        FontId::monospace(size)
    } else {
        FontId::proportional(size)
    };
    ui.painter()
        .text(egui::pos2(x, y), Align2::LEFT_CENTER, text, font, color);
}
