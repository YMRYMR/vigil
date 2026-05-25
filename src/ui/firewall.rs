//! Firewall rules tab — Phase 19 P3.
//!
//! Interactive list of all active firewall rules. Click any row to
//! see details and unblock/restore actions in the right panel.
//! Follows the Activity/Alerts pattern: left list + right inspector.

use super::{FirewallAction, FirewallSelection};
use crate::ui::theme;
use crate::{active_response, security::firewall};
use egui::{Color32, RichText, Ui};

/// Render the firewall tab. Returns an action if the user clicked a
/// button in the right panel.
pub fn show(ui: &mut Ui, selected: &mut Option<FirewallSelection>) -> Option<FirewallAction> {
    let rules = active_response::list_rules();
    let mut action: Option<FirewallAction> = None;

    // ── Left panel: rule list ──────────────────────────────────────────
    ui.horizontal(|ui| {
        let left_width = if selected.is_some() {
            ui.available_width() - 290.0
        } else {
            ui.available_width()
        };

        egui::ScrollArea::vertical()
            .id_salt("firewall-scroll")
            .max_width(left_width)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.heading("Firewall");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        backend_badge(ui);
                    });
                });
                ui.label(
                    RichText::new("Click any rule for details and actions")
                        .color(theme::TEXT2)
                        .size(10.5),
                );
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(8.0);

                profile_section(ui, &rules);
                isolation_section(ui, &rules, selected);
                blocked_ips_section(ui, &rules, selected);
                blocked_processes_section(ui, &rules, selected);
                blocked_domains_section(ui, &rules, selected);
                suspended_processes_section(ui, &rules, selected);
                ui.add_space(8.0);
            });

        // ── Right panel: inspector ─────────────────────────────────────
        if let Some(sel) = selected.as_ref() {
            let is_actionable = sel.rule_type == "ip"
                || sel.rule_type == "process"
                || sel.rule_type == "domain"
                || sel.rule_type == "isolation";
            if is_actionable {
                let mut clear_after = false;
                egui::Panel::right("firewall_detail")
                    .resizable(false)
                    .exact_size(280.0)
                    .show_inside(ui, |ui| {
                        ui.add_space(8.0);
                        ui.label(RichText::new("Rule Detail").strong().size(14.0));
                        ui.separator();
                        ui.add_space(8.0);

                        ui.label(RichText::new(&sel.target).size(13.0).monospace());
                        ui.label(
                            RichText::new(format!("Type: {}", sel.rule_type))
                                .color(theme::TEXT2)
                                .size(11.0),
                        );

                        ui.add_space(12.0);

                        match sel.rule_type.as_str() {
                            "ip" => {
                                if rules
                                    .blocked_ips
                                    .iter()
                                    .any(|b| b.rule_name == sel.rule_name)
                                    && ui
                                        .button(
                                            RichText::new("Unblock IP")
                                                .color(theme::DANGER)
                                                .size(12.0),
                                        )
                                        .clicked()
                                {
                                    clear_after = true;
                                    action = Some(FirewallAction::UnblockIp {
                                        rule_name: sel.rule_name.clone(),
                                        target: sel.target.clone(),
                                    });
                                }
                            }
                            "process" => {
                                let is_blocked = rules
                                    .blocked_processes
                                    .iter()
                                    .any(|b| b.pid == sel.pid && b.path == sel.path);
                                let is_suspended = rules
                                    .suspended_processes
                                    .iter()
                                    .any(|p| p.pid == sel.pid && p.path == sel.path);

                                if is_blocked
                                    && ui
                                        .button(
                                            RichText::new("Unblock Process")
                                                .color(theme::DANGER)
                                                .size(12.0),
                                        )
                                        .clicked()
                                {
                                    clear_after = true;
                                    action = Some(FirewallAction::UnblockProcess {
                                        rule_name: sel.rule_name.clone(),
                                        pid: sel.pid,
                                        path: sel.path.clone(),
                                    });
                                }

                                if is_suspended
                                    && ui
                                        .button(
                                            RichText::new("Resume Process")
                                                .color(theme::ACCENT)
                                                .size(12.0),
                                        )
                                        .clicked()
                                {
                                    clear_after = true;
                                    action = Some(FirewallAction::RestoreProcess {
                                        pid: sel.pid,
                                        path: sel.path.clone(),
                                    });
                                }
                            }
                            "domain" => {
                                if rules.blocked_domains.iter().any(|d| d.domain == sel.target)
                                    && ui
                                        .button(
                                            RichText::new("Clear Domain Block")
                                                .color(theme::DANGER)
                                                .size(12.0),
                                        )
                                        .clicked()
                                {
                                    clear_after = true;
                                    action = Some(FirewallAction::ClearDomainBlock {
                                        domain: sel.target.clone(),
                                    });
                                }
                            }
                            "isolation" => {
                                if rules.isolated
                                    && ui
                                        .button(
                                            RichText::new("Restore Network")
                                                .color(theme::ACCENT)
                                                .size(12.0),
                                        )
                                        .clicked()
                                {
                                    clear_after = true;
                                    action = Some(FirewallAction::RestoreIsolation);
                                }
                            }
                            _ => {}
                        }
                    });
                if clear_after {
                    *selected = None;
                }
            }
        }
    });

    action
}

// ── Sections ─────────────────────────────────────────────────────────────────

fn backend_badge(ui: &mut Ui) {
    let backend = firewall::get_backend();
    let available = backend.is_available();
    let label = backend.label();
    let (color, text): (Color32, String) = if available {
        (theme::ACCENT, label.to_string())
    } else {
        (theme::DANGER, format!("{label} (unavailable)"))
    };
    let badge = RichText::new(text).color(color).size(11.0).monospace();
    ui.label(badge).on_hover_text("Firewall engine backend");
}

fn profile_section(ui: &mut Ui, rules: &active_response::FirewallRuleList) {
    section_header(ui, "OS Profile State", "Current firewall profile settings");
    ui.add_space(4.0);

    if rules.profiles.is_empty() {
        muted(ui, "No profile data available.");
        return;
    }

    for profile in &rules.profiles {
        let (color, status) = if profile.enabled
            && profile.inbound_action == "Block"
            && profile.outbound_action == "Block"
        {
            (theme::DANGER, "Isolated")
        } else if profile.enabled {
            (theme::ACCENT, "Enabled")
        } else {
            (theme::WARN, "Disabled")
        };

        ui.horizontal(|ui| {
            ui.label(RichText::new(&profile.name).strong().size(12.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let badge = RichText::new(status).color(color).size(11.0).monospace();
                ui.label(badge);
            });
        });
        ui.label(
            RichText::new(format!(
                "Inbound: {}  •  Outbound: {}",
                profile.inbound_action, profile.outbound_action
            ))
            .color(theme::TEXT2)
            .size(11.0),
        );
        ui.add_space(4.0);
    }
    ui.add_space(4.0);
}

fn isolation_section(
    ui: &mut Ui,
    rules: &active_response::FirewallRuleList,
    selected: &mut Option<FirewallSelection>,
) {
    let is_active = rules.isolated;
    let (color, status) = if is_active {
        (theme::DANGER, "ACTIVE")
    } else {
        (theme::ACCENT, "Inactive")
    };

    section_header(ui, "Network Isolation", "Full machine network isolation");
    ui.add_space(4.0);
    let resp = ui.horizontal(|ui| {
        let badge = RichText::new(status)
            .color(color)
            .size(13.0)
            .strong()
            .monospace();
        ui.label(badge);
        if let Some(secs) = rules.isolation_remaining_secs {
            if secs > 0 {
                let mins = secs / 60;
                ui.label(
                    RichText::new(format!("  ({mins} min remaining)"))
                        .color(theme::TEXT2)
                        .size(11.0),
                );
            }
        }
    });
    let click = ui
        .interact(
            resp.response.rect,
            ui.id().with("firewall-isolation-row"),
            egui::Sense::click(),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if is_active && click.clicked() {
        *selected = Some(FirewallSelection {
            rule_name: "Network Isolation".into(),
            target: "Entire machine".into(),
            rule_type: "isolation".into(),
            direction: "both".into(),
            pid: 0,
            path: String::new(),
        });
    }
    ui.add_space(8.0);
}

fn blocked_ips_section(
    ui: &mut Ui,
    rules: &active_response::FirewallRuleList,
    selected: &mut Option<FirewallSelection>,
) {
    section_header(
        ui,
        &format!("Blocked IPs ({})", rules.blocked_ips.len()),
        "Remote IP addresses blocked by firewall rules — click to unblock",
    );
    ui.add_space(4.0);

    if rules.blocked_ips.is_empty() {
        muted(ui, "No IP blocks active.");
        return;
    }

    for entry in &rules.blocked_ips {
        let resp = ui.horizontal(|ui| {
            ui.label(RichText::new(&entry.target).size(12.0).monospace());
            if let Some(expires) = entry.expires_at_unix {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if let Some(rem) = expires.checked_sub(now) {
                    let mins = rem / 60;
                    ui.label(
                        RichText::new(format!("({mins} min)"))
                            .color(theme::TEXT2)
                            .size(10.0),
                    );
                }
            }
        });
        let click = ui
            .interact(
                resp.response.rect,
                ui.id().with(format!("firewall-blocked-ip-{}", entry.rule_name)),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if click.clicked() {
            *selected = Some(FirewallSelection {
                rule_name: entry.rule_name.clone(),
                target: entry.target.clone(),
                rule_type: "ip".into(),
                direction: "out".into(),
                pid: 0,
                path: String::new(),
            });
        }
    }
    ui.add_space(4.0);
}

fn blocked_processes_section(
    ui: &mut Ui,
    rules: &active_response::FirewallRuleList,
    selected: &mut Option<FirewallSelection>,
) {
    section_header(
        ui,
        &format!("Blocked Processes ({})", rules.blocked_processes.len()),
        "Processes with active firewall block rules — click to unblock",
    );
    ui.add_space(4.0);

    if rules.blocked_processes.is_empty() {
        muted(ui, "No process blocks active.");
        return;
    }

    for entry in &rules.blocked_processes {
        let label = if entry.path.is_empty() {
            format!("PID {}", entry.pid)
        } else {
            entry.path.clone()
        };
        let resp = ui.horizontal(|ui| {
            ui.label(RichText::new(&label).size(11.0).monospace());
        });
        let click = ui
            .interact(
                resp.response.rect,
                ui.id().with(format!(
                    "firewall-blocked-process-{}-{}",
                    entry.pid, entry.path
                )),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if click.clicked() {
            *selected = Some(FirewallSelection {
                rule_name: entry.outbound_rule_name.clone(),
                target: label,
                rule_type: "process".into(),
                direction: "out".into(),
                pid: entry.pid,
                path: entry.path.clone(),
            });
        }
    }
    ui.add_space(4.0);
}

fn blocked_domains_section(
    ui: &mut Ui,
    rules: &active_response::FirewallRuleList,
    selected: &mut Option<FirewallSelection>,
) {
    section_header(
        ui,
        &format!("Blocked Domains ({})", rules.blocked_domains.len()),
        "Domains redirected to 127.0.0.1 via hosts file — click to clear",
    );
    ui.add_space(4.0);

    if rules.blocked_domains.is_empty() {
        muted(ui, "No domain blocks active.");
        return;
    }

    for entry in &rules.blocked_domains {
        let resp = ui.label(RichText::new(&entry.domain).size(12.0).monospace());
        let click = ui
            .interact(
                resp.rect,
                ui.id().with(format!("firewall-blocked-domain-{}", entry.domain)),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if click.clicked() {
            *selected = Some(FirewallSelection {
                rule_name: format!("domain-{}", entry.domain),
                target: entry.domain.clone(),
                rule_type: "domain".into(),
                direction: "out".into(),
                pid: 0,
                path: String::new(),
            });
        }
    }
    ui.add_space(4.0);
}

fn suspended_processes_section(
    ui: &mut Ui,
    rules: &active_response::FirewallRuleList,
    selected: &mut Option<FirewallSelection>,
) {
    section_header(
        ui,
        &format!("Suspended Processes ({})", rules.suspended_processes.len()),
        "Processes suspended by Vigil — click to resume",
    );
    ui.add_space(4.0);

    if rules.suspended_processes.is_empty() {
        muted(ui, "No suspended processes.");
        return;
    }

    for entry in &rules.suspended_processes {
        let label = if !entry.proc_name.is_empty() {
            format!("{} (PID {})", entry.proc_name, entry.pid)
        } else {
            format!("PID {}", entry.pid)
        };
        let resp = ui.horizontal(|ui| {
            ui.label(RichText::new(&label).size(11.0).monospace());
        });
        let click = ui
            .interact(
                resp.response.rect,
                ui.id().with(format!(
                    "firewall-suspended-process-{}-{}",
                    entry.pid, entry.path
                )),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if click.clicked() {
            *selected = Some(FirewallSelection {
                rule_name: format!("suspend-{}", entry.pid),
                target: label,
                rule_type: "process".into(),
                direction: "both".into(),
                pid: entry.pid,
                path: entry.path.clone(),
            });
        }
    }
    ui.add_space(4.0);
}

// ── Helpers ──────────────────────────────────────────────────────────────────
fn section_header(ui: &mut Ui, title: &str, tooltip: &str) {
    ui.label(RichText::new(title).size(13.0).strong())
        .on_hover_text(tooltip);
}

fn muted(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::TEXT2).size(12.0));
}
