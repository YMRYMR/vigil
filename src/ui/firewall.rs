//! Firewall status dashboard — Phase 19 P3.
//!
//! Shows current firewall profile state, active Vigil rules,
//! blocked targets/processes/domains, and isolation status.
//! All data is read-only via the cached state — no firewall
//! operations are performed during rendering.

use crate::ui::theme;
use crate::{active_response, security::firewall};
use egui::{Color32, RichText, Ui};

/// Render the firewall tab panel.
/// Called once per frame; data is cached via `load_state_for_query` (250ms TTL).
pub fn show(ui: &mut Ui) {
    let rules = active_response::list_rules();

    egui::ScrollArea::vertical()
        .id_salt("firewall-scroll")
        .show(ui, |ui| {
            ui.add_space(8.0);

            // ── Header ──────────────────────────────────────────────
            ui.horizontal(|ui| {
                ui.heading("Firewall");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    backend_badge(ui);
                });
            });
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(8.0);

            // ── Profile state ───────────────────────────────────────
            profile_section(ui, &rules);

            // ── Isolation ────────────────────────────────────────────
            isolation_section(ui, &rules);

            // ── Blocked IPs ──────────────────────────────────────────
            blocked_ips_section(ui, &rules);

            // ── Blocked processes ────────────────────────────────────
            blocked_processes_section(ui, &rules);

            // ── Blocked domains ──────────────────────────────────────
            blocked_domains_section(ui, &rules);

            // ── Suspended processes ──────────────────────────────────
            suspended_processes_section(ui, &rules);
        });
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
        ui.label(
            RichText::new("No profile data available.")
                .color(theme::TEXT2)
                .size(12.0),
        );
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

fn isolation_section(ui: &mut Ui, rules: &active_response::FirewallRuleList) {
    let is_active = rules.isolated;
    let (color, status) = if is_active {
        (theme::DANGER, "ACTIVE")
    } else {
        (theme::ACCENT, "Inactive")
    };

    section_header(ui, "Network Isolation", "Full machine network isolation");
    ui.add_space(4.0);
    ui.horizontal(|ui| {
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
    ui.add_space(8.0);
}

fn blocked_ips_section(ui: &mut Ui, rules: &active_response::FirewallRuleList) {
    section_header(
        ui,
        &format!("Blocked IPs ({})", rules.blocked_ips.len()),
        "Remote IP addresses blocked by firewall rules",
    );
    ui.add_space(4.0);

    if rules.blocked_ips.is_empty() {
        muted(ui, "No IP blocks active.");
        return;
    }

    for entry in &rules.blocked_ips {
        ui.horizontal(|ui| {
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
    }
    ui.add_space(4.0);
}

fn blocked_processes_section(ui: &mut Ui, rules: &active_response::FirewallRuleList) {
    section_header(
        ui,
        &format!("Blocked Processes ({})", rules.blocked_processes.len()),
        "Processes with active firewall block rules",
    );
    ui.add_space(4.0);

    if rules.blocked_processes.is_empty() {
        muted(ui, "No process blocks active.");
        return;
    }

    for entry in &rules.blocked_processes {
        ui.horizontal(|ui| {
            let label = if entry.path.is_empty() {
                format!("PID {}", entry.pid)
            } else {
                entry.path.clone()
            };
            ui.label(RichText::new(label).size(11.0).monospace());
        });
    }
    ui.add_space(4.0);
}

fn blocked_domains_section(ui: &mut Ui, rules: &active_response::FirewallRuleList) {
    section_header(
        ui,
        &format!("Blocked Domains ({})", rules.blocked_domains.len()),
        "Domains redirected to 127.0.0.1 via hosts file",
    );
    ui.add_space(4.0);

    if rules.blocked_domains.is_empty() {
        muted(ui, "No domain blocks active.");
        return;
    }

    for entry in &rules.blocked_domains {
        ui.label(RichText::new(&entry.domain).size(12.0).monospace());
    }
    ui.add_space(4.0);
}

fn suspended_processes_section(ui: &mut Ui, rules: &active_response::FirewallRuleList) {
    section_header(
        ui,
        &format!("Suspended Processes ({})", rules.suspended_processes.len()),
        "Processes suspended by Vigil",
    );
    ui.add_space(4.0);

    if rules.suspended_processes.is_empty() {
        muted(ui, "No suspended processes.");
        return;
    }

    for entry in &rules.suspended_processes {
        ui.horizontal(|ui| {
            let label = if !entry.proc_name.is_empty() {
                format!("{} (PID {})", entry.proc_name, entry.pid)
            } else {
                format!("PID {}", entry.pid)
            };
            ui.label(RichText::new(label).size(11.0).monospace());
            if let Some(remaining) = entry.suspended_at_unix.checked_sub(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ) {
                let mins = remaining / 60;
                if mins > 0 {
                    ui.label(
                        RichText::new(format!("({mins} min ago)"))
                            .color(theme::TEXT2)
                            .size(10.0),
                    );
                }
            }
        });
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
