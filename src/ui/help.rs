//! Help tab - static reference documentation with a cleaner operator-console layout.

use crate::ui::theme;
use egui::RichText;

/// Render the help panel.
pub fn show(ui: &mut egui::Ui) {
    egui::ScrollArea::vertical()
        .id_salt("help_scroll")
        .show(ui, |ui| {
            ui.add_space(18.0);
            hero(ui);
            ui.add_space(16.0);

            if ui.available_width() > 780.0 {
                card(ui, "Operator workflow", |ui| {
                    field_row(ui, "Inspect", "Select a process card to see the full score and process reasons; click a child row only if you want one connection.");
                    field_row(ui, "Trust", "Add the process to the trusted list. Disabled when Vigil does not know the executable location.");
                    field_row(ui, "Open loc", "Open the executable's folder in the system file manager. Disabled when no location is known.");
                    field_row(ui, "Kill", "Terminate the process after confirmation. Unresolved PID placeholder rows are not killable.");
                    field_row(ui, "Suspend", "Freeze the selected process without killing it. Use Resume process to continue it later.");
                    field_row(ui, "Kill connection", "Immediately terminate the selected live TCP socket. On Windows this is currently available for IPv4 TCP connections when Vigil is elevated.");
                });

                ui.columns(2, |cols| {
                    cols[0].vertical(|ui| {
                        card(ui, "What Vigil does", |ui| {
                            body(ui, "Vigil watches TCP/UDP connections in real time, enriches each row with process context, and raises an alert when the score crosses the configured threshold.");
                        });

                        card(ui, "How scoring works", |ui| {
                            body(ui, "Scores stack. A chatty process with many destinations or ports gets a higher row score than a single quiet socket.");
                            ui.add_space(6.0);
                            score_row(ui, "+5", theme::DANGER, "Known malware or C2 port such as 4444, 1337, or 31337");
                            score_row(ui, "+4", theme::WARN, "LoLBin / system binary making a network connection");
                            score_row(ui, "+3", theme::WARN, "No executable path, suspicious directory, suspicious parent, beaconing, reputation hit, or recent file-drop");
                            score_row(ui, "+2", theme::TEXT2, "Untrusted process, unsigned binary, DNS tunneling signal, pre-login activity, unexpected country, long-lived connection, or DGA-like hostname");
                            score_row(ui, "+1", theme::TEXT2, "Unusual destination port for an untrusted process");
                            score_row(ui, "+1", theme::TEXT2, "Extra fan-out from the same process: more connections, more ports, more remote targets");
                        });

                        card(ui, "Persistence signals", |ui| {
                            body(ui, "Vigil also watches for persistence-style behaviour: autorun keys, pre-login connections, file drops in watched directories, and long-lived connections that stay open past the configured threshold.");
                        });

                        card(ui, "Audit trail", |ui| {
                            body(ui, "Manual and automatic response actions append JSON Lines to logs/vigil-audit.jsonl next to the normal daily logs. Each record includes a timestamp, action, outcome, and structured details such as PID, process name, and endpoints.");
                        });
                    });

                    cols[1].vertical(|ui| {
                        card(ui, "Active response", |ui| {
                            body(ui, "Vigil supports reversible intervention: kill a live connection, block a remote IP for 1 hour, 24 hours, or permanently, block a process by executable path, suspend a process while you investigate, or isolate the machine with firewall rules. Active blocks show a countdown and a quick unblock action. All actions require administrator privileges on Windows and ask for confirmation.");
                            ui.add_space(6.0);
                            bullet(ui, "Kill connection", "Terminate the selected live TCP socket immediately. Current Windows implementation uses the IPv4 TCP delete-TCB path.");
                            bullet(ui, "Suspend process", "Freeze every thread in the selected process without killing it. Resume process re-enables the same process later in the investigation.");
                            bullet(ui, "Block remote", "Choose a 1h, 24h, or permanent block for the selected connection's remote IP through the Windows firewall. IPv4 and IPv6 remote addresses are supported.");
                            bullet(ui, "Block process", "Choose a 1h, 24h, or permanent block for all traffic from the selected executable path.");
                            bullet(ui, "Isolate network", "Add reversible firewall rules that block inbound and outbound traffic.");
                            bullet(ui, "Restore network", "Remove the isolation rules and return to normal traffic flow.");
                        });

                        card(ui, "Auto response", |ui| {
                            body(ui, "Automatic response is optional and disabled by default. Dry run is enabled by default, trusted processes suppress automation, and the engine requires strong corroborating signals in addition to the score threshold.");
                            ui.add_space(6.0);
                            bullet(ui, "Dry run", "Surface the planned action in the UI and audit log without executing containment.");
                            bullet(ui, "Cooldown", "Suppress repeated automatic actions against the same target for the configured window.");
                            bullet(ui, "Trusted processes", "Processes in the trusted list never receive automatic containment.");
                            bullet(ui, "Escalation", "Enable connection kill first, then remote or process blocking only if you accept the higher blast radius.");
                        });

                        card(ui, "Telemetry and reputation", |ui| {
                            body(ui, "Offline enrichment is optional. Point the config at MaxMind GeoLite2 databases for country and ASN lookups, add blocklists for reputation hits, and enable reverse DNS only if you accept that the OS resolver may observe the lookups.");
                            ui.add_space(6.0);
                            bullet(ui, "geoip_city_db / geoip_asn_db", "MaxMind files that add country and ASN metadata.");
                            bullet(ui, "allowed_countries", "Restrict normal destinations to known-good countries.");
                            bullet(ui, "blocklist_paths", "Plain-text IP or CIDR lists for offline reputation hits.");
                            bullet(ui, "fswatch_enabled", "Correlate fresh file drops with new connections.");
                            bullet(ui, "reverse_dns_enabled", "Off by default because it leaks inspection activity.");
                        });

                        card(ui, "UI tips", |ui| {
                            bullet(ui, "Activity", "Use the filter to narrow process cards by name, host, status, or reason text.");
                            bullet(ui, "Alerts", "Alerts are the high-signal cards; the stacked connections show the traffic behind the score.");
                            bullet(ui, "Settings", "Trusted-process edits and auto-response settings auto-save, and the shipped defaults can be restored from the settings panel.");
                            bullet(ui, "Privilege state", "The header shows an Admin badge when Vigil is elevated, or a Run as Admin button otherwise.");
                            bullet(ui, "Keyboard", "The app is built for mouse-first triage, but the controls are intentionally compact and predictable.");
                        });
                    });
                });
            } else {
                card(ui, "What Vigil does", |ui| {
                    body(ui, "Vigil watches TCP/UDP connections in real time, enriches each row with process context, and raises an alert when the score crosses the configured threshold.");
                });
                card(ui, "How scoring works", |ui| {
                    body(ui, "Scores stack. A chatty process with many destinations or ports gets a higher row score than a single quiet socket.");
                    ui.add_space(6.0);
                    score_row(ui, "+5", theme::DANGER, "Known malware or C2 port such as 4444, 1337, or 31337");
                    score_row(ui, "+4", theme::WARN, "LoLBin / system binary making a network connection");
                    score_row(ui, "+3", theme::WARN, "No executable path, suspicious directory, suspicious parent, beaconing, reputation hit, or recent file-drop");
                    score_row(ui, "+2", theme::TEXT2, "Untrusted process, unsigned binary, DNS tunneling signal, pre-login activity, unexpected country, long-lived connection, or DGA-like hostname");
                    score_row(ui, "+1", theme::TEXT2, "Unusual destination port for an untrusted process");
                    score_row(ui, "+1", theme::TEXT2, "Extra fan-out from the same process: more connections, more ports, more remote targets");
                });
                card(ui, "Operator workflow", |ui| {
                    field_row(ui, "Inspect", "Select a process card to see the full score and process reasons; click a child row only if you want one connection.");
                    field_row(ui, "Trust", "Add the process to the trusted list. Disabled when Vigil does not know the executable location.");
                    field_row(ui, "Open loc", "Open the executable's folder in the system file manager. Disabled when no location is known.");
                    field_row(ui, "Kill", "Terminate the process after confirmation. Unresolved PID placeholder rows are not killable.");
                    field_row(ui, "Suspend", "Freeze the selected process without killing it. Use Resume process to continue it later.");
                    field_row(ui, "Kill connection", "Immediately terminate the selected live TCP socket. On Windows this is currently available for IPv4 TCP connections when Vigil is elevated.");
                });
                card(ui, "Active response", |ui| {
                    body(ui, "Vigil supports reversible intervention: kill a live connection, block a remote IP for 1 hour, 24 hours, or permanently, block a process by executable path, suspend a process while you investigate, or isolate the machine with firewall rules. Active blocks show a countdown and a quick unblock action. All actions require administrator privileges on Windows and ask for confirmation.");
                    ui.add_space(6.0);
                    bullet(ui, "Kill connection", "Terminate the selected live TCP socket immediately. Current Windows implementation uses the IPv4 TCP delete-TCB path.");
                    bullet(ui, "Suspend process", "Freeze every thread in the selected process without killing it. Resume process re-enables the same process later in the investigation.");
                    bullet(ui, "Block remote", "Choose a 1h, 24h, or permanent block for the selected connection's remote IP through the Windows firewall. IPv4 and IPv6 remote addresses are supported.");
                    bullet(ui, "Block process", "Choose a 1h, 24h, or permanent block for all traffic from the selected executable path.");
                    bullet(ui, "Isolate network", "Add reversible firewall rules that block inbound and outbound traffic.");
                    bullet(ui, "Restore network", "Remove the isolation rules and return to normal traffic flow.");
                });
                card(ui, "Auto response", |ui| {
                    body(ui, "Automatic response is optional and disabled by default. Dry run is enabled by default, trusted processes suppress automation, and the engine requires strong corroborating signals in addition to the score threshold.");
                    ui.add_space(6.0);
                    bullet(ui, "Dry run", "Surface the planned action in the UI and audit log without executing containment.");
                    bullet(ui, "Cooldown", "Suppress repeated automatic actions against the same target for the configured window.");
                    bullet(ui, "Trusted processes", "Processes in the trusted list never receive automatic containment.");
                    bullet(ui, "Escalation", "Enable connection kill first, then remote or process blocking only if you accept the higher blast radius.");
                });
                card(ui, "Audit trail", |ui| {
                    body(ui, "Manual and automatic response actions append JSON Lines to logs/vigil-audit.jsonl next to the normal daily logs.");
                });
                card(ui, "Persistence signals", |ui| {
                    body(ui, "Vigil also watches for persistence-style behaviour: autorun keys, pre-login connections, file drops in watched directories, and long-lived connections that stay open past the configured threshold.");
                });
                card(ui, "Telemetry and reputation", |ui| {
                    body(ui, "Offline enrichment is optional. Point the config at MaxMind GeoLite2 databases for country and ASN lookups, add blocklists for reputation hits, and enable reverse DNS only if you accept that the OS resolver may observe the lookups.");
                    ui.add_space(6.0);
                    bullet(ui, "geoip_city_db / geoip_asn_db", "MaxMind files that add country and ASN metadata.");
                    bullet(ui, "allowed_countries", "Restrict normal destinations to known-good countries.");
                    bullet(ui, "blocklist_paths", "Plain-text IP or CIDR lists for offline reputation hits.");
                    bullet(ui, "fswatch_enabled", "Correlate fresh file drops with new connections.");
                    bullet(ui, "reverse_dns_enabled", "Off by default because it leaks inspection activity.");
                });
                card(ui, "UI tips", |ui| {
                    bullet(ui, "Activity", "Use the filter to narrow process cards by name, host, status, or reason text.");
                    bullet(ui, "Alerts", "Alerts are the high-signal cards; the stacked connections show the traffic behind the score.");
                    bullet(ui, "Settings", "Trusted-process edits and auto-response settings auto-save, and the shipped defaults can be restored from the settings panel.");
                    bullet(ui, "Privilege state", "The header shows an Admin badge when Vigil is elevated, or a Run as Admin button otherwise.");
                    bullet(ui, "Keyboard", "The app is built for mouse-first triage, but the controls are intentionally compact and predictable.");
                });
            }

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("Vigil v{}", env!("CARGO_PKG_VERSION")))
                    .color(theme::TEXT3)
                    .size(10.5),
            );
            ui.add_space(10.0);
        });
}

fn hero(ui: &mut egui::Ui) {
    egui::Frame::NONE
        .fill(theme::SURFACE2)
        .stroke(egui::Stroke::new(1.0, theme::ACCENT_BG))
        .corner_radius(14.0)
        .inner_margin(egui::Margin::symmetric(18, 16))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("Operator Help")
                        .color(theme::TEXT)
                        .size(20.0)
                        .strong(),
                );
                ui.add_space(6.0);
                chip(ui, "Real-time monitoring");
                chip(ui, "Offline enrichment");
                chip(ui, "High-signal triage");
                chip(ui, "Audit trail");
            });
            ui.add_space(10.0);
            ui.label(
                RichText::new("A quick operational guide: what Vigil watches, how the score is built, where the important controls live, and what gets recorded when you respond.")
                    .color(theme::TEXT2)
                    .size(12.0),
            );
        });
}

fn card(ui: &mut egui::Ui, title: &str, f: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::symmetric(16, 14))
        .show(ui, |ui| {
            ui.label(RichText::new(title).color(theme::TEXT).size(13.5).strong());
            ui.add_space(10.0);
            f(ui);
        });
    ui.add_space(12.0);
}

fn chip(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(format!(" {text} "))
            .color(theme::ACCENT)
            .background_color(theme::ACCENT_BG)
            .size(10.5)
            .strong(),
    );
}

fn body(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).color(theme::TEXT2).size(11.7)).wrap());
}

fn bullet(ui: &mut egui::Ui, key: &str, text: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(">") .color(theme::ACCENT).size(11.0));
        ui.add_space(2.0);
        ui.label(RichText::new(key).color(theme::TEXT).size(11.0).strong());
        ui.add_space(6.0);
        ui.add(egui::Label::new(RichText::new(text).color(theme::TEXT2).size(11.0)).wrap());
    });
    ui.add_space(4.0);
}

fn score_row(ui: &mut egui::Ui, points: &str, color: egui::Color32, description: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [34.0, 18.0],
            egui::Label::new(
                RichText::new(points)
                    .color(color)
                    .monospace()
                    .size(11.7)
                    .strong(),
            ),
        );
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(description).color(theme::TEXT2).size(11.2)).wrap());
    });
    ui.add_space(4.0);
}

fn field_row(ui: &mut egui::Ui, field: &str, description: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [96.0, 18.0],
            egui::Label::new(RichText::new(field).color(theme::TEXT).size(11.7).strong()),
        );
        ui.add(egui::Label::new(RichText::new(description).color(theme::TEXT2).size(11.2)).wrap());
    });
    ui.add_space(4.0);
}
