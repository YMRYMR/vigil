//! Help tab - static reference documentation with a cleaner operator-console layout.

use crate::ui::theme;
use egui::RichText;

pub fn show(ui: &mut egui::Ui) {
    egui::ScrollArea::vertical().id_salt("help_scroll").show(ui, |ui| {
        ui.add_space(18.0);
        hero(ui);
        ui.add_space(16.0);

        if ui.available_width() > 700.0 {
            ui.columns(2, |cols| {
                cols[0].vertical(|ui| {
                    card(ui, "Operator workflow", |ui| {
                        field_row(ui, "Inspect", "Select a process card to see the full score and process reasons; click a child row only if you want one connection.");
                        field_row(ui, "Trust", "Add the process to the trusted list. Disabled when Vigil does not know the executable location.");
                        field_row(ui, "Open loc", "Open the executable's folder in the system file manager. Disabled when no location is known.");
                        field_row(ui, "Kill", "Terminate the process after confirmation. Unresolved PID placeholder rows are not killable.");
                        field_row(ui, "Suspend", "Freeze the selected process without killing it. Use Resume process to continue it later.");
                        field_row(ui, "Freeze autoruns", "Capture the current Run and RunOnce autorun values as a baseline so later changes can be reverted.");
                        field_row(ui, "Quarantine", "Current Windows implementation isolates the network, blocks the executable path when known, suspends the process when possible, disables USB storage, and pauses non-Microsoft scheduled tasks.");
                        field_row(ui, "Block domain", "Redirect the selected hostname to the local machine through the Windows hosts file. Requires a resolved hostname on the selected connection.");
                        field_row(ui, "Kill connection", "Immediately terminate the selected live TCP socket. On Windows this is currently available for IPv4 TCP connections when Vigil is elevated.");
                    });
                    card(ui, "What Vigil does", |ui| {
                        body(ui, "Vigil watches TCP/UDP connections in real time, enriches each row with process context, and raises an alert when the score crosses the configured threshold.");
                    });
                    card(ui, "How scoring works", |ui| {
                        body(ui, "Scores stack. A chatty process with many destinations or ports gets a higher row score than a single quiet socket. Phase 12 adds deeper but still explainable heuristics, so operators can see why a process crossed the line instead of trusting a black box.");
                        ui.add_space(6.0);
                        score_row(ui, "+5", theme::DANGER, "Known malware or C2 port such as 4444, 1337, or 31337");
                        score_row(ui, "+4", theme::WARN, "LoLBin / system binary making a network connection or a clearly abusive script-host pattern");
                        score_row(ui, "+3", theme::WARN, "No executable path, suspicious directory, suspicious parent, beaconing, reputation hit, recent file-drop, or signed-but-malicious corroboration");
                        score_row(ui, "+2", theme::TEXT2, "Untrusted process, unsigned binary, DNS tunneling signal, pre-login activity, unexpected country, long-lived connection, DGA-like hostname or TLS SNI, or mature baseline drift");
                        score_row(ui, "+1", theme::TEXT2, "Unusual destination port for an untrusted process or extra fan-out from the same process");
                    });
                    card(ui, "Persistence signals", |ui| {
                        body(ui, "Vigil also watches for persistence-style behaviour: autorun keys, pre-login connections, file drops in watched directories, long-lived connections that stay open past the configured threshold, and honeypot decoy touches.");
                    });
                    card(ui, "Phase 12 detection depth", |ui| {
                        body(ui, "Phase 12 is about deeper confidence, not mystery scoring. Each new signal still lands as a readable reason or ATT&CK-style tag in the UI.");
                        ui.add_space(6.0);
                        bullet(ui, "Behavioural baselines", "Stable processes build a small persisted profile of previously seen remotes, ports, and countries. Once mature, true novelty adds score as baseline drift instead of silently changing the normal profile.");
                        bullet(ui, "Script-host inspection", "PowerShell, cmd, WSH, mshta, regsvr32, and rundll32 command lines are inspected for encoded commands, stealth switches, download cradles, remote scriptlets, and similar abuse patterns.");
                        bullet(ui, "TLS ClientHello enrichment", "When an alert produces a packet capture, Vigil now extracts TLS ClientHello metadata such as SNI and the JA3 tuple into a sidecar file, audits the result, and reuses cached metadata for later matching connections to the same remote IP and port.");
                        bullet(ui, "Parent/token anomalies", "Sensitive system ancestry spawning script-capable children raises an explicit reason. This is heuristic and intentionally conservative, not a kernel anti-tamper claim.");
                        bullet(ui, "ATT&CK mappings", "When a detection heuristic suggests a known technique family, Vigil attaches an operator-facing ATT&CK-style tag to the process group and selected connection.");
                    });
                    card(ui, "Audit trail", |ui| {
                        body(ui, "Manual and automatic response actions append JSON Lines to logs/vigil-audit.jsonl next to the normal daily logs. Each record includes a timestamp, action, outcome, and structured details such as PID, process name, endpoints, domains, dump paths, packet-capture paths, TLS sidecar extraction, break-glass lifecycle events, honeypot touches, rule names, and quarantine warnings.");
                    });
                });

                cols[1].vertical(|ui| {
                    card(ui, "Active response", |ui| {
                        body(ui, "Vigil supports reversible intervention: kill a live connection, block a remote IP for 1 hour, 24 hours, or permanently, block a process by executable path, block a resolved domain through the hosts file, suspend a process while you investigate, freeze autorun keys for later rollback, apply a quarantine preset, or isolate the machine. Active blocks show a countdown and a quick unblock action. Isolation is immediate and confirmed by connectivity checks; other destructive actions keep confirmation.");
                        ui.add_space(6.0);
                        bullet(ui, "Kill connection", "Terminate the selected live TCP socket immediately. Current Windows implementation uses the IPv4 TCP delete-TCB path.");
                        bullet(ui, "Suspend process", "Freeze every thread in the selected process without killing it. Resume process re-enables the same process later in the investigation.");
                        bullet(ui, "Freeze autoruns", "Capture a baseline of Windows Run and RunOnce keys. Revert autoruns removes later additions and restores changed baseline values.");
                        bullet(ui, "Quarantine profile", "Current Windows preset: isolate the network, block the selected executable path permanently when known, suspend the process when possible, disable USB storage, and pause non-Microsoft scheduled tasks. Clear quarantine restores those same controls where possible.");
                        bullet(ui, "Block remote", "Choose a 1h, 24h, or permanent block for the selected connection's remote IP through the Windows firewall. IPv4 and IPv6 remote addresses are supported.");
                        bullet(ui, "Block domain", "Add or remove Windows hosts-file entries that redirect the selected hostname to 127.0.0.1 and ::1. Best for persistent C2 or phishing domains.");
                        bullet(ui, "Block process", "Choose a 1h, 24h, or permanent block for all traffic from the selected executable path.");
                        bullet(ui, "Isolate network", "Apply strict containment immediately: first harden firewall policy, then verify outbound reachability. If traffic is still reachable, Vigil falls back to emergency adapter cutoff. Break-glass and failsafe recovery restore saved state if the app dies.");
                    });

                    card(ui, "Auto response and allowlisting", |ui| {
                        body(ui, "Automatic response is optional and disabled by default. Dry run is enabled by default, trusted processes suppress automation, and the engine requires strong corroborating signals in addition to the score threshold. Allowlist-only mode is a separate restrictive control that can block traffic from processes outside the trusted list, the explicit allowlist, and current Microsoft-signed system binaries.");
                        ui.add_space(6.0);
                        bullet(ui, "Dry run", "Surface the planned action in the UI and audit log without executing containment.");
                        bullet(ui, "Cooldown", "Suppress repeated automatic actions against the same target for the configured window.");
                        bullet(ui, "Trusted processes", "Processes in the trusted list never receive automatic containment.");
                        bullet(ui, "Allowlist-only mode", "Operator-controlled process allowlist. Entries can be process names or full executable paths.");
                    });

                    card(ui, "User-defined response rules", |ui| {
                        body(ui, "Response rules are loaded from an operator-supplied YAML file. Rules are evaluated in order, first match wins, and they can either dry-run or execute the same containment primitives used elsewhere in Vigil.");
                        ui.add_space(6.0);
                        bullet(ui, "Supported conditions", "Minimum score, unsigned, pre-login, reputation hit, DGA-like hostname, recently dropped, long-lived, process name contains, and remote/hostname contains.");
                        bullet(ui, "Supported actions", "kill_connection, block_remote, block_process, and quarantine.");
                        bullet(ui, "Example file", "See response-rules.example.yaml in the repository root for a starting point.");
                    });

                    card(ui, "Forensics and honeypots", |ui| {
                        body(ui, "Optional forensic capture is available in Settings. Current Windows implementation can write a full user-mode process dump and a short host-wide packet window on high-score alerts, both rate-limited and logged to the audit trail. Honeypot decoys can plant lure files into common user folders and raise synthetic alerts when touched.");
                        ui.add_space(6.0);
                        bullet(ui, "Enable process dump", "Off by default. Turn it on only when you have disk space and a triage workflow for dump files.");
                        bullet(ui, "Enable PCAP capture", "Off by default. Captures a short pktmon window and converts it to pcapng for later packet analysis. Phase 12 can also derive TLS ClientHello sidecars from those captures.");
                        bullet(ui, "Honeypot decoys", "Canary files are placed in Desktop, Documents, Downloads, and Public Documents where available.");
                        bullet(ui, "Auto isolate on touch", "Optionally isolate the machine immediately after a decoy-touch alert.");
                    });

                    card(ui, "Break-glass recovery", |ui| {
                        body(ui, "Break-glass recovery reduces the risk of locking yourself out during machine isolation. Vigil always arms a watchdog task while isolation is active, keeps a heartbeat file fresh, and restores networking if the heartbeat goes stale past the timeout.");
                        ui.add_space(6.0);
                        bullet(ui, "Recovery timeout", "How long isolation may persist without a live heartbeat before the watchdog restores connectivity.");
                        bullet(ui, "Heartbeat interval", "How often the running app touches the heartbeat while healthy.");
                        bullet(ui, "Watchdog task", "Vigil uses an OS scheduler entry to run the same binary with --break-glass-recover (Windows Task Scheduler, Linux cron, macOS launchd).");
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
                });
            });
        } else {
            card(ui, "What Vigil does", |ui| { body(ui, "Vigil watches TCP/UDP connections in real time, enriches each row with process context, and raises an alert when the score crosses the configured threshold."); });
            card(ui, "Active response", |ui| { body(ui, "Active response includes connection kill, remote and process blocking, domain blocking, suspension, autorun freeze / revert, full quarantine, and machine isolation. Isolation is strict and reversible across supported platforms."); });
            card(ui, "Detection depth", |ui| { body(ui, "Phase 12 adds behavioural baselines, script-host inspection, TLS ClientHello enrichment, parent/token anomaly heuristics, and ATT&CK-style mappings while keeping the output explainable in the inspector."); });
            card(ui, "Auto response and allowlisting", |ui| { body(ui, "Auto response is optional and can dry-run. Allowlist-only mode can force containment for traffic from processes outside the trusted list, explicit allowlist, and current Microsoft-signed system processes."); });
            card(ui, "User-defined response rules", |ui| { body(ui, "Operator-supplied YAML rules can dry-run or execute kill_connection, block_remote, block_process, and quarantine actions. See response-rules.example.yaml."); });
            card(ui, "Forensics and honeypots", |ui| { body(ui, "Process dumps, PCAP capture, TLS sidecar extraction, and decoy-file touches are optional and configurable in Settings."); });
            card(ui, "Break-glass recovery", |ui| { body(ui, "Watchdog-based recovery can restore networking after an isolation lockout if Vigil dies and the heartbeat goes stale."); });
        }

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(RichText::new(format!("Vigil v{}", env!("CARGO_PKG_VERSION"))).color(theme::TEXT3).size(10.5));
        ui.add_space(10.0);
    });
}

fn hero(ui: &mut egui::Ui) {
    egui::Frame::NONE.fill(theme::SURFACE2).stroke(egui::Stroke::new(1.0, theme::ACCENT_BG)).corner_radius(14.0).inner_margin(egui::Margin::symmetric(18, 16)).show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Operator Help").color(theme::TEXT).size(20.0).strong());
            ui.add_space(6.0);
            chip(ui, "Real-time monitoring");
            chip(ui, "Offline enrichment");
            chip(ui, "Containment");
            chip(ui, "Audit trail");
        });
        ui.add_space(10.0);
        ui.label(RichText::new("A quick operational guide: what Vigil watches, how the score is built, where the important controls live, and what gets recorded when you respond.").color(theme::TEXT2).size(12.0));
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
        ui.label(RichText::new(">").color(theme::ACCENT).size(11.0));
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
