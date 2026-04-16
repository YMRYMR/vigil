//! Help tab — static reference documentation.

use crate::ui::theme;
use egui::RichText;

/// Render the help panel.
pub fn show(ui: &mut egui::Ui) {
    egui::ScrollArea::vertical()
        .id_salt("help_scroll")
        .show(ui, |ui| {
            ui.add_space(12.0);

            // ── What Vigil does ───────────────────────────────────────────────
            section(ui, "What Vigil Does");
            body(
                ui,
                "Vigil monitors every active TCP/UDP connection on this machine in real time \
                 (using the Windows ETW kernel session when available, or polling the OS \
                 every few seconds as a fallback).\n\n\
                 Each connection is scored for suspicious characteristics. \
                 Connections that reach or exceed the alert threshold are highlighted \
                 in amber or red and trigger a desktop notification.",
            );

            // ── Score table ───────────────────────────────────────────────────
            ui.add_space(8.0);
            section(ui, "How the Score Is Calculated");
            body(
                ui,
                "Scores accumulate — a single connection may hit multiple rules. \
                 For example, PowerShell launched by Word connecting to port 4444 from \
                 AppData scores 4+3+3+5+2 = 17 (display is capped at the threshold):",
            );

            ui.add_space(4.0);
            score_row(ui, "+5", theme::DANGER, "Connection to known malware/C2 port (4444, 1337, 31337, etc.)");
            score_row(ui, "+4", theme::WARN, "System binary making a network connection (living-off-the-land): cmd, powershell, certutil, mshta, wmic, etc.");
            score_row(ui, "+3", theme::WARN, "No executable path found (possible process injection or hollowing)");
            score_row(ui, "+3", theme::WARN, "Executable running from a suspicious directory (Temp, AppData\\Roaming, Downloads, etc.)");
            score_row(ui, "+3", theme::WARN, "Suspicious parent process: Office/PDF app spawning a shell, WMI spawning scripts, etc.");
            score_row(ui, "+3", theme::WARN, "Beaconing pattern detected — regular timing signature of a C2 callback (30+ s of samples needed)");
            score_row(ui, "+2", theme::TEXT2, "Unrecognised process (not in trusted list) — stacks with the unsigned binary penalty below");
            score_row(ui, "+2", theme::TEXT2, "Unsigned binary — no publisher information (stacks with Unrecognised)");
            score_row(ui, "+2", theme::TEXT2, "DNS query (port 53) from a non-DNS process — possible DNS tunneling / exfiltration");
            score_row(ui, "+2", theme::TEXT2, "Observed before user login — flagged with a red \u{201C}PL\u{201D} badge in the Time column; classic rootkit / dropper signal");
            score_row(ui, "+3", theme::WARN,  "IP reputation hit — remote matched a user-supplied blocklist (badge: REP)");
            score_row(ui, "+3", theme::WARN,  "Executable was just dropped into Temp/AppData/Downloads right before connecting (badge: DRP) — classic dropper pattern");
            score_row(ui, "+2", theme::TEXT2, "Connection to an unexpected country (requires `allowed_countries` to be set in config)");
            score_row(ui, "+2", theme::TEXT2, "Long-lived connection from an untrusted process, held open past `long_lived_secs` (badge: LL, default 1 h)");
            score_row(ui, "+2", theme::TEXT2, "Reverse-DNS hostname looks DGA-generated (high Shannon entropy; badge: DGA)");
            score_row(ui, "+1", theme::TEXT2, "Unusual destination port for an untrusted process");

            // ── Inspector fields ──────────────────────────────────────────────
            ui.add_space(8.0);
            section(ui, "Inspector Fields");

            field_row(ui, "Publisher", "Company name from the executable's version info (Windows only). Empty for system processes or binaries with no version resource.");
            field_row(ui, "Parent", "Name and PID of the process that spawned this one. PowerShell launched by Office is suspicious.");
            field_row(ui, "Service", "Windows service name, if the process is registered as a service. Helps identify svchost.exe sub-services.");
            field_row(ui, "Status", "TCP connection state: ESTABLISHED (active data link), LISTEN (bound, waiting), SYN_SENT (connection in progress), CLOSE_WAIT / TIME_WAIT (closing).");

            // ── Process tree ──────────────────────────────────────────────────
            ui.add_space(8.0);
            section(ui, "Process Tree (Inspector)");
            body(
                ui,
                "When you select a connection, the inspector shows the full process ancestry \
                 — not just the immediate parent, but every ancestor up to the system root. \
                 This is critical for detecting macro-based malware: a Word document that \
                 spawns cmd.exe that spawns PowerShell will show the full chain \
                 Word \u{2192} cmd \u{2192} PowerShell, making the attack path immediately obvious.",
            );

            // ── Action buttons ────────────────────────────────────────────────
            ui.add_space(8.0);
            section(ui, "Inspector Actions");

            field_row(ui, "Trust", "Add the process to the trusted list. The process will no longer generate +2 (unrecognised) or +1 (unusual port) alerts. Takes effect immediately; saved to vigil.json.");
            field_row(ui, "Open Location", "Open the folder containing the executable in Explorer.");
            field_row(ui, "Kill Process", "Terminate the process immediately. A confirmation prompt appears first. Does not affect child processes.");

            // ── svchost note ──────────────────────────────────────────────────
            ui.add_space(8.0);
            section(ui, "Note on svchost.exe");
            body(
                ui,
                "svchost.exe hosts many Windows services. When it appears in the Activity \
                 list, check the Service column to identify which service owns the connection. \
                 Common legitimate services: wuauserv (Windows Update), BITS, winmgmt, Dnscache.",
            );

            // ── Tips ──────────────────────────────────────────────────────────
            ui.add_space(8.0);
            section(ui, "Tips");
            tip(ui, "Run Vigil as Administrator to activate ETW mode — connections appear in under 100 ms instead of up to 5 seconds.");
            tip(ui, "Adjust the alert threshold (Settings \u{2192} Detection) between 1 (extremely sensitive — every unrecognised process alerts) and 10 (only the most severe combinations trigger alerts). A value of 3\u{2013}5 is a good balance for most users.");
            tip(ui, "Add your own internal tools to the Trusted Processes list so they don't generate +2 alerts.");
            tip(ui, "vigil.json lives next to the executable. Back it up to preserve your trusted-processes customisations.");

            // ── Registry persistence watcher ──────────────────────────────────
            ui.add_space(8.0);
            section(ui, "Registry Persistence Watcher (Windows)");
            body(
                ui,
                "Vigil polls the four standard Windows autorun keys every 30 seconds \
                 and raises a high-severity alert when a new entry appears:\n\n\
                 \u{00a0}\u{00a0}\u{2022} HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n\
                 \u{00a0}\u{00a0}\u{2022} HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n\
                 \u{00a0}\u{00a0}\u{2022} HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n\
                 \u{00a0}\u{00a0}\u{2022} HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n\n\
                 These are the most heavily abused persistence locations — malware \
                 writes itself here so it survives a reboot.  Existing entries at \
                 start-up are baselined silently; only **new** entries raise an alert.",
            );

            // ── Running before login ──────────────────────────────────────────
            ui.add_space(8.0);
            section(ui, "Running Before Login (all platforms)");
            body(
                ui,
                "Vigil can install itself as a boot-time service/daemon so it \
                 monitors network connections even before a user logs in. \
                 Connections captured before login get a +2 score bump and a red \
                 \u{201C}PL\u{201D} badge in the Time column — the first user to log \
                 in sees the backlog in the Alerts tab (subject to the 200-row cap).\n\n\
                 Install from an elevated shell:\n\n\
                 \u{00a0}\u{00a0}Windows (Admin CMD):  vigil.exe --install-service\n\
                 \u{00a0}\u{00a0}macOS   (root):       sudo vigil --install-service\n\
                 \u{00a0}\u{00a0}Linux   (root):       sudo vigil --install-service\n\n\
                 Uninstall with  --uninstall-service.  The service runs the monitor \
                 only — tray icon and UI still require a logged-in desktop session.",
            );

            // ── Reputation & Telemetry (Phase 10) ─────────────────────────────
            ui.add_space(8.0);
            section(ui, "Reputation, Geolocation & Telemetry");
            body(
                ui,
                "Vigil enriches each connection with offline reputation data when you \
                 configure the relevant fields in vigil.json:\n\n\
                 \u{00a0}\u{00a0}\u{2022} geoip_city_db / geoip_asn_db — path to MaxMind \
                 GeoLite2-City and GeoLite2-ASN .mmdb files (download free from MaxMind). \
                 Adds country code, ASN number, and AS organisation to each connection.\n\
                 \u{00a0}\u{00a0}\u{2022} allowed_countries — list of ISO country codes \
                 (e.g. [\"US\",\"GB\"]). Connections to anywhere else score +2.\n\
                 \u{00a0}\u{00a0}\u{2022} blocklist_paths — paths to plain-text IP blocklists \
                 (one IP or CIDR per line, `#` for comments). Hits score +3 and get a REP \
                 badge.\n\
                 \u{00a0}\u{00a0}\u{2022} fswatch_enabled — watches Temp, AppData, and \
                 Downloads for new .exe/.dll drops; a connection from a freshly-dropped \
                 file within fswatch_window_secs scores +3 (DRP badge).\n\
                 \u{00a0}\u{00a0}\u{2022} long_lived_secs — threshold for the +2 long-lived \
                 bonus on untrusted processes (LL badge, default 3600 s).\n\
                 \u{00a0}\u{00a0}\u{2022} reverse_dns_enabled — off by default (leaks which \
                 IPs Vigil is inspecting to the OS resolver). When on, remote IPs are \
                 reverse-resolved and high-entropy hostnames earn a +2 DGA bonus.\n\n\
                 All of these are additive: a connection can accumulate REP + DRP + LL + \
                 DGA in the same row.",
            );

            // ── Version ───────────────────────────────────────────────────────
            ui.add_space(16.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("Vigil v{}", env!("CARGO_PKG_VERSION")))
                    .color(theme::TEXT3)
                    .size(10.5),
            );
            ui.add_space(16.0);
        });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn section(ui: &mut egui::Ui, title: &str) {
    ui.label(
        RichText::new(title)
            .color(theme::TEXT)
            .size(13.0)
            .strong(),
    );
    ui.add_space(3.0);
}

fn body(ui: &mut egui::Ui, text: &str) {
    ui.add(
        egui::Label::new(RichText::new(text).color(theme::TEXT2).size(11.5)).wrap(),
    );
}

fn score_row(ui: &mut egui::Ui, points: &str, color: egui::Color32, description: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [28.0, 18.0],
            egui::Label::new(
                RichText::new(points)
                    .color(color)
                    .monospace()
                    .size(11.5)
                    .strong(),
            ),
        );
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(RichText::new(description).color(theme::TEXT2).size(11.0))
                .wrap(),
        );
    });
    ui.add_space(2.0);
}

fn field_row(ui: &mut egui::Ui, field: &str, description: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [80.0, 18.0],
            egui::Label::new(
                RichText::new(field)
                    .color(theme::TEXT)
                    .size(11.5)
                    .strong(),
            ),
        );
        ui.add(
            egui::Label::new(RichText::new(description).color(theme::TEXT2).size(11.0))
                .wrap(),
        );
    });
    ui.add_space(3.0);
}

fn tip(ui: &mut egui::Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("\u{25b8}").color(theme::ACCENT).size(11.0));
        ui.add_space(2.0);
        ui.add(
            egui::Label::new(RichText::new(text).color(theme::TEXT2).size(11.0)).wrap(),
        );
    });
    ui.add_space(2.0);
}
