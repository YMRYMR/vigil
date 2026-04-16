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
            score_row(ui, "+2", theme::TEXT2, "Unrecognised process (not in trusted list) — stacks with the unsigned binary penalty below");
            score_row(ui, "+2", theme::TEXT2, "Unsigned binary — no publisher information (stacks with Unrecognised)");
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

            // ── Running before login ──────────────────────────────────────────
            ui.add_space(8.0);
            section(ui, "Running Before Login (Windows)");
            body(
                ui,
                "Vigil can be configured to start as a Windows Service so it monitors \
                 network connections even before a user logs in — catching rootkits and \
                 malware that activates during boot. To install as a service, run the \
                 following from an elevated command prompt:\n\n\
                 \u{00a0}\u{00a0}sc create Vigil binPath= \"\\\"<path>\\vigil.exe\\\"\" start= auto\n\
                 \u{00a0}\u{00a0}sc start Vigil\n\n\
                 Note: the GUI tray icon requires a logged-in desktop session — service \
                 mode runs the monitor only, with no UI.",
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
