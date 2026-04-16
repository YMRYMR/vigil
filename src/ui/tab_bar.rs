//! Custom tab-strip widget.
//!
//! Draws a horizontal row of tab labels.  The active tab gets a 2 px
//! ACCENT underline instead of any box chrome.  Click a tab to switch.

use crate::ui::theme;
use egui::{Color32, RichText, Ui};

// ── Tab enum ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Activity,
    Alerts,
    Settings,
    Help,
}

impl Tab {
    /// Human-readable label, optionally with a badge count for Alerts.
    pub fn label(self, unseen: usize) -> String {
        match self {
            Tab::Activity => "Activity".into(),
            Tab::Alerts => {
                if unseen > 0 {
                    format!("Alerts  ({unseen})")
                } else {
                    "Alerts".into()
                }
            }
            Tab::Settings => "Settings".into(),
            Tab::Help => "Help".into(),
        }
    }
}

// ── Widget ────────────────────────────────────────────────────────────────────

/// Draw the tab bar and return the newly-active tab (same as `active` if
/// no tab was clicked).
pub fn tab_bar(ui: &mut Ui, active: Tab, unseen_alerts: usize) -> Tab {
    let all = [Tab::Activity, Tab::Alerts, Tab::Settings, Tab::Help];
    let mut result = active;

    // Separator line across the full width (drawn under the tabs)
    let full_rect = ui.available_rect_before_wrap();
    ui.painter().hline(
        full_rect.x_range(),
        full_rect.max.y - 1.0,
        egui::Stroke::new(1.0, theme::BORDER),
    );

    ui.horizontal(|ui| {
        ui.add_space(12.0);

        for tab in all {
            let is_active = tab == active;
            let badge_count = if tab == Tab::Alerts { unseen_alerts } else { 0 };
            let label_str = tab.label(badge_count);

            let text_color = if is_active {
                theme::TEXT
            } else {
                theme::TEXT2
            };
            let text = RichText::new(&label_str).color(text_color).size(12.0);

            let btn = egui::Button::new(text)
                .fill(Color32::TRANSPARENT)
                .stroke(egui::Stroke::NONE)
                .corner_radius(0.0)
                .min_size(egui::vec2(0.0, 30.0));

            let resp = ui.add(btn);

            // 2 px ACCENT underline for the active tab
            if is_active {
                let r = resp.rect;
                let y = r.max.y - 0.0; // flush with bottom of panel
                ui.painter().line_segment(
                    [egui::pos2(r.min.x, y), egui::pos2(r.max.x, y)],
                    egui::Stroke::new(2.0, theme::ACCENT),
                );
            }

            if resp.clicked() {
                result = tab;
            }

            ui.add_space(4.0);
        }
    });

    result
}
