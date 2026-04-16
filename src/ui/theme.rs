//! Dark-theme constants and egui Visuals initialisation.

use egui::{Color32, FontFamily, FontId, TextStyle};

// ── Palette ───────────────────────────────────────────────────────────────────

pub const BG: Color32 = Color32::from_rgb(0x14, 0x15, 0x1A);
pub const SURFACE: Color32 = Color32::from_rgb(0x1C, 0x1D, 0x24);
pub const SURFACE2: Color32 = Color32::from_rgb(0x25, 0x26, 0x30);
pub const SURFACE3: Color32 = Color32::from_rgb(0x2E, 0x30, 0x40);
pub const TEXT: Color32 = Color32::from_rgb(0xE2, 0xE4, 0xEA);
pub const TEXT2: Color32 = Color32::from_rgb(0x8A, 0x8D, 0x9A);
pub const TEXT3: Color32 = Color32::from_rgb(0x4A, 0x4D, 0x5C);
pub const ACCENT: Color32 = Color32::from_rgb(0x22, 0xC5, 0x5E);
pub const WARN: Color32 = Color32::from_rgb(0xF5, 0x9E, 0x0B);
pub const DANGER: Color32 = Color32::from_rgb(0xEF, 0x44, 0x44);
pub const BORDER: Color32 = Color32::from_rgb(0x2A, 0x2C, 0x38);

pub const DANGER_BG: Color32 = Color32::from_rgb(0x1E, 0x08, 0x08);
pub const WARN_BG: Color32 = Color32::from_rgb(0x21, 0x18, 0x04);
pub const ACCENT_BG: Color32 = Color32::from_rgb(0x0F, 0x23, 0x18);

// ── Score helpers ─────────────────────────────────────────────────────────────

pub fn score_colors(score: u8) -> (Color32, Color32) {
    if score >= 5 {
        (DANGER, DANGER_BG)
    } else if score >= 3 {
        (WARN, WARN_BG)
    } else {
        (ACCENT, ACCENT_BG)
    }
}

// ── Apply ─────────────────────────────────────────────────────────────────────

fn cr(n: u8) -> egui::CornerRadius {
    egui::CornerRadius::same(n)
}

/// Apply the Vigil dark theme to the given egui context.
pub fn apply(ctx: &egui::Context) {
    let mut vis = egui::Visuals::dark();

    vis.override_text_color = Some(TEXT);
    vis.window_fill = BG;
    vis.panel_fill = BG;
    vis.extreme_bg_color = SURFACE;
    vis.faint_bg_color = SURFACE2;
    vis.code_bg_color = SURFACE2;
    vis.window_stroke = egui::Stroke::new(1.0, BORDER);

    // Widget states
    vis.widgets.noninteractive.bg_fill = SURFACE;
    vis.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    vis.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT2);
    vis.widgets.noninteractive.corner_radius = cr(4);

    vis.widgets.inactive.bg_fill = SURFACE2;
    vis.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    vis.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT2);
    vis.widgets.inactive.corner_radius = cr(4);

    vis.widgets.hovered.bg_fill = SURFACE3;
    vis.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, BORDER);
    vis.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT);
    vis.widgets.hovered.corner_radius = cr(4);

    vis.widgets.active.bg_fill = SURFACE3;
    vis.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    vis.widgets.active.fg_stroke = egui::Stroke::new(1.0, ACCENT);
    vis.widgets.active.corner_radius = cr(4);

    vis.widgets.open.bg_fill = SURFACE3;
    vis.widgets.open.bg_stroke = egui::Stroke::new(1.0, BORDER);
    vis.widgets.open.fg_stroke = egui::Stroke::new(1.0, TEXT);
    vis.widgets.open.corner_radius = cr(4);

    vis.selection.bg_fill = Color32::from_rgba_unmultiplied(0x22, 0xC5, 0x5E, 0x35);
    vis.selection.stroke = egui::Stroke::new(1.0, ACCENT);

    vis.window_shadow = egui::epaint::Shadow::NONE;
    vis.popup_shadow = egui::epaint::Shadow::NONE;

    ctx.set_visuals(vis);

    let mut style = (*ctx.global_style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(12.0, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(11.5, FontFamily::Monospace)),
        (TextStyle::Button, FontId::new(12.0, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(10.5, FontFamily::Proportional)),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(6.0, 3.0);
    style.spacing.button_padding = egui::vec2(8.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(12);
    ctx.set_global_style(style);
}
