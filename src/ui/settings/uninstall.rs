use super::{section_header, setting_row, SettingsDraft};
use crate::ui::theme;
use egui::RichText;

pub(super) fn show_section(ui: &mut egui::Ui, draft: &mut SettingsDraft, label_w: f32) {
    ui.add_space(16.0);
    section_header(ui, "Uninstall");
    ui.label(
        RichText::new(
            "Remove Vigil from startup/service registration and close this running instance. This does not delete evidence, logs, or exported artifacts from disk.",
        )
        .color(theme::TEXT2)
        .size(12.0),
    );
    ui.add_space(8.0);
    setting_row(ui, label_w, "Uninstall Vigil", |ui| {
        ui.vertical(|ui| {
            let uninstall = ui
                .add(
                    egui::Button::new(
                        RichText::new("Uninstall Vigil")
                            .color(theme::DANGER)
                            .size(11.5),
                    )
                    .fill(theme::DANGER_BG)
                    .stroke(egui::Stroke::new(1.0, theme::DANGER))
                    .corner_radius(6.0),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(
                    "Ask for confirmation before uninstalling Vigil and closing the app.",
                );
            if uninstall.clicked() {
                draft.uninstall_confirm_requested = true;
            }
            ui.add_space(2.0);
            ui.label(
                RichText::new(
                    "Requires Admin Mode when service or elevated startup entries are installed.",
                )
                .color(theme::TEXT3)
                .size(10.2),
            );
        });
    });
    if draft.uninstall_confirm_requested {
        egui::Frame::NONE
            .fill(theme::DANGER_BG)
            .stroke(egui::Stroke::new(1.0, theme::DANGER))
            .corner_radius(10.0)
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Confirm uninstall? Vigil will disable its login/startup registration, remove the OS service/daemon when present, and then close.",
                    )
                    .color(theme::TEXT)
                    .size(11.5),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Yes, uninstall and close")
                                    .color(theme::DANGER)
                                    .size(11.0),
                            )
                            .fill(theme::SURFACE2)
                            .stroke(egui::Stroke::new(1.0, theme::DANGER))
                            .corner_radius(6.0),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        draft.uninstall_requested = true;
                        draft.uninstall_confirm_requested = false;
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Cancel")
                                    .color(theme::TEXT2)
                                    .size(11.0),
                            )
                            .fill(theme::SURFACE3)
                            .stroke(egui::Stroke::new(1.0, theme::BORDER))
                            .corner_radius(6.0),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        draft.uninstall_confirm_requested = false;
                    }
                });
            });
    }
}
