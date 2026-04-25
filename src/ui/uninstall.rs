use super::{NotificationKind, VigilApp};

pub(super) fn execute_from_settings(app: &mut VigilApp) {
    let autostart_removed = crate::autostart::disable();

    // Persist the user's uninstall intent before exiting. Otherwise a later
    // manual launch would reload `autostart = true` and re-enable login
    // startup during bootstrap.
    {
        let mut cfg = app.cfg.write().unwrap();
        if cfg.autostart {
            cfg.autostart = false;
            cfg.save();
        }
    }
    app.settings.autostart = false;

    match crate::service::uninstall() {
        Ok(service_msg) => {
            crate::audit::record(
                "settings_uninstall",
                "success",
                serde_json::json!({
                    "autostart_removed": autostart_removed,
                    "service_message": service_msg,
                }),
            );
            std::process::exit(0);
        }
        Err(err) => {
            crate::audit::record(
                "settings_uninstall",
                "failure",
                serde_json::json!({
                    "autostart_removed": autostart_removed,
                    "error": &err,
                }),
            );
            app.settings.status_msg = Some((
                format!("Uninstall failed: {err}"),
                std::time::Instant::now(),
            ));
            app.push_notification(NotificationKind::Error, format!("Uninstall failed: {err}"));
        }
    }
}
