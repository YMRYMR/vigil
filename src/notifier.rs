//! Desktop notification helper.
//!
//! `send_alert` fires an OS toast notification and wires up a click callback
//! that, when the user clicks the notification, will:
//!   1. set `show_window = true`  (tells the UI to un-hide the window)
//!   2. set `pending_nav = Some(info)` (tells the UI which alert to select)
//!
//! Platform strategy
//! -----------------
//! Windows  — WinRT `ToastNotification` (via the `windows` crate) is preferred
//!            because it supports the `Activated` click callback.
//!            If WinRT fails (most commonly because the AUMID `Vigil.App.1`
//!            isn't registered to a Start Menu shortcut — e.g. when running
//!            `target/debug/vigil.exe` directly rather than the installed
//!            build), we fall back to `notify-rust` so the user still sees the
//!            notification (without the click-to-navigate behaviour).
//!
//! macOS / Linux — `notify-rust` for a lightweight toast. We keep the call
//!                 fire-and-forget so the caller is never blocked.

use crate::types::ConnInfo;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// Fire a notification for `info`.  Clicking the notification will signal
/// `show_window` and fill `pending_nav` so the UI can navigate.
pub fn send_alert(
    info: &ConnInfo,
    show_window: Arc<AtomicBool>,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    platform::send(info, show_window, pending_nav);
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::*;
    use std::sync::atomic::Ordering;
    use windows::{
        Data::Xml::Dom::XmlDocument,
        Foundation::TypedEventHandler,
        UI::Notifications::{ToastNotification, ToastNotificationManager},
    };

    pub fn send(
        info: &ConnInfo,
        show_window: Arc<AtomicBool>,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
    ) {
        let xml = build_xml(info);

        let result = (|| -> windows::core::Result<()> {
            let aumid = &windows::core::HSTRING::from("Vigil.App.1");
            let notifier = ToastNotificationManager::CreateToastNotifierWithId(aumid)?;

            let doc = XmlDocument::new()?;
            doc.LoadXml(&windows::core::HSTRING::from(xml.as_str()))?;

            let toast = ToastNotification::CreateToastNotification(&doc)?;

            // Wire the click callback.
            let nav_info = info.clone();
            toast.Activated(&TypedEventHandler::new(move |_, _| {
                *pending_nav.lock().unwrap() = Some(nav_info.clone());
                show_window.store(true, Ordering::Relaxed);
                Ok(())
            }))?;

            notifier.Show(&toast)?;
            Ok(())
        })();

        if let Err(e) = result {
            tracing::warn!(
                "WinRT toast failed ({e}); falling back to notify-rust \
                 (click-to-navigate will be unavailable for this notification)"
            );
            fallback_notify_rust(info);
        }
    }

    /// Basic `notify-rust` fallback used when WinRT refuses to show the toast.
    /// Unlike macOS/Linux, the Windows backend of `notify-rust` does not
    /// support `wait_for_action`, so we only surface the alert text — the
    /// click-to-navigate wiring is lost for that one notification.
    fn fallback_notify_rust(info: &ConnInfo) {
        let body = format!(
            "{} \u{2192} {}   score: {}\n{}",
            info.proc_name,
            info.remote_addr,
            info.score,
            info.reasons.first().map(|r| r.as_str()).unwrap_or(""),
        );
        if let Err(e) = notify_rust::Notification::new()
            .summary("\u{26A0}  Vigil \u{2014} Threat Detected")
            .body(&body)
            .show()
        {
            tracing::warn!("notify-rust fallback also failed: {e}");
        }
    }

    fn build_xml(info: &ConnInfo) -> String {
        let title = "⚠  Vigil — Threat Detected";
        let line1 = xml_escape(&format!(
            "{} → {}   score: {}",
            info.proc_name, info.remote_addr, info.score,
        ));
        let line2 = xml_escape(info.reasons.first().map(|r| r.as_str()).unwrap_or(""));
        format!(
            r#"<toast><visual><binding template="ToastGeneric"><text>{title}</text><text>{line1}</text><text>{line2}</text></binding></visual></toast>"#
        )
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}

// ── macOS / Linux ─────────────────────────────────────────────────────────────

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub fn send(
        info: &ConnInfo,
        _show_window: Arc<AtomicBool>,
        _pending_nav: Arc<Mutex<Option<ConnInfo>>>,
    ) {
        let body = format!(
            "{} → {}   score: {}\n{}",
            info.proc_name,
            info.remote_addr,
            info.score,
            info.reasons.first().map(|r| r.as_str()).unwrap_or(""),
        );

        if let Err(e) = notify_rust::Notification::new()
            .summary("⚠  Vigil — Threat Detected")
            .body(&body)
            .show()
        {
            tracing::warn!("notify-rust failed: {e}");
        }
    }
}
