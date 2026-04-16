//! Desktop notification helper.
//!
//! `send_alert` fires an OS toast notification and wires up a click callback
//! that, when the user clicks the notification, will:
//!   1. set `show_window = true`  (tells the UI to un-hide the window)
//!   2. set `pending_nav = Some(info)` (tells the UI which alert to select)
//!
//! Platform strategy
//! -----------------
//! Windows  — WinRT `ToastNotification` (via the `windows` crate).
//!            The `Activated` event fires on a WinRT thread-pool thread.
//!            We avoid `notify-rust` here because its Windows backend returns
//!            `show() -> Result<()>` with no handle or callback support.
//!
//! macOS / Linux — `notify-rust` which returns a handle with
//!                 `wait_for_action(closure)`.  A background thread waits on it
//!                 so the caller is never blocked.

use crate::types::ConnInfo;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Fire a notification for `info`.  Clicking the notification will signal
/// `show_window` and fill `pending_nav` so the UI can navigate.
pub fn send_alert(
    info:        &ConnInfo,
    show_window: Arc<AtomicBool>,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    platform::send(info, show_window, pending_nav);
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::*;
    use windows::{
        Data::Xml::Dom::XmlDocument,
        Foundation::TypedEventHandler,
        UI::Notifications::{ToastNotification, ToastNotificationManager},
    };

    pub fn send(
        info:        &ConnInfo,
        show_window: Arc<AtomicBool>,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
    ) {
        let xml = build_xml(info);

        let result = (|| -> windows::core::Result<()> {
            let aumid    = &windows::core::HSTRING::from("Vigil.App.1");
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
            tracing::warn!("toast notification failed: {e}");
        }
    }

    fn build_xml(info: &ConnInfo) -> String {
        let title  = "⚠  Vigil — Threat Detected";
        let line1  = xml_escape(&format!(
            "{} → {}   score: {}",
            info.proc_name, info.remote_addr, info.score,
        ));
        let line2  = xml_escape(
            info.reasons.first().map(|r| r.as_str()).unwrap_or(""),
        );
        format!(
            r#"<toast><visual><binding template="ToastGeneric"><text>{title}</text><text>{line1}</text><text>{line2}</text></binding></visual></toast>"#
        )
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&',  "&amp;")
         .replace('<',  "&lt;")
         .replace('>',  "&gt;")
         .replace('"',  "&quot;")
         .replace('\'', "&apos;")
    }
}

// ── macOS / Linux ─────────────────────────────────────────────────────────────

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub fn send(
        info:        &ConnInfo,
        show_window: Arc<AtomicBool>,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
    ) {
        let body = format!(
            "{} → {}   score: {}\n{}",
            info.proc_name,
            info.remote_addr,
            info.score,
            info.reasons.first().map(|r| r.as_str()).unwrap_or(""),
        );

        let handle = notify_rust::Notification::new()
            .summary("⚠  Vigil — Threat Detected")
            .body(&body)
            .show();

        if let Ok(handle) = handle {
            let nav_info = info.clone();
            // `wait_for_action` blocks until the notification is dismissed or
            // clicked, so run it on a background thread.
            std::thread::spawn(move || {
                handle.wait_for_action(move |action| {
                    // "__closed" = dismissed without clicking.
                    if action != "__closed" {
                        *pending_nav.lock().unwrap() = Some(nav_info);
                        show_window.store(true, Ordering::Relaxed);
                    }
                });
            });
        }
    }
}
