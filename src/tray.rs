//! System tray icon, context menu, and event loop.
//!
//! # Threading
//! `run()` is designed to be called on a **dedicated OS thread** (not the
//! tokio runtime thread).  On Windows it drives a Win32 message pump; the
//! tray-icon crate requires that the message pump runs on the same thread
//! that created the `TrayIcon`.
//!
//! # Commands
//! The caller forwards `TrayCmd` values over a `std::sync::mpsc` channel:
//! - `Alert(Box<ConnInfo>)` — display a notification, switch icon to ⚠
//! - `ResetOk`         — switch icon back to the normal ● state
//! - `SetLockdown(bool)` — force red icon while network isolation is active
//!
//! `show_window` is an `Arc<AtomicBool>` set to `true` when the user clicks
//! "Open Vigil" in the tray menu *or* clicks a notification.
//!
//! `pending_nav` carries the `ConnInfo` of a clicked notification so the UI
//! can switch to the Alerts tab and select the matching row.

use crate::types::ConnInfo;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Receiver, Arc, Mutex};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
};

/// Commands sent from the monitor / UI to the tray thread.
#[allow(clippy::large_enum_variant)]
pub enum TrayCmd {
    /// A new threat alert — show a notification and update the icon.
    Alert(Box<ConnInfo>),
    /// Return the icon to the normal "monitoring" state.
    ResetOk,
    /// Toggle lockdown visual state (network isolation).
    SetLockdown(bool),
}

// ── Icon generation ───────────────────────────────────────────────────────────

const TRAY_GREEN_ICO: &[u8] = include_bytes!("../assets/vigil_tray_green.ico");
const TRAY_ORANGE_ICO: &[u8] = include_bytes!("../assets/vigil_tray_orange.ico");
const TRAY_RED_ICO: &[u8] = include_bytes!("../assets/vigil_tray_red.ico");

fn make_circle_icon(r: u8, g: u8, b: u8) -> tray_icon::Icon {
    const SIZE: u32 = 32;
    const CENTER: f32 = 15.5;
    const RADIUS: f32 = 13.0;
    const INNER: f32 = 11.0;

    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - CENTER;
            let dy = y as f32 - CENTER;
            let d = (dx * dx + dy * dy).sqrt();
            let idx = ((y * SIZE + x) * 4) as usize;
            if d <= RADIUS {
                let boost = if d <= INNER { 40u8 } else { 0u8 };
                rgba[idx] = r.saturating_add(boost);
                rgba[idx + 1] = g.saturating_add(boost);
                rgba[idx + 2] = b.saturating_add(boost);
                rgba[idx + 3] = 255;
            }
        }
    }
    tray_icon::Icon::from_rgba(rgba, SIZE, SIZE).expect("hardcoded icon dimensions are valid")
}

fn icon_from_embedded_ico(label: &str, bytes: &[u8]) -> Option<tray_icon::Icon> {
    let image = match image::load_from_memory_with_format(bytes, image::ImageFormat::Ico) {
        Ok(image) => image,
        Err(err) => {
            tracing::warn!("failed to decode embedded tray icon {label}: {err}");
            return None;
        }
    };
    let image = image.into_rgba8();
    let (w, h) = (image.width(), image.height());
    match tray_icon::Icon::from_rgba(image.into_raw(), w, h) {
        Ok(icon) => Some(icon),
        Err(err) => {
            tracing::warn!("failed to build tray icon {label} from decoded bitmap: {err}");
            None
        }
    }
}

fn load_tray_icons() -> TrayIcons {
    TrayIcons {
        ok: icon_from_embedded_ico("green", TRAY_GREEN_ICO)
            .unwrap_or_else(|| make_circle_icon(0x22, 0xC5, 0x5E)),
        alert: icon_from_embedded_ico("orange", TRAY_ORANGE_ICO)
            .unwrap_or_else(|| make_circle_icon(0xF5, 0x9E, 0x0B)),
        lockdown: icon_from_embedded_ico("red", TRAY_RED_ICO)
            .unwrap_or_else(|| make_circle_icon(0xEF, 0x44, 0x44)),
    }
}

fn apply_tray_visual_state(tray: &TrayIcon, icons: &TrayIcons, in_alert: bool, in_lockdown: bool) {
    if in_lockdown {
        let _ = tray.set_icon(Some(icons.lockdown.clone()));
        let _ = tray.set_tooltip(Some("Vigil — Lockdown active"));
    } else if in_alert {
        let _ = tray.set_icon(Some(icons.alert.clone()));
        let _ = tray.set_tooltip(Some("Vigil — ⚠ Threat detected"));
    } else {
        let _ = tray.set_icon(Some(icons.ok.clone()));
        let _ = tray.set_tooltip(Some("Vigil — Monitoring"));
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

struct TrayIcons {
    ok: tray_icon::Icon,
    alert: tray_icon::Icon,
    lockdown: tray_icon::Icon,
}

/// Build the tray icon and run the event loop.
///
/// - `cmd_rx`      — receives `TrayCmd` messages from the UI/monitor
/// - `show_window` — set to `true` when "Open Vigil" is clicked (menu or
///   notification click); cleared by the UI each frame
/// - `log_dir`     — path opened when "Open Logs Folder" is clicked
/// - `pending_nav` — filled with the clicked `ConnInfo` so the UI can navigate
pub fn run(
    cmd_rx: Receiver<TrayCmd>,
    show_window: Arc<AtomicBool>,
    log_dir: PathBuf,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    let icons = load_tray_icons();

    // On non-Windows, the tray-icon crate uses GTK which requires a working
    // display. Running under sudo or without a desktop session means GTK
    // can't connect. Skip the entire GTK init to avoid panics and C-level
    // warning spam on stderr.
    #[cfg(not(windows))]
    {
        let has_display = std::env::var("DISPLAY").is_ok()
            || std::env::var("WAYLAND_DISPLAY").is_ok();
        let is_root = unsafe { libc::geteuid() == 0 };
        if !has_display || is_root {
            tracing::info!("system tray skipped ({}{})", if is_root { "running as root" } else { "no display" }, if !has_display { "" } else { " — display auth may fail" });
            notification_only_loop(cmd_rx, show_window, pending_nav);
            return;
        }
    }
    let init_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // GTK must be initialized before any GTK operations (menu, tray icon).
        // The tray-icon crate on Linux uses libappindicator which depends on GTK.
        #[cfg(not(windows))]
        {
            if gtk::init().is_err() {
                return Err("GTK init failed — tray icon unavailable".into());
            }
        }

        // ── Context menu ──────────────────────────────────────────────────
        let menu = Menu::new();
        let open_item = MenuItem::new("Open Vigil", true, None);
        let logs_item = MenuItem::new("Open Logs Folder", true, None);
        let quit_item = MenuItem::new("Quit", true, None);
        let _ = menu.append_items(&[
            &open_item,
            &logs_item,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ]);
        let open_id = open_item.id().clone();
        let logs_id = logs_item.id().clone();
        let quit_id = quit_item.id().clone();

        tracing::info!("tray: building tray icon...");
        let tray = TrayIconBuilder::new()
            .with_tooltip("Vigil — Network Monitor  ●")
            .with_icon(icons.ok.clone())
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .build()?;

        Ok::<(TrayIcon, tray_icon::menu::MenuId, tray_icon::menu::MenuId, tray_icon::menu::MenuId), Box<dyn std::error::Error>>((
            tray, quit_id, open_id, logs_id,
        ))
    }));

    match init_result {
        Ok(Ok((tray, quit_id, open_id, logs_id))) => {
            event_loop(
                tray,
                icons,
                cmd_rx,
                quit_id,
                open_id,
                logs_id,
                log_dir,
                show_window,
                pending_nav,
            );
        }
        _ => {
            tracing::warn!("system tray unavailable — running without tray icon");
            notification_only_loop(cmd_rx, show_window, pending_nav);
        }
    }
}

fn notification_only_loop(
    cmd_rx: Receiver<TrayCmd>,
    show_window: Arc<AtomicBool>,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                TrayCmd::Alert(info) => {
                    crate::notifier::send_alert(
                        &info,
                        show_window.clone(),
                        pending_nav.clone(),
                    );
                }
                TrayCmd::ResetOk | TrayCmd::SetLockdown(_) => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

// ── Platform event loops ──────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn event_loop(
    tray: TrayIcon,
    icons: TrayIcons,
    cmd_rx: Receiver<TrayCmd>,
    quit_id: tray_icon::menu::MenuId,
    open_id: tray_icon::menu::MenuId,
    logs_id: tray_icon::menu::MenuId,
    log_dir: PathBuf,
    show_window: Arc<AtomicBool>,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };

    let mut msg = MSG::default();
    let mut in_alert = false;
    let mut in_lockdown = false;

    loop {
        // Drain Win32 messages without blocking.
        unsafe {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == 0x0012 {
                    return;
                } // WM_QUIT
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        // ── Tray icon click events ────────────────────────────────────────────
        // Left-click → open window directly (menu_on_left_click is false).
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = ev
            {
                show_window.store(true, Ordering::Relaxed);
            }
        }

        // ── Menu events ───────────────────────────────────────────────────────
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == quit_id {
                std::process::exit(0);
            } else if ev.id == open_id {
                show_window.store(true, Ordering::Relaxed);
            } else if ev.id == logs_id {
                let _ = open::that(&log_dir);
            }
        }

        // ── Commands from UI / monitor ────────────────────────────────────────
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                TrayCmd::Alert(info) => {
                    crate::notifier::send_alert(&info, show_window.clone(), pending_nav.clone());
                    in_alert = true;
                    apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                }
                TrayCmd::ResetOk => {
                    in_alert = false;
                    apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                }
                TrayCmd::SetLockdown(active) => {
                    in_lockdown = active;
                    apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(not(windows))]
#[allow(clippy::too_many_arguments)]
fn event_loop(
    _tray: TrayIcon,
    _icons: TrayIcons,
    cmd_rx: Receiver<TrayCmd>,
    _quit_id: tray_icon::menu::MenuId,
    _open_id: tray_icon::menu::MenuId,
    _logs_id: tray_icon::menu::MenuId,
    _log_dir: PathBuf,
    show_window: Arc<AtomicBool>,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                TrayCmd::Alert(info) => {
                    crate::notifier::send_alert(&info, show_window.clone(), pending_nav.clone());
                }
                TrayCmd::ResetOk => {}
                TrayCmd::SetLockdown(_) => {}
            }
        }
        let _ = show_window.load(Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_tray_icons_decode() {
        assert!(icon_from_embedded_ico("green-test", TRAY_GREEN_ICO).is_some());
        assert!(icon_from_embedded_ico("orange-test", TRAY_ORANGE_ICO).is_some());
        assert!(icon_from_embedded_ico("red-test", TRAY_RED_ICO).is_some());
    }
}
