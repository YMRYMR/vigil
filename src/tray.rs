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
//! - `Alert(ConnInfo)` — display a notification, switch icon to ⚠
//! - `ResetOk`         — switch icon back to the normal ● state
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
pub enum TrayCmd {
    /// A new threat alert — show a notification and update the icon.
    Alert(ConnInfo),
    /// Return the icon to the normal "monitoring" state.
    ResetOk,
}

// ── Icon generation ───────────────────────────────────────────────────────────

fn make_circle_icon(r: u8, g: u8, b: u8) -> tray_icon::Icon {
    const SIZE:   u32 = 32;
    const CENTER: f32 = 15.5;
    const RADIUS: f32 = 13.0;
    const INNER:  f32 = 11.0;

    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx  = x as f32 - CENTER;
            let dy  = y as f32 - CENTER;
            let d   = (dx * dx + dy * dy).sqrt();
            let idx = ((y * SIZE + x) * 4) as usize;
            if d <= RADIUS {
                let boost = if d <= INNER { 40u8 } else { 0u8 };
                rgba[idx]     = r.saturating_add(boost);
                rgba[idx + 1] = g.saturating_add(boost);
                rgba[idx + 2] = b.saturating_add(boost);
                rgba[idx + 3] = 255;
            }
        }
    }
    tray_icon::Icon::from_rgba(rgba, SIZE, SIZE)
        .expect("hardcoded icon dimensions are valid")
}

// ── Public entry point ────────────────────────────────────────────────────────

struct TrayIcons {
    ok:    tray_icon::Icon,
    alert: tray_icon::Icon,
}

/// Build the tray icon and run the event loop.
///
/// - `cmd_rx`      — receives `TrayCmd` messages from the UI/monitor
/// - `show_window` — set to `true` when "Open Vigil" is clicked (menu or
///                   notification click); cleared by the UI each frame
/// - `log_dir`     — path opened when "Open Logs Folder" is clicked
/// - `pending_nav` — filled with the clicked `ConnInfo` so the UI can navigate
pub fn run(
    cmd_rx:      Receiver<TrayCmd>,
    show_window: Arc<AtomicBool>,
    log_dir:     PathBuf,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    let icons = TrayIcons {
        ok:    make_circle_icon(0x22, 0xC5, 0x5E),
        alert: make_circle_icon(0xF5, 0x9E, 0x0B),
    };

    // ── Context menu ──────────────────────────────────────────────────────────
    let menu      = Menu::new();
    let open_item = MenuItem::new("Open Vigil",       true, None);
    let logs_item = MenuItem::new("Open Logs Folder", true, None);
    let quit_item = MenuItem::new("Quit",              true, None);
    let _ = menu.append_items(&[
        &open_item,
        &logs_item,
        &PredefinedMenuItem::separator(),
        &quit_item,
    ]);
    let open_id = open_item.id().clone();
    let logs_id = logs_item.id().clone();
    let quit_id = quit_item.id().clone();

    // ── Tray icon ─────────────────────────────────────────────────────────────
    // menu_on_left_click = false → left click fires TrayIconEvent (we open the
    // window ourselves); right click still shows the context menu.
    let tray = TrayIconBuilder::new()
        .with_tooltip("Vigil — Network Monitor  ●")
        .with_icon(icons.ok.clone())
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .build()
        .expect("Failed to create tray icon");

    event_loop(tray, icons, cmd_rx, quit_id, open_id, logs_id, log_dir, show_window, pending_nav);
}

// ── Platform event loops ──────────────────────────────────────────────────────

#[cfg(windows)]
fn event_loop(
    tray:        TrayIcon,
    icons:       TrayIcons,
    cmd_rx:      Receiver<TrayCmd>,
    quit_id:     tray_icon::menu::MenuId,
    open_id:     tray_icon::menu::MenuId,
    logs_id:     tray_icon::menu::MenuId,
    log_dir:     PathBuf,
    show_window: Arc<AtomicBool>,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };

    let mut msg      = MSG::default();
    let mut in_alert = false;

    loop {
        // Drain Win32 messages without blocking.
        unsafe {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == 0x0012 { return; } // WM_QUIT
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        // ── Tray icon click events ────────────────────────────────────────────
        // Left-click → open window directly (menu_on_left_click is false).
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
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
                    if !in_alert {
                        let _ = tray.set_icon(Some(icons.alert.clone()));
                        let _ = tray.set_tooltip(Some("Vigil — ⚠ Threat detected"));
                        in_alert = true;
                    }
                }
                TrayCmd::ResetOk => {
                    if in_alert {
                        let _ = tray.set_icon(Some(icons.ok.clone()));
                        let _ = tray.set_tooltip(Some("Vigil — Network Monitor  ●"));
                        in_alert = false;
                    }
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(not(windows))]
fn event_loop(
    _tray:       TrayIcon,
    _icons:      TrayIcons,
    cmd_rx:      Receiver<TrayCmd>,
    _quit_id:    tray_icon::menu::MenuId,
    _open_id:    tray_icon::menu::MenuId,
    _logs_id:    tray_icon::menu::MenuId,
    _log_dir:    PathBuf,
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
            }
        }
        let _ = show_window.load(Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
