//! Vigil — real-time network threat monitor.
//!
//! Phase 5: full egui GUI.
//!
//! # Threading model
//! eframe requires the **main thread** for the Win32 message pump and OpenGL
//! context.  We therefore build the tokio runtime manually on background
//! threads, spawn all async tasks into it, then hand the main thread to eframe.

// Suppress the console window in Windows release builds.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod autostart;
mod config;
mod logger;
mod monitor;
mod notifier;
mod process;
mod score;
mod tray;
mod types;
mod ui;

use config::Config;
use monitor::Monitor;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

fn main() {
    // ── Logging ───────────────────────────────────────────────────────────────
    // Must be first so all subsequent code can emit tracing events.
    let (_log_dir, _log_guard) = logger::init();
    let log_dir = _log_dir.clone();

    tracing::info!("Vigil v{} starting", env!("CARGO_PKG_VERSION"));

    // ── AUMID — correct taskbar / notification-centre identity ────────────────
    #[cfg(windows)]
    {
        use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
        unsafe {
            let _ = SetCurrentProcessExplicitAppUserModelID(windows::core::w!("Vigil.App.1"));
        }
    }

    // ── Tokio runtime on background threads ────────────────────────────────────
    // Main thread stays free for eframe / Win32 message pump.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    // Enter the runtime context so spawn_blocking inside Monitor::start() works.
    let _guard = rt.enter();

    // ── Config ────────────────────────────────────────────────────────────────
    let cfg = Arc::new(RwLock::new(Config::load()));

    // First-run: silently enable autostart
    {
        let mut w = cfg.write().unwrap();
        if !w.first_run_done {
            if autostart::enable() {
                w.autostart = true;
                tracing::info!("autostart enabled");
            } else {
                tracing::warn!("could not enable autostart");
            }
            w.first_run_done = true;
            w.save();
        }
    }

    // ── Monitor ───────────────────────────────────────────────────────────────
    let mon = Monitor::new(cfg.clone());
    let event_rx = mon.subscribe();
    // start() calls spawn_blocking — requires an active runtime context (_guard).
    let _mon_handle = mon.start();

    // ── Tray thread ───────────────────────────────────────────────────────────
    // `show_window`:  set by the tray thread when "Open Vigil" is clicked or
    //                 when the user clicks a notification; cleared by VigilApp.
    // `pending_nav`:  filled with the ConnInfo from a clicked notification so
    //                 the UI can switch to Alerts and select the right row.
    let show_window  = Arc::new(AtomicBool::new(false));
    let show_window_tray = show_window.clone();

    let pending_nav: Arc<std::sync::Mutex<Option<crate::types::ConnInfo>>> =
        Arc::new(std::sync::Mutex::new(None));
    let pending_nav_tray = pending_nav.clone();
    let pending_nav_ui   = pending_nav.clone();

    let (tray_tx, tray_rx) = std::sync::mpsc::sync_channel::<tray::TrayCmd>(64);

    std::thread::Builder::new()
        .name("vigil-tray".into())
        .spawn(move || tray::run(tray_rx, show_window_tray, log_dir, pending_nav_tray))
        .expect("failed to spawn tray thread");

    // ── eframe (takes the main thread) ───────────────────────────────────────
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Vigil")
            .with_inner_size([1080.0, 680.0])
            .with_min_inner_size([700.0, 440.0]),
        persist_window: true, // saves/restores size & position via eframe storage
        ..Default::default()
    };

    let cfg_ui = cfg.clone();

    eframe::run_native(
        "Vigil",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(ui::VigilApp::new(
                cc,
                cfg_ui,
                event_rx,
                tray_tx,
                show_window,
                pending_nav_ui,
            )))
        }),
    )
    .expect("eframe failed");
}
