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
mod beacon;
mod blocklist;
mod config;
mod entropy;
mod fswatch;
mod geoip;
mod logger;
mod longlived;
mod monitor;
mod notifier;
mod process;
mod registry;
mod revdns;
mod score;
mod service;
mod session;
mod tray;
mod types;
mod ui;

use config::Config;
use monitor::Monitor;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

fn main() {
    // ── CLI flags (service install / uninstall) ───────────────────────────────
    // We parse argv directly to avoid pulling in a CLI crate just for two
    // mutually-exclusive flags.  When either is passed we run the command
    // synchronously and exit — we never start the monitor or the GUI.
    let args: Vec<String> = std::env::args().collect();
    for a in &args[1..] {
        match a.as_str() {
            "--install-service" => {
                std::process::exit(service::run_cmd("install"));
            }
            "--uninstall-service" => {
                std::process::exit(service::run_cmd("uninstall"));
            }
            "--help" | "-h" => {
                println!(
                    "Vigil v{} — real-time network threat monitor\n\n\
                     Usage:  vigil [flags]\n\n\
                     Flags:\n  \
                     --install-service     register Vigil as a boot-time service\n  \
                     --uninstall-service   remove the boot-time service\n  \
                     -h, --help            show this help and exit\n\n\
                     Run with no flags to launch the GUI.",
                    env!("CARGO_PKG_VERSION"),
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }

    // ── Logging ───────────────────────────────────────────────────────────────
    // Must be first so all subsequent code can emit tracing events.
    let (_log_dir, _log_guard) = logger::init();
    let log_dir = _log_dir.clone();

    tracing::info!("Vigil v{} starting", env!("CARGO_PKG_VERSION"));
    tracing::info!("pre-login session: {}", session::is_pre_login());

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

    // ── Phase 10 services ─────────────────────────────────────────────────────
    // Each is a no-op when the relevant config entry is empty / disabled.
    {
        let c = cfg.read().unwrap();
        geoip::init(&c.geoip_city_db, &c.geoip_asn_db);
        blocklist::init(&c.blocklist_paths);
        if c.fswatch_enabled {
            fswatch::start();
        }
        if c.reverse_dns_enabled {
            revdns::start();
        }
        let (n_lists, n_entries) = blocklist::stats();
        tracing::info!(
            "Phase 10: geoip={}, blocklists={} ({} entries), fswatch={}, revdns={}",
            geoip::is_loaded(),
            n_lists,
            n_entries,
            c.fswatch_enabled,
            c.reverse_dns_enabled,
        );
    }

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

    // Keep the login-item / scheduled-task autostart entry aligned with the
    // current privilege level whenever autostart is enabled.
    {
        let c = cfg.read().unwrap();
        if c.autostart && !autostart::enable() {
            tracing::warn!("could not refresh autostart");
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
    let show_window = Arc::new(AtomicBool::new(false));
    let show_window_tray = show_window.clone();

    let pending_nav: Arc<std::sync::Mutex<Option<crate::types::ConnInfo>>> =
        Arc::new(std::sync::Mutex::new(None));
    let pending_nav_tray = pending_nav.clone();
    let pending_nav_ui = pending_nav.clone();

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
