//! Vigil — real-time network threat monitor.
//!
//! Phase 5: full egui GUI.
//!
//! # Threading model
//! eframe requires the **main thread** for the Win32 message pump and OpenGL
//! context.  We therefore build the tokio runtime manually on background
//! threads, spawn all async tasks into it, then hand the main thread to eframe.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod artifact_provenance;
mod advisory;
mod audit;
mod baseline;
mod beacon;
mod blocklist;
mod config;
mod detection_depth;
mod entropy;
mod forensics;
mod fswatch;
mod geoip;
mod honeypot;
mod logger;
mod longlived;
mod monitor;
mod notifier;
mod pcap;
mod platform;
mod process;
mod revdns;
mod score;
mod security;
mod session;
mod startup_integrity;
mod tls;
mod tls_artifacts;
mod types;
mod ui;

pub use platform::{autostart, break_glass, service, tray};
pub use security::{
    active_response, auto_response, quarantine, registry, response_rules, tamper, update,
};

use config::Config;
use monitor::Monitor;
use single_instance::SingleInstance;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const SINGLE_INSTANCE_ID: &str = "com.ymrymr.vigil.single_instance";
fn load_app_icon() -> Option<egui::IconData> {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/vigil_icon.png"))
        .or_else(|_| eframe::icon_data::from_png_bytes(include_bytes!("../assets/vigil.png")))
        .map_err(|err| {
            tracing::warn!("could not decode app icon PNG: {err}");
            err
        })
        .ok()
}

fn acquire_single_instance(wait_for_release: bool) -> Result<SingleInstance, String> {
    if !wait_for_release {
        return SingleInstance::new(SINGLE_INSTANCE_ID)
            .map_err(|err| format!("Could not acquire Vigil instance lock: {err}"));
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(12);
    let sleep_interval = Duration::from_millis(150);
    loop {
        let guard = SingleInstance::new(SINGLE_INSTANCE_ID)
            .map_err(|err| format!("Could not acquire Vigil instance lock: {err}"))?;
        if guard.is_single() {
            return Ok(guard);
        }
        if start.elapsed() >= timeout {
            return Err("Another Vigil instance is still running after elevation handoff.".into());
        }
        drop(guard);
        std::thread::sleep(sleep_interval);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if let Some(idx) = args.iter().position(|a| a == "--verify-update-manifest") {
        let manifest = args.get(idx + 1).unwrap_or_else(|| {
            eprintln!(
                "Missing manifest path.\n\nUsage: vigil --verify-update-manifest MANIFEST.json MANIFEST.json.sig"
            );
            std::process::exit(1);
        });
        let signature = args.get(idx + 2).unwrap_or_else(|| {
            eprintln!(
                "Missing signature path.\n\nUsage: vigil --verify-update-manifest MANIFEST.json MANIFEST.json.sig"
            );
            std::process::exit(1);
        });
        match update::run_cli(Path::new(manifest), Path::new(signature)) {
            Ok(()) => std::process::exit(0),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }

    if let Some(idx) = args.iter().position(|a| a == "--import-nvd-snapshot") {
        let snapshot = args.get(idx + 1).unwrap_or_else(|| {
            eprintln!("Missing snapshot path.\n\nUsage: vigil --import-nvd-snapshot SNAPSHOT.json");
            std::process::exit(1);
        });
        match advisory::run_import_cli(Path::new(snapshot)) {
            Ok(()) => std::process::exit(0),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }

    let mut elevated_relaunch = false;
    let mut elevated_launcher = false;
    for a in &args[1..] {
        match a.as_str() {
            "--install-service" => std::process::exit(service::run_cmd("install")),
            "--uninstall-service" => std::process::exit(service::run_cmd("uninstall")),
            "--break-glass-recover" => std::process::exit(break_glass::recover_if_stale()),
            autostart::ELEVATED_RELAUNCH_FLAG => {
                elevated_relaunch = true;
            }
            autostart::ELEVATED_LAUNCHER_FLAG => {
                elevated_launcher = true;
            }
            "--help" | "-h" => {
                println!("Vigil v{} — real-time network threat monitor\n\nUsage:  vigil [flags]\n\nFlags:\n  --install-service         register Vigil as a boot-time service\n  --uninstall-service       remove the boot-time service\n  --break-glass-recover     watchdog entrypoint for network recovery\n  --verify-update-manifest  MANIFEST SIG\n                           verify a signed release manifest against the embedded trust anchor\n  --import-nvd-snapshot     SNAPSHOT.json\n                           import an NVD CVE JSON snapshot into the protected advisory cache\n  -h, --help                show this help and exit\n\nRun with no flags to launch the GUI.", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => {}
        }
    }

    if elevated_launcher {
        match autostart::launch_elevated_child() {
            Ok(()) => std::process::exit(0),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }

    let _single_instance_guard = match acquire_single_instance(elevated_relaunch) {
        Ok(guard) => guard,
        Err(err) => {
            if !elevated_relaunch && err.contains("instance lock") {
                eprintln!("{err}");
            } else if !elevated_relaunch {
                eprintln!("Vigil is already running.");
            } else {
                eprintln!("{err}");
            }
            std::process::exit(1);
        }
    };
    if !_single_instance_guard.is_single() {
        eprintln!("Vigil is already running.");
        return;
    }

    let (_log_dir, _log_guard) = logger::init();
    let log_dir = _log_dir.clone();

    tracing::info!("Vigil v{} starting", env!("CARGO_PKG_VERSION"));
    tracing::info!("pre-login session: {}", session::is_pre_login());

    #[cfg(windows)]
    {
        use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
        unsafe {
            let _ = SetCurrentProcessExplicitAppUserModelID(windows::core::w!("Vigil.App.1"));
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let _guard = rt.enter();

    let loaded_cfg = match Config::load() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    startup_integrity::run();
    startup_integrity::scan_operator_inputs(&loaded_cfg);
    let cfg = Arc::new(RwLock::new(loaded_cfg));
    let cfg_bootstrap = cfg.clone();
    std::thread::Builder::new()
        .name("vigil-bootstrap".into())
        .spawn(move || {
            let c = cfg_bootstrap.read().unwrap().clone();
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
                c.reverse_dns_enabled
            );
            advisory::log_cache_status();

            active_response::reconcile();
            break_glass::start_heartbeat_loop(cfg_bootstrap.clone());

            {
                let mut w = cfg_bootstrap.write().unwrap();
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

            let c = cfg_bootstrap.read().unwrap();
            if c.autostart && !autostart::enable() {
                tracing::warn!("could not refresh autostart");
            }
        })
        .expect("failed to spawn bootstrap thread");

    let mon = Monitor::new(cfg.clone());
    let event_rx = mon.subscribe();
    let _mon_handle = mon.start();

    let show_window = Arc::new(AtomicBool::new(false));
    let paused_flag = Arc::new(AtomicBool::new(false));
    let show_window_tray = show_window.clone();
    let pending_nav: Arc<std::sync::Mutex<Option<crate::types::ConnInfo>>> =
        Arc::new(std::sync::Mutex::new(None));
    let pending_nav_tray = pending_nav.clone();
    let pending_nav_ui = pending_nav.clone();
    let (tray_tx, tray_rx) = std::sync::mpsc::sync_channel::<tray::TrayCmd>(64);
    let ui_rx = ui::spawn_event_worker(event_rx, cfg.clone(), tray_tx.clone(), paused_flag.clone());

    let egui_ctx: Arc<std::sync::OnceLock<egui::Context>> = Arc::new(std::sync::OnceLock::new());
    let egui_ctx_tray = egui_ctx.clone();
    let egui_ctx_ui = egui_ctx.clone();

    std::thread::Builder::new()
        .name("vigil-tray".into())
        .spawn(move || {
            tray::run(
                tray_rx,
                show_window_tray,
                log_dir,
                pending_nav_tray,
                egui_ctx_tray,
            )
        })
        .expect("failed to spawn tray thread");

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Vigil")
        .with_app_id("vigil")
        .with_inner_size([1080.0, 680.0])
        .with_min_inner_size([700.0, 440.0]);
    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        persist_window: true,
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
                ui_rx,
                tray_tx,
                show_window,
                pending_nav_ui,
                paused_flag,
                egui_ctx_ui,
            )))
        }),
    )
    .expect("eframe failed");
}
