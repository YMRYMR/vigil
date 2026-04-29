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

mod advisory;
mod advisory_status;
mod artifact_provenance;
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
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const SINGLE_INSTANCE_ID: &str = "com.ymrymr.vigil.single_instance";
const BACKGROUND_INSTANCE_ID: &str = "com.ymrymr.vigil.background";
fn load_app_icon() -> Option<egui::IconData> {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/vigil_icon.png"))
        .or_else(|_| eframe::icon_data::from_png_bytes(include_bytes!("../assets/vigil.png")))
        .map_err(|err| {
            tracing::warn!("could not decode app icon PNG: {err}");
            err
        })
        .ok()
}

fn report_startup_failure(message: &str) {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

        let title = windows::core::HSTRING::from("Vigil startup failed");
        let body = windows::core::HSTRING::from(message);
        unsafe {
            let _ = MessageBoxW(None, &body, &title, MB_OK | MB_ICONERROR);
        }
    }

    #[cfg(not(windows))]
    eprintln!("{message}");
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
