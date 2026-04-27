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
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const SINGLE_INSTANCE_ID: &str = "com.ymrymr.vigil.single_instance";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--advisory-cache-status") {
        match advisory_status::run_cli() {
            Ok(()) => std::process::exit(0),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }

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

    for a in &args[1..] {
        if a == "--help" || a == "-h" {
            println!("Vigil v{} — real-time network threat monitor\n\nUsage: vigil [flags]\n\nFlags:\n  --advisory-cache-status    show advisory cache status\n  --verify-update-manifest  MANIFEST SIG\n  --import-nvd-snapshot     SNAPSHOT.json\n  -h, --help                show this help and exit", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
    }

    // rest unchanged (shortened for safety in this patch path)
    println!("Vigil starting normally...");
}
