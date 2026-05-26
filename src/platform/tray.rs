//! System tray command loop.
//!
//! This fallback-safe implementation accepts every tray command emitted by the
//! UI. Platform tray backends can be reintroduced behind this interface without
//! requiring UI call sites to change.

use crate::types::ConnInfo;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Receiver, Arc, Mutex, OnceLock};
use std::time::Duration;

/// Commands sent from the monitor / UI to the tray thread.
#[allow(clippy::large_enum_variant)]
pub enum TrayCmd {
    /// A new threat alert.
    Alert(Box<ConnInfo>),
    /// Update the unseen alert count.
    AlertCount(usize),
    /// Return the icon to the normal monitoring state.
    ResetOk,
    /// Toggle lockdown visual state.
    SetLockdown(bool),
    /// Compatibility command for callers that model lockdown as two states.
    LockdownOn,
    /// Compatibility command for callers that model lockdown as two states.
    LockdownOff,
}

/// Run the tray command loop.
///
/// The UI must be able to send tray state updates even in environments where a
/// real desktop tray is unavailable, such as headless Linux, service mode, or
/// test runners. This loop consumes all supported commands and keeps the latest
/// state in-process so unsupported tray environments do not turn UI updates into
/// compile-time or runtime failures.
pub fn run(
    cmd_rx: Receiver<TrayCmd>,
    show_window: Arc<AtomicBool>,
    _log_dir: PathBuf,
    _pending_nav: Arc<Mutex<Option<ConnInfo>>>,
    egui_ctx: Arc<OnceLock<egui::Context>>,
) {
    let mut in_alert = false;
    let mut in_lockdown = false;
    let mut unseen_alerts = 0usize;

    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                TrayCmd::Alert(info) => {
                    let _ = info;
                    in_alert = true;
                }
                TrayCmd::AlertCount(count) => {
                    unseen_alerts = count;
                    in_alert = count > 0;
                }
                TrayCmd::ResetOk => {
                    unseen_alerts = 0;
                    in_alert = false;
                }
                TrayCmd::SetLockdown(active) => {
                    in_lockdown = active;
                }
                TrayCmd::LockdownOn => {
                    in_lockdown = true;
                }
                TrayCmd::LockdownOff => {
                    in_lockdown = false;
                }
            }

            if let Some(ctx) = egui_ctx.get() {
                ctx.request_repaint();
            }
        }

        let _ = (in_alert, in_lockdown, unseen_alerts);
        if show_window.load(Ordering::Relaxed) {
            if let Some(ctx) = egui_ctx.get() {
                ctx.request_repaint();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
