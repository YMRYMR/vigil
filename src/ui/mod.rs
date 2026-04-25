//! Main UI module — eframe application.
//!
//! `VigilApp` is the single `eframe::App` implementor.
//! In eframe 0.34, `App::ui(ui, frame)` receives the window-level `Ui`; panels
//! are added with `show_inside(ui, …)` instead of `show(ctx, …)`.

pub mod activity;
pub mod alerts;
pub mod help;
pub mod inspector;
pub mod process_list;
pub mod settings;
pub mod tab_bar;
pub mod theme;

use crate::active_response;
use crate::auto_response;
use crate::config::Config;
use crate::response_rules;
use crate::tray::TrayCmd;
use crate::types::{ConnEvent, ConnInfo};
use chrono::{Local, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use tab_bar::Tab;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableState {
    pub filter: String,
    pub sort_col: usize,
    pub sort_asc: bool,
    #[serde(default)]
    pub collapsed_pids: HashSet<u32>,
    #[serde(default)]
    pub expanded_endpoints: HashSet<String>,
}
impl TableState {
    pub fn new(default_col: usize, default_asc: bool) -> Self {
        Self {
            filter: String::new(),
            sort_col: default_col,
            sort_asc: default_asc,
            collapsed_pids: HashSet::new(),
            expanded_endpoints: HashSet::new(),
        }
    }
    pub fn toggle(&mut self, col: usize) {
        if self.sort_col == col {
            self.sort_asc = !self.sort_asc;
        } else {
            self.sort_col = col;
            self.sort_asc = true;
        }
    }
    pub fn arrow(&self, col: usize) -> &'static str {
        if self.sort_col == col {
            if self.sort_asc {
                " ^"
            } else {
                " v"
            }
        } else {
            ""
        }
    }
    pub fn is_collapsed(&self, pid: u32) -> bool {
        self.collapsed_pids.contains(&pid)
    }
    pub fn toggle_collapsed(&mut self, pid: u32) {
        if !self.collapsed_pids.insert(pid) {
            self.collapsed_pids.remove(&pid);
        }
        if self.collapsed_pids.len() > COLLAPSED_PIDS_CAP {
            self.collapsed_pids.clear();
        }
    }
    #[allow(dead_code)]
    pub fn is_endpoint_expanded(&self, endpoint_key: &str) -> bool {
        self.expanded_endpoints.contains(endpoint_key)
    }
    #[allow(dead_code)]
    pub fn toggle_endpoint(&mut self, endpoint_key: &str) {
        if !self.expanded_endpoints.insert(endpoint_key.to_string()) {
            self.expanded_endpoints.remove(endpoint_key);
        }
        if self.expanded_endpoints.len() > EXPANDED_ENDPOINTS_CAP {
            self.expanded_endpoints.clear();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiState {
    active_tab: Tab,
    activity_table: TableState,
    alerts_table: TableState,
}
impl Default for UiState {
    fn default() -> Self {
        Self {
            active_tab: Tab::Activity,
            activity_table: TableState::new(0, false),
            alerts_table: TableState::new(4, false),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotificationKind {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub(crate) enum UiMessage {
    Event(Box<ConnEvent>),
    Notification(NotificationKind, String),
    ResponseStatus(active_response::Status),
}

#[derive(Debug, Clone)]
struct Notification {
    id: u64,
    kind: NotificationKind,
    text: String,
    expires_at: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkOperationKind {
    Isolate,
    Restore,
}

struct NetworkOperation {
    kind: NetworkOperationKind,
    rx: mpsc::Receiver<NetworkOperationResult>,
}

struct NetworkOperationResult {
    message: String,
    status: active_response::Status,
}

pub fn spawn_event_worker(
    mut event_rx: tokio::sync::broadcast::Receiver<ConnEvent>,
    cfg: Arc<RwLock<Config>>,
    tray_tx: std::sync::mpsc::SyncSender<TrayCmd>,
    paused: Arc<AtomicBool>,
) -> mpsc::Receiver<UiMessage> {
    let (ui_tx, ui_rx) = mpsc::channel::<UiMessage>();
    std::thread::Builder::new()
        .name("vigil-ui-events".into())
        .spawn(move || {
            let mut auto_response_state = auto_response::EngineState::default();
            let mut response_rule_state = response_rules::EngineState::default();
            loop {
                match event_rx.blocking_recv() {
                    Ok(event) => {
                        if paused.load(Ordering::Relaxed) {
                            continue;
                        }
                        match &event {
                            ConnEvent::Alert(info) => {
                                let _ = tray_tx.try_send(TrayCmd::Alert(Box::new(info.clone())));
                                let cfg_snapshot = cfg.read().unwrap().clone();
                                if let Some(message) = auto_response::maybe_apply(
                                    info,
                                    &cfg_snapshot,
                                    &mut auto_response_state,
                                ) {
                                    let _ = ui_tx.send(UiMessage::Notification(
                                        NotificationKind::Info,
                                        message,
                                    ));
                                    let _ = ui_tx
                                        .send(UiMessage::ResponseStatus(active_response::status()));
                                }
                                if let Some(message) = response_rules::maybe_apply(
                                    info,
                                    &cfg_snapshot,
                                    &mut response_rule_state,
                                ) {
                                    let _ = ui_tx.send(UiMessage::Notification(
                                        NotificationKind::Info,
                                        message,
                                    ));
                                    let _ = ui_tx
                                        .send(UiMessage::ResponseStatus(active_response::status()));
                                }
                            }
                            ConnEvent::New(info) => {
                                let cfg_snapshot = cfg.read().unwrap().clone();
                                if let Some(message) = auto_response::maybe_apply(
                                    info,
                                    &cfg_snapshot,
                                    &mut auto_response_state,
                                ) {
                                    let _ = ui_tx.send(UiMessage::Notification(
                                        NotificationKind::Info,
                                        message,
                                    ));
                                    let _ = ui_tx
                                        .send(UiMessage::ResponseStatus(active_response::status()));
                                }
                                if let Some(message) = response_rules::maybe_apply(
                                    info,
                                    &cfg_snapshot,
                                    &mut response_rule_state,
                                ) {
                                    let _ = ui_tx.send(UiMessage::Notification(
                                        NotificationKind::Info,
                                        message,
                                    ));
                                    let _ = ui_tx
                                        .send(UiMessage::ResponseStatus(active_response::status()));
                                }
                            }
                            ConnEvent::Closed { .. } => {}
                        }
                        let _ = ui_tx.send(UiMessage::Event(Box::new(event)));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("UI worker dropped {n} broadcast events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
        .expect("failed to spawn Vigil UI worker");
    ui_rx
}

#[derive(Clone)]
pub struct ProcessSelection {
    pub pid: u32,
    pub proc_name: String,
    pub proc_path: String,
    pub proc_user: String,
    pub parent_user: String,
    pub command_line: String,
    pub parent_name: String,
    pub parent_pid: u32,
    pub service_name: String,
    pub publisher: String,
    pub score: u8,
    pub reasons: Vec<String>,
    pub attack_tags: Vec<String>,
    pub baseline_deviation: bool,
    pub script_host_suspicious: bool,
    pub timestamp: String,
    pub status: String,
    pub remote_addr: String,
    pub connection_count: usize,
    pub distinct_ports: usize,
    pub distinct_remotes: usize,
    pub statuses: Vec<String>,
    pub selected_connection: Option<ConnInfo>,
}

#[derive(Clone)]
enum PendingResponse {
    BlockRemote {
        target: String,
        preset: active_response::DurationPreset,
    },
    BlockDomain {
        domain: String,
    },
    BlockProcess {
        pid: u32,
        path: String,
        preset: active_response::DurationPreset,
    },
    SuspendProcess {
        pid: u32,
        path: String,
        proc_name: String,
    },
    ResumeProcess {
        pid: u32,
        path: String,
    },
    FreezeAutoruns,
    RevertAutoruns,
    QuarantineProfile {
        pid: u32,
        path: String,
        proc_name: String,
    },
    ClearQuarantineProfile {
        pid: u32,
        path: String,
    },
    KillConnection(Box<ConnInfo>),
    UnblockRemote(String),
    UnblockDomain(String),
    UnblockProcess {
        pid: u32,
        path: String,
    },
    IsolateMachine,
    RestoreNetwork,
}

pub fn is_ghost_process_name(name: &str) -> bool {
    let Some(inner) = name
        .trim()
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
    else {
        return false;
    };
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit())
}
pub fn has_known_location(sel: &ProcessSelection) -> bool {
    !sel.proc_path.is_empty() && !is_ghost_process_name(sel.proc_name)
}

pub struct VigilApp {
    vigil_logo: Option<egui::TextureHandle>,
    activity: VecDeque<ConnInfo>,
    alerts: VecDeque<ConnInfo>,
    selected_activity: Option<ProcessSelection>,
    selected_alert: Option<ProcessSelection>,
    active_tab: Tab,
    unseen_alerts: usize,
    ui_rx: mpsc::Receiver<UiMessage>,
    tray_tx: std::sync::mpsc::SyncSender<TrayCmd>,
    show_window: Arc<AtomicBool>,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
    cfg: Arc<RwLock<Config>>,
    paused_flag: Arc<AtomicBool>,
    settings: settings::SettingsDraft,
    kill_confirm: bool,
    response_confirm: Option<PendingResponse>,
    response_status: active_response::Status,
    tray_lockdown_sent: bool,
    network_operation: Option<NetworkOperation>,
    reconcile_rx: Option<mpsc::Receiver<active_response::Status>>,
    scheduled_target: Option<bool>,
    notifications: VecDeque<Notification>,
    next_notification_id: u64,
    exit_requested: bool,
    last_response_reconcile: std::time::Instant,
    last_schedule_check: std::time::Instant,
    scheduled_lockdown_active: bool,
    paused: bool,
    last_applied_pixels_per_point: Option<f32>,
    activity_table: TableState,
    alerts_table: TableState,
    /// Monotonically increasing version counter for activity/alerts data.
    /// Incremented when new events are drained. Used to invalidate UI caches.
    data_version: u64,
    /// Cached group view for the activity tab.
    activity_cache: Option<process_list::CachedGroupView>,
    /// Cached group view for the alerts tab.
    alerts_cache: Option<process_list::CachedGroupView>,
    /// Cached distinct process count for activity tab labels.
    cached_activity_process_count: usize,
    /// Cached distinct process count for alerts tab labels.
    cached_alerts_process_count: usize,
}
const UI_EVENT_BUDGET: usize = 128;
/// Maximum time spent draining events per frame (prevents frame stalls under burst load).
const UI_EVENT_TIME_BUDGET: std::time::Duration = std::time::Duration::from_millis(5);
const UI_IDLE_REPAINT: std::time::Duration = std::time::Duration::from_secs(1);
const UI_BUSY_REPAINT: std::time::Duration = std::time::Duration::from_millis(100);
const NOTIFICATION_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const COLLAPSED_PIDS_CAP: usize = 256;
#[allow(dead_code)]
const EXPANDED_ENDPOINTS_CAP: usize = 128;

fn apply_pixels_per_point(ctx: &egui::Context, scale: f32) {
    let native_ppp = ctx.native_pixels_per_point().unwrap_or(1.0);
    let target_ppp = (native_ppp * scale.clamp(0.8, 1.8)).clamp(0.6, 4.0);
    ctx.set_pixels_per_point(target_ppp);
}

"}