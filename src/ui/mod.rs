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
    !sel.proc_path.is_empty() && !is_ghost_process_name(&sel.proc_name)
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

fn trim_transparent_border(image: image::RgbaImage) -> image::RgbaImage {
    let (width, height) = image.dimensions();
    let mut min_x = width;
    let mut min_y = height;
    let mut max_x = 0;
    let mut max_y = 0;
    let mut found = false;

    for (x, y, pixel) in image.enumerate_pixels() {
        if pixel[3] > 0 {
            found = true;
            min_x = min_x.min(x);
            min_y = min_y.min(y);
            max_x = max_x.max(x);
            max_y = max_y.max(y);
        }
    }

    if !found {
        return image;
    }

    let pad = 2;
    let left = min_x.saturating_sub(pad);
    let top = min_y.saturating_sub(pad);
    let right = (max_x + pad + 1).min(width);
    let bottom = (max_y + pad + 1).min(height);
    image::imageops::crop_imm(&image, left, top, right - left, bottom - top).to_image()
}

fn load_vigil_logo(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let image = image::load_from_memory_with_format(
        include_bytes!("../../assets/vigil_logo.png"),
        image::ImageFormat::Png,
    )
    .ok()?
    .into_rgba8();
    let image = trim_transparent_border(image);
    let size = [image.width() as usize, image.height() as usize];
    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
    Some(ctx.load_texture("vigil-logo", color_image, egui::TextureOptions::default()))
}

impl VigilApp {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        cfg: Arc<RwLock<Config>>,
        ui_rx: mpsc::Receiver<UiMessage>,
        tray_tx: std::sync::mpsc::SyncSender<TrayCmd>,
        show_window: Arc<AtomicBool>,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
        paused_flag: Arc<AtomicBool>,
        egui_ctx: Arc<std::sync::OnceLock<egui::Context>>,
    ) -> Self {
        theme::apply(&cc.egui_ctx);
        let _ = egui_ctx.set(cc.egui_ctx.clone());
        let initial_ui_scale = {
            let c = cfg.read().unwrap();
            c.sanitised_ui_scale()
        };
        apply_pixels_per_point(&cc.egui_ctx, initial_ui_scale);
        let settings = {
            let c = cfg.read().unwrap();
            settings::SettingsDraft::from_config(&c)
        };
        let persisted = cc
            .storage
            .and_then(|storage| eframe::get_value::<UiState>(storage, "ui"))
            .unwrap_or_default();
        let response_status = active_response::status();
        let vigil_logo = load_vigil_logo(&cc.egui_ctx);
        cc.egui_ctx.request_repaint_after(UI_IDLE_REPAINT);
        #[cfg(target_os = "linux")]
        {
            let wake_ctx = cc.egui_ctx.clone();
            let wake_show_window = show_window.clone();
            let wake_pending_nav = pending_nav.clone();
            let _ = std::thread::Builder::new()
                .name("vigil-window-waker".into())
                .spawn(move || loop {
                    let should_wake = wake_show_window.load(Ordering::Relaxed)
                        || wake_pending_nav
                            .lock()
                            .map(|pending| pending.is_some())
                            .unwrap_or(false);
                    if should_wake {
                        wake_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                        wake_ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        wake_ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        wake_ctx.request_repaint();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(120));
                });
        }
        Self {
            vigil_logo,
            activity: VecDeque::new(),
            alerts: VecDeque::new(),
            selected_activity: None,
            selected_alert: None,
            active_tab: persisted.active_tab,
            unseen_alerts: 0,
            ui_rx,
            tray_tx,
            show_window,
            pending_nav,
            cfg,
            paused_flag,
            settings,
            kill_confirm: false,
            response_confirm: None,
            response_status,
            tray_lockdown_sent: !response_status.isolated,
            network_operation: None,
            reconcile_rx: None,
            scheduled_target: None,
            notifications: VecDeque::new(),
            next_notification_id: 1,
            exit_requested: false,
            last_response_reconcile: std::time::Instant::now(),
            last_schedule_check: std::time::Instant::now() - std::time::Duration::from_secs(60),
            scheduled_lockdown_active: false,
            paused: false,
            last_applied_pixels_per_point: None,
            activity_table: persisted.activity_table,
            alerts_table: persisted.alerts_table,
            data_version: 0,
            activity_cache: None,
            alerts_cache: None,
            cached_activity_process_count: 0,
            cached_alerts_process_count: 0,
        }
    }
    fn handle_font_zoom_shortcut(&mut self, ctx: &egui::Context) {
        let (ctrl, wheel_y): (bool, f32) =
            ctx.input(|i| (i.modifiers.ctrl, i.smooth_scroll_delta.y));
        if !ctrl || wheel_y.abs() < f32::EPSILON {
            return;
        }
        let step = if wheel_y > 0.0 { 0.05 } else { -0.05 };
        let mut cfg = self.cfg.write().unwrap();
        let old = cfg.sanitised_ui_scale();
        let new = (old + step).clamp(0.8, 1.8);
        if (new - old).abs() < f32::EPSILON {
            return;
        }
        cfg.ui_scale = new;
        cfg.save();
        self.settings.ui_scale = new;
    }
    fn sync_ui_scale(&mut self, ctx: &egui::Context) {
        let scale = {
            let cfg = self.cfg.read().unwrap();
            cfg.sanitised_ui_scale()
        };
        let native_ppp = ctx.native_pixels_per_point().unwrap_or(1.0);
        let target_ppp = (native_ppp * scale).clamp(0.6, 4.0);
        let should_apply = match self.last_applied_pixels_per_point {
            Some(last) => (last - target_ppp).abs() > 0.01,
            None => true,
        };
        if should_apply {
            ctx.set_pixels_per_point(target_ppp);
            self.last_applied_pixels_per_point = Some(target_ppp);
        }
    }
    fn history_caps(&self) -> (usize, usize) {
        let cfg = self.cfg.read().unwrap();
        (
            cfg.sanitised_activity_history_cap(),
            cfg.sanitised_alerts_history_cap(),
        )
    }
    fn trim_history_buffers(&mut self) {
        let (activity_cap, alerts_cap) = self.history_caps();
        truncate_deque(&mut self.activity, activity_cap);
        truncate_deque(&mut self.alerts, alerts_cap);
    }
    fn drain_events(&mut self, max_events: usize) -> bool {
        let mut handled = false;
        let deadline = std::time::Instant::now() + UI_EVENT_TIME_BUDGET;
        let (activity_cap, alerts_cap) = self.history_caps();
        for _ in 0..max_events {
            if std::time::Instant::now() > deadline {
                break;
            }
            match self.ui_rx.try_recv() {
                Ok(message) => {
                    handled = true;
                    match message {
                        UiMessage::Event(event) => {
                            let event = *event;
                            if self.paused {
                                continue;
                            }
                            match event {
                                ConnEvent::Alert(info) => {
                                    push_capped(&mut self.activity, info.clone(), activity_cap);
                                    push_capped(&mut self.alerts, info.clone(), alerts_cap);
                                    self.unseen_alerts += 1;
                                }
                                ConnEvent::New(info) => {
                                    push_capped(&mut self.activity, info.clone(), activity_cap);
                                }
                                ConnEvent::Closed { .. } => {}
                            }
                        }
                        UiMessage::Notification(kind, text) => {
                            self.push_notification(kind, text);
                        }
                        UiMessage::ResponseStatus(status) => {
                            self.response_status = status;
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if handled {
            self.data_version = self.data_version.wrapping_add(1);
            self.cached_activity_process_count =
                process_list::count_distinct_processes(&self.activity);
            self.cached_alerts_process_count = process_list::count_distinct_processes(&self.alerts);
        }
        handled
    }
    fn execute_uninstall_from_settings(&mut self) {
        let autostart_removed = crate::autostart::disable();

        // Persist the user's uninstall intent before exiting. Otherwise a later
        // manual launch would reload `autostart = true` and re-enable login
        // startup during bootstrap.
        {
            let mut cfg = self.cfg.write().unwrap();
            if cfg.autostart {
                cfg.autostart = false;
                cfg.save();
            }
        }
        self.settings.autostart = false;

        match crate::service::uninstall() {
            Ok(service_msg) => {
                crate::audit::record(
                    "settings_uninstall",
                    "success",
                    serde_json::json!({
                        "autostart_removed": autostart_removed,
                        "service_message": service_msg,
                    }),
                );
                std::process::exit(0);
            }
            Err(err) => {
                crate::audit::record(
                    "settings_uninstall",
                    "failure",
                    serde_json::json!({
                        "autostart_removed": autostart_removed,
                        "error": &err,
                    }),
                );
                self.settings.status_msg = Some((
                    format!("Uninstall failed: {err}"),
                    std::time::Instant::now(),
                ));
                self.push_notification(NotificationKind::Error, format!("Uninstall failed: {err}"));
            }
        }
    }

    fn handle_inspector_action(&mut self, action: inspector::Action, _ctx: &egui::Context) {
        let selected_info: Option<ProcessSelection> = match self.active_tab {
            Tab::Activity => self.selected_activity.clone(),
            Tab::Alerts => self.selected_alert.clone(),
            _ => None,
        };
        let Some(info) = selected_info else {
            return;
        };
        match action {
            inspector::Action::KillConnection(conn) => {
                self.response_confirm = Some(PendingResponse::KillConnection(Box::new(conn)));
            }
            inspector::Action::BlockRemote { target, preset } => {
                self.response_confirm = Some(PendingResponse::BlockRemote { target, preset });
            }
            inspector::Action::BlockDomain { domain } => {
                self.response_confirm = Some(PendingResponse::BlockDomain { domain });
            }
            inspector::Action::BlockProcess { preset } => {
                self.response_confirm = Some(PendingResponse::BlockProcess {
                    pid: info.pid,
                    path: info.proc_path.clone(),
                    preset,
                });
            }
            inspector::Action::SuspendProcess => {
                self.response_confirm = Some(PendingResponse::SuspendProcess {
                    pid: info.pid,
                    path: info.proc_path.clone(),
                    proc_name: info.proc_name.clone(),
                });
            }
            inspector::Action::ResumeProcess => {
                self.response_confirm = Some(PendingResponse::ResumeProcess {
                    pid: info.pid,
                    path: info.proc_path.clone(),
                });
            }
            inspector::Action::FreezeAutoruns => {
                self.response_confirm = Some(PendingResponse::FreezeAutoruns);
            }
            inspector::Action::RevertAutoruns => {
                self.response_confirm = Some(PendingResponse::RevertAutoruns);
            }
            inspector::Action::QuarantineProfile => {
                self.response_confirm = Some(PendingResponse::QuarantineProfile {
                    pid: info.pid,
                    path: info.proc_path.clone(),
                    proc_name: info.proc_name.clone(),
                });
            }
            inspector::Action::ClearQuarantineProfile => {
                self.response_confirm = Some(PendingResponse::ClearQuarantineProfile {
                    pid: info.pid,
                    path: info.proc_path.clone(),
                });
            }
            inspector::Action::UnblockRemote(target) => {
                self.response_confirm = Some(PendingResponse::UnblockRemote(target));
            }
            inspector::Action::UnblockDomain(domain) => {
                self.response_confirm = Some(PendingResponse::UnblockDomain(domain));
            }
            inspector::Action::UnblockProcess => {
                self.response_confirm = Some(PendingResponse::UnblockProcess {
                    pid: info.pid,
                    path: info.proc_path.clone(),
                });
            }
            inspector::Action::IsolateMachine => {
                self.response_confirm = Some(PendingResponse::IsolateMachine);
            }
            inspector::Action::RestoreNetwork => {
                self.response_confirm = Some(PendingResponse::RestoreNetwork);
            }
        }
    }

    fn request_tray_refresh(&mut self) {
        let _ = self.tray_tx.try_send(TrayCmd::Refresh);
    }

    fn maybe_reconcile_response_status(&mut self) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_response_reconcile) < std::time::Duration::from_secs(2) {
            return;
        }
        self.last_response_reconcile = now;
        if self.reconcile_rx.is_none() {
            let (tx, rx) = mpsc::channel();
            self.reconcile_rx = Some(rx);
            std::thread::spawn(move || {
                let _ = tx.send(active_response::status());
            });
        }
        if let Some(rx) = &self.reconcile_rx {
            match rx.try_recv() {
                Ok(status) => {
                    self.response_status = status;
                    self.reconcile_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.reconcile_rx = None;
                }
            }
        }
    }

    fn maybe_run_scheduled_lockdown(&mut self) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_schedule_check) < std::time::Duration::from_secs(30) {
            return;
        }
        self.last_schedule_check = now;
        let cfg = self.cfg.read().unwrap().clone();
        if !cfg.scheduled_lockdown_enabled {
            return;
        }
        let current = Local::now();
        let current_minutes = current.hour() * 60 + current.minute();
        let start = u32::from(cfg.scheduled_lockdown_start_hour) * 60
            + u32::from(cfg.scheduled_lockdown_start_minute);
        let end = u32::from(cfg.scheduled_lockdown_end_hour) * 60
            + u32::from(cfg.scheduled_lockdown_end_minute);
        let should_isolate = if start == end {
            false
        } else if start < end {
            current_minutes >= start && current_minutes < end
        } else {
            current_minutes >= start || current_minutes < end
        };
        if should_isolate == self.scheduled_lockdown_active {
            return;
        }
        if self.network_operation.is_some() {
            return;
        }
        self.scheduled_target = Some(should_isolate);
        let started = self.start_network_operation(if should_isolate {
            NetworkOperationKind::Isolate
        } else {
            NetworkOperationKind::Restore
        });
        if !started {
            self.scheduled_target = None;
        }
    }

    fn kind_from_status(status: &str) -> NotificationKind {
        match status {
            "success" => NotificationKind::Success,
            "warning" => NotificationKind::Warning,
            "error" => NotificationKind::Error,
            _ => NotificationKind::Info,
        }
    }

    fn restore_from_navigation(&mut self) {
        let Ok(mut pending) = self.pending_nav.lock() else {
            return;
        };
        if let Some(conn) = pending.take() {
            self.active_tab = Tab::Alerts;
            self.selected_alert = Some(ProcessSelection::from_conn(&conn, &self.alerts));
            self.show_window.store(true, Ordering::Relaxed);
            self.request_tray_refresh();
        }
    }

    fn restore_window(&self, ctx: &egui::Context) {
        if !self.show_window.swap(false, Ordering::Relaxed) {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.request_repaint();
    }

    fn toolbar(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            ui.heading("Vigil");
            ui.separator();
            tab_bar::tab_button(ui, &mut self.active_tab, Tab::Activity, || {
                format!("Activity ({})", self.cached_activity_process_count)
            });
            tab_bar::tab_button(ui, &mut self.active_tab, Tab::Alerts, || {
                let suffix = if self.unseen_alerts > 0 {
                    format!(" [{}]", self.unseen_alerts)
                } else {
                    String::new()
                };
                format!("Alerts ({}){}", self.cached_alerts_process_count, suffix)
            });
            tab_bar::tab_button(ui, &mut self.active_tab, Tab::Inspector, || "Inspector".into());
            tab_bar::tab_button(ui, &mut self.active_tab, Tab::Settings, || "Settings".into());
            tab_bar::tab_button(ui, &mut self.active_tab, Tab::Help, || "Help".into());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Quit").clicked() {
                    self.exit_requested = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
    }
}

fn push_capped<T>(deque: &mut VecDeque<T>, item: T, cap: usize) {
    deque.push_front(item);
    if deque.len() > cap {
        deque.pop_back();
    }
}
fn truncate_deque<T>(deque: &mut VecDeque<T>, cap: usize) {
    while deque.len() > cap {
        deque.pop_back();
    }
}
pub fn conn_matches_selection(info: &ConnInfo, selected: Option<&ConnInfo>) -> bool {
    selected.is_some_and(|sel| {
        info.timestamp == sel.timestamp
            && info.pid == sel.pid
            && info.proc_name == sel.proc_name
            && info.local_addr == sel.local_addr
            && info.remote_addr == sel.remote_addr
    })
}
fn remove_pid(rows: &mut VecDeque<ConnInfo>, pid: u32) {
    rows.retain(|info| info.pid != pid);
}
fn kill_process(pid: u32) {
    use sysinfo::{Pid, ProcessesToUpdate, System};
    let target = Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[target]), false);
    if let Some(proc) = sys.process(target) {
        proc.kill();
    }
}
