//! Main UI module — eframe application.
//!
//! `VigilApp` is the single `eframe::App` implementor.
//! In eframe 0.34, `App::ui(ui, frame)` receives the window-level `Ui`; panels
//! are added with `show_inside(ui, …)` instead of `show(ctx, …)`.

pub mod activity;
pub mod alerts;
pub mod firewall;
pub mod help;
pub mod inspector;
pub mod process_list;
pub mod process_list_fast;
pub mod settings;
pub mod tab_bar;
pub mod theme;
pub mod uninstall;

use crate::active_response;
use crate::auto_response;
use crate::config::Config;
use crate::response_rules;
use crate::tray::TrayCmd;
use crate::types::{ConnEvent, ConnInfo};
use chrono::{Local, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::path::Path;
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
    scheduled: bool,
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
    notify_tx: std::sync::mpsc::SyncSender<ConnInfo>,
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
                                if let Err(err) = notify_tx.try_send(info.clone()) {
                                    tracing::warn!("desktop alert notification dropped: {err}");
                                }
                                if let Err(err) =
                                    tray_tx.try_send(TrayCmd::Alert(Box::new(info.clone())))
                                {
                                    tracing::warn!("tray alert state update dropped: {err}");
                                }
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
    pub reason_summary: inspector::ReasonSummary,
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
    pub selected_connection_reason_summary: Option<inspector::ReasonSummary>,
}

#[derive(Clone)]
pub struct FirewallSelection {
    pub rule_name: String,
    pub target: String,
    pub rule_type: String,
    #[allow(dead_code)]
    pub direction: String,
    pub pid: u32,
    pub path: String,
}

#[derive(Clone)]
pub enum FirewallAction {
    UnblockIp {
        #[allow(dead_code)]
        rule_name: String,
        target: String,
    },
    UnblockProcess {
        #[allow(dead_code)]
        rule_name: String,
        pid: u32,
        path: String,
    },
    ClearDomainBlock {
        domain: String,
    },
    RestoreIsolation,
    RestoreProcess {
        pid: u32,
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InspectorSnapshotKey {
    pid: u32,
    proc_path: String,
    remote_addr: Option<String>,
    hostname: Option<String>,
    tls_sni: Option<String>,
}

#[derive(Clone)]
struct InspectorSnapshotRequest {
    key: InspectorSnapshotKey,
    pid: u32,
    proc_path: String,
    selected_connection: Option<ConnInfo>,
}

impl InspectorSnapshotRequest {
    fn from_selection(sel: &ProcessSelection) -> Self {
        let selected_connection = sel.selected_connection.clone();
        let key = InspectorSnapshotKey {
            pid: sel.pid,
            proc_path: sel.proc_path.clone(),
            remote_addr: selected_connection
                .as_ref()
                .map(|conn| conn.remote_addr.clone()),
            hostname: selected_connection
                .as_ref()
                .and_then(|conn| conn.hostname.clone()),
            tls_sni: selected_connection
                .as_ref()
                .and_then(|conn| conn.tls_sni.clone()),
        };
        Self {
            key,
            pid: sel.pid,
            proc_path: sel.proc_path.clone(),
            selected_connection,
        }
    }
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
    selected_firewall: Option<FirewallSelection>,
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
    inspector_snapshot: active_response::InspectorSnapshot,
    inspector_snapshot_key: Option<InspectorSnapshotKey>,
    inspector_snapshot_rx:
        Option<mpsc::Receiver<(InspectorSnapshotKey, active_response::InspectorSnapshot)>>,
    inspector_snapshot_last_started: std::time::Instant,
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
    data_version: u64,
    activity_cache: Option<process_list::CachedGroupView>,
    alerts_cache: Option<process_list::CachedGroupView>,
    cached_activity_process_count: usize,
    cached_alerts_process_count: usize,
}
const UI_EVENT_BUDGET: usize = 128;
const UI_EVENT_TIME_BUDGET: std::time::Duration = std::time::Duration::from_millis(5);
const UI_IDLE_REPAINT: std::time::Duration = std::time::Duration::from_secs(1);
const UI_BUSY_REPAINT: std::time::Duration = std::time::Duration::from_millis(100);
const INSPECTOR_SNAPSHOT_REFRESH: std::time::Duration = std::time::Duration::from_secs(1);
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

fn admin_chip(ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new(" Admin Mode ")
            .color(theme::ACCENT)
            .background_color(theme::ACCENT_BG)
            .size(10.5)
            .strong(),
    );
}

fn admin_btn(text: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(text).color(theme::ACCENT).size(11.0))
        .fill(theme::ACCENT_BG)
        .stroke(egui::Stroke::new(1.0, theme::ACCENT))
        .corner_radius(4.0)
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
        let inspector_snapshot = active_response::InspectorSnapshot {
            status: response_status,
            ..Default::default()
        };
        let tray_lockdown_sent = !response_status.isolated;
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
            selected_firewall: None,
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
            inspector_snapshot,
            inspector_snapshot_key: None,
            inspector_snapshot_rx: None,
            inspector_snapshot_last_started: std::time::Instant::now() - INSPECTOR_SNAPSHOT_REFRESH,
            tray_lockdown_sent,
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
        let mut trimmed = false;
        if self.activity.len() > activity_cap {
            trimmed = true;
        }
        truncate_deque(&mut self.activity, activity_cap);
        if self.alerts.len() > alerts_cap {
            trimmed = true;
        }
        truncate_deque(&mut self.alerts, alerts_cap);
        if trimmed {
            self.refresh_selection_after_trim();
            self.data_version = self.data_version.wrapping_add(1);
            self.activity_cache = None;
            self.alerts_cache = None;
        }
    }
    fn current_inspector_request(&self) -> Option<InspectorSnapshotRequest> {
        let selection = match self.active_tab {
            Tab::Activity => self.selected_activity.as_ref(),
            Tab::Alerts => self.selected_alert.as_ref(),
            _ => None,
        }?;
        if selection.pid == 0 && selection.proc_path.is_empty() {
            return None;
        }
        Some(InspectorSnapshotRequest::from_selection(selection))
    }
    fn spawn_inspector_snapshot_worker(
        request: InspectorSnapshotRequest,
    ) -> mpsc::Receiver<(InspectorSnapshotKey, active_response::InspectorSnapshot)> {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("vigil-inspector-snapshot".into())
            .spawn(move || {
                let snapshot = active_response::snapshot_target(
                    request.pid,
                    request.selected_connection.as_ref(),
                    (!request.proc_path.is_empty()).then_some(request.proc_path.as_str()),
                );
                let _ = tx.send((request.key, snapshot));
            })
            .expect("failed to spawn inspector snapshot worker");
        rx
    }
    fn refresh_inspector_snapshot(&mut self, request: Option<InspectorSnapshotRequest>) {
        if let Some(rx) = self.inspector_snapshot_rx.take() {
            match rx.try_recv() {
                Ok((key, mut snapshot)) => {
                    if self.inspector_snapshot_key.as_ref() == Some(&key) {
                        snapshot.status = self.response_status;
                        self.inspector_snapshot = snapshot;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.inspector_snapshot_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {}
            }
        }

        let Some(request) = request else {
            self.inspector_snapshot_key = None;
            self.inspector_snapshot_rx = None;
            self.inspector_snapshot = active_response::InspectorSnapshot {
                status: self.response_status,
                ..Default::default()
            };
            return;
        };

        let key_changed = self.inspector_snapshot_key.as_ref() != Some(&request.key);
        if key_changed {
            self.inspector_snapshot_key = Some(request.key.clone());
            self.inspector_snapshot_rx = None;
            self.inspector_snapshot = active_response::InspectorSnapshot {
                status: self.response_status,
                ..Default::default()
            };
        }

        let should_refresh = if key_changed {
            self.inspector_snapshot_rx.is_none()
        } else {
            self.inspector_snapshot_rx.is_none()
                && self.inspector_snapshot_last_started.elapsed() >= INSPECTOR_SNAPSHOT_REFRESH
        };

        if should_refresh {
            self.inspector_snapshot_last_started = std::time::Instant::now();
            self.inspector_snapshot_rx = Some(Self::spawn_inspector_snapshot_worker(request));
        }
    }
    fn selection_matches_conn(sel: &ProcessSelection, info: &ConnInfo) -> bool {
        sel.pid == info.pid
            && sel.proc_name == info.proc_name
            && conn_matches_selection(info, sel.selected_connection.as_ref())
    }
    fn process_ui_message(&mut self, message: UiMessage) {
        match message {
            UiMessage::Event(event) => self.handle_event(*event),
            UiMessage::Notification(kind, text) => self.push_notification(kind, text),
            UiMessage::ResponseStatus(status) => {
                self.response_status = status;
                self.inspector_snapshot.status = status;
            }
        }
    }
    fn start_network_operation(&mut self, kind: NetworkOperationKind, scheduled: bool) -> bool {
        if self.network_operation.is_some() {
            return false;
        }
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("vigil-network-operation".into())
            .spawn(move || {
                let result = match kind {
                    NetworkOperationKind::Isolate => {
                        let message = match active_response::isolate_machine() {
                            Ok(msg) => msg,
                            Err(err) => format!("Isolation failed: {err}"),
                        };
                        let status = active_response::status();
                        NetworkOperationResult { message, status }
                    }
                    NetworkOperationKind::Restore => {
                        let message = match active_response::restore_machine() {
                            Ok(msg) => msg,
                            Err(err) => format!("Restore failed: {err}"),
                        };
                        let status = active_response::status();
                        NetworkOperationResult { message, status }
                    }
                };
                let _ = tx.send(result);
            })
            .expect("failed to spawn network operation worker");
        self.network_operation = Some(NetworkOperation {
            kind,
            scheduled,
            rx,
        });
        true
    }
    fn poll_network_operation(&mut self) {
        let Some(op) = self.network_operation.take() else {
            return;
        };
        match op.rx.try_recv() {
            Ok(result) => {
                self.response_status = result.status;
                self.inspector_snapshot.status = self.response_status;
                let kind = if result.message.contains("failed") || result.message.contains("No ") {
                    NotificationKind::Error
                } else {
                    NotificationKind::Success
                };
                if !op.scheduled {
                    self.push_notification(kind, result.message.clone());
                } else if matches!(kind, NotificationKind::Error) {
                    self.push_notification(kind, result.message.clone());
                }
                let succeeded = !matches!(kind, NotificationKind::Error);
                if op.scheduled && succeeded {
                    self.scheduled_lockdown_active = matches!(op.kind, NetworkOperationKind::Isolate);
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.network_operation = Some(op);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.push_notification(
                    NotificationKind::Error,
                    "Network action failed: background task ended unexpectedly.",
                );
            }
        }
    }
    fn push_notification(&mut self, kind: NotificationKind, text: impl Into<String>) {
        if self.notifications.len() >= 8 {
            self.notifications.pop_front();
        }
        self.notifications.push_back(Notification {
            id: self.next_notification_id,
            kind,
            text: text.into(),
            expires_at: std::time::Instant::now() + NOTIFICATION_TTL,
        });
        self.next_notification_id = self.next_notification_id.wrapping_add(1);
    }
    fn add_conn_to_activity(&mut self, info: ConnInfo) {
        let (activity_cap, _) = self.history_caps();
        push_capped(&mut self.activity, info, activity_cap);
        self.data_version = self.data_version.wrapping_add(1);
        self.activity_cache = None;
    }
    fn add_conn_to_alerts(&mut self, info: ConnInfo) {
        let (_, alerts_cap) = self.history_caps();
        push_capped(&mut self.alerts, info, alerts_cap);
        self.data_version = self.data_version.wrapping_add(1);
        self.alerts_cache = None;
    }
    fn sync_tray_state(&mut self) {
        let lockdown_now = self.response_status.isolated;
        if lockdown_now == self.tray_lockdown_sent {
            return;
        }
        let send_result = if lockdown_now {
            self.tray_tx.try_send(TrayCmd::LockdownOn)
        } else {
            self.tray_tx.try_send(TrayCmd::LockdownOff)
        };
        if send_result.is_ok() {
            self.tray_lockdown_sent = lockdown_now;
        }
    }
    fn spawn_reconcile_worker(&mut self) {
        if self.reconcile_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("vigil-response-reconcile".into())
            .spawn(move || {
                active_response::reconcile();
                let _ = tx.send(active_response::status());
            })
            .expect("failed to spawn response reconcile worker");
        self.reconcile_rx = Some(rx);
    }
    fn refresh_active_response_state(&mut self) {
        let schedule = {
            let cfg = self.cfg.read().unwrap();
            cfg.lockdown_schedule.clone().or_else(|| {
                cfg.scheduled_lockdown_start_hour.map(|start_hour| active_response::LockdownSchedule {
                    start_hour,
                    start_minute: cfg.scheduled_lockdown_start_minute.unwrap_or(0),
                    end_hour: cfg.scheduled_lockdown_end_hour.unwrap_or(start_hour),
                    end_minute: cfg.scheduled_lockdown_end_minute.unwrap_or(0),
                })
            })
        };
        let now = std::time::Instant::now();
        let mut state_dirty = false;
        if let Some(rx) = self.reconcile_rx.take() {
            match rx.try_recv() {
                Ok(status) => {
                    self.response_status = status;
                    self.inspector_snapshot.status = status;
                    state_dirty = true;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.reconcile_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.response_status = active_response::status();
                    self.inspector_snapshot.status = self.response_status;
                    state_dirty = true;
                }
            }
        }
        let schedule_due = now.duration_since(self.last_schedule_check)
            >= std::time::Duration::from_secs(30);
        let reconcile_due = now.duration_since(self.last_response_reconcile)
            >= std::time::Duration::from_secs(15);
        if schedule_due {
            self.last_schedule_check = now;
        }
        if reconcile_due && self.reconcile_rx.is_none() {
            self.spawn_reconcile_worker();
            self.last_response_reconcile = now;
        }
        let scheduled_target = schedule.as_ref().map(|window| {
            let local = Local::now();
            active_response::schedule_contains(
                window,
                local.hour() as u8,
                local.minute() as u8,
            )
        });
        self.scheduled_target = scheduled_target;
        if let Some(target) = scheduled_target {
            if target && self.response_status.isolated {
                self.scheduled_lockdown_active = true;
            }
            if target && !self.scheduled_lockdown_active && !self.response_status.isolated {
                if self.start_network_operation(NetworkOperationKind::Isolate, true) {
                    state_dirty = true;
                }
            } else if !target && self.scheduled_lockdown_active && self.response_status.isolated {
                if self.start_network_operation(NetworkOperationKind::Restore, true) {
                    state_dirty = true;
                }
            } else if !target && !self.response_status.isolated {
                self.scheduled_lockdown_active = false;
            }
        } else {
            self.scheduled_lockdown_active = false;
        }
        if state_dirty {
            self.sync_tray_state();
        }
    }
    fn handle_event(&mut self, ev: ConnEvent) {
        match ev {
            ConnEvent::New(info) => {
                self.add_conn_to_activity(info);
                self.trim_history_buffers();
                self.cached_activity_process_count = process_list::process_count(&self.activity);
                self.cached_alerts_process_count = process_list::process_count(&self.alerts);
            }
            ConnEvent::Alert(info) => {
                self.add_conn_to_activity(info.clone());
                self.add_conn_to_alerts(info);
                self.unseen_alerts = self.unseen_alerts.saturating_add(1);
                let _ = self.tray_tx.try_send(TrayCmd::AlertCount(self.unseen_alerts));
                self.trim_history_buffers();
                self.cached_activity_process_count = process_list::process_count(&self.activity);
                self.cached_alerts_process_count = process_list::process_count(&self.alerts);
            }
            ConnEvent::Closed {
                pid,
                proc_name,
                local_addr,
                remote_addr,
            } => {
                self.activity.retain(|info| {
                    !(info.pid == pid
                        && info.proc_name == proc_name
                        && info.local_addr == local_addr
                        && info.remote_addr == remote_addr)
                });
                self.activity_cache = None;
                self.cached_activity_process_count = process_list::process_count(&self.activity);
                let mut selected_activity_pid = None;
                if self.selected_activity.as_ref().is_some_and(|sel| {
                    sel.pid == pid
                        && sel.proc_name == proc_name
                        && sel.selected_connection.as_ref().is_some_and(|conn| {
                            conn.local_addr == local_addr && conn.remote_addr == remote_addr
                        })
                }) {
                    selected_activity_pid = Some(pid);
                    self.selected_activity = process_list::selection_for_pid(
                        &self.activity,
                        pid,
                        None,
                        process_list::Kind::Activity,
                    );
                    if self.selected_activity.is_none() {
                        self.inspector_snapshot_key = None;
                        self.inspector_snapshot_rx = None;
                        self.inspector_snapshot = active_response::InspectorSnapshot {
                            status: self.response_status,
                            ..Default::default()
                        };
                    }
                }
                let mut selected_alert_pid = None;
                if self.selected_alert.as_ref().is_some_and(|sel| {
                    sel.pid == pid
                        && sel.proc_name == proc_name
                        && sel.selected_connection.as_ref().is_some_and(|conn| {
                            conn.local_addr == local_addr && conn.remote_addr == remote_addr
                        })
                }) {
                    selected_alert_pid = Some(pid);
                    self.selected_alert = process_list::selection_for_pid(
                        &self.alerts,
                        pid,
                        None,
                        process_list::Kind::Alerts,
                    );
                    if self.selected_alert.is_none() {
                        self.inspector_snapshot_key = None;
                        self.inspector_snapshot_rx = None;
                        self.inspector_snapshot = active_response::InspectorSnapshot {
                            status: self.response_status,
                            ..Default::default()
                        };
                    }
                }
                if selected_activity_pid != Some(pid)
                    && self.selected_activity.as_ref().is_some_and(|sel| {
                        sel.selected_connection.as_ref().is_some_and(|conn| {
                            conn.local_addr == local_addr && conn.remote_addr == remote_addr
                        })
                    })
                {
                    let next = self.selected_activity.as_ref().and_then(|sel| {
                        process_list::selection_for_pid(
                            &self.activity,
                            sel.pid,
                            None,
                            process_list::Kind::Activity,
                        )
                    });
                    self.selected_activity = next;
                }
                if selected_alert_pid != Some(pid)
                    && self.selected_alert.as_ref().is_some_and(|sel| {
                        sel.selected_connection.as_ref().is_some_and(|conn| {
                            conn.local_addr == local_addr && conn.remote_addr == remote_addr
                        })
                    })
                {
                    let next = self.selected_alert.as_ref().and_then(|sel| {
                        process_list::selection_for_pid(
                            &self.alerts,
                            sel.pid,
                            None,
                            process_list::Kind::Alerts,
                        )
                    });
                    self.selected_alert = next;
                }
            }
        }
    }
    fn execute_pending_response(&mut self) {
        let Some(action) = self.response_confirm.take() else {
            return;
        };
        let msg = match action {
            PendingResponse::BlockRemote { target, preset } => {
                match active_response::block_remote(&target, preset) {
                    Ok(msg) => msg,
                    Err(e) => format!("Block failed: {e}"),
                }
            }
            PendingResponse::BlockDomain { domain } => match active_response::block_domain(&domain) {
                Ok(msg) => msg,
                Err(e) => format!("Block failed: {e}"),
            },
            PendingResponse::BlockProcess { pid, path, preset } => {
                match active_response::block_process(pid, &path, preset) {
                    Ok(msg) => msg,
                    Err(e) => format!("Block failed: {e}"),
                }
            }
            PendingResponse::SuspendProcess {
                pid,
                path,
                proc_name: _,
            } => match active_response::suspend_process(pid, &path) {
                Ok(msg) => msg,
                Err(e) => format!("Suspend failed: {e}"),
            },
            PendingResponse::ResumeProcess { pid, path } => {
                match active_response::resume_process(pid, &path) {
                    Ok(msg) => msg,
                    Err(e) => format!("Resume failed: {e}"),
                }
            }
            PendingResponse::FreezeAutoruns => match active_response::freeze_autoruns() {
                Ok(msg) => msg,
                Err(e) => format!("Freeze failed: {e}"),
            },
            PendingResponse::RevertAutoruns => match active_response::revert_autoruns() {
                Ok(msg) => msg,
                Err(e) => format!("Revert failed: {e}"),
            },
            PendingResponse::QuarantineProfile {
                pid,
                path,
                proc_name,
            } => match active_response::quarantine_profile(pid, &path, &proc_name) {
                Ok(msg) => msg,
                Err(e) => format!("Quarantine failed: {e}"),
            },
            PendingResponse::ClearQuarantineProfile { pid, path } => {
                match active_response::clear_quarantine_profile(pid, &path) {
                    Ok(msg) => msg,
                    Err(e) => format!("Clear quarantine failed: {e}"),
                }
            }
            PendingResponse::KillConnection(conn) => {
                match active_response::kill_connection_by_tuple(
                    conn.pid,
                    &conn.proc_name,
                    &conn.local_addr,
                    &conn.remote_addr,
                ) {
                    Ok(msg) => msg,
                    Err(e) => format!("Kill connection failed: {e}"),
                }
            }
            PendingResponse::UnblockRemote(target) => match active_response::unblock_remote(&target) {
                Ok(msg) => msg,
                Err(e) => format!("Unblock failed: {e}"),
            },
            PendingResponse::UnblockDomain(domain) => {
                match active_response::unblock_domain(&domain) {
                    Ok(msg) => msg,
                    Err(e) => format!("Clear domain block failed: {e}"),
                }
            }
            PendingResponse::UnblockProcess { pid, path } => {
                match active_response::unblock_process(pid, &path) {
                    Ok(msg) => msg,
                    Err(e) => format!("Unblock failed: {e}"),
                }
            }
            PendingResponse::IsolateMachine => {
                if self.start_network_operation(NetworkOperationKind::Isolate, false) {
                    return;
                }
                if self.network_operation.is_some() {
                    "Isolation failed: another network action is already in progress.".to_string()
                } else {
                    return;
                }
            }
            PendingResponse::RestoreNetwork => {
                if self.start_network_operation(NetworkOperationKind::Restore, false) {
                    return;
                }
                if self.network_operation.is_some() {
                    "Restore failed: another network action is already in progress.".to_string()
                } else {
                    return;
                }
            }
        };
        self.response_status = active_response::status();
        self.inspector_snapshot.status = self.response_status;
        self.push_notification(
            if msg.contains("failed") || msg.contains("No ") {
                NotificationKind::Error
            } else {
                NotificationKind::Success
            },
            msg,
        );
    }
    fn inspector_confirm_text(action: &PendingResponse) -> (String, String) {
        match action {
            PendingResponse::BlockRemote { target, preset } => (
                "Block IP".into(),
                format!(
                    "Block all traffic to {target} for {}?",
                    active_response::duration_preset_label(*preset)
                ),
            ),
            PendingResponse::BlockDomain { domain } => (
                "Block Domain".into(),
                format!("Add {domain} to the firewall deny list?"),
            ),
            PendingResponse::BlockProcess { pid, path, preset } => (
                "Block Process".into(),
                format!(
                    "Block process {} ({}) for {}?",
                    display_target_label(path, *pid),
                    pid,
                    active_response::duration_preset_label(*preset)
                ),
            ),
            PendingResponse::SuspendProcess {
                pid,
                path,
                proc_name,
            } => (
                "Suspend Process".into(),
                format!(
                    "Suspend {} ({}, pid {})?",
                    proc_name,
                    display_target_label(path, *pid),
                    pid
                ),
            ),
            PendingResponse::ResumeProcess { pid, path } => (
                "Resume Process".into(),
                format!("Resume process {} (pid {})?", display_target_label(path, *pid), pid),
            ),
            PendingResponse::FreezeAutoruns => (
                "Freeze Autoruns".into(),
                "Apply the autorun freeze preset to startup entries and scheduled tasks?".into(),
            ),
            PendingResponse::RevertAutoruns => (
                "Revert Autoruns".into(),
                "Revert the autorun freeze preset changes?".into(),
            ),
            PendingResponse::QuarantineProfile {
                pid,
                path,
                proc_name,
            } => (
                "Quarantine Profile".into(),
                format!(
                    "Apply the containment profile to {} ({}, pid {})?",
                    proc_name,
                    display_target_label(path, *pid),
                    pid
                ),
            ),
            PendingResponse::ClearQuarantineProfile { pid, path } => (
                "Clear Quarantine".into(),
                format!(
                    "Clear the containment profile for {} (pid {})?",
                    display_target_label(path, *pid),
                    pid
                ),
            ),
            PendingResponse::KillConnection(conn) => (
                "Kill Connection".into(),
                format!("Terminate {} <-> {}?", conn.local_addr, conn.remote_addr),
            ),
            PendingResponse::UnblockRemote(target) => (
                "Unblock IP".into(),
                format!("Remove the temporary firewall block for {target}?"),
            ),
            PendingResponse::UnblockDomain(domain) => (
                "Clear Domain Block".into(),
                format!("Remove the block for {domain}?"),
            ),
            PendingResponse::UnblockProcess { pid, path } => (
                "Unblock Process".into(),
                format!(
                    "Remove the temporary firewall block for {} (pid {})?",
                    display_target_label(path, *pid),
                    pid
                ),
            ),
            PendingResponse::IsolateMachine => (
                "Isolate Host".into(),
                "Apply network isolation for this host?".into(),
            ),
            PendingResponse::RestoreNetwork => (
                "Restore Network".into(),
                "Remove network isolation for this host?".into(),
            ),
        }
    }
    fn handle_inspector_action(&mut self, action: inspector::Action, ctx: &egui::Context) {
        self.kill_confirm = false;
        match action {
            inspector::Action::KillProcess => {
                self.kill_confirm = true;
            }
            inspector::Action::KillConnection(conn) => {
                self.response_confirm = Some(PendingResponse::KillConnection(Box::new(conn)));
            }
            inspector::Action::BlockRemote { target, preset } => {
                self.response_confirm = Some(PendingResponse::BlockRemote { target, preset });
            }
            inspector::Action::BlockDomain { domain } => {
                self.response_confirm = Some(PendingResponse::BlockDomain { domain });
            }
            inspector::Action::BlockProcess { pid, path, preset } => {
                self.response_confirm = Some(PendingResponse::BlockProcess { pid, path, preset });
            }
            inspector::Action::SuspendProcess {
                pid,
                path,
                proc_name,
            } => {
                self.response_confirm = Some(PendingResponse::SuspendProcess {
                    pid,
                    path,
                    proc_name,
                });
            }
            inspector::Action::ResumeProcess { pid, path } => {
                self.response_confirm = Some(PendingResponse::ResumeProcess { pid, path });
            }
            inspector::Action::FreezeAutoruns => {
                self.response_confirm = Some(PendingResponse::FreezeAutoruns);
            }
            inspector::Action::RevertAutoruns => {
                self.response_confirm = Some(PendingResponse::RevertAutoruns);
            }
            inspector::Action::QuarantineProfile {
                pid,
                path,
                proc_name,
            } => {
                self.response_confirm = Some(PendingResponse::QuarantineProfile {
                    pid,
                    path,
                    proc_name,
                });
            }
            inspector::Action::ClearQuarantineProfile { pid, path } => {
                self.response_confirm = Some(PendingResponse::ClearQuarantineProfile { pid, path });
            }
            inspector::Action::UnblockRemote(target) => {
                self.response_confirm = Some(PendingResponse::UnblockRemote(target));
            }
            inspector::Action::UnblockDomain(domain) => {
                self.response_confirm = Some(PendingResponse::UnblockDomain(domain));
            }
            inspector::Action::UnblockProcess { pid, path } => {
                self.response_confirm = Some(PendingResponse::UnblockProcess { pid, path });
            }
            inspector::Action::IsolateMachine => {
                self.response_confirm = Some(PendingResponse::IsolateMachine);
            }
            inspector::Action::RestoreNetwork => {
                self.response_confirm = Some(PendingResponse::RestoreNetwork);
            }
            inspector::Action::Copy(value) => {
                ctx.copy_text(value);
                self.push_notification(NotificationKind::Info, "Copied to clipboard");
            }
            inspector::Action::RequestAdmin => match crate::autostart::relaunch_as_admin() {
                Ok(()) => {
                    std::process::exit(0);
                }
                Err(err) => {
                    self.push_notification(
                        NotificationKind::Error,
                        format!("Could not elevate: {err}"),
                    );
                }
            },
        }
    }
    fn refresh_selection_after_trim(&mut self) {
        if let Some(sel) = self.selected_activity.as_ref() {
            let selected_conn = sel.selected_connection.as_ref();
            let target_pid = self.activity.iter().find(|info| {
                info.pid == sel.pid && firewall::firewall_matches_selection(info, selected_conn)
            });
            self.selected_activity = target_pid.and_then(|info| {
                process_list::selection_for_pid(
                    &self.activity,
                    info.pid,
                    Some(info),
                    process_list::Kind::Activity,
                )
            });
            if self.selected_activity.is_none() {
                self.inspector_snapshot_key = None;
                self.inspector_snapshot_rx = None;
                self.inspector_snapshot = active_response::InspectorSnapshot {
                    status: self.response_status,
                    ..Default::default()
                };
            }
        }
        if let Some(sel) = self.selected_alert.as_ref() {
            let selected_conn = sel.selected_connection.as_ref();
            let target = self.alerts.iter().find(|info| {
                info.pid == sel.pid && firewall::firewall_matches_selection(info, selected_conn)
            });
            self.selected_alert = target.and_then(|info| {
                process_list::selection_for_pid(
                    &self.alerts,
                    info.pid,
                    Some(info),
                    process_list::Kind::Alerts,
                )
            });
            if self.selected_alert.is_none() {
                self.inspector_snapshot_key = None;
                self.inspector_snapshot_rx = None;
                self.inspector_snapshot = active_response::InspectorSnapshot {
                    status: self.response_status,
                    ..Default::default()
                };
            }
        }
        if let Some(sel) = self.selected_firewall.as_ref() {
            let still_exists = firewall::current_entries(
                &self.activity,
                self.selected_activity.as_ref(),
                self.selected_alert.as_ref(),
                &self.response_status,
            )
            .into_iter()
            .any(|entry| {
                entry.rule_name == sel.rule_name
                    && entry.target == sel.target
                    && entry.rule_type == sel.rule_type
                    && entry.pid == sel.pid
                    && entry.path == sel.path
            });
            if !still_exists {
                self.selected_firewall = None;
            }
        }
    }
    fn show_response_confirm_window(&mut self, ctx: &egui::Context) {
        let Some(action) = self.response_confirm.as_ref() else {
            return;
        };
        let (title, body) = Self::inspector_confirm_text(action);
        let mut execute = false;
        let mut close = false;
        egui::Window::new(title)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .frame(
                egui::Frame::window(&ctx.style())
                    .fill(theme::SURFACE)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER)),
            )
            .show(ctx, |ui| {
                ui.set_min_width(360.0);
                ui.label(body);
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                    if ui.button("Confirm").clicked() {
                        execute = true;
                    }
                });
            });
        if close {
            self.response_confirm = None;
        } else if execute {
            self.execute_pending_response();
        }
    }
    fn show_kill_confirm_window(&mut self, ctx: &egui::Context) {
        if !self.kill_confirm {
            return;
        }
        let sel = match self.active_tab {
            Tab::Activity => self.selected_activity.as_ref(),
            Tab::Alerts => self.selected_alert.as_ref(),
            _ => None,
        };
        let Some(sel) = sel else {
            self.kill_confirm = false;
            return;
        };
        let mut execute = false;
        let mut close = false;
        egui::Window::new("Terminate Process")
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .frame(
                egui::Frame::window(&ctx.style())
                    .fill(theme::SURFACE)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER)),
            )
            .show(ctx, |ui| {
                ui.set_min_width(360.0);
                ui.label(format!(
                    "Terminate {} (pid {})?",
                    display_target_label(&sel.proc_path, sel.pid),
                    sel.pid
                ));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                    if ui.button("Kill").clicked() {
                        execute = true;
                    }
                });
            });
        if close {
            self.kill_confirm = false;
        } else if execute {
            kill_process(sel.pid);
            remove_pid(&mut self.activity, sel.pid);
            remove_pid(&mut self.alerts, sel.pid);
            self.selected_activity = None;
            self.selected_alert = None;
            self.inspector_snapshot_key = None;
            self.inspector_snapshot_rx = None;
            self.inspector_snapshot = active_response::InspectorSnapshot {
                status: self.response_status,
                ..Default::default()
            };
            self.activity_cache = None;
            self.alerts_cache = None;
            self.cached_activity_process_count = process_list::process_count(&self.activity);
            self.cached_alerts_process_count = process_list::process_count(&self.alerts);
            self.kill_confirm = false;
            self.push_notification(NotificationKind::Success, "Process terminated.");
        }
    }
    fn drain_events(&mut self, max_events: usize) -> bool {
        let start = std::time::Instant::now();
        let mut processed_any = false;
        for _ in 0..max_events {
            if start.elapsed() >= UI_EVENT_TIME_BUDGET {
                break;
            }
            match self.ui_rx.try_recv() {
                Ok(message) => {
                    processed_any = true;
                    self.process_ui_message(message);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        processed_any
    }
    fn show_header(&mut self, ui: &mut egui::Ui) -> Option<inspector::Action> {
        let mut action = None;
        ui.add_space(4.0);
        ui.horizontal_centered(|ui| {
            if let Some(texture) = &self.vigil_logo {
                let image = egui::Image::new(texture).fit_to_exact_size(egui::vec2(28.0, 28.0));
                ui.add(image);
                ui.add_space(10.0);
            }
            ui.heading(
                egui::RichText::new("Vigil")
                    .size(26.0)
                    .color(theme::TEXT)
                    .strong(),
            );
            ui.add_space(10.0);
            if crate::autostart::is_elevated() {
                admin_chip(ui);
            } else if ui.add(admin_btn("Request Admin")).clicked() {
                action = Some(inspector::Action::RequestAdmin);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new(if self.paused {
                                "Resume Stream"
                            } else {
                                "Pause Stream"
                            })
                            .size(11.0),
                        )
                        .fill(if self.paused {
                            theme::ACCENT_BG
                        } else {
                            theme::SURFACE2
                        })
                        .stroke(egui::Stroke::new(
                            1.0,
                            if self.paused {
                                theme::ACCENT
                            } else {
                                theme::BORDER
                            },
                        )),
                    )
                    .clicked()
                {
                    self.paused = !self.paused;
                    self.paused_flag.store(self.paused, Ordering::Relaxed);
                    self.push_notification(
                        NotificationKind::Info,
                        if self.paused {
                            "Telemetry stream paused"
                        } else {
                            "Telemetry stream resumed"
                        },
                    );
                }
                ui.add_space(8.0);
                let status_text = if self.response_status.isolated {
                    "Host isolated"
                } else {
                    "Monitoring"
                };
                let status_color = if self.response_status.isolated {
                    theme::WARN
                } else {
                    theme::ACCENT
                };
                ui.label(
                    egui::RichText::new(status_text)
                        .color(status_color)
                        .size(12.0)
                        .strong(),
                );
            });
        });
        ui.add_space(4.0);
        action
    }
    fn show_network_operation_overlay(&mut self, ctx: &egui::Context) {
        if self.network_operation.is_none() {
            return;
        }
        let label = match self
            .network_operation
            .as_ref()
            .map(|op| op.kind)
            .unwrap_or(NetworkOperationKind::Isolate)
        {
            NetworkOperationKind::Isolate => "Applying host isolation...",
            NetworkOperationKind::Restore => "Restoring network access...",
        };
        egui::Area::new("network-operation-overlay".into())
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .interactable(false)
            .show(ctx, |ui| {
                egui::Frame::NONE
                    .fill(egui::Color32::from_black_alpha(180))
                    .stroke(egui::Stroke::new(1.0, theme::BORDER))
                    .corner_radius(12.0)
                    .inner_margin(egui::Margin::symmetric(18, 16))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().size(18.0));
                            ui.add_space(10.0);
                            ui.label(
                                egui::RichText::new(label)
                                    .color(theme::TEXT)
                                    .size(12.5)
                                    .strong(),
                            );
                        });
                    });
            });
    }
    fn show_notifications_overlay(&mut self, ctx: &egui::Context) {
        if self.notifications.is_empty() {
            return;
        }
        let now = std::time::Instant::now();
        self.notifications.retain(|n| n.expires_at > now);
        if self.notifications.is_empty() {
            return;
        }
        let max_height = (ctx.available_rect().height() * 0.45).max(140.0);
        let width = 340.0_f32.min(ctx.available_rect().width() - 24.0);
        egui::Area::new("notifications-overlay".into())
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-14.0, -14.0))
            .show(ctx, |ui| {
                ui.set_width(width);
                egui::Frame::NONE
                    .fill(egui::Color32::from_black_alpha(168))
                    .stroke(egui::Stroke::new(1.0, theme::BORDER))
                    .corner_radius(12.0)
                    .inner_margin(egui::Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("Notifications")
                                    .color(theme::TEXT2)
                                    .size(10.5)
                                    .strong(),
                            );
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(format!("{} open", self.notifications.len()))
                                    .color(theme::TEXT3)
                                    .size(10.0),
                            );
                        });
                        ui.add_space(6.0);
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .max_height(max_height)
                            .show(ui, |ui| {
                                let ids: Vec<u64> = self.notifications.iter().map(|n| n.id).collect();
                                for id in ids {
                                    let Some(index) = self.notifications.iter().position(|n| n.id == id)
                                    else {
                                        continue;
                                    };
                                    let (kind, text, expires_at) = {
                                        let n = &self.notifications[index];
                                        (n.kind, n.text.clone(), n.expires_at)
                                    };
                                    let remaining = expires_at
                                        .saturating_duration_since(now)
                                        .as_secs_f32()
                                        / NOTIFICATION_TTL.as_secs_f32();
                                    let secs_left = expires_at.saturating_duration_since(now).as_secs();
                                    let (accent, label) = match kind {
                                        NotificationKind::Info => (theme::ACCENT, "Info"),
                                        NotificationKind::Success => (theme::ACCENT, "Success"),
                                        NotificationKind::Warning => (theme::WARN, "Warning"),
                                        NotificationKind::Error => (theme::DANGER, "Error"),
                                    };
                                    egui::Frame::NONE
                                        .fill(theme::SURFACE2)
                                        .stroke(egui::Stroke::new(1.0, theme::BORDER))
                                        .corner_radius(10.0)
                                        .inner_margin(egui::Margin::symmetric(10, 9))
                                        .show(ui, |ui| {
                                            ui.horizontal_top(|ui| {
                                                let countdown = Self::show_notification_countdown_circle(
                                                    ui,
                                                    remaining.clamp(0.0, 1.0),
                                                    accent,
                                                )
                                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                .on_hover_text(format!(
                                                    "Auto-dismiss in {secs_left}s. Click to reset to 60s."
                                                ));
                                                if countdown.clicked() {
                                                    if let Some(notification) = self.notifications.iter_mut().find(|n| n.id == id) {
                                                        notification.expires_at = std::time::Instant::now() + NOTIFICATION_TTL;
                                                    }
                                                }
                                                ui.add_space(8.0);
                                                let (bar_rect, _) = ui.allocate_exact_size(
                                                    egui::vec2(3.0, 34.0),
                                                    egui::Sense::hover(),
                                                );
                                                ui.painter().rect_filled(bar_rect, 2.0, accent);
                                                ui.add_space(8.0);
                                                ui.vertical(|ui| {
                                                    ui.label(
                                                        egui::RichText::new(label)
                                                            .color(accent)
                                                            .size(10.0)
                                                            .strong(),
                                                    );
                                                    ui.add(
                                                        egui::Label::new(
                                                            egui::RichText::new(text)
                                                                .color(theme::TEXT)
                                                                .size(11.0),
                                                        )
                                                        .wrap(),
                                                    );
                                                });
                                                ui.with_layout(
                                                    egui::Layout::right_to_left(egui::Align::TOP),
                                                    |ui| {
                                                        let close = ui
                                                            .add(
                                                                egui::Button::new(
                                                                    egui::RichText::new("x")
                                                                        .color(theme::TEXT2)
                                                                        .size(10.5),
                                                                )
                                                                .fill(theme::SURFACE3)
                                                                .stroke(egui::Stroke::new(
                                                                    1.0,
                                                                    theme::BORDER,
                                                                ))
                                                                .corner_radius(4.0),
                                                            )
                                                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                            .on_hover_text("Dismiss this notification.");
                                                        if close.clicked() {
                                                            self.notifications.remove(index);
                                                        }
                                                    },
                                                );
                                            });
                                        });
                                    ui.add_space(8.0);
                                }
                            });
                    });
            });
    }
    fn show_notification_countdown_circle(
        ui: &mut egui::Ui,
        progress: f32,
        accent: egui::Color32,
    ) -> egui::Response {
        let (rect, response) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
        let center = rect.center();
        let radius = 7.0;
        let stroke_bg = egui::Stroke::new(2.0, theme::BORDER);
        let stroke_fg = egui::Stroke::new(2.2, accent);
        ui.painter().circle_stroke(center, radius, stroke_bg);
        let clamped = progress.clamp(0.0, 1.0);
        if clamped > 0.0 {
            let start_angle = -std::f32::consts::FRAC_PI_2;
            let sweep = std::f32::consts::TAU * clamped;
            let segments = ((sweep / std::f32::consts::TAU) * 40.0).ceil().max(2.0) as usize;
            let mut points = Vec::with_capacity(segments + 1);
            for i in 0..=segments {
                let t = i as f32 / segments as f32;
                let angle = start_angle + sweep * t;
                points.push(egui::pos2(
                    center.x + angle.cos() * radius,
                    center.y + angle.sin() * radius,
                ));
            }
            ui.painter().add(egui::Shape::line(points, stroke_fg));
        }
        response
    }
}

impl eframe::App for VigilApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_font_zoom_shortcut(&ctx);
        self.sync_ui_scale(&ctx);
        self.refresh_active_response_state();
        self.poll_network_operation();
        self.sync_tray_state();
        self.trim_history_buffers();
        if self.show_window.swap(false, Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if let Some(nav) = self.pending_nav.lock().unwrap().take() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            self.active_tab = Tab::Alerts;
            self.kill_confirm = false;
            self.unseen_alerts = 0;
            let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
            self.selected_alert = process_list::selection_for_pid(
                &self.alerts,
                nav.pid,
                self.alerts.iter().find(|a| {
                    a.timestamp == nav.timestamp
                        && a.proc_name == nav.proc_name
                        && a.remote_addr == nav.remote_addr
                }),
                process_list::Kind::Alerts,
            );
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.exit_requested {
            #[cfg(target_os = "linux")]
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            #[cfg(not(target_os = "linux"))]
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        let handled_events = self.drain_events(UI_EVENT_BUDGET);
        if handled_events {
            ctx.request_repaint();
        }
        if self.active_tab == Tab::Alerts && self.unseen_alerts > 0 {
            self.unseen_alerts = 0;
            let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
        }
        let header_action = egui::Panel::top("header")
            .exact_size(48.0)
            .frame(egui::Frame::NONE.fill(theme::SURFACE))
            .show_inside(ui, |ui| self.show_header(ui));
        if let Some(action) = header_action.inner {
            self.handle_inspector_action(action, &ctx);
        }
        let new_tab = egui::Panel::top("tabs")
            .exact_size(36.0)
            .frame(egui::Frame::NONE.fill(theme::SURFACE))
            .show_inside(ui, |ui| {
                tab_bar::tab_bar(
                    ui,
                    self.active_tab,
                    self.cached_activity_process_count,
                    self.cached_alerts_process_count,
                )
            })
            .inner;
        if new_tab != self.active_tab {
            self.active_tab = new_tab;
            self.kill_confirm = false;
        }
        let mut inspector_action: Option<inspector::Action> = None;
        let inspector_request = self.current_inspector_request();
        self.refresh_inspector_snapshot(inspector_request);
        if matches!(self.active_tab, Tab::Activity | Tab::Alerts) {
            let selected_info: Option<&ProcessSelection> = match self.active_tab {
                Tab::Activity => self.selected_activity.as_ref(),
                Tab::Alerts => self.selected_alert.as_ref(),
                _ => None,
            };
            let kill_confirm = self.kill_confirm;
            inspector_action = egui::Panel::right("inspector")
                .exact_size(320.0)
                .resizable(false)
                .frame(
                    egui::Frame::NONE
                        .fill(theme::SURFACE)
                        .stroke(egui::Stroke::new(1.0, theme::BORDER))
                        .inner_margin(egui::Margin::symmetric(12, 0)),
                )
                .show_inside(ui, |ui| {
                    inspector::show(ui, selected_info, kill_confirm, &self.inspector_snapshot)
                })
                .inner;
        }
        if let Some(action) = inspector_action {
            self.handle_inspector_action(action, &ctx);
        }
        self.show_response_confirm_window(&ctx);
        self.show_kill_confirm_window(&ctx);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::same(12)),
            )
            .show_inside(ui, |ui| match self.active_tab {
                Tab::Activity => {
                    if activity::show(
                        ui,
                        &self.activity,
                        &mut self.selected_activity,
                        &mut self.activity_table,
                        self.data_version,
                        &mut self.activity_cache,
                    ) {
                        self.activity.clear();
                        self.selected_activity = None;
                    }
                }
                Tab::Alerts => {
                    if alerts::show(
                        ui,
                        &self.alerts,
                        &mut self.selected_alert,
                        &mut self.alerts_table,
                        self.data_version,
                        &mut self.alerts_cache,
                    ) {
                        self.alerts.clear();
                        self.selected_alert = None;
                        self.unseen_alerts = 0;
                        let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
                    }
                }
                Tab::Settings => {
                    let elevated = crate::autostart::is_elevated();
                    let changed = settings::show(ui, &mut self.settings, elevated);
                    if self.settings.grant_capabilities_requested {
                        self.settings.grant_capabilities_requested = false;
                        match crate::autostart::relaunch_as_admin() {
                            Ok(()) => {
                                std::process::exit(0);
                            }
                            Err(err) => {
                                self.push_notification(
                                    NotificationKind::Error,
                                    format!("Could not elevate: {err}"),
                                );
                            }
                        }
                    }
                    if self.settings.uninstall_requested {
                        self.settings.uninstall_requested = false;
                        self.execute_uninstall_from_settings();
                    }
                    if changed {
                        let locked_policy_changes;
                        {
                            let mut cfg = self.cfg.write().unwrap();
                            locked_policy_changes =
                                !elevated && self.settings.policy_edits_pending(&cfg);
                            self.settings.apply_to(&mut cfg, elevated);
                            if cfg.autostart {
                                if crate::autostart::enable() {
                                    cfg.autostart = true;
                                }
                            } else {
                                crate::autostart::disable();
                            }
                            cfg.save();
                            self.settings = settings::SettingsDraft::from_config(&cfg);
                        }
                        if locked_policy_changes {
                            self.settings.status_msg = Some((
                                "Admin Mode is required to save policy changes; only non-sensitive preferences were persisted.".into(),
                                std::time::Instant::now(),
                            ));
                            self.push_notification(
                                NotificationKind::Warning,
                                "Policy edits require Admin Mode. Only non-sensitive preferences were saved.",
                            );
                        }
                        self.sync_ui_scale(&ctx);
                        if self.settings.status_msg.is_none() {
                            self.settings.status_msg =
                                Some(("Settings auto-saved.".into(), std::time::Instant::now()));
                        }
                    }
                }
                Tab::Firewall => {
                    if let Some(fw_action) = firewall::show(ui, &mut self.selected_firewall) {
                        let message = match fw_action {
                            FirewallAction::UnblockIp { rule_name: _, target } => Some(
                                match active_response::unblock_remote(&target) {
                                    Ok(msg) => msg,
                                    Err(e) => format!("Unblock failed: {e}"),
                                },
                            ),
                            FirewallAction::UnblockProcess { rule_name: _, pid, path } => {
                                Some(match active_response::unblock_process(pid, &path) {
                                    Ok(msg) => msg,
                                    Err(e) => format!("Unblock failed: {e}"),
                                })
                            }
                            FirewallAction::ClearDomainBlock { domain } => Some(
                                match active_response::unblock_domain(&domain) {
                                    Ok(msg) => msg,
                                    Err(e) => format!("Clear domain block failed: {e}"),
                                },
                            ),
                            FirewallAction::RestoreIsolation => {
                                if self.start_network_operation(NetworkOperationKind::Restore, false) {
                                    None
                                } else if self.network_operation.is_some() {
                                    Some(
                                        "Restore failed: another network action is already in progress."
                                            .to_string(),
                                    )
                                } else {
                                    None
                                }
                            }
                            FirewallAction::RestoreProcess { pid, path } => Some(
                                match active_response::resume_process(pid, &path) {
                                    Ok(msg) => msg,
                                    Err(e) => format!("Resume failed: {e}"),
                                },
                            ),
                        };
                        if let Some(msg) = message {
                            self.push_notification(
                                if msg.contains("failed") || msg.contains("No ") {
                                    NotificationKind::Error
                                } else {
                                    NotificationKind::Success
                                },
                                msg,
                            );
                        }
                    }
                }
                Tab::Help => help::show(ui),
            });
        self.show_notifications_overlay(&ctx);
        self.show_network_operation_overlay(&ctx);
        ctx.request_repaint_after(
            if self.network_operation.is_some()
                || self.inspector_snapshot_rx.is_some()
                || !self.notifications.is_empty()
            {
                UI_BUSY_REPAINT
            } else {
                UI_IDLE_REPAINT
            },
        );
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [
            0x14 as f32 / 255.0,
            0x15 as f32 / 255.0,
            0x1A as f32 / 255.0,
            1.0,
        ]
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        let state = UiState {
            active_tab: self.active_tab,
            activity_table: self.activity_table.clone(),
            alerts_table: self.alerts_table.clone(),
        };
        eframe::set_value(storage, "ui", &state);
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

fn display_target_label(path: &str, pid: u32) -> String {
    if !path.is_empty() {
        return path.to_string();
    }
    if pid != 0 {
        return format!("PID {pid}");
    }
    "the selected target".to_string()
}
