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
            self.invalidate_group_caches();
            self.refresh_selection_after_trim();
        }
    }
    fn refresh_selection_after_trim(&mut self) {
        let activity_pid = self.selected_activity.as_ref().map(|sel| sel.pid);
        self.selected_activity = activity_pid.and_then(|pid| {
            process_list::selection_for_pid(
                &self.activity,
                pid,
                self.selected_activity
                    .as_ref()
                    .and_then(|sel| sel.selected_connection.as_ref()),
                process_list::Kind::Activity,
            )
        });
        let alert_pid = self.selected_alert.as_ref().map(|sel| sel.pid);
        self.selected_alert = alert_pid.and_then(|pid| {
            process_list::selection_for_pid(
                &self.alerts,
                pid,
                self.selected_alert
                    .as_ref()
                    .and_then(|sel| sel.selected_connection.as_ref()),
                process_list::Kind::Alerts,
            )
        });
        self.selected_firewall = self.selected_firewall.as_ref().and_then(|sel| {
            if active_response::list_rules().iter().any(|rule| {
                firewall_matches_selection(rule, &sel.target, &sel.rule_type, sel.pid, &sel.path)
            }) {
                Some(sel.clone())
            } else {
                None
            }
        });
    }
    fn invalidate_group_caches(&mut self) {
        self.activity_cache = None;
        self.alerts_cache = None;
    }
    fn update_cached_process_counts(&mut self) {
        self.cached_activity_process_count = process_list::process_count(&self.activity);
        self.cached_alerts_process_count = process_list::process_count(&self.alerts);
    }
    fn handle_event(&mut self, event: ConnEvent) {
        let (activity_cap, alerts_cap) = self.history_caps();
        match &event {
            ConnEvent::New(info) => {
                push_capped(&mut self.activity, info.clone(), activity_cap);
                if let Some(sel) = self.selected_activity.as_ref() {
                    self.selected_activity = process_list::selection_for_pid(
                        &self.activity,
                        sel.pid,
                        sel.selected_connection.as_ref(),
                        process_list::Kind::Activity,
                    );
                }
            }
            ConnEvent::Alert(info) => {
                push_capped(&mut self.activity, info.clone(), activity_cap);
                push_capped(&mut self.alerts, info.clone(), alerts_cap);
                self.unseen_alerts = self.unseen_alerts.saturating_add(1);
                self.settings.alert_count = self.settings.alert_count.saturating_add(1);
                let _ = self
                    .tray_tx
                    .try_send(TrayCmd::AlertCount(self.unseen_alerts));
                if let Some(sel) = self.selected_activity.as_ref() {
                    self.selected_activity = process_list::selection_for_pid(
                        &self.activity,
                        sel.pid,
                        sel.selected_connection.as_ref(),
                        process_list::Kind::Activity,
                    );
                }
                if let Some(sel) = self.selected_alert.as_ref() {
                    self.selected_alert = process_list::selection_for_pid(
                        &self.alerts,
                        sel.pid,
                        sel.selected_connection.as_ref(),
                        process_list::Kind::Alerts,
                    );
                }
            }
            ConnEvent::Closed {
                pid,
                local_addr,
                remote_addr,
            } => {
                let (activity_removed, alert_removed) = {
                    let activity_removed = close_matching(
                        &mut self.activity,
                        *pid,
                        local_addr.as_str(),
                        remote_addr.as_str(),
                    );
                    let alert_removed = close_matching(
                        &mut self.alerts,
                        *pid,
                        local_addr.as_str(),
                        remote_addr.as_str(),
                    );
                    (activity_removed, alert_removed)
                };
                if activity_removed {
                    let current = self
                        .selected_activity
                        .as_ref()
                        .and_then(|sel| sel.selected_connection.as_ref().cloned());
                    self.selected_activity = process_list::selection_for_pid(
                        &self.activity,
                        *pid,
                        current.as_ref(),
                        process_list::Kind::Activity,
                    )
                    .or_else(|| {
                        if self
                            .selected_activity
                            .as_ref()
                            .is_some_and(|sel| sel.pid == *pid)
                        {
                            self.selected_activity.clone()
                        } else {
                            None
                        }
                    });
                }
                if alert_removed {
                    let current = self
                        .selected_alert
                        .as_ref()
                        .and_then(|sel| sel.selected_connection.as_ref().cloned());
                    self.selected_alert = process_list::selection_for_pid(
                        &self.alerts,
                        *pid,
                        current.as_ref(),
                        process_list::Kind::Alerts,
                    )
                    .or_else(|| {
                        if self
                            .selected_alert
                            .as_ref()
                            .is_some_and(|sel| sel.pid == *pid)
                        {
                            self.selected_alert.clone()
                        } else {
                            None
                        }
                    });
                }
            }
        }
        self.data_version = self.data_version.wrapping_add(1);
        self.invalidate_group_caches();
        self.update_cached_process_counts();
        self.refresh_selection_after_trim();
    }
    fn drain_events(&mut self, budget: usize) -> bool {
        let start = std::time::Instant::now();
        let mut handled = false;
        for _ in 0..budget {
            if start.elapsed() >= UI_EVENT_TIME_BUDGET {
                break;
            }
            match self.ui_rx.try_recv() {
                Ok(UiMessage::Event(event)) => {
                    self.handle_event(*event);
                    handled = true;
                }
                Ok(UiMessage::Notification(kind, message)) => {
                    self.push_notification(kind, message);
                    handled = true;
                }
                Ok(UiMessage::ResponseStatus(status)) => {
                    self.response_status = status;
                    self.inspector_snapshot.status = status;
                    handled = true;
                }
                Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        handled
    }
    fn show_header(&mut self, ui: &mut egui::Ui) -> Option<inspector::Action> {
        let mut action = None;
        ui.vertical_centered(|ui| {
            ui.set_height(48.0);
            ui.horizontal(|ui| {
                if let Some(logo) = &self.vigil_logo {
                    ui.add(
                        egui::Image::new(logo)
                            .fit_to_exact_size(egui::vec2(142.0, 54.0))
                            .maintain_aspect_ratio(true),
                    );
                } else {
                    ui.heading(
                        egui::RichText::new("Vigil")
                            .color(theme::TEXT)
                            .size(22.0)
                            .strong(),
                    );
                }
                ui.add_space(12.0);
                if crate::autostart::is_elevated() {
                    admin_chip(ui);
                } else {
                    ui.label(
                        egui::RichText::new(" Standard User ")
                            .color(theme::WARN)
                            .background_color(theme::WARN_BG)
                            .size(10.5)
                            .strong(),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.settings.ui_scale >= 1.75 {
                        ui.add_space(8.0);
                    }
                    if ui.add(admin_btn(" Request Admin ")).clicked() {
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
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(if self.paused {
                                    " Resume Stream "
                                } else {
                                    " Pause Stream "
                                })
                                .color(theme::TEXT)
                                .size(11.0)
                                .strong(),
                            )
                            .fill(if self.paused {
                                theme::SURFACE2
                            } else {
                                theme::ACCENT_BG
                            })
                            .stroke(egui::Stroke::new(
                                1.0,
                                if self.paused {
                                    theme::BORDER
                                } else {
                                    theme::ACCENT
                                },
                            ))
                            .corner_radius(4.0),
                        )
                        .clicked()
                    {
                        self.paused = !self.paused;
                        self.paused_flag.store(self.paused, Ordering::Relaxed);
                    }
                });
            });
        });
        if matches!(self.active_tab, Tab::Activity | Tab::Alerts) {
            let selected_info: Option<&ProcessSelection> = match self.active_tab {
                Tab::Activity => self.selected_activity.as_ref(),
                Tab::Alerts => self.selected_alert.as_ref(),
                _ => None,
            };
            ui.horizontal(|ui| {
                let selected = selected_info.is_some();
                if ui
                    .add_enabled(
                        selected,
                        egui::Button::new(
                            egui::RichText::new(" Kill ")
                                .color(theme::TEXT)
                                .size(11.0)
                                .strong(),
                        )
                        .fill(theme::DANGER_BG)
                        .stroke(egui::Stroke::new(1.0, theme::DANGER))
                        .corner_radius(4.0),
                    )
                    .clicked()
                {
                    action = Some(inspector::Action::Kill);
                }
                if ui
                    .add_enabled(
                        selected,
                        egui::Button::new(
                            egui::RichText::new(" Isolate ")
                                .color(theme::TEXT)
                                .size(11.0)
                                .strong(),
                        )
                        .fill(theme::WARN_BG)
                        .stroke(egui::Stroke::new(1.0, theme::WARN))
                        .corner_radius(4.0),
                    )
                    .clicked()
                {
                    action = Some(inspector::Action::IsolateMachine);
                }
                if ui
                    .add_enabled(
                        selected,
                        egui::Button::new(
                            egui::RichText::new(" Restore ")
                                .color(theme::TEXT)
                                .size(11.0)
                                .strong(),
                        )
                        .fill(theme::ACCENT_BG)
                        .stroke(egui::Stroke::new(1.0, theme::ACCENT))
                        .corner_radius(4.0),
                    )
                    .clicked()
                {
                    action = Some(inspector::Action::RestoreNetwork);
                }
            });
        }
        action
    }
    fn current_inspector_request(&self) -> Option<InspectorSnapshotRequest> {
        match self.active_tab {
            Tab::Activity => self
                .selected_activity
                .as_ref()
                .map(InspectorSnapshotRequest::from_selection),
            Tab::Alerts => self
                .selected_alert
                .as_ref()
                .map(InspectorSnapshotRequest::from_selection),
            _ => None,
        }
    }
    fn refresh_inspector_snapshot(&mut self, request: Option<InspectorSnapshotRequest>) {
        if let Some(rx) = &self.inspector_snapshot_rx {
            if let Ok((key, snapshot)) = rx.try_recv() {
                if self.inspector_snapshot_key.as_ref() == Some(&key) {
                    self.inspector_snapshot = snapshot;
                }
                self.inspector_snapshot_rx = None;
            }
        }
        let Some(request) = request else {
            self.inspector_snapshot_key = None;
            self.inspector_snapshot = active_response::InspectorSnapshot {
                status: self.response_status,
                ..Default::default()
            };
            return;
        };
        let key_changed = self.inspector_snapshot_key.as_ref() != Some(&request.key);
        if key_changed {
            self.inspector_snapshot_key = Some(request.key.clone());
            self.inspector_snapshot = active_response::InspectorSnapshot {
                status: self.response_status,
                ..Default::default()
            };
        }
        if key_changed
            || self.inspector_snapshot_last_started.elapsed() >= INSPECTOR_SNAPSHOT_REFRESH
        {
            self.inspector_snapshot_last_started = std::time::Instant::now();
            let (tx, rx) = mpsc::channel();
            let key = request.key.clone();
            std::thread::spawn(move || {
                let snapshot = active_response::inspector_snapshot(
                    request.pid,
                    &request.proc_path,
                    request.selected_connection.as_ref(),
                );
                let _ = tx.send((key, snapshot));
            });
            self.inspector_snapshot_rx = Some(rx);
        }
    }
    fn push_notification(&mut self, kind: NotificationKind, text: impl Into<String>) {
        let text = text.into();
        self.notifications.push_back(Notification {
            id: self.next_notification_id,
            kind,
            text,
            expires_at: std::time::Instant::now() + NOTIFICATION_TTL,
        });
        self.next_notification_id = self.next_notification_id.wrapping_add(1);
        while self.notifications.len() > 24 {
            self.notifications.pop_front();
        }
    }
    fn handle_inspector_action(&mut self, action: inspector::Action, ctx: &egui::Context) {
        let selected_info = match self.active_tab {
            Tab::Activity => self.selected_activity.as_ref(),
            Tab::Alerts => self.selected_alert.as_ref(),
            _ => None,
        };
        match action {
            inspector::Action::Kill => {
                if selected_info.is_some() {
                    self.kill_confirm = true;
                }
            }
            inspector::Action::BlockRemote(duration) => {
                if let Some(info) = selected_info {
                    self.response_confirm = Some(PendingResponse::BlockRemote {
                        target: info.remote_addr.clone(),
                        preset: duration,
                    });
                }
            }
            inspector::Action::BlockDomain => {
                if let Some(info) = selected_info {
                    if let Some(domain) =
                        active_response::connection_domain(info.selected_connection.as_ref())
                    {
                        self.response_confirm = Some(PendingResponse::BlockDomain { domain });
                    }
                }
            }
            inspector::Action::BlockProcess(duration) => {
                if let Some(info) = selected_info {
                    self.response_confirm = Some(PendingResponse::BlockProcess {
                        pid: info.pid,
                        path: info.proc_path.clone(),
                        preset: duration,
                    });
                }
            }
            inspector::Action::SuspendProcess => {
                if let Some(info) = selected_info {
                    self.response_confirm = Some(PendingResponse::SuspendProcess {
                        pid: info.pid,
                        path: info.proc_path.clone(),
                        proc_name: info.proc_name.clone(),
                    });
                }
            }
            inspector::Action::ResumeProcess => {
                if let Some(info) = selected_info {
                    self.response_confirm = Some(PendingResponse::ResumeProcess {
                        pid: info.pid,
                        path: info.proc_path.clone(),
                    });
                }
            }
            inspector::Action::FreezeAutoruns => {
                self.response_confirm = Some(PendingResponse::FreezeAutoruns);
            }
            inspector::Action::RevertAutoruns => {
                self.response_confirm = Some(PendingResponse::RevertAutoruns);
            }
            inspector::Action::QuarantineProfile => {
                if let Some(info) = selected_info {
                    self.response_confirm = Some(PendingResponse::QuarantineProfile {
                        pid: info.pid,
                        path: info.proc_path.clone(),
                        proc_name: info.proc_name.clone(),
                    });
                }
            }
            inspector::Action::ClearQuarantineProfile => {
                if let Some(info) = selected_info {
                    self.response_confirm = Some(PendingResponse::ClearQuarantineProfile {
                        pid: info.pid,
                        path: info.proc_path.clone(),
                    });
                }
            }
            inspector::Action::KillConnection => {
                if let Some(conn) = selected_info.and_then(|info| info.selected_connection.clone())
                {
                    self.response_confirm = Some(PendingResponse::KillConnection(Box::new(conn)));
                }
            }
            inspector::Action::UnblockRemote => {
                if let Some(info) = selected_info {
                    self.response_confirm =
                        Some(PendingResponse::UnblockRemote(info.remote_addr.clone()));
                }
            }
            inspector::Action::UnblockDomain => {
                if let Some(info) = selected_info {
                    if let Some(domain) =
                        active_response::connection_domain(info.selected_connection.as_ref())
                    {
                        self.response_confirm = Some(PendingResponse::UnblockDomain(domain));
                    }
                }
            }
            inspector::Action::UnblockProcess => {
                if let Some(info) = selected_info {
                    self.response_confirm = Some(PendingResponse::UnblockProcess {
                        pid: info.pid,
                        path: info.proc_path.clone(),
                    });
                }
            }
            inspector::Action::KillConfirmed => {
                if let Some(info) = selected_info {
                    self.kill_confirm = false;
                    kill_process(info.pid);
                    self.push_notification(
                        NotificationKind::Success,
                        format!("Sent kill signal to PID {}", info.pid),
                    );
                }
            }
            inspector::Action::KillCancelled => {
                self.kill_confirm = false;
            }
            inspector::Action::IsolateMachine => {
                self.response_confirm = Some(PendingResponse::IsolateMachine);
            }
            inspector::Action::RestoreNetwork => {
                self.response_confirm = Some(PendingResponse::RestoreNetwork);
            }
            inspector::Action::Copy(text) => {
                ctx.copy_text(text);
                self.push_notification(NotificationKind::Success, "Copied to clipboard.");
            }
        }
    }
    fn start_network_operation(&mut self, kind: NetworkOperationKind, scheduled: bool) -> bool {
        if self.network_operation.is_some() {
            return false;
        }
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = match kind {
                NetworkOperationKind::Isolate => match active_response::isolate_machine() {
                    Ok(message) => NetworkOperationResult {
                        message,
                        status: active_response::status(),
                    },
                    Err(err) => NetworkOperationResult {
                        message: format!("Isolation failed: {err}"),
                        status: active_response::status(),
                    },
                },
                NetworkOperationKind::Restore => match active_response::restore_network() {
                    Ok(message) => NetworkOperationResult {
                        message,
                        status: active_response::status(),
                    },
                    Err(err) => NetworkOperationResult {
                        message: format!("Restore failed: {err}"),
                        status: active_response::status(),
                    },
                },
            };
            let _ = tx.send(result);
        });
        self.network_operation = Some(NetworkOperation {
            kind,
            scheduled,
            rx,
        });
        true
    }
    fn poll_network_operation(&mut self) {
        let Some(operation) = self.network_operation.take() else {
            return;
        };
        match operation.rx.try_recv() {
            Ok(result) => {
                self.response_status = result.status;
                self.inspector_snapshot.status = self.response_status;
                if operation.scheduled {
                    self.scheduled_lockdown_active = self.response_status.isolated;
                }
                self.push_notification(Self::kind_from_message(&result.message), result.message);
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.network_operation = Some(operation);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.push_notification(
                    NotificationKind::Error,
                    "Network action did not return a result.",
                );
            }
        }
    }
    fn refresh_active_response_state(&mut self) {
        if let Some(rx) = &self.reconcile_rx {
            if let Ok(status) = rx.try_recv() {
                self.response_status = status;
                self.reconcile_rx = None;
            }
        }
        if self.reconcile_rx.is_none()
            && self.last_response_reconcile.elapsed() >= std::time::Duration::from_secs(5)
        {
            self.last_response_reconcile = std::time::Instant::now();
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                active_response::reconcile();
                let _ = tx.send(active_response::status());
            });
            self.reconcile_rx = Some(rx);
        }
        let schedule = {
            let cfg = self.cfg.read().unwrap();
            cfg.lockdown_schedule.clone()
        };
        if self.last_schedule_check.elapsed() >= std::time::Duration::from_secs(1) {
            self.last_schedule_check = std::time::Instant::now();
            self.scheduled_target = schedule.and_then(|sched| {
                let now = Local::now();
                let weekday = now.weekday().number_from_monday() as u8;
                let minute = now.hour() as u16 * 60 + now.minute() as u16;
                if sched.days.contains(&weekday)
                    && minute >= sched.start_minute
                    && minute < sched.end_minute
                {
                    Some(true)
                } else {
                    Some(false)
                }
            });
        }
        if let Some(target) = self.scheduled_target {
            if target {
                if self.response_status.isolated {
                    self.scheduled_lockdown_active = true;
                } else if !self.scheduled_lockdown_active {
                    let _ = self.start_network_operation(NetworkOperationKind::Isolate, true);
                }
            } else if self.scheduled_lockdown_active {
                if self.response_status.isolated {
                    let _ = self.start_network_operation(NetworkOperationKind::Restore, true);
                } else {
                    self.scheduled_lockdown_active = false;
                }
            }
        }
    }
    fn sync_tray_state(&mut self) {
        let isolated = self.response_status.isolated;
        if isolated != self.tray_lockdown_sent {
            let _ = self.tray_tx.try_send(if isolated {
                TrayCmd::LockdownOn
            } else {
                TrayCmd::LockdownOff
            });
            self.tray_lockdown_sent = isolated;
        }
    }
    fn execute_uninstall_from_settings(&mut self) {
        match uninstall::run() {
            Ok(message) => self.push_notification(NotificationKind::Success, message),
            Err(err) => {
                self.push_notification(NotificationKind::Error, format!("Uninstall failed: {err}"))
            }
        }
    }
    fn show_kill_confirm_window(&mut self, ctx: &egui::Context) {
        if !self.kill_confirm {
            return;
        }
        let selected_info = match self.active_tab {
            Tab::Activity => self.selected_activity.as_ref(),
            Tab::Alerts => self.selected_alert.as_ref(),
            _ => None,
        };
        let Some(info) = selected_info else {
            self.kill_confirm = false;
            return;
        };
        let label = if !info.proc_path.is_empty() {
            info.proc_path.as_str()
        } else {
            info.proc_name.as_str()
        };
        let title = "Terminate process";
        let body = format!("Kill {label} (PID {})?", info.pid);
        let mut keep_open = true;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .frame(
                egui::Frame::window(&ctx.style())
                    .fill(theme::SURFACE)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER))
                    .inner_margin(egui::Margin::symmetric(14, 12)),
            )
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(body).color(theme::TEXT).size(11.0));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Kill")
                                    .color(theme::TEXT)
                                    .size(11.0)
                                    .strong(),
                            )
                            .fill(theme::DANGER_BG)
                            .stroke(egui::Stroke::new(1.0, theme::DANGER))
                            .corner_radius(6.0)
                            .min_size(egui::vec2(82.0, 28.0)),
                        )
                        .clicked()
                    {
                        kill_process(info.pid);
                        remove_pid(&mut self.activity, info.pid);
                        remove_pid(&mut self.alerts, info.pid);
                        if self
                            .selected_activity
                            .as_ref()
                            .is_some_and(|sel| sel.pid == info.pid)
                        {
                            self.selected_activity = None;
                        }
                        if self
                            .selected_alert
                            .as_ref()
                            .is_some_and(|sel| sel.pid == info.pid)
                        {
                            self.selected_alert = None;
                        }
                        self.invalidate_group_caches();
                        self.push_notification(
                            NotificationKind::Warning,
                            format!("Terminated {label} (PID {})", info.pid),
                        );
                        self.kill_confirm = false;
                        keep_open = false;
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Cancel")
                                    .color(theme::TEXT)
                                    .size(11.0)
                                    .strong(),
                            )
                            .fill(theme::SURFACE2)
                            .stroke(egui::Stroke::new(1.0, theme::BORDER))
                            .corner_radius(6.0)
                            .min_size(egui::vec2(82.0, 28.0)),
                        )
                        .clicked()
                    {
                        self.kill_confirm = false;
                        keep_open = false;
                    }
                });
            });
        if !keep_open {
            self.kill_confirm = false;
        }
    }
    fn execute_pending_response(&mut self, pending: PendingResponse) {
        match pending {
            PendingResponse::BlockRemote { target, preset } => {
                let message = match active_response::block_remote_for(&target, preset) {
                    Ok(message) => message,
                    Err(err) => format!("Block remote failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::BlockDomain { domain } => {
                let message = match active_response::block_domain(&domain) {
                    Ok(message) => message,
                    Err(err) => format!("Block domain failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::BlockProcess { pid, path, preset } => {
                let message = match active_response::block_process_for(pid, &path, preset) {
                    Ok(message) => message,
                    Err(err) => format!("Block process failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::SuspendProcess {
                pid,
                path,
                proc_name: _,
            } => {
                let message = match active_response::suspend_process(pid, &path) {
                    Ok(message) => message,
                    Err(err) => format!("Suspend failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::ResumeProcess { pid, path } => {
                let message = match active_response::resume_process(pid, &path) {
                    Ok(message) => message,
                    Err(err) => format!("Resume failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::FreezeAutoruns => {
                let message = match active_response::freeze_autoruns() {
                    Ok(message) => message,
                    Err(err) => format!("Autorun freeze failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::RevertAutoruns => {
                let message = match active_response::revert_autoruns() {
                    Ok(message) => message,
                    Err(err) => format!("Autorun restore failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::QuarantineProfile {
                pid,
                path,
                proc_name: _,
            } => {
                let message = match active_response::quarantine_profile(pid, &path) {
                    Ok(message) => message,
                    Err(err) => format!("Profile quarantine failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::ClearQuarantineProfile { pid, path } => {
                let message = match active_response::clear_quarantine_profile(pid, &path) {
                    Ok(message) => message,
                    Err(err) => format!("Profile restore failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::KillConnection(conn) => {
                crate::active_response::terminate_live_connection(&conn);
                self.push_notification(
                    NotificationKind::Success,
                    format!("Terminated connection {}", conn.remote_addr),
                );
            }
            PendingResponse::UnblockRemote(target) => {
                let message = match active_response::unblock_remote(&target) {
                    Ok(message) => message,
                    Err(err) => format!("Remove block failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::UnblockDomain(domain) => {
                let message = match active_response::unblock_domain(&domain) {
                    Ok(message) => message,
                    Err(err) => format!("Remove domain block failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::UnblockProcess { pid, path } => {
                let message = match active_response::unblock_process(pid, &path) {
                    Ok(message) => message,
                    Err(err) => format!("Remove process block failed: {err}"),
                };
                self.response_status = active_response::status();
                self.inspector_snapshot.status = self.response_status;
                self.push_notification(Self::kind_from_message(&message), message);
            }
            PendingResponse::IsolateMachine => {
                if !self.start_network_operation(NetworkOperationKind::Isolate, false) {
                    self.push_notification(
                        NotificationKind::Warning,
                        "Another network action is already in progress.",
                    );
                }
            }
            PendingResponse::RestoreNetwork => {
                if !self.start_network_operation(NetworkOperationKind::Restore, false) {
                    self.push_notification(
                        NotificationKind::Warning,
                        "Another network action is already in progress.",
                    );
                }
            }
        }
    }

    fn kind_from_message(message: &str) -> NotificationKind {
        let lower = message.to_ascii_lowercase();
        if lower.contains("could not")
            || lower.contains("failed")
            || lower.contains("error")
            || lower.contains("denied")
            || lower.contains("not found")
            || lower.contains("no ")
        {
            NotificationKind::Error
        } else {
            NotificationKind::Success
        }
    }

    fn show_network_operation_overlay(&self, ctx: &egui::Context) {
        let Some(operation) = self.network_operation.as_ref() else {
            return;
        };
        let label = match operation.kind {
            NetworkOperationKind::Isolate => "Applying machine isolation",
            NetworkOperationKind::Restore => "Restoring network access",
        };
        egui::Area::new(egui::Id::new("network_operation_overlay"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 16.0))
            .show(ctx, |ui| {
                egui::Frame::NONE
                    .fill(egui::Color32::from_black_alpha(192))
                    .stroke(egui::Stroke::new(1.0, theme::BORDER))
                    .corner_radius(12.0)
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().size(14.0));
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new(label)
                                    .color(theme::TEXT)
                                    .size(11.0)
                                    .strong(),
                            );
                        });
                    });
            });
    }
    fn show_response_confirm_window(&mut self, ctx: &egui::Context) {
        let Some(pending) = self.response_confirm.as_ref() else {
            return;
        };
        let title = match pending {
            PendingResponse::BlockRemote { .. } => "Block remote",
            PendingResponse::BlockDomain { .. } => "Block domain",
            PendingResponse::BlockProcess { .. } => "Block process",
            PendingResponse::SuspendProcess { .. } => "Suspend process",
            PendingResponse::ResumeProcess { .. } => "Resume process",
            PendingResponse::FreezeAutoruns => "Freeze autoruns",
            PendingResponse::RevertAutoruns => "Restore autoruns",
            PendingResponse::QuarantineProfile { .. } => "Quarantine profile",
            PendingResponse::ClearQuarantineProfile { .. } => "Clear quarantine profile",
            PendingResponse::KillConnection(_) => "Kill connection",
            PendingResponse::UnblockRemote(_) => "Remove block",
            PendingResponse::UnblockDomain(_) => "Remove domain block",
            PendingResponse::UnblockProcess { .. } => "Remove process block",
            PendingResponse::IsolateMachine => "Isolate machine",
            PendingResponse::RestoreNetwork => "Restore network",
        };
        let message = match pending {
            PendingResponse::BlockRemote { target, preset } => format!(
                "Block network access to {target} for {}?",
                active_response::describe_duration(*preset)
            ),
            PendingResponse::BlockDomain { domain } => {
                format!("Block outbound connections to {domain}?")
            }
            PendingResponse::BlockProcess { pid, path, preset } => format!(
                "Block process {} ({pid}) for {}?",
                display_target_label(path, *pid),
                active_response::describe_duration(*preset)
            ),
            PendingResponse::SuspendProcess {
                pid,
                path,
                proc_name: _,
            } => format!(
                "Suspend process {} ({pid})?",
                display_target_label(path, *pid)
            ),
            PendingResponse::ResumeProcess { pid, path } => format!(
                "Resume process {} ({pid})?",
                display_target_label(path, *pid)
            ),
            PendingResponse::FreezeAutoruns => {
                "Freeze startup entries and services for the selected process tree?"
                    .to_string()
            }
            PendingResponse::RevertAutoruns => {
                "Restore autoruns previously frozen by Vigil?".to_string()
            }
            PendingResponse::QuarantineProfile {
                pid,
                path,
                proc_name: _,
            } => format!(
                "Create a quarantine profile for {} ({pid})?",
                display_target_label(path, *pid)
            ),
            PendingResponse::ClearQuarantineProfile { pid, path } => format!(
                "Clear the quarantine profile for {} ({pid})?",
                display_target_label(path, *pid)
            ),
            PendingResponse::KillConnection(conn) => format!(
                "Kill the selected connection to {} for {} ({})?",
                conn.remote_addr,
                conn.proc_name,
                conn.pid
            ),
            PendingResponse::UnblockRemote(target) => {
                format!("Remove the network block for {target}?")
            }
            PendingResponse::UnblockDomain(domain) => {
                format!("Remove the domain block for {domain}?")
            }
            PendingResponse::UnblockProcess { pid, path } => {
                format!("Remove the process block for {} ({pid})?", display_target_label(path, *pid))
            }
            PendingResponse::IsolateMachine => {
                "Isolate this machine from the network? This applies the dedicated isolation rule set."
                    .to_string()
            }
            PendingResponse::RestoreNetwork => {
                "Restore network connectivity? This removes the isolation rule set and reapplies scheduled policy state if needed."
                    .to_string()
            }
        };
        let mut keep_open = true;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .frame(
                egui::Frame::window(&ctx.style())
                    .fill(theme::SURFACE)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER))
                    .inner_margin(egui::Margin::symmetric(14, 12)),
            )
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(message).color(theme::TEXT).size(11.0));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Confirm")
                                    .color(theme::TEXT)
                                    .size(11.0)
                                    .strong(),
                            )
                            .fill(theme::ACCENT_BG)
                            .stroke(egui::Stroke::new(1.0, theme::ACCENT))
                            .corner_radius(6.0)
                            .min_size(egui::vec2(82.0, 28.0)),
                        )
                        .clicked()
                    {
                        keep_open = false;
                        self.execute_pending_response(pending.clone());
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Cancel")
                                    .color(theme::TEXT)
                                    .size(11.0)
                                    .strong(),
                            )
                            .fill(theme::SURFACE2)
                            .stroke(egui::Stroke::new(1.0, theme::BORDER))
                            .corner_radius(6.0)
                            .min_size(egui::vec2(82.0, 28.0)),
                        )
                        .clicked()
                    {
                        keep_open = false;
                    }
                });
            });
        if !keep_open {
            self.response_confirm = None;
        }
    }
    fn show_notifications_overlay(&mut self, ctx: &egui::Context) {
        let now = std::time::Instant::now();
        self.notifications
            .retain(|notification| notification.expires_at > now);
        if self.notifications.is_empty() {
            return;
        }
        let width = 420.0;
        let max_height = 360.0;
        egui::Area::new(egui::Id::new("notifications_overlay"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -12.0))
            .show(ctx, |ui| {
                ui.set_max_width(width);
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