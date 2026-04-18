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
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableState {
    pub filter: String,
    pub sort_col: usize,
    pub sort_asc: bool,
    #[serde(default)]
    pub collapsed_pids: HashSet<u32>,
}
impl TableState {
    pub fn new(default_col: usize, default_asc: bool) -> Self {
        Self { filter: String::new(), sort_col: default_col, sort_asc: default_asc, collapsed_pids: HashSet::new() }
    }
    pub fn toggle(&mut self, col: usize) {
        if self.sort_col == col { self.sort_asc = !self.sort_asc; } else { self.sort_col = col; self.sort_asc = true; }
    }
    pub fn arrow(&self, col: usize) -> &'static str {
        if self.sort_col == col { if self.sort_asc { " ^" } else { " v" } } else { "" }
    }
    pub fn is_collapsed(&self, pid: u32) -> bool { self.collapsed_pids.contains(&pid) }
    pub fn toggle_collapsed(&mut self, pid: u32) { if !self.collapsed_pids.insert(pid) { self.collapsed_pids.remove(&pid); } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiState {
    active_tab: Tab,
    activity_table: TableState,
    alerts_table: TableState,
}
impl Default for UiState {
    fn default() -> Self { Self { active_tab: Tab::Activity, activity_table: TableState::new(0, false), alerts_table: TableState::new(4, false) } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationKind { Info, Success, Warning, Error }
#[derive(Debug, Clone)]
struct Notification { id: u64, kind: NotificationKind, text: String }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkOperationKind { Isolate, Restore }
struct NetworkOperation { kind: NetworkOperationKind, rx: mpsc::Receiver<String> }

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
    BlockRemote { target: String, preset: active_response::DurationPreset },
    BlockDomain { domain: String },
    BlockProcess { pid: u32, path: String, preset: active_response::DurationPreset },
    SuspendProcess { pid: u32, path: String, proc_name: String },
    ResumeProcess { pid: u32, path: String },
    FreezeAutoruns,
    RevertAutoruns,
    QuarantineProfile { pid: u32, path: String, proc_name: String },
    ClearQuarantineProfile { pid: u32, path: String },
    KillConnection(Box<ConnInfo>),
    UnblockRemote(String),
    UnblockDomain(String),
    UnblockProcess { pid: u32, path: String },
    IsolateMachine,
    RestoreNetwork,
}

pub fn is_ghost_process_name(name: &str) -> bool {
    let Some(inner) = name.trim().strip_prefix('<').and_then(|s| s.strip_suffix('>')) else { return false; };
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit())
}
pub fn has_known_location(sel: &ProcessSelection) -> bool { !sel.proc_path.is_empty() && !is_ghost_process_name(&sel.proc_name) }

pub struct VigilApp {
    activity: VecDeque<ConnInfo>, alerts: VecDeque<ConnInfo>, selected_activity: Option<ProcessSelection>, selected_alert: Option<ProcessSelection>, active_tab: Tab, unseen_alerts: usize,
    event_rx: broadcast::Receiver<ConnEvent>, tray_tx: std::sync::mpsc::SyncSender<TrayCmd>, show_window: Arc<AtomicBool>, pending_nav: Arc<Mutex<Option<ConnInfo>>>, cfg: Arc<RwLock<Config>>, settings: settings::SettingsDraft,
    kill_confirm: bool, response_confirm: Option<PendingResponse>, response_status: active_response::Status, network_operation: Option<NetworkOperation>, notifications: VecDeque<Notification>, next_notification_id: u64,
    auto_response_state: auto_response::EngineState, response_rule_state: response_rules::EngineState, exit_requested: bool, last_response_reconcile: std::time::Instant, last_schedule_check: std::time::Instant, scheduled_lockdown_active: bool, paused: bool, activity_table: TableState, alerts_table: TableState,
}
const ACTIVITY_CAP: usize = 4096;
const ALERTS_CAP: usize = 2048;

impl VigilApp {
    pub fn new(cc: &eframe::CreationContext<'_>, cfg: Arc<RwLock<Config>>, event_rx: broadcast::Receiver<ConnEvent>, tray_tx: std::sync::mpsc::SyncSender<TrayCmd>, show_window: Arc<AtomicBool>, pending_nav: Arc<Mutex<Option<ConnInfo>>>) -> Self {
        theme::apply(&cc.egui_ctx);
        let settings = { let c = cfg.read().unwrap(); settings::SettingsDraft::from_config(&c) };
        let persisted = cc.storage.and_then(|storage| eframe::get_value::<UiState>(storage, "ui")).unwrap_or_default();
        cc.egui_ctx.request_repaint_after(std::time::Duration::from_millis(16));
        Self { activity: VecDeque::new(), alerts: VecDeque::new(), selected_activity: None, selected_alert: None, active_tab: persisted.active_tab, unseen_alerts: 0, event_rx, tray_tx, show_window, pending_nav, cfg, settings, kill_confirm: false, response_confirm: None, response_status: active_response::status(), network_operation: None, notifications: VecDeque::new(), next_notification_id: 1, auto_response_state: auto_response::EngineState::default(), response_rule_state: response_rules::EngineState::default(), exit_requested: false, last_response_reconcile: std::time::Instant::now(), last_schedule_check: std::time::Instant::now() - std::time::Duration::from_secs(60), scheduled_lockdown_active: false, paused: false, activity_table: persisted.activity_table, alerts_table: persisted.alerts_table }
    }
    fn drain_events(&mut self) -> bool {
        use broadcast::error::TryRecvError;
        let mut handled = false;
        loop {
            match self.event_rx.try_recv() {
                Ok(event) => {
                    handled = true;
                    if self.paused { continue; }
                    match event {
                        ConnEvent::Alert(info) => { push_capped(&mut self.activity, info.clone(), ACTIVITY_CAP); push_capped(&mut self.alerts, info.clone(), ALERTS_CAP); self.unseen_alerts += 1; let _ = self.tray_tx.try_send(TrayCmd::Alert(Box::new(info.clone()))); self.maybe_apply_auto_response(&info); }
                        ConnEvent::New(info) => { push_capped(&mut self.activity, info.clone(), ACTIVITY_CAP); self.maybe_apply_auto_response(&info); }
                        ConnEvent::Closed { .. } => {}
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Lagged(n)) => tracing::warn!("UI dropped {n} broadcast events"),
                Err(TryRecvError::Closed) => break,
            }
        }
        handled
    }
    fn maybe_apply_auto_response(&mut self, info: &ConnInfo) {
        let cfg = self.cfg.read().unwrap().clone();
        if let Some(message) = auto_response::maybe_apply(info, &cfg, &mut self.auto_response_state) { self.push_notification(NotificationKind::Info, message); self.response_status = active_response::status(); }
        if let Some(message) = response_rules::maybe_apply(info, &cfg, &mut self.response_rule_state) { self.push_notification(NotificationKind::Info, message); self.response_status = active_response::status(); }
    }
    fn handle_inspector_action(&mut self, action: inspector::Action, ctx: &egui::Context) {
        let selected_info: Option<ProcessSelection> = match self.active_tab { Tab::Activity => self.selected_activity.clone(), Tab::Alerts => self.selected_alert.clone(), _ => None };
        match action {
            inspector::Action::Trust => {
                if let Some(info) = selected_info { if !has_known_location(&info) { return; } let mut cfg = self.cfg.write().unwrap(); if cfg.add_trusted(&info.proc_name) { cfg.save(); self.settings = settings::SettingsDraft::from_config(&cfg); } }
            }
            inspector::Action::OpenLocation => {
                if let Some(info) = selected_info { if has_known_location(&info) { let path = std::path::Path::new(&info.proc_path); let dir = path.parent().unwrap_or(path); let _ = open::that(dir); } }
            }
            inspector::Action::Kill => self.kill_confirm = true,
            inspector::Action::SuspendProcess => if let Some(info) = selected_info { self.response_confirm = Some(PendingResponse::SuspendProcess { pid: info.pid, path: info.proc_path, proc_name: info.proc_name }); },
            inspector::Action::ResumeProcess => if let Some(info) = selected_info { self.response_confirm = Some(PendingResponse::ResumeProcess { pid: info.pid, path: info.proc_path }); },
            inspector::Action::FreezeAutoruns => self.response_confirm = Some(PendingResponse::FreezeAutoruns),
            inspector::Action::RevertAutoruns => self.response_confirm = Some(PendingResponse::RevertAutoruns),
            inspector::Action::QuarantineProfile => if let Some(info) = selected_info { self.response_confirm = Some(PendingResponse::QuarantineProfile { pid: info.pid, path: info.proc_path, proc_name: info.proc_name }); },
            inspector::Action::ClearQuarantineProfile => if let Some(info) = selected_info { self.response_confirm = Some(PendingResponse::ClearQuarantineProfile { pid: info.pid, path: info.proc_path }); },
            inspector::Action::BlockRemote(preset) => if let Some(info) = selected_info { if let Some(conn) = info.selected_connection.as_ref() { if let Some(target) = active_response::extract_remote_target(&conn.remote_addr) { self.response_confirm = Some(PendingResponse::BlockRemote { target, preset }); } } },
            inspector::Action::BlockDomain => if let Some(info) = selected_info { if let Some(conn) = info.selected_connection.as_ref() { if let Some(domain) = active_response::extract_domain_target(conn) { self.response_confirm = Some(PendingResponse::BlockDomain { domain }); } } },
            inspector::Action::BlockProcess(preset) => if let Some(info) = selected_info { if has_known_location(&info) { self.response_confirm = Some(PendingResponse::BlockProcess { pid: info.pid, path: info.proc_path, preset }); } },
            inspector::Action::KillConnection => if let Some(info) = selected_info { if let Some(conn) = info.selected_connection { self.response_confirm = Some(PendingResponse::KillConnection(Box::new(conn))); } },
            inspector::Action::UnblockRemote => if let Some(info) = selected_info { if let Some(conn) = info.selected_connection.as_ref() { if let Some(target) = active_response::extract_remote_target(&conn.remote_addr) { self.response_confirm = Some(PendingResponse::UnblockRemote(target)); } } },
            inspector::Action::UnblockDomain => if let Some(info) = selected_info { if let Some(conn) = info.selected_connection.as_ref() { if let Some(domain) = active_response::extract_domain_target(conn) { self.response_confirm = Some(PendingResponse::UnblockDomain(domain)); } } },
            inspector::Action::UnblockProcess => if let Some(info) = selected_info { if has_known_location(&info) { self.response_confirm = Some(PendingResponse::UnblockProcess { pid: info.pid, path: info.proc_path }); } },
            inspector::Action::IsolateMachine => self.start_network_operation(NetworkOperationKind::Isolate),
            inspector::Action::RestoreNetwork => self.start_network_operation(NetworkOperationKind::Restore),
            inspector::Action::RequestAdmin => match crate::autostart::relaunch_as_admin() { Ok(()) => { self.exit_requested = true; self.push_notification(NotificationKind::Info, "Reopened Vigil as administrator."); ctx.send_viewport_cmd(egui::ViewportCommand::Close); } Err(err) => { self.push_notification(NotificationKind::Error, format!("Could not relaunch as admin: {err}")); } },
            inspector::Action::KillConfirmed => { if let Some(info) = selected_info { if !is_ghost_process_name(&info.proc_name) { kill_process(info.pid); remove_pid(&mut self.activity, info.pid); remove_pid(&mut self.alerts, info.pid); if self.selected_activity.as_ref().is_some_and(|sel| sel.pid == info.pid) { self.selected_activity = None; } if self.selected_alert.as_ref().is_some_and(|sel| sel.pid == info.pid) { self.selected_alert = None; } if self.alerts.is_empty() { self.unseen_alerts = 0; let _ = self.tray_tx.try_send(TrayCmd::ResetOk); } } } self.kill_confirm = false; }
            inspector::Action::KillCancelled => self.kill_confirm = false,
        }
    }
    fn show_header(&mut self, ui: &mut egui::Ui) -> Option<inspector::Action> { /* unchanged omitted for brevity in patch generation */
        let mut action = None; let network_busy = self.network_operation.is_some();
        ui.horizontal_centered(|ui| {
            ui.add_space(12.0); ui.label(egui::RichText::new("Vigil").color(theme::TEXT).size(16.0).strong()); ui.add_space(10.0);
            let admin = crate::autostart::is_elevated(); let (label, color, filled) = if self.paused { ("Paused", theme::TEXT2, false) } else { ("Monitoring", theme::ACCENT, true) };
            ui.horizontal_wrapped(|ui| {
                let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover()); if filled { ui.painter().circle_filled(dot_rect.center(), 4.0, color); } else { ui.painter().circle_stroke(dot_rect.center(), 4.0, egui::Stroke::new(1.4, color)); }
                ui.add_space(4.0); ui.label(egui::RichText::new(label).color(color).size(11.5)); ui.add_space(6.0);
                if admin { admin_chip(ui); } else { let relaunch = ui.add(admin_btn("Run as Admin")).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Relaunch Vigil with administrator privileges so it can inspect more network activity."); if relaunch.clicked() { action = Some(inspector::Action::RequestAdmin); } }
                if self.settings.scheduled_lockdown_enabled { let schedule_label = if self.scheduled_lockdown_active { format!(" Scheduled {:02}:{:02}-{:02}:{:02} ", self.settings.scheduled_lockdown_start_hour, self.settings.scheduled_lockdown_start_minute, self.settings.scheduled_lockdown_end_hour, self.settings.scheduled_lockdown_end_minute) } else { format!(" Schedule {:02}:{:02}-{:02}:{:02} ", self.settings.scheduled_lockdown_start_hour, self.settings.scheduled_lockdown_start_minute, self.settings.scheduled_lockdown_end_hour, self.settings.scheduled_lockdown_end_minute) }; ui.label(egui::RichText::new(schedule_label).color(if self.scheduled_lockdown_active { theme::DANGER } else { theme::TEXT2 }).background_color(if self.scheduled_lockdown_active { theme::DANGER_BG } else { theme::SURFACE2 }).size(10.0).strong()); }
                if self.response_status.frozen_autoruns { ui.label(egui::RichText::new(" Autoruns frozen ").color(theme::WARN).background_color(theme::WARN_BG).size(10.0).strong()); }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(12.0);
                let btn_label = if self.paused { "Resume" } else { "Pause" };
                let btn = egui::Button::new(egui::RichText::new(btn_label).color(theme::TEXT2).size(11.0)).fill(theme::SURFACE2).stroke(egui::Stroke::new(1.0, theme::BORDER)).corner_radius(4.0);
                let resp = ui.add_enabled(!network_busy, btn).on_hover_cursor(egui::CursorIcon::PointingHand); if resp.clicked() { self.paused = !self.paused; if !self.paused { let _ = self.tray_tx.try_send(TrayCmd::ResetOk); } }
                ui.add_space(8.0);
                let isolate_label = if self.response_status.isolated { "Restore Net" } else { "Isolate Net" };
                let can_act = active_response::can_isolate_network();
                let resp_btn = ui.add_enabled(can_act && !network_busy, egui::Button::new(egui::RichText::new(isolate_label).color(theme::DANGER).size(11.0)).fill(theme::DANGER_BG).stroke(egui::Stroke::new(1.0, theme::DANGER)).corner_radius(4.0));
                let resp_btn = if network_busy { resp_btn.on_hover_text("A network action is already in progress.") } else if can_act { resp_btn.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp_btn.on_hover_text("Administrator privileges are required for network isolation.") };
                if resp_btn.clicked() { action = Some(if self.response_status.isolated { inspector::Action::RestoreNetwork } else { inspector::Action::IsolateMachine }); }
            });
        });
        action
    }
}

/* rest of file unchanged */
