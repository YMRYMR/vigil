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
use crate::tray::TrayCmd;
use crate::types::{ConnEvent, ConnInfo};
use chrono::{Local, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
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
    pub fn toggle(&mut self, col: usize) { if self.sort_col == col { self.sort_asc = !self.sort_asc; } else { self.sort_col = col; self.sort_asc = true; } }
    pub fn arrow(&self, col: usize) -> &'static str { if self.sort_col == col { if self.sort_asc { " ^" } else { " v" } } else { "" } }
    pub fn is_collapsed(&self, pid: u32) -> bool { self.collapsed_pids.contains(&pid) }
    pub fn toggle_collapsed(&mut self, pid: u32) { if !self.collapsed_pids.insert(pid) { self.collapsed_pids.remove(&pid); } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiState { active_tab: Tab, activity_table: TableState, alerts_table: TableState }
impl Default for UiState { fn default() -> Self { Self { active_tab: Tab::Activity, activity_table: TableState::new(0, false), alerts_table: TableState::new(4, false) } } }

#[derive(Clone)]
pub struct ProcessSelection {
    pub pid: u32,
    pub proc_name: String,
    pub proc_path: String,
    pub proc_user: String,
    pub parent_name: String,
    pub parent_pid: u32,
    pub service_name: String,
    pub publisher: String,
    pub score: u8,
    pub reasons: Vec<String>,
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
    QuarantineProfile { pid: u32, path: String, proc_name: String },
    ClearQuarantineProfile { pid: u32, path: String },
    KillConnection(ConnInfo),
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
    kill_confirm: bool, response_confirm: Option<PendingResponse>, response_status: active_response::Status, response_message: Option<(String, std::time::Instant)>, admin_message: Option<(String, std::time::Instant)>, auto_response_state: auto_response::EngineState,
    exit_requested: bool, last_response_reconcile: std::time::Instant, last_schedule_check: std::time::Instant, scheduled_lockdown_active: bool, paused: bool, activity_table: TableState, alerts_table: TableState,
}
const ACTIVITY_CAP: usize = 4096; const ALERTS_CAP: usize = 2048;

impl VigilApp {
    pub fn new(cc: &eframe::CreationContext<'_>, cfg: Arc<RwLock<Config>>, event_rx: broadcast::Receiver<ConnEvent>, tray_tx: std::sync::mpsc::SyncSender<TrayCmd>, show_window: Arc<AtomicBool>, pending_nav: Arc<Mutex<Option<ConnInfo>>>) -> Self {
        theme::apply(&cc.egui_ctx);
        let settings = { let c = cfg.read().unwrap(); settings::SettingsDraft::from_config(&c) };
        let persisted = cc.storage.and_then(|storage| eframe::get_value::<UiState>(storage, "ui")).unwrap_or_default();
        cc.egui_ctx.request_repaint_after(std::time::Duration::from_millis(16));
        Self { activity: VecDeque::new(), alerts: VecDeque::new(), selected_activity: None, selected_alert: None, active_tab: persisted.active_tab, unseen_alerts: 0, event_rx, tray_tx, show_window, pending_nav, cfg, settings, kill_confirm: false, response_confirm: None, response_status: active_response::status(), response_message: None, admin_message: None, auto_response_state: auto_response::EngineState::default(), exit_requested: false, last_response_reconcile: std::time::Instant::now(), last_schedule_check: std::time::Instant::now() - std::time::Duration::from_secs(60), scheduled_lockdown_active: false, paused: false, activity_table: persisted.activity_table, alerts_table: persisted.alerts_table }
    }
    fn drain_events(&mut self) -> bool { use broadcast::error::TryRecvError; let mut handled=false; loop { match self.event_rx.try_recv() { Ok(event)=>{ handled=true; if self.paused { continue; } match event { ConnEvent::Alert(info)=>{ push_capped(&mut self.activity, info.clone(), ACTIVITY_CAP); push_capped(&mut self.alerts, info.clone(), ALERTS_CAP); self.unseen_alerts += 1; let _ = self.tray_tx.try_send(TrayCmd::Alert(Box::new(info.clone()))); self.maybe_apply_auto_response(&info); } ConnEvent::New(info)=>{ push_capped(&mut self.activity, info.clone(), ACTIVITY_CAP); self.maybe_apply_auto_response(&info); } ConnEvent::Closed { .. }=>{} } } Err(TryRecvError::Empty)=>break, Err(TryRecvError::Lagged(n))=>tracing::warn!("UI dropped {n} broadcast events"), Err(TryRecvError::Closed)=>break } } handled }
    fn maybe_apply_auto_response(&mut self, info: &ConnInfo) { let cfg = self.cfg.read().unwrap().clone(); if let Some(message) = auto_response::maybe_apply(info, &cfg, &mut self.auto_response_state) { self.response_message = Some((message, std::time::Instant::now())); self.response_status = active_response::status(); } }
    fn handle_inspector_action(&mut self, action: inspector::Action, ctx: &egui::Context) {
        let selected_info: Option<ProcessSelection> = match self.active_tab { Tab::Activity => self.selected_activity.clone(), Tab::Alerts => self.selected_alert.clone(), _ => None };
        match action {
            inspector::Action::Trust => if let Some(info)=selected_info { if !has_known_location(&info) { return; } let mut cfg=self.cfg.write().unwrap(); if cfg.add_trusted(&info.proc_name) { cfg.save(); self.settings=settings::SettingsDraft::from_config(&cfg); } },
            inspector::Action::OpenLocation => if let Some(info)=selected_info { if has_known_location(&info) { let path=std::path::Path::new(&info.proc_path); let dir=path.parent().unwrap_or(path); let _=open::that(dir); } },
            inspector::Action::Kill => self.kill_confirm = true,
            inspector::Action::SuspendProcess => if let Some(info)=selected_info { self.response_confirm=Some(PendingResponse::SuspendProcess{pid:info.pid,path:info.proc_path,proc_name:info.proc_name}); },
            inspector::Action::ResumeProcess => if let Some(info)=selected_info { self.response_confirm=Some(PendingResponse::ResumeProcess{pid:info.pid,path:info.proc_path}); },
            inspector::Action::QuarantineProfile => if let Some(info)=selected_info { self.response_confirm=Some(PendingResponse::QuarantineProfile{pid:info.pid,path:info.proc_path,proc_name:info.proc_name}); },
            inspector::Action::ClearQuarantineProfile => if let Some(info)=selected_info { self.response_confirm=Some(PendingResponse::ClearQuarantineProfile{pid:info.pid,path:info.proc_path}); },
            inspector::Action::BlockRemote(preset) => if let Some(info)=selected_info { if let Some(conn)=info.selected_connection.as_ref() { if let Some(target)=active_response::extract_remote_target(&conn.remote_addr) { self.response_confirm=Some(PendingResponse::BlockRemote{target,preset}); } } },
            inspector::Action::BlockDomain => if let Some(info)=selected_info { if let Some(conn)=info.selected_connection.as_ref() { if let Some(domain)=active_response::extract_domain_target(conn) { self.response_confirm=Some(PendingResponse::BlockDomain{domain}); } } },
            inspector::Action::BlockProcess(preset) => if let Some(info)=selected_info { if has_known_location(&info) { self.response_confirm=Some(PendingResponse::BlockProcess{pid:info.pid,path:info.proc_path,preset}); } },
            inspector::Action::KillConnection => if let Some(info)=selected_info { if let Some(conn)=info.selected_connection { self.response_confirm=Some(PendingResponse::KillConnection(conn)); } },
            inspector::Action::UnblockRemote => if let Some(info)=selected_info { if let Some(conn)=info.selected_connection.as_ref() { if let Some(target)=active_response::extract_remote_target(&conn.remote_addr) { self.response_confirm=Some(PendingResponse::UnblockRemote(target)); } } },
            inspector::Action::UnblockDomain => if let Some(info)=selected_info { if let Some(conn)=info.selected_connection.as_ref() { if let Some(domain)=active_response::extract_domain_target(conn) { self.response_confirm=Some(PendingResponse::UnblockDomain(domain)); } } },
            inspector::Action::UnblockProcess => if let Some(info)=selected_info { if has_known_location(&info) { self.response_confirm=Some(PendingResponse::UnblockProcess{pid:info.pid,path:info.proc_path}); } },
            inspector::Action::IsolateMachine => self.response_confirm=Some(PendingResponse::IsolateMachine),
            inspector::Action::RestoreNetwork => { self.scheduled_lockdown_active=false; self.response_confirm=Some(PendingResponse::RestoreNetwork); },
            inspector::Action::RequestAdmin => match crate::autostart::relaunch_as_admin() { Ok(()) => { self.exit_requested=true; self.admin_message=Some(("Reopened Vigil as administrator.".into(), std::time::Instant::now())); ctx.send_viewport_cmd(egui::ViewportCommand::Close); } Err(err) => { self.admin_message=Some((format!("Could not relaunch as admin: {err}"), std::time::Instant::now())); } },
            inspector::Action::KillConfirmed => { if let Some(info)=selected_info { if !is_ghost_process_name(&info.proc_name) { kill_process(info.pid); remove_pid(&mut self.activity, info.pid); remove_pid(&mut self.alerts, info.pid); if self.selected_activity.as_ref().is_some_and(|sel| sel.pid == info.pid) { self.selected_activity=None; } if self.selected_alert.as_ref().is_some_and(|sel| sel.pid == info.pid) { self.selected_alert=None; } if self.alerts.is_empty() { self.unseen_alerts=0; let _=self.tray_tx.try_send(TrayCmd::ResetOk); } } } self.kill_confirm=false; },
            inspector::Action::KillCancelled => self.kill_confirm=false,
        }
    }
    fn show_header(&mut self, ui: &mut egui::Ui) -> Option<inspector::Action> {
        let mut action=None; ui.horizontal_centered(|ui| { ui.add_space(12.0); ui.label(egui::RichText::new("Vigil").color(theme::TEXT).size(16.0).strong()); ui.add_space(10.0);
            let admin=crate::autostart::is_elevated(); let (label,color,filled)=if self.paused { ("Paused", theme::TEXT2, false) } else { ("Monitoring", theme::ACCENT, true) };
            ui.horizontal_wrapped(|ui| { let (dot_rect,_) = ui.allocate_exact_size(egui::vec2(8.0,8.0), egui::Sense::hover()); if filled { ui.painter().circle_filled(dot_rect.center(),4.0,color); } else { ui.painter().circle_stroke(dot_rect.center(),4.0,egui::Stroke::new(1.4,color)); } ui.add_space(4.0); ui.label(egui::RichText::new(label).color(color).size(11.5)); ui.add_space(6.0); if admin { admin_chip(ui); } else { let relaunch=ui.add(admin_btn("Run as Admin")).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Relaunch Vigil with administrator privileges so it can inspect more network activity."); if relaunch.clicked() { action=Some(inspector::Action::RequestAdmin); } } if self.settings.scheduled_lockdown_enabled { let schedule_label=if self.scheduled_lockdown_active { format!(" Scheduled {:02}:{:02}-{:02}:{:02} ", self.settings.scheduled_lockdown_start_hour, self.settings.scheduled_lockdown_start_minute, self.settings.scheduled_lockdown_end_hour, self.settings.scheduled_lockdown_end_minute) } else { format!(" Schedule {:02}:{:02}-{:02}:{:02} ", self.settings.scheduled_lockdown_start_hour, self.settings.scheduled_lockdown_start_minute, self.settings.scheduled_lockdown_end_hour, self.settings.scheduled_lockdown_end_minute) }; ui.label(egui::RichText::new(schedule_label).color(if self.scheduled_lockdown_active { theme::DANGER } else { theme::TEXT2 }).background_color(if self.scheduled_lockdown_active { theme::DANGER_BG } else { theme::SURFACE2 }).size(10.0).strong()); } });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { ui.add_space(12.0); let btn_label=if self.paused { "Resume" } else { "Pause" }; let btn=egui::Button::new(egui::RichText::new(btn_label).color(theme::TEXT2).size(11.0)).fill(theme::SURFACE2).stroke(egui::Stroke::new(1.0, theme::BORDER)).corner_radius(4.0); let resp=ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand); if resp.clicked() { self.paused=!self.paused; if !self.paused { let _=self.tray_tx.try_send(TrayCmd::ResetOk); } } ui.add_space(8.0); let isolate_label=if self.response_status.isolated { "Restore Net" } else { "Isolate Net" }; let can_act=active_response::can_modify_firewall(); let resp_btn=ui.add_enabled(can_act, egui::Button::new(egui::RichText::new(isolate_label).color(theme::DANGER).size(11.0)).fill(theme::DANGER_BG).stroke(egui::Stroke::new(1.0, theme::DANGER)).corner_radius(4.0)); let resp_btn=if can_act { resp_btn.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp_btn.on_hover_text("Administrator privileges are required for network isolation.") }; if resp_btn.clicked() { action=Some(if self.response_status.isolated { inspector::Action::RestoreNetwork } else { inspector::Action::IsolateMachine }); } }); }); action }
}

impl eframe::App for VigilApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx=ui.ctx().clone(); self.refresh_active_response_state(); if self.show_window.swap(false, Ordering::Relaxed) { ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true)); ctx.send_viewport_cmd(egui::ViewportCommand::Focus); }
        if let Some(nav)=self.pending_nav.lock().unwrap().take() { ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true)); ctx.send_viewport_cmd(egui::ViewportCommand::Focus); self.active_tab=Tab::Alerts; self.kill_confirm=false; self.unseen_alerts=0; let _=self.tray_tx.try_send(TrayCmd::ResetOk); self.selected_alert=process_list::selection_for_pid(&self.alerts, nav.pid, self.alerts.iter().find(|a| a.timestamp == nav.timestamp && a.proc_name == nav.proc_name && a.remote_addr == nav.remote_addr), process_list::Kind::Alerts); }
        if ctx.input(|i| i.viewport().close_requested()) && !self.exit_requested { ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false)); ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose); }
        let handled_events=self.drain_events(); if handled_events { ctx.request_repaint(); }
        if self.active_tab == Tab::Alerts && self.unseen_alerts > 0 { self.unseen_alerts=0; let _=self.tray_tx.try_send(TrayCmd::ResetOk); }
        let header_action=egui::Panel::top("header").exact_size(48.0).frame(egui::Frame::NONE.fill(theme::SURFACE)).show_inside(ui, |ui| self.show_header(ui)); if let Some(action)=header_action.inner { self.handle_inspector_action(action, &ctx); }
        let new_tab=egui::Panel::top("tabs").exact_size(36.0).frame(egui::Frame::NONE.fill(theme::SURFACE)).show_inside(ui, |ui| tab_bar::tab_bar(ui, self.active_tab, process_count(&self.activity), process_count(&self.alerts))).inner; if new_tab != self.active_tab { self.active_tab=new_tab; self.kill_confirm=false; }
        let mut inspector_action: Option<inspector::Action>=None; if matches!(self.active_tab, Tab::Activity | Tab::Alerts) { let selected_info: Option<&ProcessSelection>=match self.active_tab { Tab::Activity => self.selected_activity.as_ref(), Tab::Alerts => self.selected_alert.as_ref(), _ => None }; let kill_confirm=self.kill_confirm; inspector_action=egui::Panel::right("inspector").exact_size(320.0).resizable(false).frame(egui::Frame::NONE.fill(theme::SURFACE).stroke(egui::Stroke::new(1.0, theme::BORDER)).inner_margin(egui::Margin::symmetric(12, 0))).show_inside(ui, |ui| inspector::show(ui, selected_info, kill_confirm)).inner; }
        if let Some(action)=inspector_action { self.handle_inspector_action(action, &ctx); }
        if let Some(message)=self.response_message.as_ref() { if message.1.elapsed().as_secs() < 4 { egui::Panel::top("active_response_message").exact_size(28.0).frame(egui::Frame::NONE.fill(theme::BG)).show_inside(ui, |ui| { ui.horizontal(|ui| { ui.label(egui::RichText::new(&message.0).color(theme::DANGER).size(10.8).strong()); }); }); } else { self.response_message=None; } }
        if let Some(message)=self.admin_message.as_ref() { if message.1.elapsed().as_secs() < 4 { egui::Panel::top("admin_message").exact_size(28.0).frame(egui::Frame::NONE.fill(theme::BG)).show_inside(ui, |ui| { ui.horizontal(|ui| { ui.label(egui::RichText::new(&message.0).color(theme::ACCENT).size(10.8).strong()); }); }); } else { self.admin_message=None; } }
        self.show_response_confirm(ctx.clone());
        egui::CentralPanel::default().frame(egui::Frame::NONE.fill(theme::BG).inner_margin(egui::Margin::same(12))).show_inside(ui, |ui| match self.active_tab { Tab::Activity => { if activity::show(ui, &self.activity, &mut self.selected_activity, &mut self.activity_table) { self.activity.clear(); self.selected_activity=None; } } Tab::Alerts => { if alerts::show(ui, &self.alerts, &mut self.selected_alert, &mut self.alerts_table) { self.alerts.clear(); self.selected_alert=None; self.unseen_alerts=0; let _=self.tray_tx.try_send(TrayCmd::ResetOk); } } Tab::Settings => { let changed=settings::show(ui, &mut self.settings); if changed { let mut cfg=self.cfg.write().unwrap(); self.settings.apply_to(&mut cfg); if cfg.autostart { if crate::autostart::enable() { cfg.autostart=true; } } else { crate::autostart::disable(); } cfg.save(); self.settings.status_msg=Some(("Settings auto-saved.".into(), std::time::Instant::now())); } } Tab::Help => help::show(ui) });
        ctx.request_repaint_after(std::time::Duration::from_millis(16));
    }
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] { [0x14 as f32 / 255.0, 0x15 as f32 / 255.0, 0x1A as f32 / 255.0, 1.0] }
    fn save(&mut self, storage: &mut dyn eframe::Storage) { let state=UiState { active_tab: self.active_tab, activity_table: self.activity_table.clone(), alerts_table: self.alerts_table.clone() }; eframe::set_value(storage, "ui", &state); }
}

fn admin_chip(ui:&mut egui::Ui){ ui.label(egui::RichText::new(" Admin ").color(theme::ACCENT).background_color(theme::ACCENT_BG).size(10.5).strong()); }
fn admin_btn(text:&str)->egui::Button<'_>{ egui::Button::new(egui::RichText::new(text).color(theme::ACCENT).size(11.0)).fill(theme::ACCENT_BG).stroke(egui::Stroke::new(1.0, theme::ACCENT)).corner_radius(4.0) }

impl VigilApp {
    fn refresh_active_response_state(&mut self) { if self.last_response_reconcile.elapsed().as_secs() >= 1 { active_response::reconcile(); self.response_status=active_response::status(); self.last_response_reconcile=std::time::Instant::now(); } if self.last_schedule_check.elapsed().as_secs() >= 30 { self.apply_scheduled_lockdown(); self.last_schedule_check=std::time::Instant::now(); } }
    fn apply_scheduled_lockdown(&mut self) { let cfg=self.cfg.read().unwrap().clone(); if !cfg.scheduled_lockdown_enabled { self.scheduled_lockdown_active=false; return; } if !active_response::can_modify_firewall() { return; } let now=Local::now(); let minute_of_day=now.hour()*60 + now.minute(); let start=u32::from(cfg.scheduled_lockdown_start_hour.min(23))*60 + u32::from(cfg.scheduled_lockdown_start_minute.min(59)); let end=u32::from(cfg.scheduled_lockdown_end_hour.min(23))*60 + u32::from(cfg.scheduled_lockdown_end_minute.min(59)); let should_lock=if start == end { false } else if start < end { minute_of_day >= start && minute_of_day < end } else { minute_of_day >= start || minute_of_day < end }; if should_lock && !self.scheduled_lockdown_active { match active_response::isolate_machine() { Ok(msg)=>{ self.scheduled_lockdown_active=true; self.response_message=Some((format!("Scheduled lockdown: {msg}"), std::time::Instant::now())); self.response_status=active_response::status(); } Err(err)=> self.response_message=Some((format!("Scheduled lockdown failed: {err}"), std::time::Instant::now())) } } else if !should_lock && self.scheduled_lockdown_active { match active_response::restore_machine() { Ok(msg)=>{ self.scheduled_lockdown_active=false; self.response_message=Some((format!("Scheduled lockdown ended: {msg}"), std::time::Instant::now())); self.response_status=active_response::status(); } Err(err)=> self.response_message=Some((format!("Scheduled restore failed: {err}"), std::time::Instant::now())) } } }
    fn show_response_confirm(&mut self, ctx: egui::Context) { let Some(pending)=self.response_confirm.clone() else { return; }; let (title, body, confirm_label)=match &pending { PendingResponse::BlockRemote { target, preset } => { let (duration,label)=match preset { active_response::DurationPreset::OneHour => ("1 hour","Block 1h"), active_response::DurationPreset::OneDay => ("24 hours","Block 24h"), active_response::DurationPreset::Permanent => ("an unlimited duration","Block permanent") }; ("Block remote IP", format!("Temporarily block outbound traffic to {target} for {duration}?"), label.to_string()) } PendingResponse::BlockDomain { domain } => ("Block domain", format!("Redirect {domain} to the local machine through the Windows hosts file?"), "Block domain".to_string()), PendingResponse::BlockProcess { path, preset, .. } => { let (duration,label)=match preset { active_response::DurationPreset::OneHour => ("1 hour","Block process"), active_response::DurationPreset::OneDay => ("24 hours","Block process"), active_response::DurationPreset::Permanent => ("an unlimited duration","Block process") }; ("Block process", format!("Temporarily block inbound and outbound traffic for {path} for {duration}?"), label.to_string()) } PendingResponse::SuspendProcess { pid, path, .. } => ("Suspend process", if path.is_empty() { format!("Freeze PID {pid} until you explicitly resume it?") } else { format!("Freeze PID {pid} ({path}) until you explicitly resume it?") }, "Suspend".to_string()), PendingResponse::ResumeProcess { pid, path } => ("Resume process", if path.is_empty() { format!("Resume every suspended thread in PID {pid}?") } else { format!("Resume every suspended thread in PID {pid} ({path})?") }, "Resume".to_string()), PendingResponse::QuarantineProfile { pid, path, .. } => ("Quarantine profile", if path.is_empty() { format!("Apply the quarantine preset to PID {pid}? This isolates the network and suspends the process when possible.") } else { format!("Apply the quarantine preset to PID {pid} ({path})? This isolates the network, blocks the executable path, and suspends the process when possible.") }, "Quarantine".to_string()), PendingResponse::ClearQuarantineProfile { pid, path } => ("Clear quarantine", if path.is_empty() { format!("Undo the quarantine preset for PID {pid}? This restores the network and resumes the process when possible.") } else { format!("Undo the quarantine preset for PID {pid} ({path})? This restores the network, removes the process block, and resumes the process when possible.") }, "Clear".to_string()), PendingResponse::KillConnection(conn) => ("Kill connection", format!("Immediately terminate the live TCP connection {} -> {}?", conn.local_addr, conn.remote_addr), "Kill connection".to_string()), PendingResponse::UnblockRemote(target) => ("Remove remote block", format!("Remove the temporary firewall rule for {target}?"), "Unblock".to_string()), PendingResponse::UnblockDomain(domain) => ("Remove domain block", format!("Remove the local hosts-file block for {domain}?"), "Unblock domain".to_string()), PendingResponse::UnblockProcess { path, .. } => ("Remove process block", format!("Remove the temporary firewall rules for {path}?"), "Unblock".to_string()), PendingResponse::IsolateMachine => ("Isolate machine", "Temporarily block inbound and outbound traffic with reversible firewall rules.".to_string(), "Isolate".to_string()), PendingResponse::RestoreNetwork => ("Restore network", "Remove the temporary network-isolation firewall rules?".to_string(), "Restore".to_string()) }; egui::Window::new(title).id(egui::Id::new("active_response_confirm")).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0,0.0)).frame(egui::Frame::NONE.fill(theme::SURFACE2).stroke(egui::Stroke::new(1.0, theme::BORDER)).corner_radius(12.0)).show(&ctx, |ui| { ui.set_min_width(360.0); ui.label(egui::RichText::new(body).color(theme::TEXT2).size(11.5)); ui.add_space(12.0); ui.horizontal(|ui| { let confirm=ui.add(egui::Button::new(egui::RichText::new(confirm_label.as_str()).color(theme::DANGER).size(11.0)).fill(theme::DANGER_BG).stroke(egui::Stroke::new(1.0, theme::DANGER)).corner_radius(6.0)).on_hover_cursor(egui::CursorIcon::PointingHand); if confirm.clicked() { let result=self.execute_pending_response(&pending); self.response_message=Some((result, std::time::Instant::now())); self.response_status=active_response::status(); self.response_confirm=None; } if ui.add(egui::Button::new(egui::RichText::new("Cancel").color(theme::TEXT2).size(11.0)).fill(theme::SURFACE3).stroke(egui::Stroke::new(1.0, theme::BORDER)).corner_radius(6.0)).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() { self.response_confirm=None; } }); }); }
    fn execute_pending_response(&mut self, pending:&PendingResponse)->String { match pending { PendingResponse::BlockRemote { target, preset } => match active_response::block_remote(target,*preset) { Ok(msg)=>msg, Err(err)=>format!("Could not block {target}: {err}") }, PendingResponse::BlockDomain { domain } => match active_response::block_domain(domain) { Ok(msg)=>msg, Err(err)=>format!("Could not block {domain}: {err}") }, PendingResponse::BlockProcess { pid, path, preset } => match active_response::block_process(*pid,path,*preset) { Ok(msg)=>msg, Err(err)=>format!("Could not block {path}: {err}") }, PendingResponse::SuspendProcess { pid, path, proc_name } => match active_response::suspend_process(*pid,path,proc_name) { Ok(msg)=>msg, Err(err)=>format!("Could not suspend PID {pid}: {err}") }, PendingResponse::ResumeProcess { pid, path } => match active_response::resume_process(*pid,path) { Ok(msg)=>msg, Err(err)=>format!("Could not resume PID {pid}: {err}") }, PendingResponse::QuarantineProfile { pid, path, proc_name } => match active_response::apply_quarantine_profile(*pid,path,proc_name) { Ok(msg)=>msg, Err(err)=>format!("Could not apply quarantine profile: {err}") }, PendingResponse::ClearQuarantineProfile { pid, path } => match active_response::clear_quarantine_profile(*pid,path) { Ok(msg)=>msg, Err(err)=>format!("Could not clear quarantine profile: {err}") }, PendingResponse::KillConnection(conn) => match active_response::kill_connection(conn) { Ok(msg)=>msg, Err(err)=>format!("Could not kill {} -> {}: {err}", conn.local_addr, conn.remote_addr) }, PendingResponse::UnblockRemote(target) => match active_response::unblock_remote(target) { Ok(msg)=>msg, Err(err)=>format!("Could not unblock {target}: {err}") }, PendingResponse::UnblockDomain(domain) => match active_response::unblock_domain(domain) { Ok(msg)=>msg, Err(err)=>format!("Could not unblock {domain}: {err}") }, PendingResponse::UnblockProcess { pid, path } => match active_response::unblock_process(*pid,path) { Ok(msg)=>msg, Err(err)=>format!("Could not unblock {path}: {err}") }, PendingResponse::IsolateMachine => match active_response::isolate_machine() { Ok(msg)=>msg, Err(err)=>format!("Could not isolate the machine: {err}") }, PendingResponse::RestoreNetwork => match active_response::restore_machine() { Ok(msg)=>msg, Err(err)=>format!("Could not restore the network: {err}") } } }
}

fn push_capped<T>(deque:&mut VecDeque<T>, item:T, cap:usize){ deque.push_front(item); if deque.len() > cap { deque.pop_back(); } }
pub fn conn_matches_selection(info:&ConnInfo, selected:Option<&ConnInfo>)->bool { selected.is_some_and(|sel| info.timestamp == sel.timestamp && info.pid == sel.pid && info.proc_name == sel.proc_name && info.local_addr == sel.local_addr && info.remote_addr == sel.remote_addr) }
fn remove_pid(rows:&mut VecDeque<ConnInfo>, pid:u32){ rows.retain(|info| info.pid != pid); }
fn process_count(rows:&VecDeque<ConnInfo>)->usize{ use std::collections::HashSet; rows.iter().map(|info| info.pid).collect::<HashSet<_>>().len() }
fn kill_process(pid:u32){ use sysinfo::{Pid, ProcessesToUpdate, System}; let target=Pid::from_u32(pid); let mut sys=System::new(); sys.refresh_processes(ProcessesToUpdate::Some(&[target]), false); if let Some(proc)=sys.process(target){ proc.kill(); } }
