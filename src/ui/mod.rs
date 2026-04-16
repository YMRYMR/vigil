//! Main UI module — eframe application.
//!
//! `VigilApp` is the single `eframe::App` implementor.
//! In eframe 0.34, `App::ui(ui, frame)` receives the window-level `Ui`; panels
//! are added with `show_inside(ui, …)` instead of `show(ctx, …)`.

pub mod activity;
pub mod alerts;
pub mod help;
pub mod inspector;
pub mod settings;
pub mod tab_bar;
pub mod theme;

use crate::config::Config;
use crate::tray::TrayCmd;
use crate::types::{ConnEvent, ConnInfo};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tab_bar::Tab;
use tokio::sync::broadcast;

// ── Table sort / filter state ─────────────────────────────────────────────────

pub struct TableState {
    pub filter:   String,
    pub sort_col: usize,
    pub sort_asc: bool,
}

impl TableState {
    pub fn new(default_col: usize, default_asc: bool) -> Self {
        Self { filter: String::new(), sort_col: default_col, sort_asc: default_asc }
    }

    /// Called when a column header is clicked.
    /// Toggles direction if same column; resets to ascending on a new column.
    pub fn toggle(&mut self, col: usize) {
        if self.sort_col == col {
            self.sort_asc = !self.sort_asc;
        } else {
            self.sort_col = col;
            self.sort_asc = true;
        }
    }

    /// Arrow indicator appended to the active sort column header label.
    pub fn arrow(&self, col: usize) -> &'static str {
        if self.sort_col == col { if self.sort_asc { " ▲" } else { " ▼" } } else { "" }
    }
}

// ── App state ─────────────────────────────────────────────────────────────────

pub struct VigilApp {
    activity: VecDeque<ConnInfo>, // all connections, newest first, max 500
    alerts: VecDeque<ConnInfo>,   // scored threats only, newest first, max 200
    selected_activity: Option<usize>,
    selected_alert: Option<usize>,
    active_tab: Tab,
    unseen_alerts: usize,
    event_rx: broadcast::Receiver<ConnEvent>,
    tray_tx: std::sync::mpsc::SyncSender<TrayCmd>,
    show_window: Arc<AtomicBool>,
    /// Set by the tray thread when the user clicks a notification.
    /// Drained each frame: open window → Alerts tab → select row.
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
    cfg: Arc<RwLock<Config>>,
    settings: settings::SettingsDraft,
    kill_confirm: bool,
    paused: bool,
    activity_state: TableState,
    alerts_state: TableState,
}

impl VigilApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        cfg: Arc<RwLock<Config>>,
        event_rx: broadcast::Receiver<ConnEvent>,
        tray_tx: std::sync::mpsc::SyncSender<TrayCmd>,
        show_window: Arc<AtomicBool>,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
    ) -> Self {
        theme::apply(&cc.egui_ctx);

        let settings = {
            let c = cfg.read().unwrap();
            settings::SettingsDraft::from_config(&c)
        };

        cc.egui_ctx
            .request_repaint_after(std::time::Duration::from_millis(100));

        Self {
            activity: VecDeque::new(),
            alerts: VecDeque::new(),
            selected_activity: None,
            selected_alert: None,
            active_tab: Tab::Activity,
            unseen_alerts: 0,
            event_rx,
            tray_tx,
            show_window,
            pending_nav,
            cfg,
            settings,
            kill_confirm: false,
            paused: false,
            activity_state: TableState::new(0, false), // Time col, newest-first
            alerts_state:   TableState::new(4, false), // Score col, highest-first
        }
    }

    // ── Event draining ────────────────────────────────────────────────────────

    fn drain_events(&mut self) {
        use broadcast::error::TryRecvError;
        loop {
            match self.event_rx.try_recv() {
                Ok(event) => {
                    if self.paused {
                        continue;
                    }
                    match event {
                        ConnEvent::Alert(info) => {
                            push_capped(&mut self.activity, info.clone(), 500);
                            push_capped(&mut self.alerts, info.clone(), 200);
                            self.unseen_alerts += 1;
                            let _ = self.tray_tx.try_send(TrayCmd::Alert(info));
                        }
                        ConnEvent::New(info) => {
                            push_capped(&mut self.activity, info, 500);
                        }
                        ConnEvent::Closed { .. } => {}
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Lagged(n)) => {
                    tracing::warn!("UI dropped {n} broadcast events");
                }
                Err(TryRecvError::Closed) => break,
            }
        }
    }

    // ── Inspector action handler ──────────────────────────────────────────────

    fn handle_inspector_action(&mut self, action: inspector::Action) {
        let selected_info: Option<ConnInfo> = match self.active_tab {
            Tab::Activity => self
                .selected_activity
                .and_then(|i| self.activity.get(i))
                .cloned(),
            Tab::Alerts => self
                .selected_alert
                .and_then(|i| self.alerts.get(i))
                .cloned(),
            _ => None,
        };

        match action {
            inspector::Action::Trust => {
                if let Some(info) = selected_info {
                    let mut cfg = self.cfg.write().unwrap();
                    if cfg.add_trusted(&info.proc_name) {
                        cfg.save();
                        self.settings = settings::SettingsDraft::from_config(&cfg);
                    }
                }
            }
            inspector::Action::OpenLocation => {
                if let Some(info) = selected_info {
                    if !info.proc_path.is_empty() {
                        let path = std::path::Path::new(&info.proc_path);
                        let dir = path.parent().unwrap_or(path);
                        let _ = open::that(dir);
                    }
                }
            }
            inspector::Action::Kill => {
                self.kill_confirm = true;
            }
            inspector::Action::KillConfirmed => {
                if let Some(info) = selected_info {
                    kill_process(info.pid);
                }
                self.kill_confirm = false;
            }
            inspector::Action::KillCancelled => {
                self.kill_confirm = false;
            }
        }
    }

    // ── Header ────────────────────────────────────────────────────────────────

    fn show_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_centered(|ui| {
            ui.add_space(12.0);

            ui.label(
                egui::RichText::new("Vigil")
                    .color(theme::TEXT)
                    .size(15.0)
                    .strong(),
            );
            ui.add_space(10.0);

            let (dot, label, color) = if self.paused {
                ("○", "Paused", theme::TEXT2)
            } else {
                ("●", "Monitoring", theme::ACCENT)
            };
            ui.label(
                egui::RichText::new(format!("{dot}  {label}"))
                    .color(color)
                    .size(11.5),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(12.0);
                let btn_label = if self.paused { "Resume" } else { "Pause" };
                let btn = egui::Button::new(
                    egui::RichText::new(btn_label)
                        .color(theme::TEXT2)
                        .size(11.0),
                )
                .fill(theme::SURFACE2)
                .stroke(egui::Stroke::new(1.0, theme::BORDER))
                .corner_radius(4.0);

                if ui.add(btn).clicked() {
                    self.paused = !self.paused;
                    if !self.paused {
                        let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
                    }
                }
            });
        });
    }
}

// ── eframe::App impl ──────────────────────────────────────────────────────────

impl eframe::App for VigilApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        // ── Tray "Open Vigil" signal ──────────────────────────────────────────
        if self.show_window.swap(false, Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }

        // ── Notification click → navigate to alert ────────────────────────────
        if let Some(nav) = self.pending_nav.lock().unwrap().take() {
            // Show and focus the window
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            // Switch to Alerts tab
            self.active_tab    = Tab::Alerts;
            self.kill_confirm  = false;
            self.unseen_alerts = 0;
            let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
            // Find the matching alert and select it.
            // Match on timestamp + proc_name + remote_addr (unique enough).
            if let Some(idx) = self.alerts.iter().position(|a| {
                a.timestamp   == nav.timestamp
                    && a.proc_name   == nav.proc_name
                    && a.remote_addr == nav.remote_addr
            }) {
                self.selected_alert = Some(idx);
            }
        }

        // ── Hide to tray on window close ──────────────────────────────────────
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }

        // ── Drain monitor events ──────────────────────────────────────────────
        self.drain_events();

        // ── Clear unseen_alerts counter when on the Alerts tab ────────────────
        if self.active_tab == Tab::Alerts && self.unseen_alerts > 0 {
            self.unseen_alerts = 0;
            let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
        }

        // ── Header panel ──────────────────────────────────────────────────────
        egui::Panel::top("header")
            .exact_size(48.0)
            .frame(egui::Frame::NONE.fill(theme::SURFACE))
            .show_inside(ui, |ui| {
                self.show_header(ui);
            });

        // ── Tab bar panel ─────────────────────────────────────────────────────
        let new_tab = egui::Panel::top("tabs")
            .exact_size(36.0)
            .frame(egui::Frame::NONE.fill(theme::SURFACE))
            .show_inside(ui, |ui| {
                tab_bar::tab_bar(ui, self.active_tab, self.unseen_alerts)
            })
            .inner;

        if new_tab != self.active_tab {
            self.active_tab = new_tab;
            self.kill_confirm = false;
        }

        // ── Inspector side panel (Activity / Alerts only) ─────────────────────
        let mut inspector_action: Option<inspector::Action> = None;

        if matches!(self.active_tab, Tab::Activity | Tab::Alerts) {
            let selected_info: Option<&ConnInfo> = match self.active_tab {
                Tab::Activity => self
                    .selected_activity
                    .and_then(|i| self.activity.get(i)),
                Tab::Alerts => self.selected_alert.and_then(|i| self.alerts.get(i)),
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
                .show_inside(ui, |ui| inspector::show(ui, selected_info, kill_confirm))
                .inner;
        }

        if let Some(action) = inspector_action {
            self.handle_inspector_action(action);
        }

        // ── Central content ───────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(theme::BG).inner_margin(egui::Margin::ZERO))
            .show_inside(ui, |ui| match self.active_tab {
                Tab::Activity => {
                    if activity::show(ui, &self.activity, &mut self.selected_activity, &mut self.activity_state) {
                        self.activity.clear();
                        self.selected_activity = None;
                    }
                }
                Tab::Alerts => {
                    if alerts::show(ui, &self.alerts, &mut self.selected_alert, &mut self.alerts_state) {
                        self.alerts.clear();
                        self.selected_alert = None;
                        self.unseen_alerts = 0;
                        let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
                    }
                }
                Tab::Settings => {
                    let saved = settings::show(ui, &mut self.settings);
                    if saved {
                        let mut cfg = self.cfg.write().unwrap();
                        self.settings.apply_to(&mut cfg);
                        if cfg.autostart {
                            if crate::autostart::enable() {
                                cfg.autostart = true;
                            }
                        } else {
                            crate::autostart::disable();
                        }
                        cfg.save();
                    }
                }
                Tab::Help => {
                    help::show(ui);
                }
            });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [0x14 as f32 / 255.0, 0x15 as f32 / 255.0, 0x1A as f32 / 255.0, 1.0]
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn push_capped<T>(deque: &mut VecDeque<T>, item: T, cap: usize) {
    deque.push_front(item);
    if deque.len() > cap {
        deque.pop_back();
    }
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
