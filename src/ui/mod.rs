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
    pub filter: String,
    pub sort_col: usize,
    pub sort_asc: bool,
}

impl TableState {
    pub fn new(default_col: usize, default_asc: bool) -> Self {
        Self {
            filter: String::new(),
            sort_col: default_col,
            sort_asc: default_asc,
        }
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
        if self.sort_col == col {
            if self.sort_asc {
                " ▲"
            } else {
                " ▼"
            }
        } else {
            ""
        }
    }
}

/// Current selection in the Activity / Alerts views.
///
/// `selected_connection` is optional so the inspector can show the whole
/// process summary when the card header is clicked, or a specific socket when
/// a stacked connection row is clicked.
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

/// Returns `true` when the process name is just a resolved-PID placeholder
/// like `<11540>` rather than a real executable name.
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

/// Returns `true` when the UI knows enough about the process to offer path
/// based actions such as Open Loc or Trust.
pub fn has_known_location(sel: &ProcessSelection) -> bool {
    !sel.proc_path.is_empty() && !is_ghost_process_name(&sel.proc_name)
}

// ── App state ─────────────────────────────────────────────────────────────────

pub struct VigilApp {
    activity: VecDeque<ConnInfo>, // all connections, newest first, max 500
    alerts: VecDeque<ConnInfo>,   // scored threats only, newest first, max 200
    selected_activity: Option<ProcessSelection>,
    selected_alert: Option<ProcessSelection>,
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
    /// Shared table state — the **same** `TableState` drives both the Activity
    /// and Alerts grids, so clicking a column header (or resizing — egui
    /// persists the widths keyed on `id_salt` which we now set identically)
    /// affects both views.  The user asked for the two grids to share sort
    /// order and column widths, and this is the minimal-diff way to do it.
    table_state: TableState,
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
            // Shared default: sort by Time (column 0) descending (newest first).
            // The Alerts tab previously defaulted to Score-descending; since the
            // grids now share state, picking one default means the user sees a
            // consistent view when switching tabs.  Score is just one click away.
            table_state: TableState::new(0, false),
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
                            let _ = self.tray_tx.try_send(TrayCmd::Alert(Box::new(info)));
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
        let selected_info: Option<ProcessSelection> = match self.active_tab {
            Tab::Activity => self.selected_activity.clone(),
            Tab::Alerts => self.selected_alert.clone(),
            _ => None,
        };

        match action {
            inspector::Action::Trust => {
                if let Some(info) = selected_info {
                    if !has_known_location(&info) {
                        return;
                    }
                    let mut cfg = self.cfg.write().unwrap();
                    if cfg.add_trusted(&info.proc_name) {
                        cfg.save();
                        self.settings = settings::SettingsDraft::from_config(&cfg);
                    }
                }
            }
            inspector::Action::OpenLocation => {
                if let Some(info) = selected_info {
                    if has_known_location(&info) {
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
                    if !is_ghost_process_name(&info.proc_name) {
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
                        if self.alerts.is_empty() {
                            self.unseen_alerts = 0;
                            let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
                        }
                    }
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
                    .size(16.0)
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

                let resp = ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand);
                if resp.clicked() {
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
                tab_bar::tab_bar(
                    ui,
                    self.active_tab,
                    process_count(&self.activity),
                    process_count(&self.alerts),
                )
            })
            .inner;

        if new_tab != self.active_tab {
            self.active_tab = new_tab;
            self.kill_confirm = false;
        }

        // ── Inspector side panel (Activity / Alerts only) ─────────────────────
        let mut inspector_action: Option<inspector::Action> = None;

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
                .show_inside(ui, |ui| inspector::show(ui, selected_info, kill_confirm))
                .inner;
        }

        if let Some(action) = inspector_action {
            self.handle_inspector_action(action);
        }

        // ── Central content ───────────────────────────────────────────────────
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
                        &mut self.table_state,
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
                        &mut self.table_state,
                    ) {
                        self.alerts.clear();
                        self.selected_alert = None;
                        self.unseen_alerts = 0;
                        let _ = self.tray_tx.try_send(TrayCmd::ResetOk);
                    }
                }
                Tab::Settings => {
                    let changed = settings::show(ui, &mut self.settings);
                    if changed {
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
                        self.settings.status_msg =
                            Some(("Settings auto-saved.".into(), std::time::Instant::now()));
                    }
                }
                Tab::Help => {
                    help::show(ui);
                }
            });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [
            0x14 as f32 / 255.0,
            0x15 as f32 / 255.0,
            0x1A as f32 / 255.0,
            1.0,
        ]
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn push_capped<T>(deque: &mut VecDeque<T>, item: T, cap: usize) {
    deque.push_front(item);
    if deque.len() > cap {
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

fn process_count(rows: &VecDeque<ConnInfo>) -> usize {
    use std::collections::HashSet;
    rows.iter()
        .map(|info| info.pid)
        .collect::<HashSet<_>>()
        .len()
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
