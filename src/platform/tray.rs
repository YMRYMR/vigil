//! System tray icon, context menu, and event loop.
//!
//! # Threading
//! `run()` is designed to be called on a **dedicated OS thread** (not the
//! tokio runtime thread). On Windows/macOS it drives the `tray-icon` crate's
//! event loop. On Linux it uses `ksni` (a pure-Rust StatusNotifierItem client
//! over zbus) to avoid pulling in the unmaintained gtk3 stack.
//!
//! # Commands
//! The caller forwards `TrayCmd` values over a `std::sync::mpsc` channel:
//! - `Alert(Box<ConnInfo>)` — display a notification, switch icon to ⚠
//! - `ResetOk`         — switch icon back to the normal ● state
//! - `SetLockdown(bool)` — force red icon while network isolation is active
//!
//! `show_window` is an `Arc<AtomicBool>` set to `true` when the user clicks
//! "Open Vigil" in the tray menu *or* clicks a notification.
//!
//! `pending_nav` carries the `ConnInfo` of a clicked notification so the UI
//! can switch to the Alerts tab and select the matching row.

use crate::types::ConnInfo;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc::Receiver, Arc, Mutex, OnceLock};

/// Commands sent from the monitor / UI to the tray thread.
#[allow(clippy::large_enum_variant)]
pub enum TrayCmd {
    /// A new threat alert — show a notification and update the icon.
    Alert(Box<ConnInfo>),
    /// Return the icon to the normal "monitoring" state.
    ResetOk,
    /// Toggle lockdown visual state (network isolation).
    SetLockdown(bool),
}

// ── Embedded icon bytes (shared across platforms) ────────────────────────────

const TRAY_GREEN_ICO: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/vigil_tray_green.ico"
));
const TRAY_ORANGE_ICO: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/vigil_tray_orange.ico"
));
const TRAY_RED_ICO: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/vigil_tray_red.ico"
));

// ── Shared fallback loop for environments without a usable tray ──────────────

fn notification_only_loop(
    cmd_rx: Receiver<TrayCmd>,
    show_window: Arc<AtomicBool>,
    pending_nav: Arc<Mutex<Option<ConnInfo>>>,
) {
    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                TrayCmd::Alert(info) => {
                    crate::notifier::send_alert(&info, show_window.clone(), pending_nav.clone());
                }
                TrayCmd::ResetOk | TrayCmd::SetLockdown(_) => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Windows + macOS: tray-icon crate
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;
    use std::sync::atomic::Ordering;
    use tray_icon::{
        menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
        MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    struct TrayIcons {
        ok: tray_icon::Icon,
        alert: tray_icon::Icon,
        lockdown: tray_icon::Icon,
    }

    fn make_circle_icon(r: u8, g: u8, b: u8) -> tray_icon::Icon {
        const SIZE: u32 = 32;
        const CENTER: f32 = 15.5;
        const RADIUS: f32 = 13.0;
        const INNER: f32 = 11.0;

        let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
        for y in 0..SIZE {
            for x in 0..SIZE {
                let dx = x as f32 - CENTER;
                let dy = y as f32 - CENTER;
                let d = (dx * dx + dy * dy).sqrt();
                let idx = ((y * SIZE + x) * 4) as usize;
                if d <= RADIUS {
                    let boost = if d <= INNER { 40u8 } else { 0u8 };
                    rgba[idx] = r.saturating_add(boost);
                    rgba[idx + 1] = g.saturating_add(boost);
                    rgba[idx + 2] = b.saturating_add(boost);
                    rgba[idx + 3] = 255;
                }
            }
        }
        tray_icon::Icon::from_rgba(rgba, SIZE, SIZE).expect("hardcoded icon dimensions are valid")
    }

    fn icon_from_embedded_ico(label: &str, bytes: &[u8]) -> Option<tray_icon::Icon> {
        let image = match image::load_from_memory_with_format(bytes, image::ImageFormat::Ico) {
            Ok(image) => image,
            Err(err) => {
                tracing::warn!("failed to decode embedded tray icon {label}: {err}");
                return None;
            }
        };
        let image = image.into_rgba8();
        let (w, h) = (image.width(), image.height());
        match tray_icon::Icon::from_rgba(image.into_raw(), w, h) {
            Ok(icon) => Some(icon),
            Err(err) => {
                tracing::warn!("failed to build tray icon {label} from decoded bitmap: {err}");
                None
            }
        }
    }

    fn load_tray_icons() -> TrayIcons {
        TrayIcons {
            ok: icon_from_embedded_ico("green", TRAY_GREEN_ICO)
                .unwrap_or_else(|| make_circle_icon(0x22, 0xC5, 0x5E)),
            alert: icon_from_embedded_ico("orange", TRAY_ORANGE_ICO)
                .unwrap_or_else(|| make_circle_icon(0xF5, 0x9E, 0x0B)),
            lockdown: icon_from_embedded_ico("red", TRAY_RED_ICO)
                .unwrap_or_else(|| make_circle_icon(0xEF, 0x44, 0x44)),
        }
    }

    fn apply_tray_visual_state(
        tray: &TrayIcon,
        icons: &TrayIcons,
        in_alert: bool,
        in_lockdown: bool,
    ) {
        if in_lockdown {
            let _ = tray.set_icon(Some(icons.lockdown.clone()));
            let _ = tray.set_tooltip(Some("Vigil — Lockdown active"));
        } else if in_alert {
            let _ = tray.set_icon(Some(icons.alert.clone()));
            let _ = tray.set_tooltip(Some("Vigil — ⚠ Threat detected"));
        } else {
            let _ = tray.set_icon(Some(icons.ok.clone()));
            let _ = tray.set_tooltip(Some("Vigil — Monitoring"));
        }
    }

    pub fn run(
        cmd_rx: Receiver<TrayCmd>,
        show_window: Arc<AtomicBool>,
        log_dir: PathBuf,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
        egui_ctx: Arc<OnceLock<egui::Context>>,
    ) {
        let icons = load_tray_icons();

        let init_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let menu = Menu::new();
            let open_item = MenuItem::new("Open Vigil", true, None);
            let logs_item = MenuItem::new("Open Logs Folder", true, None);
            let quit_item = MenuItem::new("Quit", true, None);
            let _ = menu.append_items(&[
                &open_item,
                &logs_item,
                &PredefinedMenuItem::separator(),
                &quit_item,
            ]);
            let open_id = open_item.id().clone();
            let logs_id = logs_item.id().clone();
            let quit_id = quit_item.id().clone();

            let tray = TrayIconBuilder::new()
                .with_tooltip("Vigil — Network Monitor  ●")
                .with_icon(icons.ok.clone())
                .with_menu(Box::new(menu))
                .with_menu_on_left_click(false)
                .build()
                .map_err(|e| e.to_string())?;

            Ok::<_, String>((tray, quit_id, open_id, logs_id))
        }));

        match init_result {
            Ok(Ok((tray, quit_id, open_id, logs_id))) => {
                event_loop(
                    tray,
                    icons,
                    cmd_rx,
                    quit_id,
                    open_id,
                    logs_id,
                    log_dir,
                    show_window,
                    pending_nav,
                    egui_ctx,
                );
            }
            _ => {
                tracing::warn!("tray init failed — running without tray icon");
                notification_only_loop(cmd_rx, show_window, pending_nav);
            }
        }
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn event_loop(
        tray: TrayIcon,
        icons: TrayIcons,
        cmd_rx: Receiver<TrayCmd>,
        quit_id: tray_icon::menu::MenuId,
        open_id: tray_icon::menu::MenuId,
        logs_id: tray_icon::menu::MenuId,
        log_dir: PathBuf,
        show_window: Arc<AtomicBool>,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
        _egui_ctx: Arc<OnceLock<egui::Context>>,
    ) {
        use windows::Win32::UI::WindowsAndMessaging::{
            DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
        };

        let mut msg = MSG::default();
        let mut in_alert = false;
        let mut in_lockdown = false;

        loop {
            unsafe {
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    if msg.message == 0x0012 {
                        return;
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }

            while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = ev
                {
                    show_window.store(true, Ordering::Relaxed);
                }
            }

            while let Ok(ev) = MenuEvent::receiver().try_recv() {
                if ev.id == quit_id {
                    std::process::exit(0);
                } else if ev.id == open_id {
                    show_window.store(true, Ordering::Relaxed);
                } else if ev.id == logs_id {
                    let _ = open::that(&log_dir);
                }
            }

            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    TrayCmd::Alert(info) => {
                        crate::notifier::send_alert(
                            &info,
                            show_window.clone(),
                            pending_nav.clone(),
                        );
                        in_alert = true;
                        apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                    }
                    TrayCmd::ResetOk => {
                        in_alert = false;
                        apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                    }
                    TrayCmd::SetLockdown(active) => {
                        in_lockdown = active;
                        apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                    }
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    // macOS: tray-icon crate runs its event loop via the AppKit run loop
    // driven by the process's main thread. Since the tray thread here is
    // a dedicated std::thread, we just poll commands and let tray-icon's
    // internal handlers process events on their own.
    #[cfg(target_os = "macos")]
    #[allow(clippy::too_many_arguments)]
    fn event_loop(
        tray: TrayIcon,
        icons: TrayIcons,
        cmd_rx: Receiver<TrayCmd>,
        quit_id: tray_icon::menu::MenuId,
        open_id: tray_icon::menu::MenuId,
        logs_id: tray_icon::menu::MenuId,
        log_dir: PathBuf,
        show_window: Arc<AtomicBool>,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
        _egui_ctx: Arc<OnceLock<egui::Context>>,
    ) {
        let mut in_alert = false;
        let mut in_lockdown = false;

        loop {
            while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = ev
                {
                    show_window.store(true, Ordering::Relaxed);
                }
            }

            while let Ok(ev) = MenuEvent::receiver().try_recv() {
                if ev.id == quit_id {
                    std::process::exit(0);
                } else if ev.id == open_id {
                    show_window.store(true, Ordering::Relaxed);
                } else if ev.id == logs_id {
                    let _ = open::that(&log_dir);
                }
            }

            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    TrayCmd::Alert(info) => {
                        crate::notifier::send_alert(
                            &info,
                            show_window.clone(),
                            pending_nav.clone(),
                        );
                        in_alert = true;
                        apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                    }
                    TrayCmd::ResetOk => {
                        in_alert = false;
                        apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                    }
                    TrayCmd::SetLockdown(active) => {
                        in_lockdown = active;
                        apply_tray_visual_state(&tray, &icons, in_alert, in_lockdown);
                    }
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn embedded_tray_icons_decode() {
            assert!(icon_from_embedded_ico("green-test", TRAY_GREEN_ICO).is_some());
            assert!(icon_from_embedded_ico("orange-test", TRAY_ORANGE_ICO).is_some());
            assert!(icon_from_embedded_ico("red-test", TRAY_RED_ICO).is_some());
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Linux: ksni (pure-Rust StatusNotifierItem, no gtk3)
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use ksni::blocking::{Handle, TrayMethods};
    use ksni::menu::{MenuItem as KsniMenuItem, StandardItem};
    use ksni::Tray;
    use std::sync::atomic::Ordering;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum IconState {
        Ok,
        Alert,
        Lockdown,
    }

    impl IconState {
        fn icon_name(self) -> &'static str {
            match self {
                IconState::Ok => "vigil-tray-green",
                IconState::Alert => "vigil-tray-orange",
                IconState::Lockdown => "vigil-tray-red",
            }
        }

        fn tooltip(self) -> &'static str {
            match self {
                IconState::Ok => "Vigil — Monitoring",
                IconState::Alert => "Vigil — ⚠ Threat detected",
                IconState::Lockdown => "Vigil — Lockdown active",
            }
        }
    }

    /// Tray state owned by ksni's background task. Menu activation
    /// callbacks run here and mutate the `Arc<AtomicBool>` / open the
    /// logs folder directly — no cross-thread channel needed for them.
    struct VigilTray {
        state: IconState,
        show_window: Arc<AtomicBool>,
        log_dir: PathBuf,
        egui_ctx: Arc<OnceLock<egui::Context>>,
    }

    impl VigilTray {
        fn wake_ui(&self) {
            self.show_window.store(true, Ordering::Relaxed);
            if let Some(ec) = self.egui_ctx.get() {
                ec.request_repaint();
            }
        }
    }

    impl Tray for VigilTray {
        fn id(&self) -> String {
            "vigil".into()
        }

        fn title(&self) -> String {
            "Vigil".into()
        }

        fn icon_name(&self) -> String {
            self.state.icon_name().into()
        }

        fn icon_theme_path(&self) -> String {
            linux_icon_dir().to_str().unwrap_or("").to_string()
        }

        fn tool_tip(&self) -> ksni::ToolTip {
            ksni::ToolTip {
                title: self.state.tooltip().into(),
                ..Default::default()
            }
        }

        fn activate(&mut self, _x: i32, _y: i32) {
            // Left-click on the icon itself.
            self.wake_ui();
        }

        fn menu(&self) -> Vec<KsniMenuItem<Self>> {
            vec![
                StandardItem {
                    label: "Open Vigil".into(),
                    activate: Box::new(|this: &mut Self| this.wake_ui()),
                    ..Default::default()
                }
                .into(),
                StandardItem {
                    label: "Open Logs Folder".into(),
                    activate: Box::new(|this: &mut Self| {
                        let _ = open::that(&this.log_dir);
                    }),
                    ..Default::default()
                }
                .into(),
                KsniMenuItem::Separator,
                StandardItem {
                    label: "Quit".into(),
                    icon_name: "application-exit".into(),
                    activate: Box::new(|_this: &mut Self| std::process::exit(0)),
                    ..Default::default()
                }
                .into(),
            ]
        }
    }

    fn linux_icon_dir() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(".local/share/icons/hicolor/32x32/apps")
    }

    /// Write embedded ICOs as PNGs to the user's hicolor theme dir so SNI
    /// hosts (GNOME AppIndicator, KDE tray, etc.) can render them by name.
    fn ensure_themed_icons() {
        let dir = linux_icon_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!("tray: cannot create icon dir {:?}: {e}", dir);
            return;
        }

        let icons: &[(&str, &[u8])] = &[
            ("vigil-tray-green.png", TRAY_GREEN_ICO),
            ("vigil-tray-orange.png", TRAY_ORANGE_ICO),
            ("vigil-tray-red.png", TRAY_RED_ICO),
        ];

        for &(name, ico_bytes) in icons {
            let path = dir.join(name);
            if path.exists() {
                continue;
            }
            match image::load_from_memory_with_format(ico_bytes, image::ImageFormat::Ico) {
                Ok(img) => {
                    let img = img.resize_exact(32, 32, image::imageops::FilterType::Lanczos3);
                    if let Err(e) = img.save(&path) {
                        tracing::warn!("tray: failed to write {:?}: {e}", path);
                    }
                }
                Err(e) => {
                    tracing::warn!("tray: failed to decode icon {name}: {e}");
                }
            }
        }
    }

    pub fn run(
        cmd_rx: Receiver<TrayCmd>,
        show_window: Arc<AtomicBool>,
        log_dir: PathBuf,
        pending_nav: Arc<Mutex<Option<ConnInfo>>>,
        egui_ctx: Arc<OnceLock<egui::Context>>,
    ) {
        // No display → no SNI host. Skip the tray, still deliver notifications.
        let has_display =
            std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();
        let is_root = unsafe { libc::geteuid() == 0 };
        if !has_display || is_root {
            tracing::info!(
                "system tray skipped ({})",
                if is_root {
                    "running as root"
                } else {
                    "no display"
                }
            );
            notification_only_loop(cmd_rx, show_window, pending_nav);
            return;
        }

        ensure_themed_icons();

        let tray = VigilTray {
            state: IconState::Ok,
            show_window: show_window.clone(),
            log_dir,
            egui_ctx,
        };

        let handle: Handle<VigilTray> = match tray.spawn() {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("ksni tray init failed ({e}) — notifications only");
                notification_only_loop(cmd_rx, show_window, pending_nav);
                return;
            }
        };

        let mut in_alert = false;
        let mut in_lockdown = false;
        let mut alert_since: Option<std::time::Instant> = None;
        const ALERT_HOLD: std::time::Duration = std::time::Duration::from_secs(5);

        let apply = |handle: &Handle<VigilTray>, in_alert: bool, in_lockdown: bool| {
            let state = if in_lockdown {
                IconState::Lockdown
            } else if in_alert {
                IconState::Alert
            } else {
                IconState::Ok
            };
            handle.update(move |t: &mut VigilTray| {
                t.state = state;
            });
        };

        loop {
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    TrayCmd::Alert(info) => {
                        crate::notifier::send_alert(
                            &info,
                            show_window.clone(),
                            pending_nav.clone(),
                        );
                        in_alert = true;
                        alert_since = Some(std::time::Instant::now());
                        apply(&handle, in_alert, in_lockdown);
                    }
                    TrayCmd::ResetOk => {
                        // Hold the alert icon for ALERT_HOLD so the colour
                        // change is noticeable.
                        if alert_since.map_or(true, |t| t.elapsed() >= ALERT_HOLD) {
                            in_alert = false;
                            alert_since = None;
                            apply(&handle, in_alert, in_lockdown);
                        }
                    }
                    TrayCmd::SetLockdown(active) => {
                        in_lockdown = active;
                        apply(&handle, in_alert, in_lockdown);
                    }
                }
            }

            // Deferred ResetOk (holding period expired).
            if let Some(t) = alert_since {
                if t.elapsed() >= ALERT_HOLD && in_alert {
                    in_alert = false;
                    alert_since = None;
                    apply(&handle, in_alert, in_lockdown);
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

pub use imp::run;
