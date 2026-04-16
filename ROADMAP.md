# Vigil — Development Roadmap

Each phase ends with a working, runnable binary. No phase leaves the project broken.

---

## Phase 0 — Scaffolding ✅ COMPLETE

- [x] Name chosen: **Vigil**
- [x] Architecture decided (tokio + egui + ETW)
- [x] CLAUDE.md written
- [x] ROADMAP.md written
- [x] `cargo init vigil` at `C:\dev\vigil`
- [x] `Cargo.toml` with all dependencies (516 crates resolved)
- [x] `.gitignore`
- [x] `src/main.rs` stub — prints "Vigil v0.1.0 — scaffold OK"
- [x] `cargo build` succeeded (2m 31s first build; incremental will be seconds)

**Verified:** `./target/debug/vigil.exe` → `Vigil v0.1.0 — scaffold OK`

---

## Phase 1 — Core Types + Config ✅ COMPLETE

**Goal:** the data layer compiles clean and config survives a round-trip.

- [x] `src/types.rs` — `ConnInfo`, `ConnEvent`, `TrayState`, `MonitorMsg`
- [x] `src/config.rs` — `Config` struct with serde, compiled-in defaults JSON,
      `load()`, `save()`, `add_trusted()`, `remove_trusted()`, `get_trusted()`
- [x] `src/score.rs` — `score(conn: &PartialConn, proc: &ProcessInfo, cfg: &Config) -> (u8, Vec<String>)`
      Threat scoring engine with 6 point cases, fully unit-tested.
- [x] Unit tests: `cargo test` — all score cases pass (6/6 score cases, 19 tests total)

**Files written:** `types.rs`, `config.rs`, `score.rs`  
**Verified:** `cargo test` green; config.json written and re-read correctly.

---

## Phase 2 — Cross-Platform Process + Connection Monitor (Polling) ✅ COMPLETE

**Goal:** connections flow into the terminal. No GUI yet.

- [x] `src/process/mod.rs` — `ProcessInfo` struct; `collect(pid) -> ProcessInfo`
      - name, path, user via `sysinfo::System`
      - parent name + pid via `sysinfo::Process::parent()`
      - service name (Windows: `EnumServicesStatusExW`, others: empty)
- [x] `src/process/publisher.rs` — `#[cfg(windows)]` `get_publisher(path) -> String`
      Reads PE version info via `windows-rs` `VerQueryValueW`.
      Cache in `std::sync::OnceLock<DashMap<String, String>>`.
- [x] `src/monitor/poll.rs` — `poll_connections(cfg, known) -> Vec<ConnEvent>`
      - Windows: `GetExtendedTcpTable` + `GetExtendedUdpTable` via `windows-rs`
      Filter status: ESTABLISHED, LISTEN, SYN_SENT, SYN_RECV, CLOSE_WAIT
- [x] `src/monitor/mod.rs` — `Monitor` struct; `start()` launches `spawn_blocking` loop;
      exposes `broadcast::Receiver<ConnEvent>`
- [x] Wire into `main.rs`: print each ConnEvent to stdout

**Verified:** Vigil running; browser connections visible in terminal within poll interval.

---

## Phase 3 — ETW Real-Time Monitor (Windows) ✅ COMPLETE

**Goal:** connections detected in <100 ms instead of up to 5 seconds.

- [x] `src/monitor/etw.rs` — `#[cfg(windows)]`
      - NT Kernel Logger ETW session via `StartTraceW` (classic MOF, no TDH needed)
      - `EVENT_TRACE_FLAG_NETWORK_TCPIP` (`0x0001_0000`) for TCP events
      - `ProcessTrace` in dedicated `std::thread::spawn` (blocking); `CloseTrace` on exit
      - Parse classic `TcpIpV4` 20-byte payload for opcodes 12 (connect) / 18 (accept)
      - Fire `RawConn` via `OnceLock<UnboundedSender<RawConn>>` global callback context
- [x] `src/monitor/mod.rs` — hybrid: ETW fast path via `tokio::select!` + periodic poll
      fallback (every 30–60 s) for closed connections and startup snapshot
- [x] Startup poll captures pre-existing connections before ETW begins
- [x] `tokio::select!` with `recv_etw()` helper (returns `pending()` when ETW inactive)

**Key API notes (windows-rs 0.62):**
- `EVENT_TRACE_FLAG`, `EVENT_TRACE_CONTROL` are newtypes — wrap literal with `EventXxx(val)`
- `ProcessTrace` takes `&[PROCESSTRACE_HANDLE]` slice, not pointer+count
- `PROCESSTRACE_HANDLE` invalid sentinel is `.Value == u64::MAX` (not `.0`)
- `Win32_System_Time` feature required for `OpenTraceW` / `EVENT_TRACE_LOGFILEW`

**Verified:** ETW fires within milliseconds of a new TCP connection.

---

## Phase 4 — Tray + Notifications + Autostart ✅ COMPLETE

**Goal:** vigil sits in the system tray, shows notifications, survives reboot.

- [x] `src/tray.rs` — tray icon + Win32 event loop
      - 32×32 RGBA circle icons generated in Rust: green `#22C55E` (ok), amber `#F59E0B` (alert)
      - Context menu: "Open Vigil" + separator + "Quit" via `tray-icon::menu`
      - `TrayCmd` channel (`std::sync::mpsc::sync_channel`) for Alert / ResetOk commands
      - Win32 `PeekMessageW` message pump at 50 ms cadence on dedicated OS thread
      - Alert → amber icon + "⚠ Threat detected" tooltip; ResetOk → restores green
- [x] `src/notifier.rs` — `send_alert(&ConnInfo)` via `notify-rust` (fire-and-forget)
- [x] `src/autostart.rs` — thin wrapper over `auto-launch 0.6.0`; enable / disable / is_enabled
- [x] First-run logic in `main.rs` — enables autostart and sets `first_run_done = true`
- [x] Tray thread spawned with `std::thread::Builder` (not tokio task — Win32 HWND must stay on creating thread)

**Key notes:**
- `tray-icon 0.22` requires Win32 message pump on the thread that created the `TrayIcon`
- `#![windows_subsystem = "windows"]` left commented out in `main.rs` until Phase 7 (console useful for debug)
- `Win32_UI_WindowsAndMessaging` feature required for `PeekMessageW` / `DispatchMessageW`

**Verified:** `cargo build` clean; 19/19 tests pass; tray icon appears, amber on alert, notification fires.

---

## Phase 5 — GUI (egui) ✅ COMPLETE

**Goal:** full UI matching the Python version's functionality and dark theme.

### 5a — App shell + tab bar ✅
- [x] `src/ui/mod.rs` — `VigilApp` implementing `eframe::App` (`fn ui` in eframe 0.34)
      - Drains `broadcast::Receiver<ConnEvent>` via `try_recv` loop each frame
      - `VecDeque<ConnInfo>` for activity (cap 500) and alerts (cap 200)
      - `selected_activity/alert: Option<usize>` (index into VecDeque)
      - `active_tab: Tab` enum, `unseen_alerts: usize`, `paused: bool`, `kill_confirm: bool`
- [x] `src/ui/theme.rs` — 11 colour constants; `apply()` sets egui Visuals + text styles
- [x] `src/ui/tab_bar.rs` — `Tab` enum + `tab_bar()` widget; ACCENT 2 px underline on active

### 5b — Activity + Alerts tables ✅
- [x] `src/ui/activity.rs` — `egui_extras::TableBuilder`: Time · Process · Remote · Status · Score
      Score-coloured process name; monospace remote addr; click any cell to select row
- [x] `src/ui/alerts.rs` — columns: Time · Process · Score · Remote · Reasons
      Empty-state placeholder; DANGER/WARN text colour on process column

### 5c — Inspector panel ✅
- [x] `src/ui/inspector.rs` — `show(ui, info, kill_confirm) -> Option<Action>`
      Placeholder when nothing selected; score badge + kv rows + reasons when selected
      Actions: Trust / Open Location / Kill (with kill-confirm dialogue)

### 5d — Settings panel ✅
- [x] `src/ui/settings.rs` — `SettingsDraft` buffers edits until Save is clicked
      Sliders: alert_threshold 1–10, poll_interval_secs 2–60
      Checkboxes: log_all_connections, autostart
      Trusted processes list with inline Add/Remove; "Settings saved." transient msg

### 5e — Help panel ✅
- [x] `src/ui/help.rs` — static scrollable content: What Vigil does, score table,
      inspector field explanations, action button explanations, svchost note, tips, version

### 5f — Wire everything ✅
- [x] Status pill ("● Monitoring" green / "○ Paused" muted) in header
- [x] Pause/Resume button in header — paused state discards incoming events
- [x] Window hides on close (cancel close + `ViewportCommand::Visible(false)`)
- [x] "Open Vigil" in tray → `Arc<AtomicBool>` → `ViewportCommand::Focus` in next frame
- [x] Alerts tab resets unseen counter + sends `TrayCmd::ResetOk` on open
- [x] Trust / Kill / Open Location inspector actions wired to config + sysinfo + open crate

**Key API notes (eframe 0.34 / egui 0.34):**
- `eframe::App::ui(&mut self, ui: &mut Ui, frame: &mut Frame)` — NOT `update(ctx, frame)`;
  access Context via `ui.ctx().clone()`
- Panels use `.show_inside(ui, …)` instead of `.show(ctx, …)`; order determines layout
- `Rounding` → `CornerRadius`; `Button::rounding` → `Button::corner_radius`
- `Margin::same/symmetric` takes `i8`, not `f32`; use `Margin::ZERO` for zero margin
- `ctx.style()` → `ctx.global_style()`, `ctx.set_style()` → `ctx.set_global_style()`
- `Slider::clamp_to_range(true)` → `Slider::clamping(SliderClamping::Always)`
- `sysinfo 0.38`: `System::refresh_process(pid)` → `System::refresh_processes(ProcessesToUpdate::Some(&[pid]), false)`

**Verified:** `cargo build` clean (warnings only); 19/19 tests pass.

---

## Phase 6 — Logging + Polish ✅ COMPLETE

- [x] `tracing_appender::rolling::daily` log to `<exe_dir>/logs/vigil.YYYY-MM-DD`
- [x] Log format: `TIMESTAMP [LEVEL] proc_name (pid) | local → remote | score=N`
- [x] "Open Logs Folder" tray menu item uses `open::that(log_dir)`
- [x] App icon embedded as `.ico` resource on Windows (build.rs + `winres` crate)
- [x] Version string from `CARGO_PKG_VERSION` shown in Help tab footer
- [x] Window title: "Vigil" (not "egui app" default)
- [x] Correct taskbar/notification-centre app name via AUMID

**Files written/changed:** `src/logger.rs`, `build.rs`, `src/tray.rs`, `src/monitor/mod.rs`,
`src/main.rs`, `Cargo.toml`

**Key notes:**
- `tracing_subscriber::fmt::time::FormatTime` trait — implement on a unit struct with `chrono::Local::now()`
- `tracing_appender::rolling::daily(dir, "vigil")` → files named `vigil.YYYY-MM-DD`
- `WorkerGuard` returned by `non_blocking()` must be kept alive for the process lifetime (drop = flush + close)
- `winres` is a `[build-dependencies]` entry (not target-specific); build.rs checks `CARGO_CFG_TARGET_OS` before calling it
- ICO generated programmatically in `build.rs` (ICONDIR + ICONDIRENTRYs + BITMAPINFOHEADER + BGRA bottom-to-top + AND mask); no binary asset in repo
- `SetCurrentProcessExplicitAppUserModelID(w!("Vigil.App.1"))` from `Win32_UI_Shell` feature (added to `windows` crate features)
- `logger::init()` must be called before any `tracing::info!/warn!` calls — returns `(PathBuf, LogGuard)`

**Verified:** `cargo build` clean (pre-existing warnings only); 19/19 tests pass.

---

## Phase 7 — Build + Distribution ✅ COMPLETE

- [x] `build.rs` — embed icon on Windows using `winres` crate (done in Phase 6)
- [x] `justfile` recipes: `build`, `release`, `build-windows`, `install`, `test`, `lint`, `fmt`, `ci`
- [x] GitHub Actions CI (`.github/workflows/ci.yml`):
      - Format + lint job (ubuntu, fast gate)
      - Build + test matrix: Windows (x86_64-pc-windows-msvc), macOS (aarch64-apple-darwin), Linux (x86_64-unknown-linux-gnu)
      - `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`
      - Upload release artifacts on tag push via `softprops/action-gh-release`
- [x] `README.md` — installation, feature list, score table, config reference, log format, build instructions
- [x] `LICENSE` — MIT
- [x] `.github/ISSUE_TEMPLATE/bug_report.md` + `feature_request.md`
- [x] `#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]` uncommented

**Key notes:**
- `windows_subsystem = "windows"` suppresses the console in release builds; use `cfg_attr` with both `not(debug_assertions)` and `target_os = "windows"` so it compiles cleanly on all platforms
- `softprops/action-gh-release@v2` requires `permissions: contents: write` in the job
- `just` `[windows]` / `[unix]` attributes select platform-specific recipe implementations
- `Swatinem/rust-cache@v2` with `key: ${{ matrix.target }}` keeps caches separate per target

**Verified:** `cargo build` clean; 19/19 tests pass.

### Installer (post-Phase-7 addition)

Cross-platform installers via **`cargo-dist`**:

- **Windows** — Inno Setup wizard EXE (`Vigil-Setup-<ver>-x86_64.exe`)
- **macOS** — drag-to-Applications DMG (`Vigil-<ver>-aarch64.dmg`)
- **Linux** — portable AppImage (`Vigil-<ver>-x86_64.AppImage`)

Release workflow in `.github/workflows/release.yml` (fires on every `v*` tag push).
All three platforms build in parallel; a final `publish` job creates a GitHub Release
with all three installers attached.

---

## Phase 8 — UX, Detection & Quality Overhaul ✅ COMPLETE

**Goal:** ship a polished v1.1 with meaningfully better threat coverage, a faster UI, and
zero rough edges before seeking public adoption.

### Detection improvements
- [x] **Suspicious parent scoring** (+3 points) — 14 known attack patterns
      (e.g. `cmd.exe` spawned by `winword.exe`, `powershell.exe` from `excel.exe`,
      `mshta.exe` from any Office app, `wscript.exe` from browsers, etc.)
- [x] **Unsigned binary penalty** (+2 points) — any process with a non-empty path but
      no code-signing publisher is flagged; cached per path so it only runs once
- [x] **Full ancestor chain** — `walk_ancestors()` walks up to 8 levels of parent
      processes with cycle detection; stored in `ConnInfo.ancestor_chain`
- [x] Score tests updated; `ScoreInput` gains `publisher` and `ancestors` fields

### UI / UX improvements
- [x] **Row selection fixed** — `ui.interact(max_rect, id, Sense::click())` per cell;
      `TableBuilder::sense(Sense::hover())` so child widgets don't swallow clicks
- [x] **Parent column** added to Activity and Alerts grids (after Process column)
- [x] **Process tree in inspector** — replaces plain "Parent" kv row; shows indented
      ancestor chain with `└─` tree characters and PIDs at each level
- [x] **Right-click context menu** on both grids — "Clear all" option
- [x] **Notification click navigation** — clicking a Windows toast notification opens
      Vigil, switches to the Alerts tab, and selects the triggering row
      (`Arc<Mutex<Option<ConnInfo>>>` pending_nav; WinRT `Activated` event on Windows,
      `notify-rust` background thread on macOS/Linux)
- [x] **Tray left-click = open UI** — `with_menu_on_left_click(false)` + event polling;
      right-click still shows the context menu
- [x] **Window size/position persistence** — `persist_window: true` in `NativeOptions`
- [x] **Responsive settings layout** — centred content capped at 700 px; adapts to any
      window width from narrow to maximised
- [x] **Trusted processes as filterable grid** — `TableBuilder` with filter bar
      (shown when >4 entries), per-row Remove button, correct removal under filter

### Code quality
- [x] All `eprintln!` / `println!` replaced with `tracing::` calls — zero console output
      in release builds
- [x] `row_tint()` dead-code removed from `theme.rs`
- [x] `Frame::NONE` (was deprecated `Frame::none()`), `ui.close()` (was `ui.close_menu()`),
      `egui::Panel::top/right` + `exact_size` (was deprecated TopBottomPanel/SidePanel aliases)

### Help tab updated
- [x] 8-row score table (all rules including new +3 and +2)
- [x] "Process Tree" section explaining ancestor chain display
- [x] "Running Before Login (Windows)" section with service install instructions
- [x] Threshold tip clarified for 1–10 range

**Files changed:** `score.rs`, `types.rs`, `process/mod.rs`, `monitor/mod.rs`,
`notifier.rs`, `tray.rs`, `main.rs`, `ui/mod.rs`, `ui/activity.rs`, `ui/alerts.rs`,
`ui/inspector.rs`, `ui/settings.rs`, `ui/help.rs`, `ui/theme.rs`

---

## Phase 9 — Enhanced Detection (backlog)

Features planned for v2.x. Implement after the v1.1 community release.

- [ ] **IP reputation** — check remote IPs against AbuseIPDB / Shodan free API; configurable API key
- [ ] **Geolocation** — MaxMind GeoLite2 offline DB; flag connections to unusual regions
- [ ] **Beaconing detection** — track connection intervals per (pid, remote_ip); alert if stddev < 5s over 10+ samples
- [ ] **File system watcher** — `notify` crate watching Temp/AppData; correlate new exes with network connections
- [ ] **Registry persistence watcher** — watch HKCU Run / HKLM Run; alert on new entries
- [ ] **Unsigned DLL detection** — enumerate loaded modules per network process; flag unsigned ones from temp paths
- [ ] **Volume anomaly** — track bytes/sec per process (Windows: `GetPerTcpConnectionEStats`); alert on spikes
- [ ] **DNS monitoring** — flag DNS queries to non-standard ports or from unexpected processes
- [ ] **Pre-login service mode** — install as a Windows service (`sc create`) so monitoring begins before user login

---

## Version Plan

| Version | Phase | Description | Status |
|---|---|---|---|
| 0.1.0 | 1–2 | Types + config + polling monitor (no GUI, prints to terminal) | ✅ Done |
| 0.2.0 | 3   | ETW real-time detection added | ✅ Done |
| 0.3.0 | 4   | Tray + notifications + autostart | ✅ Done |
| 0.4.0 | 5   | Full GUI | ✅ Done |
| 0.5.0 | 6   | Logging + polish | ✅ Done |
| 1.0.0 | 7   | Build pipeline + open-source release | ✅ Done |
| 1.1.0 | 8   | UX, detection & quality overhaul | ✅ Done |
| 2.x   | 9   | Enhanced detection features | 🔲 Backlog |
