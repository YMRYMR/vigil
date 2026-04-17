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
- [x] `src/autostart.rs` — login-item wrapper with Windows privilege-aware autostart
      (normal Run key on unelevated launches, highest-privilege scheduled task
      when Vigil itself is launched elevated)
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
      - process-first `selected_activity/alert: Option<ProcessSelection>`
      - `active_tab: Tab` enum, per-grid `TableState`, `unseen_alerts: usize`,
        `paused: bool`, `kill_confirm: bool`
- [x] `src/ui/theme.rs` — 11 colour constants; `apply()` sets egui Visuals + text styles
- [x] `src/ui/tab_bar.rs` — `Tab` enum + `tab_bar()` widget; ACCENT 2 px underline on active

### 5b — Activity + Alerts tables ✅
- [x] `src/ui/activity.rs` — `egui_extras::TableBuilder`: Time · Process · Remote · Status · Score
      Process-grouped cards with stacked connections; click process header for the
      full process summary, or a child row for a specific connection; sort state is
      persisted per grid
- [x] `src/ui/alerts.rs` — columns: Time · Process · Score · Remote · Reasons
      Empty-state placeholder; DANGER/WARN text colour on process column

### 5c — Inspector panel ✅
- [x] `src/ui/inspector.rs` — `show(ui, selection, kill_confirm) -> Option<Action>`
      Process-first summary with score badge, combined reasons, and optional
      selected-connection details; Trust / Open Location / Kill actions
      are disabled for unresolved or location-less rows, with kill-confirm dialogue

### 5d — Settings panel ✅
- [x] `src/ui/settings.rs` — `SettingsDraft` auto-saves on change
      Sliders: alert_threshold 1–10, poll_interval_secs 2–60
      Checkboxes: log_all_connections, autostart
      Trusted processes grid with inline Add/Remove and shipped-default reset

### 5e — Help panel ✅
- [x] `src/ui/help.rs` — polished operator-help layout: what Vigil does, score table,
      process-first inspector explanation, action gating, tips, and version

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
- [x] **Per-grid sort persistence** — Activity and Alerts remember their own sort
      order and filter state across launches
- [x] **Responsive settings layout** — full-width settings canvas with auto-save and
      compact trusted-process rows
- [x] **Trusted processes as filterable grid** — filter bar, per-row Remove button,
      shipped-default reset, correct removal under filter

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

## Phase 9 — Enhanced Detection ✅ COMPLETE

Second round of detection features and cross-platform hardening.

### Detection
- [x] **Beaconing detection** (`src/beacon.rs`) — tracks inter-arrival times per
      `(pid, remote_ip)` across a rolling 30-sample window; flags regular C2
      callbacks when stddev < 5 s and mean 1 – 600 s; adds **+3** to score
- [x] **DNS tunneling detection** — flags any port-53 connection from a
      non-DNS process and non-trusted binary; adds **+2** to score
- [x] **Registry persistence watcher** (`src/registry.rs`, Windows) — polls
      `HKCU\…\Run`, `HKLM\…\Run`, and both `RunOnce` keys every 30 s;
      baselines at startup, raises a high-severity synthetic alert on any
      newly-added autorun entry
- [x] **Pre-login detection** (`src/session.rs`) — cross-platform check
      (WTS API on Windows; `USER` / `DISPLAY` / `WAYLAND_DISPLAY` /
      `XDG_SESSION_TYPE` on Unix) that tags events observed before any
      interactive user session with `pre_login: true`; adds **+2** to score
      and renders a red **`PL`** badge in the UI Time column

### Cross-platform service mode
- [x] `--install-service` / `--uninstall-service` CLI flags in `main.rs`
- [x] `src/service.rs` — shared module with per-OS implementations:
      Windows SCM (`sc create`), macOS launchd system daemon at
      `/Library/LaunchDaemons/com.vigil.monitor.plist`, Linux systemd unit
      at `/etc/systemd/system/vigil.service`
- [x] Help tab + README document the install command per OS

### UI
- [x] **Independent grids** — Activity and Alerts now keep their own persisted
      sort/filter state; clicking a column header in one grid no longer forces
      the other tab to follow the same order
- [x] **Pre-login badge** rendered in both grids' Time column
- [x] Inspector selection works again via `row.response()` on
      `TableBuilder::sense(Sense::click())`

### Reliability
- [x] **ETW race-condition retry** — `process::collect()` retries once with
      100 ms delay if the PID isn't yet in sysinfo's snapshot, eliminating
      most `<pid>` ghost rows
- [x] **Ghost-row scoring** — scorer skips the "+3 no executable path"
      penalty when the process name matches the `<pid>` ghost pattern
- [x] **Notification fallback** — Windows branch of `notifier.rs` falls back
      to `notify-rust` when WinRT's `ToastNotification::Show` fails (most
      commonly because the AUMID isn't registered to a Start Menu shortcut,
      e.g. running `target/debug/vigil.exe` directly)

**Files added:** `src/beacon.rs`, `src/registry.rs`, `src/session.rs`,
`src/service.rs`
**Files changed:** `src/score.rs`, `src/types.rs`, `src/monitor/mod.rs`,
`src/process/mod.rs`, `src/notifier.rs`, `src/main.rs`, `src/ui/mod.rs`,
`src/ui/activity.rs`, `src/ui/alerts.rs`, `src/ui/help.rs`,
`README.md`, `ROADMAP.md`

**Verified:** `cargo build` clean; 25/25 tests pass.

---

## Phase 10 — Reputation & Telemetry ✅ COMPLETE

Shipped in 1.3.0. Enrichment signals layered on top of behavioural scoring,
all off-by-default and configurable in `vigil.json`.

### Shipped
- [x] **IP reputation via local blocklists** — `src/blocklist.rs`: load plain-text IP/CIDR lists, +3 on hit, REP badge. Online API lookups (AbuseIPDB / Shodan / VirusTotal) deferred.
- [x] **Geolocation** — `src/geoip.rs`: MaxMind GeoLite2-City offline DB; country code per connection; +2 for countries outside `allowed_countries`.
- [x] **ASN / hosting classification** — `src/geoip.rs`: GeoLite2-ASN DB; ASN number + AS organisation shown in Inspector. Bulletproof-hoster flagging deferred to Phase 12.
- [x] **File system watcher** — `src/fswatch.rs`: `notify` crate watches Temp / AppData / Downloads for new `.exe`/`.dll`/`.scr`/`.ps1`/…; +3 and DRP badge when a fresh drop makes a connection within `fswatch_window_secs` (default 600 s).
- [x] **Long-lived connection tracker** — `src/longlived.rs`: tracks first-seen per `(pid, remote_ip)`; +2 and LL badge when untrusted process stays connected past `long_lived_secs` (default 3600 s).
- [x] **DGA entropy scoring** — `src/entropy.rs`: Shannon entropy over leftmost hostname label; +2 and DGA badge when above `dga_entropy_threshold` (default 3.2 bits/char).
- [x] **Reverse DNS (cached)** — `src/revdns.rs`: background worker + in-memory cache; opt-in via `reverse_dns_enabled` (off by default because of resolver leakage).

### Deferred to later phases
- [ ] **Domain reputation** — Umbrella / Quad9 feed lookup (requires network round-trip)
- [ ] **Newly registered domain (NRD) detection** — WHOIS client
- [ ] **Unsigned DLL detection** — PSAPI module enumeration + Authenticode verification per DLL (Phase 12 detection-depth work)
- [ ] **Volume anomaly** — Windows `GetPerTcpConnectionEStats` / Linux `/proc/net/tcp` byte-counter diffs (Phase 12)
- [ ] **Online reputation APIs** — AbuseIPDB / Shodan / VirusTotal REST clients with SQLite cache (Phase 13 integration work)

---

## Phase 11 — Active Response (backlog)

Move Vigil from passive observer to intervening defender. All actions must be explicit, reversible, and auditable.

### Per-connection and per-process blocking
- [ ] **Block single connection** — kill one socket without killing the owning process
  - Windows: `SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB` (requires admin)
  - Linux: `ss -K dst <ip> dport = <port>` (needs `CONFIG_INET_DIAG_DESTROY`) or `conntrack -D`
  - macOS: `pfctl` rule injection + state flush (no native socket-kill API)
- [x] **Block all connections from a process** (without killing it) — Windows implementation uses reversible firewall rules scoped to the executable path, with duration presets and cleanup on expiry
  - Windows: implemented via temporary firewall rules bound to the process image path
  - Linux: `nftables` rule matching `meta skuid` / cgroup v2 `net_cls` — Vigil moves the offending PID into a quarantine cgroup that has a deny-all netfilter rule; process continues running but all new sockets are dropped
  - macOS: `pf` anchor per-process via `pfctl` + Network Extension content-filter (needs entitlement)
  - UI: inspector shows `Block process` / `Unblock process` with duration presets
- [x] **Active-response UX** — temporary blocks show live countdowns and inline unblock buttons; the header reflects privilege state with `Admin` / `Run as Admin`
- [x] **Block remote IP / CIDR** system-wide — temporary Windows firewall rule with confirmation, persisted state, and cleanup on expiry
- [ ] **Block remote domain** — inject into `hosts` file or local DNS sinkhole
- [ ] **Kill process** (current: manual) — add one-click "Terminate" in inspector with confirmation
- [ ] **Suspend process** — freeze the process (Windows: `NtSuspendProcess`, Unix: `SIGSTOP`) while the user investigates; resumable

### Machine-wide lockdown
- [x] **Panic button — full network isolation** — reversible Windows firewall rules added from the UI, with a matching restore action and confirmation prompt
  - Linux/macOS-specific adapter / pf / nft equivalents remain backlog
- [ ] **Allowlist-only mode** — invert the firewall: only signed Microsoft processes, or a user-curated list, may talk to the network; everything else blocked
- [ ] **Quarantine profile** — preset combining: lockdown + disable USB storage (Windows: `USBSTOR` registry) + pause scheduled tasks
- [ ] **Break-glass recovery** — if Vigil crashes while network is locked down, a watchdog timer (separate service) restores connectivity after N minutes unless a heartbeat file is touched

### Rule engine and automation
- [ ] **User-defined response rules** — "if score ≥ 8 AND process is unsigned → auto-quarantine process"
  - YAML rule file with condition DSL (same fields as `ScoreInput`)
  - Dry-run mode that logs what would have been blocked
- [ ] **Threshold escalation** — first offence notify, second block connection, third quarantine process
- [ ] **Time-boxed blocks** — every block has an expiry; auto-revert at TTL
- [ ] **Scheduled lockdown** — isolate machine automatically during specified hours (e.g. overnight)

### Containment and forensics
- [ ] **PCAP capture on alert** — spawn a short ring-buffered packet capture when a high-score alert fires (Windows: `pktmon`; Linux: `tcpdump`; macOS: `tcpdump`)
- [ ] **Process memory dump on alert** — optional minidump for offline analysis (Windows: `MiniDumpWriteDump`)
- [ ] **Freeze autorun entries** — snapshot HKCU/HKLM Run keys; revert additions made after snapshot
- [ ] **Honeypot decoy files** — canary files in common locations; alert + auto-lockdown if touched

---

## Phase 12 — Detection Depth (backlog)

Raise detection ceiling with richer signals and correlation.

- [ ] **Behavioural baselines** — per-process profile of typical remote endpoints and ports over N days; flag deviations
- [ ] **Process lineage chains** — track full ancestor chain (not just parent); alert on chains like `winword → powershell → cmd → curl`
- [ ] **Script-host content inspection** — ETW scriptblock logging (PowerShell) and command-line capture for `cmd.exe` / `wscript.exe` / `mshta.exe`; pattern-match for downloader patterns
- [ ] **Signed-but-malicious detection** — maintain revocation list of abused code-signing certs (e.g. known leaked certs)
- [ ] **LOLBAS/GTFOBins coverage** — expand beyond the current `certutil`/`bitsadmin`/`mshta` list to the full LOLBAS catalogue; auto-sync from upstream JSON
- [ ] **Driver load monitoring** — ETW Microsoft-Windows-Kernel-PnP events; alert on unsigned or recently dropped drivers
- [ ] **Token manipulation detection** — ETW process token events; alert on SeDebugPrivilege acquisition by non-admin processes
- [ ] **Parent-spoofing detection** — compare reported parent PID against creation-time parent via ETW `Process/Start`
- [ ] **TLS SNI / JA3 fingerprinting** — capture TLS ClientHello via ETW-Tls or eBPF; score on SNI mismatch with reverse DNS and on known-malicious JA3
- [ ] **MITRE ATT&CK mapping** — tag every detection with ATT&CK technique ID; dashboard shows coverage heatmap

---

## Phase 13 — Integration & Fleet (backlog)

Make Vigil useful beyond a single endpoint.

- [ ] **SIEM export** — syslog / CEF / JSON over TCP push for Splunk, Elastic, Sentinel
- [ ] **Webhook alerts** — configurable HTTPS POST per alert (Discord, Slack, ntfy, PagerDuty)
- [ ] **Fleet mode** — optional central server aggregates alerts from many Vigil instances; read-only dashboard
- [ ] **Remote lockdown** — signed command from central server triggers Phase 11 isolation on a target host
- [ ] **Shared blocklist sync** — subscribe to community-curated IP/domain blocklists with HTTPS pull + signature verification
- [ ] **Threat-intel STIX/TAXII client** — pull IoCs from standard feeds
- [ ] **Export alert as ATT&CK Navigator layer** — share incidents in standard format

---

## Phase 14 — Hardening & Self-defence (backlog)

Vigil must resist tampering to be trustworthy.

- [ ] **Self-protection** — prevent non-admin processes from killing Vigil (Windows: PPL / protected process light; Linux: `PR_SET_DUMPABLE=0` + seccomp)
- [ ] **Config signing** — require signed config changes; reject tampered `config.json`
- [ ] **Tamper-evident audit log** — hash-chained append-only log of every alert and user action; detect truncation
- [ ] **Secure update channel** — signed release bundles (minisign / cosign); auto-verify before replacing binary
- [ ] **Sandboxed providers** — move file-watcher and DLL-enumeration helpers into separate low-privilege worker processes; IPC over a pipe
- [ ] **Anti-debug heuristics** — refuse to run under a debugger unless `--debug` flag passed explicitly
- [ ] **Compromised-host mode** — if self-integrity check fails, refuse to start and write a red banner to the event log

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
| 1.2.0 | 9   | Beaconing, DNS, registry, pre-login, cross-platform service | ✅ Done |
| 1.3.0 | 10  | Reputation, geolocation, file-drop correlation, long-lived, DGA | ✅ Done |
| 3.0.0 | 11  | Active response: per-process block, machine isolation, rule engine | 🔲 Backlog |
| 3.x   | 12  | Detection depth: behavioural baselines, script inspection, JA3 | 🔲 Backlog |
| 4.x   | 13  | Integration & fleet: SIEM, webhooks, central server | 🔲 Backlog |
| 4.x   | 14  | Hardening & self-defence | 🔲 Backlog |
