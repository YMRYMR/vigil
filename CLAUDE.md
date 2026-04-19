# Vigil — Claude Context File

> **Read this first in every session. It replaces reading the whole codebase.**
> Vigil is a Rust port of `C:\dev\threat_detector` (Python). The Python source is
> the canonical reference for behaviour; this file is the canonical reference for
> architecture and decisions.

---

## Identity

| Field | Value |
|---|---|
| Project | **Vigil** — real-time network threat monitor |
| Language | Rust (edition 2021) |
| Binary | `vigil` (tray app, no console window) |
| Python source | `C:\dev\threat_detector\` |
| Repo root | `C:\dev\vigil\` |
| License | MIT (to be open-sourced) |
| Min Rust | 1.77 (let chains, `impl Trait` in fn args) |

---

## Current Phase

> **Update this section at the end of every session.**

**Phase:** 13 ✅ — Optimization & Efficiency FEATURE COMPLETE
**Last session:** eBPF real-time TCP monitoring on Linux (aya 0.13, tracepoint:sock:inet_sock_set_state). Linux system tray with GNOME AppIndicator integration (themed icons, GTK init, GLib D-Bus, menu event handling).
**Next action:** Phase 14 — Hardening & Self-defence (protected policy store, tamper evidence)

### Completed phase notes

#### Phase 0
- egui/eframe/egui_extras locked to **0.34** (latest as of session)
- `egui_extras` does NOT have a `table` feature in 0.34 — `TableBuilder` is always available
- `dashmap` locked to **5** (v7 is RC, skip it)
- `windows` crate at **0.62.2**
- `winreg` at **0.56.0**
- `tray-icon` at **0.22.0**, uses `muda 0.17` for menus
- `sysinfo` at **0.38.4**

#### Phase 1
- `union_str` (case-insensitive String) and `union_eq` (exact u16) — two merge helpers needed, not one generic
- 19 unit tests all pass

#### Phase 2
- `GetFileVersionInfoW` in windows 0.62: dwHandle → `Option<u32>`, pass `Some(0)`
- `VerQueryValueW` returns `BOOL` (not `Result`) → `.as_bool()`
- Windows service map via `EnumServicesStatusExW`

#### Phase 5
- `eframe 0.34` uses `fn ui(&mut self, ui: &mut Ui, frame: &mut Frame)` — NOT `update(ctx, frame)`
- Access Context via `ui.ctx().clone()`; panels use `.show_inside(ui, …)` not `.show(ctx, …)`
- `Rounding` renamed to `CornerRadius`; field `vis.window_rounding` does NOT exist in 0.34 — skip it
- `Margin::same/symmetric` takes `i8`, not `f32`; `Margin::ZERO` for zero
- `Button::rounding` → `Button::corner_radius`
- `ctx.style()` → `ctx.global_style()`; `ctx.set_style()` → `ctx.set_global_style()`
- `Slider::clamp_to_range(true)` → `Slider::clamping(SliderClamping::Always)`
- `sysinfo 0.38`: `System::refresh_process(pid)` gone; use `System::refresh_processes(ProcessesToUpdate::Some(&[pid]), false)`
- `TopBottomPanel` / `SidePanel` type aliases deprecated; use `egui::containers::panel::TopBottomPanel` etc. (still warns — acceptable)
- Main thread given to `eframe::run_native`; tokio runtime built with `Builder::new_multi_thread()` and entered with `rt.enter()` guard; `Monitor::start()` called while guard is alive

#### Phase 4
- `auto-launch 0.6.0` builder API: `AutoLaunchBuilder::new().set_app_name().set_app_path().build()`
- Windows requires `Win32_UI_WindowsAndMessaging` feature for `PeekMessageW` / `DispatchMessageW`
- Tray thread is a dedicated `std::thread::spawn` (NOT a tokio task) because Win32 message pump must run on the thread that created the `TrayIcon`
- `tray_icon::Icon` is `Clone`; `muda::MenuId` is `Clone(String)`
- `TrayCmd::Alert(ConnInfo)` forwarded via `std::sync::mpsc::sync_channel(64)` from async → tray thread
- `notify-rust` can be called from any thread (fire-and-forget, errors silently swallowed)
- `#![windows_subsystem = "windows"]` kept commented — will be uncommented in Phase 7

#### Phase 3
- `OpenTraceW` / `EVENT_TRACE_LOGFILEW` require `"Win32_System_Time"` feature in Cargo.toml — **added**
- `StartTraceW` returns `WIN32_ERROR` (not `u32`) — compare with `ERROR_SUCCESS` / `ERROR_ALREADY_EXISTS`
- `ControlTraceW` control code is `EVENT_TRACE_CONTROL` newtype — use `EVENT_TRACE_CONTROL(3)` for UPDATE
- `EVENT_TRACE_PROPERTIES.EnableFlags` is `EVENT_TRACE_FLAG` newtype
- `PROCESSTRACE_HANDLE` field is `.Value` (not `.0`)
- `ProcessTrace` signature: `(&[PROCESSTRACE_HANDLE], Option<*const FILETIME>, Option<*const FILETIME>)` — 3 args, first is a slice
- NT Kernel Logger approach (classic MOF events) chosen over `EnableTraceEx2` + manifest provider: simpler binary parsing, no TDH needed
- ETW feeds `RawConn` via `tokio::sync::mpsc::UnboundedSender` into an async `select!` loop
- Full poll still runs every `interval * 6` seconds (capped 30–60 s) when ETW is active, for closed-connection cleanup

---

## Architecture — Locked In (do not relitigate)

### Runtime
- **`tokio`** full async runtime. `main` is `#[tokio::main]`.
- Monitor runs as a `tokio::task::spawn_blocking` (ETW blocks; polling uses `tokio::time::interval`).
- UI runs on the **main thread** (required by egui/eframe and most OS GUI toolkits).
- All cross-thread communication uses `tokio::sync::broadcast` or `std::sync::mpsc`.

### GUI
- **`egui` + `eframe`** (immediate-mode). No alternatives — decided.
- Dark theme hand-coded in `ui/theme.rs` (colours below).
- Layout: header bar → custom tab strip → body (list left, inspector right 310 px).
- Inspector hidden when Settings or Help tab active.

### Tray
- **`tray-icon`** crate. Menu built with `tray-icon::menu::Menu`.
- Icon from embedded `.ico` assets (green/orange/red) with programmatic RGBA fallback.
- Three states: `ok` (green), `alert` (amber), `lockdown` (red).
- **Linux:** Uses libappindicator/AppIndicator. Requires `gtk::init()` before menu/tray creation. GNOME needs themed icon names via `set_icon_full()` instead of raw pixel data. GLib `MainContext::iteration(false)` required for D-Bus registration.

### Notifications
- **`notify-rust`** crate. Clicking a notification on Windows brings window to front and switches to Alerts tab.

### Autostart
- **`auto-launch`** crate. Abstracts Windows Registry, macOS LaunchAgent, Linux `.desktop`.

### Logging
- **`tracing`** + **`tracing-appender`**. Daily rolling log to `<exe_dir>/logs/vigil_YYYY-MM-DD.log`.

### Config persistence
- Single JSON file next to the binary: `vigil.json`.
- Loaded at startup, merged with compiled-in defaults (user additions union, not overwrite).
- Shared as `Arc<RwLock<Config>>` — monitor reads it every poll cycle.

### ETW (Windows, Phase 3)
- Provider: `Microsoft-Windows-TCPIP` GUID `{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}`
- API: `windows::Win32::System::Diagnostics::Etw::{StartTrace, EnableTraceEx2, ProcessTrace}`
- Runs in `spawn_blocking`; fires `ConnectionEvent` into the broadcast channel instantly.
- Cross-platform fallback (Phase 2): `GetExtendedTcpTable` on Windows, `/proc/net/tcp` on Linux,
  `sysctl(CTL_NET)` on macOS — all behind a `Monitor::poll()` called every `config.poll_interval_secs`.

### eBPF (Linux, Phase 13)
- Tracepoint: `sock:inet_sock_set_state` via `aya::EbpfLoader`
- Pre-compiled BPF object embedded as `&[u8]` const (`src/monitor/ebpf_bytecode.rs`, 8 KB)
- Requires capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`
- Falls back to `/proc/net/tcp` polling if kernel too old or capabilities missing
- ELF alignment: must copy BPF_OBJ to `Vec<u8>` before loading (aya parser requires heap-aligned data)

---

## Crate Dependency Map

```toml
[dependencies]
tokio        = { version = "1",    features = ["full"] }
egui         = "0.34"
eframe       = { version = "0.34", default-features = false,
                 features = ["default_fonts", "glow", "persistence"] }
egui_extras  = { version = "0.34", features = ["all_loaders"] }
tray-icon    = "0.22"
notify-rust  = "4"
image        = { version = "0.25", default-features = false, features = ["bmp", "ico", "png"] }
sysinfo      = "0.38"
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
serde_yaml   = "0.9"
tracing      = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-appender   = "0.2"
chrono       = { version = "0.4", features = ["serde"] }
open         = "5"
dashmap      = "5"
auto-launch  = "0.6"
maxminddb    = "0.24"
notify       = "6"
dns-lookup   = "2"
ipnetwork    = "0.20"

[target.'cfg(windows)'.dependencies]
windows = { version = "0.62", features = [
    "Win32_System_Diagnostics_Etw",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_System_Time",
    "Win32_System_Services",
    "Win32_Foundation",
    "Win32_NetworkManagement_IpHelper",
    "Win32_System_ProcessStatus",
    "Win32_System_Threading",
    "Win32_System_SystemInformation",
    "Win32_Storage_FileSystem",
    "Win32_Security",
    "Win32_UI_WindowsAndMessaging",
    "Win32_UI_Shell",
    "Foundation",
    "UI_Notifications",
    "Data_Xml_Dom",
] }
winreg = "0.56"

[target.'cfg(target_os = "linux")'.dependencies]
eframe = { version = "0.34", features = ["default_fonts", "glow", "persistence", "wayland", "x11"] }
aya = "0.13"
bytes = "1"
libc = "0.2"
gtk = "0.18"
glib = "0.18"
libappindicator = "0.9"
```

---

## Module Map

```
src/
├── main.rs              # tokio runtime setup; spawns monitor, tray, ui; wires channels
├── config.rs            # Config struct (serde), defaults, load/save, add/remove trusted
├── types.rs             # ConnInfo, ConnEvent, PipelineTimings, TrayState, MonitorMsg enums
├── score.rs             # score(conn, proc, config) -> (u8, Vec<String>)  [pure fn]
├── monitor/
│   ├── mod.rs           # Monitor::new / start / stop; owns broadcast::Sender<ConnEvent>
│   ├── poll.rs          # cross-platform polling via raw OS APIs
│   ├── etw.rs           # #[cfg(windows)] ETW session; fires same ConnEvent
│   ├── ebpf.rs          # #[cfg(linux)] aya 0.13 eBPF tracepoint; stub on other platforms
│   ├── ebpf_bytecode.rs # pre-compiled BPF object (8 KB embedded const)
│   └── ebpf_tcp_state.bpf.c # BPF C source (compiled to ebpf_bytecode.rs)
├── process/
│   ├── mod.rs           # ProcessInfo { name, path, user, parent_name, parent_pid, service, publisher }
│   └── publisher.rs     # #[cfg(windows)] VerQueryValueW → company name, cached in DashMap
├── tray.rs              # TrayIcon; menu; icon states; platform event loops (Win32 / GLib)
├── notifier.rs          # send(title, body) via notify-rust
├── autostart.rs         # thin wrapper over auto-launch crate
├── active_response.rs   # reversible response actions (kill, suspend, block, isolate)
├── auto_response.rs     # automated response rule engine
├── baseline.rs          # behavioural baseline profiles (capped at 512, LRU eviction)
├── beacon.rs            # beaconing pattern detection
├── blocklist.rs         # IP/domain blocklist loading and matching
├── break_glass.rs       # network isolation break-glass recovery
├── detection_depth.rs   # detection depth scoring signals
├── entropy.rs           # entropy-based anomaly detection
├── forensics.rs         # process memory dump (global throttle 30s)
├── fswatch.rs           # filesystem change monitoring
├── geoip.rs             # MaxMind GeoIP city/ASN lookups
├── honeypot.rs          # honeypot port monitoring
├── logger.rs            # tracing initialization with daily rolling log
├── longlived.rs         # long-lived connection detection
├── pcap.rs              # PCAP capture (global throttle 60s)
├── quarantine.rs        # file quarantine
├── registry.rs          # Windows registry monitoring
├── response_rules.rs    # user-defined response rules
├── revdns.rs            # async reverse DNS (cache capped at 4096)
├── service.rs           # Windows service install/uninstall
├── session.rs           # pre-login session detection
├── tamper.rs            # tamper detection heuristics
├── tls.rs               # TLS session metadata
├── tls_artifacts.rs     # TLS ClientHello artifacts (JA3, SNI; cache capped at 1024)
├── audit.rs             # audit logging
└── ui/
    ├── mod.rs           # VigilApp: eframe::App impl; holds state, receives ConnEvents
    ├── theme.rs         # colour constants + egui Visuals setup
    ├── process_list.rs  # process-grouped tables with cached grouping
    ├── activity.rs      # activity table + row storage
    ├── alerts.rs        # alerts table + row storage
    ├── inspector.rs     # right-hand detail panel; show(info) / show_placeholder()
    ├── settings.rs      # settings panel (sliders, trusted list, save)
    └── help.rs          # static help content
```

---

## Core Types  (`src/types.rs`)

```rust
/// Everything captured about a single connection event.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub timestamp:    String,       // "HH:MM:SS"
    pub proc_name:    String,
    pub pid:          u32,
    pub proc_path:    String,       // empty if unavailable
    pub proc_user:    String,
    pub local_addr:   String,       // "ip:port"
    pub remote_addr:  String,       // "ip:port" or "LISTEN"
    pub status:       String,       // ESTABLISHED | LISTEN | …
    pub score:        u8,
    pub reasons:      Vec<String>,
    // enrichment
    pub parent_name:  String,
    pub parent_pid:   u32,
    pub service_name: String,
    pub publisher:    String,
}

/// Sent over the broadcast channel from monitor → UI.
#[derive(Debug, Clone)]
pub enum ConnEvent {
    NewConnection(ConnInfo),        // score < threshold
    NewAlert(ConnInfo),             // score >= threshold
    ConnectionClosed { pid: u32, local: String, remote: String },
}

/// Tray icon state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrayState { Ok, Alert, Stopped }

/// Messages from UI → monitor (control plane).
pub enum MonitorMsg {
    Stop,
    UpdateConfig(crate::config::Config),
}
```

---

## Scoring Algorithm  (`src/score.rs`)

Exact logic ported from Python. Returns `(score, reasons)`. **Do not change scoring
values without updating the Help tab text.**

```
if remote is loopback/unspecified OR status == LISTEN with no remote → return (0, [])

+3  no executable path AND proc_name ∉ {"system", "kernel"}
    reason: "No executable path (possible process injection)"

+3  path.to_uppercase() contains any suspicious_path_fragment (uppercased)
    reason: "Running from suspicious path: {path}"
    (break after first match)

+4  proc_name (lowercase, strip .exe) ∈ lolbins set
    reason: "System binary making network connection: {name} (living-off-the-land)"

+5  remote_port ∈ malware_ports
    reason: "Connection to known malware port {port}"

+1  remote_port ∉ common_ports AND proc_name ∉ trusted_processes
    reason: "Unusual destination port {port}"

+2  proc_name ∉ trusted_processes
    reason: "Unrecognised process: {name}"
```

---

## Config Defaults  (`src/config.rs`)

Compile these in as a `const &str` JSON blob so the binary works with no config file.

```json
{
  "poll_interval_secs": 5,
  "alert_threshold": 3,
  "log_all_connections": false,
  "autostart": false,
  "first_run_done": false,
  "trusted_processes": [
    "svchost","lsass","services","system","smss","csrss","wininit","winlogon",
    "explorer","runtimebroker","searchhost","startmenuexperiencehost","shellhost",
    "sihost","ctfmon","textinputhost","shellexperiencehost","widgetservice",
    "widgetboard","crossdeviceservice","crossdeviceresume","phoneexperiencehost",
    "castsrv","chrome","msedge","firefox","opera","brave","vivaldi",
    "msedgewebview2","cefsharp.browsersubprocess","onedrive","systemsettings",
    "microsoftstartfeedprovider","avgsvc","avgui","avgbidsagent","avgdriverupdsvc",
    "avgtuneupssvc","vpnsvc","tuneupssvc","avgwscreporter","avgAntitrack",
    "antitrackSvc","securevpn","su_worker","avgtoolssvc","wa_3rd_party_host_64",
    "avlaunch","claude","node","python","python3","spotify","steam",
    "epicgameslauncher","ealauncher","eadesktop","eabackgroundservice",
    "whatsapp","whatsapp.root","zoom","slack","discord","telegram",
    "ollama","ollama_llama_server","nvdisplay.containerlocalsystem",
    "nvbroadcast.containerlocalsystem","rtkaudiouniversalservice",
    "intelgraphicssoftwareservice","waasmedicsvc","wsaifabricsvc"
  ],
  "common_ports": [80,443,8080,8443,53,853,22,21,25,587,465,993,995,
                   110,143,5222,5228,3478,3479,7500,27275],
  "malware_ports": [4444,1337,31337,6666,6667,6668,6669,9999,1234,
                    54321,12345,23,5900,5901,4899,8888],
  "suspicious_path_fragments": [
    "\\Temp\\","\\AppData\\Local\\Temp\\","\\AppData\\Roaming\\",
    "\\Downloads\\","\\Public\\","/tmp/","/var/tmp/"
  ],
  "lolbins": [
    "cmd","powershell","pwsh","wscript","cscript","mshta","regsvr32",
    "rundll32","certutil","bitsadmin","wmic","msiexec","installutil",
    "regasm","regsvcs","forfiles"
  ]
}
```

---

## UI Design Language

Goal: **simple, dark, polished** — feels like a native app, not a toolkit demo.

- **Fonts:** embed Inter (UI text) + JetBrains Mono (addresses, paths, code) via `egui::FontData`
- **Rounding:** 6px on panels, 4px on badges, 2px on buttons
- **Spacing:** 8px base unit — all padding/margin is a multiple of 4px
- **Shadows:** `egui::epaint::Shadow` on the inspector panel left edge
- **Borders:** 1px BORDER colour separators, never raised/sunken 3D effects
- **Score badges:** coloured pill (fg + bg pair), bold monospace score number
- **Tables:** alternating row bg (SURFACE / SURFACE2), no visible grid lines
- **Buttons:** flat, no border, bg on hover only — not the default egui square look
- **Tab bar:** custom widget, ACCENT 2px bottom underline on active, no box chrome
- **Animations:** none needed — immediate mode, keep it snappy
- **Icons:** inline Unicode characters (● ○ ▸ ✓ ✕) — no icon font needed for v1

## UI Theme Constants  (`src/ui/theme.rs`)

```rust
pub const BG:       egui::Color32 = egui::Color32::from_rgb(0x14, 0x15, 0x1A);
pub const SURFACE:  egui::Color32 = egui::Color32::from_rgb(0x1C, 0x1D, 0x24);
pub const SURFACE2: egui::Color32 = egui::Color32::from_rgb(0x25, 0x26, 0x30);
pub const SURFACE3: egui::Color32 = egui::Color32::from_rgb(0x2E, 0x30, 0x40);
pub const TEXT:     egui::Color32 = egui::Color32::from_rgb(0xE2, 0xE4, 0xEA);
pub const TEXT2:    egui::Color32 = egui::Color32::from_rgb(0x8A, 0x8D, 0x9A);
pub const TEXT3:    egui::Color32 = egui::Color32::from_rgb(0x4A, 0x4D, 0x5C);
pub const ACCENT:   egui::Color32 = egui::Color32::from_rgb(0x22, 0xC5, 0x5E); // green
pub const WARN:     egui::Color32 = egui::Color32::from_rgb(0xF5, 0x9E, 0x0B); // amber
pub const DANGER:   egui::Color32 = egui::Color32::from_rgb(0xEF, 0x44, 0x44); // red
pub const BORDER:   egui::Color32 = egui::Color32::from_rgb(0x2A, 0x2C, 0x38);
```

Score badge colours:
- score 0–2 → fg=ACCENT, bg=`#0F2318`
- score 3–4 → fg=WARN,   bg=`#211804`
- score 5+  → fg=DANGER, bg=`#1E0808`

---

## UI Layout Description  (`src/ui/mod.rs`)

```
┌─────────────────────────────────────────────────────────┐
│ Header: "Vigil"  [● Monitoring]            [Pause]      │ SURFACE bg
├──────────────────────────────────────────────────────────┤
│ [Activity] [Alerts (n)] [Settings] [Help]               │ SURFACE, ACCENT underline on active
├──────────────────────────────────────────────────────────┤
│                                       │                  │
│  ← List panel (fill, expand)          │ Inspector 310px  │
│  (Activity or Alerts treeview,        │ (hidden on       │
│   Settings form, or Help scroll)      │  Settings/Help)  │
│                                       │                  │
└───────────────────────────────────────┴──────────────────┘
```

Column widths (Activity): Time 72 · Process 210 (stretch) · Remote 155 · Status 108 · Score 56  
Column widths (Alerts):   Time 72 · Process 185 · Score 56 · Remote 155 · Reasons (stretch)

Inspector sections (top → bottom):
1. Score badge + timestamp
2. Process name (bold, 12pt) + full path (7pt, muted)
3. **Process** section: Publisher · Parent (name + PID) · Service · User · PID
4. **Connection** section: Remote · Local · Status
5. **Why it scored** section: bulleted reasons
6. **Actions** section: `[Trust]` `[Open Location]` `[Kill Process]`

---

## Channel Architecture

```
                    Arc<RwLock<Config>>
                           │
Monitor (spawn_blocking) ──┤── broadcast::Sender<ConnEvent>
  ├── poll.rs (fallback)   │        │
  ├── etw.rs (Windows)     │        ▼
  └── ebpf.rs (Linux)      │   VigilApp (main thread / egui)
                           │        │
Tray thread (std::thread)  │        ├── activity table
  ├── Win32 msg pump       │        ├── alerts table
  └── GLib MainContext     │        ├── inspector panel
                           │        └── tray::TrayCmd channel → tray thread
TrayCmd channel ◄──────────┘
  (Alert, ResetOk, SetLockdown)
```

---

## Windows-Only Code Sections

Always guard with `#[cfg(target_os = "windows")]` or `cfg!(windows)` inline.

- `process/publisher.rs` — `VerQueryValueW` for PE company name
- `monitor/etw.rs` — ETW session
- Windows service map: `EnumServicesStatusExW` → `HashMap<u32, String>` (pid → service name)
- Autostart: handled by `auto-launch` crate (no manual cfg needed)
- `SetCurrentProcessExplicitAppUserModelID("Vigil.App.1")` in `main.rs`

---

## First-Run Behaviour

On first launch (`config.first_run_done == false`):
1. Enable autostart via `auto-launch`
2. Set `config.autostart = true`
3. Set `config.first_run_done = true`
4. Save config

---

## Session Workflow

Every new coding session:
1. Read this file (`CLAUDE.md`)
2. Read `ROADMAP.md` — check current phase and next action
3. Read only the specific `src/*.rs` files you will edit
4. Write code; ask user to run `cargo check` or `cargo build` after each module
5. Update the **Current Phase** section at the top of this file before ending

**Never** read `C:\dev\threat_detector\*.py` unless you need to verify exact behaviour
of a specific feature. The Python source is reference only.

---

## Things That Must Not Change

- Scoring values (+1/+2/+3/+4/+5) — help text hardcodes them
- ConnInfo field names — used across all modules
- Colour constants — match the Python version's dark theme exactly
- The first-run autostart behaviour
- Alert threshold default of 3
