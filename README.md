# Vigil

Real-time network threat monitor for Windows, macOS, and Linux.

Vigil watches every TCP/UDP connection on your machine, scores each one for
suspicious behaviour, and alerts you — via a system tray icon, desktop
notification, and a full GUI — the moment something looks wrong.

---

## Features

- **Sub-100 ms detection** on Windows via ETW (Event Tracing for Windows);
  polling fallback on other platforms
- **Multi-signal threat scoring** (0–10+) across eight detection categories
- **Full ancestor process tree** — see exactly which process spawned which,
  up to 8 levels deep
- **System tray** — amber icon + tooltip on alert; green when all-clear;
  left-click opens the UI, right-click shows the menu
- **Clickable notifications** — clicking a desktop alert opens Vigil and
  navigates directly to the triggering connection
- **Full GUI** — sortable/filterable Activity and Alerts tables, Inspector
  panel (trust, kill, open file location), Settings, Help
- **Rolling daily log** at `<install-dir>/logs/vigil.YYYY-MM-DD`
- **Autostart at login** enabled on first run (configurable in Settings)

---

## How the score works

Each new connection is scored independently across eight signals. Points
stack — a PowerShell process spawned by Word, connecting to port 4444, can
score 3 + 3 + 4 + 5 = 15. The alert threshold is configurable (default: 3).

| Points | Signal |
|--------|--------|
| +5 | Connection to a known malware / C2 port (4444, 1337, 31337, …) |
| +4 | Living-off-the-land binary making a network connection (`powershell`, `cmd`, `mshta`, …) |
| +3 | No executable path found — possible process injection or hollowing |
| +3 | Running from a suspicious directory (`\Temp\`, `\AppData\Roaming\`, …) |
| +3 | Suspicious parent process (e.g. `winword.exe` spawning `powershell.exe`) |
| +2 | Unrecognised process (not on your trusted list) |
| +2 | Unsigned binary — no code-signing certificate |
| +1 | Unusual destination port for an untrusted process |

Trusted processes skip the **+2 unrecognised** and **+2 unsigned** penalties,
so routine connections from browsers and system services score 0.  High-severity
signals (malware ports, LoLBins) still apply — if a trusted app suddenly dials
a C2 port, you want to know.

---

## Installation

### Windows — one-click installer

1. Download `Vigil-Setup-<version>-x86_64.exe` from the [latest release].
2. Run the installer — it places Vigil in `Program Files`, creates a Start
   Menu shortcut, and registers it for autostart.

> **Note:** ETW-based real-time monitoring requires Administrator rights.
> Without elevation, Vigil falls back to polling every few seconds — all
> other features work normally.

### macOS — DMG

1. Download `Vigil-<version>-aarch64.dmg` from the [latest release].
2. Open the DMG and drag **Vigil.app** to your Applications folder.
3. Launch Vigil — it will ask for network monitoring permission on first run.

### Linux — AppImage

1. Download `Vigil-<version>-x86_64.AppImage` from the [latest release].
2. Make it executable: `chmod +x Vigil-*.AppImage`
3. Double-click to run, or launch from the terminal.

---

## Building from source

**Prerequisites:** [Rust stable](https://rustup.rs) 1.75+

```sh
git clone https://github.com/YMRYMR/vigil.git
cd vigil
cargo build --release
```

The binary is written to `target/release/vigil` (or `vigil.exe` on Windows).

### Using `just`

Install [just](https://just.systems) then:

```sh
just build      # debug build
just release    # optimised release build
just test       # run the test suite
just lint       # clippy -D warnings
just install    # copy release binary to the system (platform-specific)
just ci         # fmt-check + lint + test (mirrors CI)
```

### Windows icon embedding

`build.rs` generates a multi-size `.ico` file and embeds it via
[`winres`](https://crates.io/crates/winres).  This requires the Windows SDK
(`rc.exe`) or [`llvm-rc`](https://llvm.org/docs/CommandGuide/llvm-rc.html).
If neither is present the build still succeeds — it just won't have the
custom icon in the taskbar.

---

## Configuration

Settings are stored in `vigil.json` next to the executable and are fully
editable in-app via the **Settings** tab:

| Setting | Default | Description |
|---------|---------|-------------|
| `alert_threshold` | 3 | Minimum score to trigger an alert |
| `poll_interval_secs` | 5 | Seconds between full connection polls |
| `log_all_connections` | false | Log every connection, not just suspicious ones |
| `autostart` | true | Launch Vigil at login |
| `trusted_processes` | *(see below)* | Process names exempt from low-level scoring |

### Default trusted processes

Vigil ships with a curated list of common trusted processes (browsers,
Windows system services, antivirus, communication apps, etc.) so you get
useful alerts out of the box without tuning.  You can add or remove entries
in the **Settings → Trusted Processes** table, or click **Trust** in the
Inspector panel while a connection is selected.

---

## Logs

Log files land in `<exe-dir>/logs/` and rotate daily:

```
vigil.2025-07-04
vigil.2025-07-05
```

Each line follows the format:

```
2025-07-04 14:23:01.412  INFO chrome.exe (1234) | 192.168.1.5:54321 → 142.250.80.46:443 | score=0
2025-07-04 14:23:05.119  WARN powershell.exe (9012) | 10.0.0.2:61000 → 10.10.10.10:4444 | score=9
```

Open the log folder via the tray icon context menu → **Open Logs Folder**.

---

## Running before login (Windows service mode)

Vigil can be installed as a Windows service so monitoring starts before any
user logs in — useful for detecting rogue processes that activate early in
the boot sequence:

```cmd
sc create Vigil binPath= "C:\Program Files\Vigil\vigil.exe" start= auto
sc description Vigil "Real-time network threat monitor"
sc start Vigil
```

Note: service mode runs without a GUI. Alerts are written to the log file
only.  The GUI launches normally when a user logs in.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on bug reports, feature
requests, and pull requests.

---

## License

[MIT](LICENSE)

[latest release]: https://github.com/YMRYMR/vigil/releases/latest
