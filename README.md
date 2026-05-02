# Vigil

[![CI](https://github.com/YMRYMR/vigil/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/YMRYMR/vigil/actions/workflows/ci.yml)
[![CodeQL](https://github.com/YMRYMR/vigil/actions/workflows/codeql.yml/badge.svg?branch=master&event=push)](https://github.com/YMRYMR/vigil/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/YMRYMR/vigil/badge)](https://securityscorecards.dev/viewer/?uri=github.com/YMRYMR/vigil)
[![Snyk](https://github.com/YMRYMR/vigil/actions/workflows/snyk-open-source.yml/badge.svg?branch=master&event=push)](https://github.com/YMRYMR/vigil/actions/workflows/snyk-open-source.yml)
[![Dependency Review](https://github.com/YMRYMR/vigil/actions/workflows/dependency-review.yml/badge.svg?event=pull_request)](https://github.com/YMRYMR/vigil/actions/workflows/dependency-review.yml)
[![Artifact hygiene](https://github.com/YMRYMR/vigil/actions/workflows/artifact-hygiene.yml/badge.svg?branch=master)](https://github.com/YMRYMR/vigil/actions/workflows/artifact-hygiene.yml)
[![Secret scan](https://github.com/YMRYMR/vigil/actions/workflows/secret-scan.yml/badge.svg?branch=master)](https://github.com/YMRYMR/vigil/actions/workflows/secret-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/YMRYMR/vigil?label=release)](https://github.com/YMRYMR/vigil/releases/latest)

Cross-platform endpoint defense for Windows, macOS, and Linux.

Vigil watches live network and process activity on your machine, scores suspicious
behaviour, shows you the process and connection context behind each alert, and
can take reversible containment actions when something needs to be stopped.

It is designed for local machine protection first: detect suspicious outbound
activity quickly, help the operator understand what is happening, preserve
evidence when needed, and contain the machine or process without turning every
high-noise event into a destructive action.

![Vigil current UI](docs/images/vigil-current.png)

---

## Documentation

- [User guide](docs/USER-GUIDE.md) — released functionality, operator workflows, and day-to-day use
- [Security policy](SECURITY.md) — vulnerability reporting and security contacts
- [OpenSSF Best Practices controls](docs/OPENSSF-BEST-PRACTICES.md) — repository controls and maintainer settings
- [Codebase inventory](docs/CODEBASES.md) — repositories that are part of Vigil
- [Advisory source compliance](docs/ADVISORY-SOURCE-COMPLIANCE.md) — attribution, caching, and reuse rules for public vulnerability and advisory feeds

---

## Download the latest build

- [Windows installer](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-windows-x86_64.exe)
- [macOS DMG](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-macos-aarch64.dmg)
- [Linux AppImage](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-linux-x86_64.AppImage)
- [All supported OSs bundle](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-all-supported-os.zip)
- [Signed update manifest](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-update-manifest.json)
- [Manifest signature](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-update-manifest.json.sig)
- GHCR Linux package image: `ghcr.io/YMRYMR/vigil`

The latest-release links above are refreshed by the release pipeline after a
merged `master` change finishes CI and the tag-driven publishing workflow
completes.

The GHCR image tracks the latest released Linux AppImage as a container package
so it is easy to mirror, automate, or consume in CI environments:

```bash
docker pull ghcr.io/YMRYMR/vigil:latest
```

Each release asset is published with a GitHub artifact attestation. Verify a
downloaded file with:

```bash
gh attestation verify PATH/TO/FILE -R YMRYMR/vigil
```

The release workflow also emits SLSA3 provenance for the published assets via
the GitHub Actions SLSA generator. That provenance is attached to the release
for users who prefer `slsa-verifier`-style supply-chain checks.

Merged pull requests to `master` now cut the next patch release automatically
after the `CI` workflow succeeds. That automated version bump creates the tag
that feeds the existing signed release pipeline, so `releases/latest` and the
signed update manifest stay in sync with merged code.

The signed update manifest is the trust anchor for Vigil's update channel. It
lists the release assets and their SHA-256 digests, then gets signed with an
embedded Ed25519 public key in the app. You can verify it offline with:

```bash
vigil --verify-update-manifest Vigil-latest-update-manifest.json Vigil-latest-update-manifest.json.sig
```

Vigil's offline advisory importer also accepts one or more local NVD CVE JSON
files in a single run, which is useful when the export is split into pages or
incremental batches:

```bash
vigil --import-nvd-snapshot nvdcve-page-1.json nvdcve-page-2.json
```

Vigil can also pull the live NVD CVE API directly into the same protected
cache. The sync path uses incremental `lastModStartDate` / `lastModEndDate`
windows after the first fetch, respects the NVD's 2-hour automated polling
guidance, and keeps the last trusted cache if refresh fails:

```bash
vigil --sync-nvd
```

Vigil can also maintain a separate protected cache of the public NVD CVE
change-history feed so operators can audit re-analysis and upstream metadata
changes over time:

```bash
vigil --sync-nvd-change-history
vigil --advisory-change-history-status
```

For offline or batched imports, pass one or more local NVD CVE change-history
JSON snapshots:

```bash
vigil --import-nvd-change-history nvdcvehistory-page-1.json nvdcvehistory-page-2.json
```

When Vigil is using the live NVD API, `vigil --advisory-cache-status` now shows
the required notice: "This product uses the NVD API but is not endorsed or
certified by the NVD."

Use `--sync-nvd --force` only when you need to override the normal 2-hour
minimum interval. Provide an API key via `VIGIL_NVD_API_KEY` if your deployment
needs higher NVD API headroom.

---

## What Vigil Does

### Detect and surface suspicious activity

- **Sub-100 ms detection** on Windows via ETW (Event Tracing for Windows);
  on Linux via eBPF (`sock:inet_sock_set_state` tracepoint); DTrace-assisted
  fallback on macOS when available; polling fallback on older kernels and other
  degraded paths
- **Visible backend status** — the header now makes it clear whether Vigil is
  running on ETW, eBPF, DTrace-assisted fallback, or a polling fallback, and
  current macOS builds show an explicit native-backend fallback notice instead
  of implying full Endpoint Security coverage
- **Multi-signal threat scoring** across behavioural, reputation, persistence,
  and execution-context signals so alerts stay explainable instead of opaque
- **Passive persistence and timing signals** including registry autoruns,
  beaconing behaviour, pre-login activity, long-lived connections, and DGA-like
  hostnames
- **Offline enrichment** with local blocklists, geolocation, ASN data, reverse
  DNS, and file-drop correlation

### Help investigate what is happening
- **Full ancestor process tree** — see exactly which process spawned which,
  up to 8 levels deep
- **Process-first GUI** — Activity and Alerts views are grouped around the local
  process, with a detailed Inspector for path, parent, publisher, user, remote
  endpoint, score reasons, badges, and enrichment context
- **Clickable notifications and tray workflow** — alerts can take you straight
  into the relevant connection from the desktop or tray icon
- **Boot-time service mode** — monitor before login so early persistence and
  pre-user activity are still visible when the operator signs in

### Protect and contain the machine

- **Active response** — reversible actions (Windows + Linux) for killing a live
  TCP connection, suspending or resuming a process during investigation,
  blocking a remote IP for 1 hour, 24 hours, or permanently, blocking a
  process by executable path, or isolating the machine
- **Containment safety rails** — confirmation prompts for destructive actions,
  live countdowns for temporary blocks, inline unblock controls, and break-glass
  recovery for isolation
- **Policy-driven automation** — user-defined response rules, scheduled
  lockdown, allowlist-only mode, and threshold-based escalation planning

### Preserve trust, evidence, and operator control

- **Forensic capture on high-confidence alerts (Windows today)** — short PCAP
  capture, process memory dump, TLS sidecar metadata, and provenance manifests
- **Tamper-evident local state** — protected policy store, integrity-backed
  generated state, audit-log chaining, and signed update manifests
- **Daily rolling logs and audit trail** — operator-visible records for alerts,
  actions, integrity events, and other security-relevant state changes
- **Privilege-aware UX** — Vigil makes clear when elevated permissions are
  required for deeper visibility or containment

---

## How the score works

Each new connection is scored independently across seventeen signals. Points
stack — a PowerShell process spawned by Word, connecting to port 4444, can
score 3 + 3 + 4 + 5 = 15. The alert threshold is configurable (default: 3).

| Points | Signal |
|--------|--------|
| +5 | Connection to a known malware / C2 port (4444, 1337, 31337, …) |
| +4 | Living-off-the-land binary making a network connection (`powershell`, `cmd`, `mshta`, …) |
| +3 | No executable path found — possible process injection or hollowing |
| +3 | Running from a suspicious directory (`\\Temp\\`, `\\AppData\\Roaming\\`, …) |
| +3 | Suspicious parent process (e.g. `winword.exe` spawning `powershell.exe`) |
| +3 | Beaconing pattern detected — regular C2 callback timing signature |
| +3 | IP reputation hit — remote matched a user-supplied blocklist (**Phase 10**, REP badge) |
| +3 | Executable was just dropped into Temp/AppData/Downloads before connecting (**Phase 10**, DRP badge) |
| +2 | Unrecognised process (not on your trusted list) |
| +2 | Unsigned binary — no code-signing certificate |
| +2 | DNS query (port 53) from a non-DNS process — possible DNS tunneling |
| +2 | Connection observed **before user login** — rootkit / dropper signal (PL badge) |
| +2 | Connection to an unexpected country (**Phase 10**, requires `allowed_countries`) |
| +2 | Long-lived connection from untrusted process past threshold (**Phase 10**, LL badge) |
| +2 | Hostname looks DGA-generated — high Shannon entropy (**Phase 10**, DGA badge) |
| +1 | Unusual destination port for an untrusted process |

Trusted processes skip the **+2 unrecognised** and **+2 unsigned** penalties,
so routine connections from browsers and system services score 0. High-severity
signals (malware ports, LoLBins, pre-login activity) still apply — if a trusted
app suddenly dials a C2 port, you want to know.

Vigil also runs two passive persistence watchers that raise synthetic alerts
(independent of active connections):

- **Registry autorun watcher** (Windows) — polls `HKCU\\…\\Run`, `HKLM\\…\\Run`,
  and both `RunOnce` keys every 30 s; alerts on any new entry.
- **Beaconing detector** — tracks inter-arrival time per `(pid, remote_ip)`
  across a rolling 30-sample window; flags stddev < 5 s / mean 1 – 600 s.

---

## Installation

### Windows — one-click installer

1. Download `Vigil-Setup-<version>-x86_64.exe` from the [latest release].
2. Run the installer — by default it installs for the current user, creates a
   Start Menu shortcut, and registers it for autostart. If you choose an
   all-users install during setup, Vigil is installed in `Program Files`.

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
[`winres`](https://crates.io/crates/winres). This requires the Windows SDK
(`rc.exe`) or [`llvm-rc`](https://llvm.org/docs/CommandGuide/llvm-rc.html).
If neither is present the build still succeeds — it just won't have the
custom icon in the taskbar.

---

## Configuration

Settings are stored in `vigil.json` in the per-user Vigil data directory and are fully
editable in-app via the **Settings** tab:

| Setting | Default | Description |
|---------|---------|-------------|
| `alert_threshold` | 3 | Minimum score to trigger an alert |
| `poll_interval_secs` | 5 | Seconds between full connection polls |
| `log_all_connections` | false | Log every connection, not just suspicious ones |
| `autostart` | true | Launch Vigil at login; elevated Windows runs use a highest-privilege scheduled task |
| `trusted_processes` | *(see below)* | Process names exempt from low-level scoring |

### Default trusted processes

Vigil ships with a curated list of common trusted processes (browsers,
Windows system services, antivirus, communication apps, etc.) so you get
useful alerts out of the box without tuning. On first run that list is
written into `vigil.json` in the per-user Vigil data directory as the
starting config, and any later edits you make in-app persist immediately.
You can add or remove entries in the
**Settings → Trusted Processes** grid, or click **Trust** in the Inspector
panel while a real process with a known executable location is selected.
The Settings tab also includes a `Reset shipped defaults` button if you want
to restore the bundled list.

The Inspector disables `Trust` and `Open Loc` when the executable location is
unknown, and disables `Kill` for unresolved PID placeholder rows like
`<11540>`.

### Active response

The top bar also reflects privilege state: it shows an `Admin` badge when
Vigil is elevated. On Windows and Linux, the app can also offer an in-app
elevation action when that relaunch path is supported. Current macOS builds
require starting Vigil from an elevated shell for privileged features.

When Vigil is running with elevated privileges (admin on Windows,
`CAP_NET_ADMIN` or root on Linux), the Inspector can take reversible action:

- **Kill connection** immediately tears down the selected live TCP socket.
- **Suspend process** freezes the selected PID without killing it; **Resume process** continues it later.
- **Block remote** lets you choose a 1 hour, 24 hour, or permanent outbound
  firewall rule for the selected connection's remote IP. Temporary blocks show
  a live countdown and an inline unblock button.
- **Block process** lets you choose a 1 hour, 24 hour, or permanent firewall
  rule for all traffic from the selected executable path. Temporary blocks
  show a live countdown and an inline unblock button.
- **Isolate network** (Windows, Linux, macOS) now uses strict containment:
  it first applies firewall-level isolation (iptables on Linux) and verifies outbound reachability.
  If outbound traffic is still possible, Vigil falls back to emergency adapter
  cutoff and keeps snapshot state for restore.
- **Restore network** restores the saved firewall and adapter state.
- **Isolation failsafe**: isolation always carries an auto-restore deadline,
  and Vigil always arms break-glass recovery while isolation is active so a
  crash can restore networking from saved state.
- Isolation/restore run immediately from the panic button; confirmation remains
  for destructive process/connection actions.

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
The folder is inside the per-user Vigil data directory.

---

## Running before login (all platforms)

Vigil can install itself as a boot-time service so monitoring starts
**before any user logs in** — useful for detecting rogue processes that
activate early in the boot sequence (rootkits, dropper callbacks,
persistence mechanisms).

Connections captured before login get a **+2 score bump** and a red
**`PL`** badge in the Time column, so when the first user logs in they
immediately see everything the monitor caught during boot.

From an elevated shell:

| OS      | Command                                          |
| ------- | ------------------------------------------------ |
| Windows | `vigil.exe --install-service`   *(Admin CMD)*    |
| macOS   | `sudo vigil --install-service`                   |
| Linux   | `sudo vigil --install-service`                   |

To remove the boot-time service, replace with `--uninstall-service`.

Under the hood:

- Windows uses the Service Control Manager (`sc create Vigil …`).
- macOS writes a launchd system daemon at
  `/Library/LaunchDaemons/com.vigil.monitor.plist` and `launchctl load`s it.
- Linux writes a systemd unit at `/etc/systemd/system/vigil.service` and
  enables it with `systemctl enable --now vigil.service`.

Note: service mode runs the **monitor only** — the tray icon and GUI
require a logged-in desktop session and launch normally via autostart.

---

## Reputation, geolocation & file-drop correlation (Phase 10)

Vigil layers offline reputation data on top of its behavioural scoring.
All of it is off by default; point the config at your data to enable it.

### Add geolocation and ASN lookup

Download the free MaxMind GeoLite2-City and GeoLite2-ASN `.mmdb` files
from https://www.maxmind.com/en/geolite2/signup and drop them anywhere
on disk. Then edit the `vigil.json` file in the per-user Vigil data directory:

```json
{
  "geoip_city_db": "C:\\vigil\\GeoLite2-City.mmdb",
  "geoip_asn_db":  "C:\\vigil\\GeoLite2-ASN.mmdb",
  "allowed_countries": ["US", "GB", "ES"]
}
```

With the City DB, every row in Activity and Alerts gets a country code
in the Remote column. With the ASN DB, the Inspector shows the remote's
ASN number and AS organisation (e.g. `AS15169  Google LLC`). With
`allowed_countries` set, connections to anywhere else score **+2**.

### Add IP blocklists

Drop plain-text blocklists anywhere and list them:

```json
{
  "blocklist_paths": [
    "C:\\vigil\\abuseipdb.txt",
    "C:\\vigil\\firehol-level1.txt"
  ]
}
```

Format: one IP or CIDR per line, `#` starts a comment. Each blocklist file
must have a matching `<filename>.sha256` sidecar in standard `sha256sum`
format or Vigil will refuse to load it. Hits add **+3** and the Alerts row
gets a red `REP` badge naming the source list.

### File-drop correlation

Enabled by default. Vigil watches `%TEMP%`, `%LOCALAPPDATA%\\Temp`,
`%APPDATA%`, `Downloads`, and (on Unix) `/tmp` and `/var/tmp` for new
`.exe` / `.dll` / `.ps1` / `.scr` / `.msi` / `.sh` / `.py` drops. When a
connection originates from a file that was dropped within the last
`fswatch_window_secs` seconds (default 600), Vigil adds **+3** and shows
a `DRP` badge. This catches staged-payload chains
(phish → macro → dropper → callback) in flagrante.

### Long-lived connection bonus

Untrusted processes that hold a connection open past `long_lived_secs`
(default 3600 s = 1 h) earn **+2** and an `LL` badge. Browsers and other
trusted processes are exempt.

### DGA hostname detection

Off by default because reverse-DNS queries leak the fact Vigil is
watching to the OS resolver. Turn it on with `"reverse_dns_enabled":
true` in the config. Hostnames whose leftmost label has Shannon entropy
≥ `dga_entropy_threshold` (default 3.2 bits/char) earn **+2** and a
`DGA` badge. Brand names like `google.com` or `paypal.com` score well
below the threshold; machine-generated strings like `xj4k8s9qzr.com`
trip it.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on bug reports, feature
requests, and pull requests.

---

## License

[MIT](LICENSE)

[latest release]: https://github.com/YMRYMR/vigil/releases/latest