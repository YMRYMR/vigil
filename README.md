# Vigil

[![CI](https://github.com/YMRYMR/vigil/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/YMRYMR/vigil/actions/workflows/ci.yml)
[![CodeQL](https://github.com/YMRYMR/vigil/actions/workflows/codeql.yml/badge.svg?branch=master&event=push)](https://github.com/YMRYMR/vigil/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/YMRYMR/vigil/badge)](https://securityscorecards.dev/viewer/?uri=github.com/YMRYMR/vigil)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/YMRYMR/vigil?label=release)](https://github.com/YMRYMR/vigil/releases/latest)

Endpoint defense for **Windows and Linux**.

Vigil watches live network and process activity, scores suspicious behaviour,
shows the process and connection context behind each alert, and can take
reversible containment actions when something needs to be stopped.

The active support scope is Windows and Linux only. See
[`docs/SUPPORTED-PLATFORMS.md`](docs/SUPPORTED-PLATFORMS.md) for the support
contract and startup-safety rule.

---

## Documentation

- [User guide](docs/USER-GUIDE.md) — released functionality and operator workflows
- [Supported platforms](docs/SUPPORTED-PLATFORMS.md) — Windows/Linux support contract
- [Security policy](SECURITY.md) — vulnerability reporting and security contacts
- [OpenSSF Best Practices controls](docs/OPENSSF-BEST-PRACTICES.md) — repository controls and maintainer settings
- [Codebase inventory](docs/CODEBASES.md) — repositories that are part of Vigil
- [Advisory source compliance](docs/ADVISORY-SOURCE-COMPLIANCE.md) — attribution, caching, and reuse rules for public vulnerability and advisory feeds

---

## Download the latest build

- [Windows installer](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-windows-x86_64.exe)
- [Linux AppImage](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-linux-x86_64.AppImage)
- [Signed update manifest](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-update-manifest.json)
- [Manifest signature](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-update-manifest.json.sig)
- GHCR Linux package image: `ghcr.io/YMRYMR/vigil`

The latest-release links are refreshed by the release pipeline after a merged
`master` change finishes CI and the tag-driven publishing workflow completes.

The GHCR image tracks the latest released Linux AppImage as a container package:

```bash
docker pull ghcr.io/YMRYMR/vigil:latest
```

Each release asset is published with a GitHub artifact attestation. Verify a
downloaded file with:

```bash
gh attestation verify PATH/TO/FILE -R YMRYMR/vigil
```

The signed update manifest is the trust anchor for Vigil's update channel. It
lists release assets and SHA-256 digests, then gets signed with the embedded
Ed25519 public key. Verify it offline with:

```bash
vigil --verify-update-manifest Vigil-latest-update-manifest.json Vigil-latest-update-manifest.json.sig
```

---

## What Vigil does

### Detect and surface suspicious activity

- **Sub-100 ms detection** on Windows via ETW and on Linux via eBPF when available.
- **Polling fallback** when the realtime backend is unavailable.
- **Multi-signal threat scoring** across behaviour, reputation, persistence, and execution context.
- **Passive persistence and timing signals** such as registry autoruns, beaconing, pre-login activity, long-lived connections, and DGA-like hostnames.
- **Offline enrichment** with local blocklists, geolocation, ASN data, reverse DNS, and file-drop correlation.

### Help investigate what is happening

- **Full ancestor process tree** up to 8 levels deep.
- **Process-first GUI** with Activity, Alerts, Settings, Help, and a detailed Inspector.
- **Clickable notifications and tray workflow** for fast triage.
- **Boot-time service mode** for monitoring before login on supported platforms.

### Protect and contain the machine

- **Active response** on Windows and Linux: kill a live TCP connection, suspend/resume a process, block a remote IP, block a process by executable path, or isolate the machine.
- **Containment safety rails**: confirmation prompts, countdowns for temporary blocks, inline unblock controls, and break-glass recovery.
- **Policy-driven automation**: user-defined response rules, scheduled lockdown, allowlist-only mode, and threshold escalation.

### Preserve trust, evidence, and operator control

- **Forensic capture on high-confidence alerts** where supported, including PCAP, process dump, TLS sidecar metadata, and provenance manifests.
- **Tamper-evident local state** for policy, generated state, audit logs, and update manifests.
- **Daily rolling logs and audit trail** for alerts, actions, integrity events, and other security-relevant changes.
- **Privilege-aware UX** that shows when deeper visibility or containment requires elevation.

---

## Public advisory and vulnerability intelligence

Vigil treats public vulnerability and advisory matches conservatively. A match
means Vigil found a plausible link between local software and a public CVE or
advisory record from its local source cache; it does not prove exploitation or
compromise.

Offline import examples:

```bash
vigil --import-nvd-snapshot nvdcve-page-1.json nvdcve-page-2.json
vigil --import-nvd-change-history nvdcvehistory-page-1.json
vigil --import-euvd euvd-export.json
vigil --import-jvn jvn-export.json jvndbrss.xml
vigil --import-ncsc ncsc-feed.xml ncsc-mirror.json
vigil --import-bsi certbund-feed.xml bsi-advisories.json
```

Live NVD sync:

```bash
vigil --sync-nvd
vigil --sync-nvd-change-history
vigil --advisory-cache-status
vigil --advisory-change-history-status
```

Use `--sync-nvd --force` only when you need to override the normal 2-hour
minimum interval. Provide an API key via `VIGIL_NVD_API_KEY` if the deployment
needs higher NVD API headroom.

The standalone inventory helper can inspect local Windows/Linux software
metadata without touching Vigil's startup path:

```bash
vigil_inventory
```

---

## Installation

### Windows

1. Download the Windows installer from the latest release.
2. Run the installer. By default it installs for the current user, creates a Start Menu shortcut, and enables Vigil at login.
3. For before-login monitoring, choose an all-users install or run the service install command from an elevated shell.

> ETW-backed realtime monitoring requires Administrator rights. Without elevation, Vigil falls back to polling.

### Linux

1. Download the Linux AppImage from the latest release.
2. Make it executable:

```bash
chmod +x Vigil-*.AppImage
```

3. Launch it from the desktop or terminal.

Linux active response requires root or the required Linux capabilities, depending on the action.

---

## Building from source

Prerequisite: Rust stable 1.75+.

```bash
git clone https://github.com/YMRYMR/vigil.git
cd vigil
cargo build --release
```

The binary is written to `target/release/vigil` or `target/release/vigil.exe`.

Using `just`:

```bash
just build
just release
just test
just lint
just install
just ci
```

### Windows icon embedding

`build.rs` generates a multi-size `.ico` file and embeds it via `winres`. This
requires the Windows SDK `rc.exe` or `llvm-rc`. If neither is present, the build
still succeeds without the custom taskbar icon.

---

## Configuration

Settings are stored in `vigil.json` in the per-user Vigil data directory and are
editable in-app through Settings.

Common settings include:

| Setting | Default | Description |
|---------|---------|-------------|
| `alert_threshold` | 3 | Minimum score to trigger an alert |
| `poll_interval_secs` | 5 | Seconds between full connection polls |
| `log_all_connections` | false | Log every connection, not just suspicious ones |
| `autostart` | true | Launch Vigil at login |
| `trusted_processes` | shipped defaults | Process names exempt from low-level scoring |

---

## Running before login

Vigil can install a boot-time monitor so monitoring starts before any user logs
in. This is useful for detecting early persistence and pre-user activity.

| OS | Install | Remove |
|---|---|---|
| Windows | `vigil.exe --install-service` | `vigil.exe --uninstall-service` |
| Linux | `sudo vigil --install-service` | `sudo vigil --uninstall-service` |

Under the hood:

- Windows uses Task Scheduler with an `ONSTART` task that runs Vigil as `SYSTEM`.
- Linux writes a systemd unit at `/etc/systemd/system/vigil.service` and enables it with `systemctl enable --now vigil.service`.

Startup safety rule: Vigil must fail open. A Vigil bug, hang, network failure,
advisory-cache failure, package-inventory failure, or service-mode error must
not repeatedly prevent the machine from reaching a usable login/session state.

---

## Logs

Log files land in the Vigil data directory and rotate daily. Open the log folder
from the tray icon context menu with **Open Logs Folder**.

Audit events include active response actions, integrity scan summaries,
uninstall attempts, and other security-relevant state changes.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on bug reports, feature
requests, and pull requests.

---

## License

[MIT](LICENSE)

[latest release]: https://github.com/YMRYMR/vigil/releases/latest
