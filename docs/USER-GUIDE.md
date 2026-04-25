# Vigil User Guide

This guide covers the basic functionality available in released Vigil builds.

## Install and launch

### Windows

1. Download the Windows installer from the latest GitHub Release.
2. Run the installer.
3. Launch Vigil from the Start Menu or the installed shortcut.
4. Use **Run as Admin** in the header when you need ETW visibility or active response actions.

### macOS

1. Download the macOS DMG from the latest GitHub Release.
2. Drag `Vigil.app` to Applications.
3. Launch Vigil and approve any operating system prompts that are required for network visibility.

Current macOS builds use a degraded fallback path because the native Endpoint Security backend is not integrated yet. When `dtrace` is available and permitted, Vigil uses DTrace-assisted polling to surface new connections faster; otherwise it falls back to polling-only. Detection remains functional, but coverage is still behind the Windows ETW and Linux eBPF paths, and privileged features currently require launching from an elevated shell.

### Linux

1. Download the Linux AppImage from the latest GitHub Release.
2. Run `chmod +x Vigil-*.AppImage`.
3. Launch it from the desktop or terminal.

## Main screens

### Activity

The Activity tab shows current and recently observed connections grouped by process. Use it to see which local process is talking to which remote address, the connection status, and the current risk score.

### Alerts

The Alerts tab shows connections and synthetic events that crossed the configured alert threshold. Alert rows include the score, reason chips, protocol or detection badges when available, and process context.

### Inspector

Select a row in Activity or Alerts to open process and connection details in the Inspector. Depending on platform and privilege level, the Inspector can show:

- process name and PID
- executable path
- publisher or signing information
- parent process context
- local and remote addresses
- score reasons
- geolocation / ASN / reputation context when configured
- active response controls

### Settings

The Settings tab stores changes automatically. Common settings include:

- alert threshold
- polling interval
- log-all-connections mode
- autostart at login
- trusted processes
- allowlist-only mode
- user-defined response rules
- scheduled lockdown
- break-glass recovery timeout
- forensic capture options
- honeypot decoy settings
- uninstall confirmation flow

Policy-sensitive settings require Admin Mode when protected policy editing is enabled.

### Help

The Help tab summarizes scoring, controls, and safe operating guidance inside the app.

## Active response

When Vigil has the needed privileges, it can perform reversible response actions:

- kill a live TCP connection
- suspend or resume a process
- block a remote IP temporarily or permanently
- block a process by executable path
- isolate the machine from the network
- restore networking after isolation

Temporary actions show countdowns and unblock controls. Isolation always arms break-glass recovery so networking can be restored if Vigil crashes.

## Forensics

When enabled, Vigil can capture forensic evidence for high-confidence alerts:

- process memory dumps
- short PCAP captures
- TLS sidecar metadata
- provenance manifests with SHA-256 and alert context

Generated artifacts are stored under the Vigil data directory unless a custom path is configured.

## Logs and audit trail

Vigil writes rolling logs and an audit stream under the per-user Vigil data directory. The tray menu includes an **Open Logs Folder** shortcut.

Audit events include active response actions, integrity scan summaries, uninstall attempts, and other security-relevant state changes.

At launch, Vigil also verifies protected policy state, operator-managed blocklists and rule files, and forensic artifact manifests. Blocklists and response-rule YAML files must have matching SHA-256 sidecars; Vigil combines that verification with a protected local provenance registry, so an expected local edit shows up as a warning while a missing sidecar, mismatch, or unreadable file is treated as a failure. Corrupted forensic artifact sets are moved under `quarantine/integrity/` in the Vigil data directory so they are no longer mixed with trusted evidence.

## Boot-time service mode

To monitor before login, install the OS service from an elevated shell:

| OS | Install | Remove |
|---|---|---|
| Windows | `vigil.exe --install-service` | `vigil.exe --uninstall-service` |
| macOS | `sudo vigil --install-service` | `sudo vigil --uninstall-service` |
| Linux | `sudo vigil --install-service` | `sudo vigil --uninstall-service` |

Service mode runs the monitor without the desktop UI. The GUI/tray launches normally after login.

## Uninstall from Settings

Settings includes **Uninstall Vigil**. It asks for confirmation, disables login/startup registration, removes the OS service or daemon when present, records an audit event, and closes Vigil after successful cleanup.

If privileged service removal is required and Vigil is not elevated, the app stays open and shows an error so you can relaunch with the required privileges.

## Updating

Download the latest release from GitHub. Release assets include GitHub artifact attestations, SLSA provenance, and a signed update manifest.

To verify an update manifest offline:

```bash
vigil --verify-update-manifest Vigil-latest-update-manifest.json Vigil-latest-update-manifest.json.sig
```
