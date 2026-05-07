# Vigil User Guide

This guide covers the basic functionality available in released Vigil builds for Windows and Linux.

## What Vigil is for

Vigil is a local machine protection tool with a network-first view.

It is built to help you:

- see suspicious network and process activity quickly
- understand which local process is responsible and why it looks risky
- contain a process, connection, or machine when you decide the risk is real
- preserve an audit trail for follow-up investigation and, where supported, capture forensic artifacts

Vigil is intentionally conservative about action. Scores and advisory context are there to help an operator make better decisions, not to pretend every suspicious connection is a confirmed compromise.

## Supported platforms

Vigil's active support targets are Windows and Linux. New feature work should define behavior for both platforms, or clearly state when a feature is platform-limited.

See [Supported platforms](SUPPORTED-PLATFORMS.md) for the support contract and startup safety rule.

## Install and launch

### Windows

1. Download the Windows installer from the latest GitHub Release.
2. Run the installer. By default it installs for the current user and enables Vigil to start when you log in.
3. If you want Vigil to start before login, choose an all-users install during setup. On Windows, that elevated installer path registers the boot-time monitor service automatically.
4. Launch Vigil from the Start Menu or installed shortcut.
5. Use **Run as Admin** in the header when you need ETW visibility or active response actions.

### Linux

1. Download the Linux AppImage from the latest GitHub Release.
2. Run `chmod +x Vigil-*.AppImage`.
3. Launch it from the desktop or terminal.
4. Use root or the required Linux capabilities when you need deeper monitoring or active response actions.

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
Configured blocklists and response-rule YAML stay operator-managed: Vigil can verify optional `.sha256` sidecars when you provide them, and it also records first-seen and changed hashes in its protected local provenance registry so later edits are visible without treating every intentional update as corruption.

### Help

The Help tab summarizes scoring, controls, and safe operating guidance inside the app.

## Common operator workflows

### Investigate a suspicious connection

1. Open **Alerts** or **Activity**.
2. Select the process or connection.
3. Review the Inspector for the executable path, parent chain, remote endpoint, score reasons, and any enrichment badges.
4. Decide whether the activity is expected, merely unusual, or worth containing.

### Contain something without losing the thread

When Vigil is elevated and the selected item supports it, you can take reversible action from the Inspector:

- kill a live TCP connection
- suspend or resume a process
- block a remote IP temporarily or permanently
- block a process by executable path
- isolate the machine from the network
- restore networking after isolation

Temporary actions show countdowns and unblock controls. Isolation always arms break-glass recovery so networking can be restored if Vigil crashes.

### Capture evidence on high-confidence alerts

When forensic capture is enabled and supported, Vigil can preserve:

- process memory dumps
- short PCAP captures
- TLS sidecar metadata
- provenance manifests with SHA-256 and alert context

Generated artifacts are stored under the Vigil data directory unless a custom path is configured.

## Privileges and visibility

Vigil does more with elevated privileges, but it is still usable without them.

- On Windows, elevation enables ETW-backed near-real-time visibility and active response actions.
- On Linux, elevated privileges or the needed capabilities are required for actions such as firewall-based containment and some deeper monitoring paths.

The header and controls are meant to make that state visible so you can tell when Vigil is observing only, and when it is able to act.

## Logs and audit trail

Vigil writes rolling logs and an audit stream under the per-user Vigil data directory. The tray menu includes an **Open Logs Folder** shortcut.

Audit events include active response actions, integrity scan summaries, uninstall attempts, and other security-relevant state changes.
At startup, Vigil also checks configured operator-managed inputs and Vigil-owned forensic artifact manifests. Changed blocklists or response-rule files are recorded as provenance events, while unreadable or tampered Vigil-owned artifacts are logged as integrity failures and may be moved into the integrity quarantine under the data directory.

At launch, Vigil also verifies protected policy state, operator-managed blocklists and rule files, and forensic artifact manifests. Blocklists and response-rule YAML files must have matching SHA-256 sidecars; Vigil combines that verification with a protected local provenance registry, so an expected local edit shows up as a warning while a missing sidecar, mismatch, or unreadable file is treated as a failure. Corrupted forensic artifact sets are moved under `quarantine/integrity/` in the Vigil data directory so they are no longer mixed with trusted evidence.

## Boot-time service mode

To monitor before login, install the OS service from an elevated shell:

| OS | Install | Remove |
|---|---|---|
| Windows | `vigil.exe --install-service` | `vigil.exe --uninstall-service` |
| Linux | `sudo vigil --install-service` | `sudo vigil --uninstall-service` |

On Windows, the all-users installer path performs service registration automatically. Service mode runs the monitor without the desktop UI. The GUI/tray launches normally after login.

Startup safety rule: Vigil must fail open. A Vigil bug, hang, network failure, advisory-cache failure, package-inventory failure, or service-mode error must not repeatedly prevent the machine from reaching a usable login/session state.

## Uninstall from Settings

Settings includes **Uninstall Vigil**. It asks for confirmation, disables login/startup registration, removes the OS service when present, records an audit event, and closes Vigil after successful cleanup.

If privileged service removal is required and Vigil is not elevated, the app stays open and shows an error so you can relaunch with the required privileges.

## Updating

Download the latest release from GitHub. Release assets include GitHub artifact attestations, SLSA provenance, and a signed update manifest.

To verify an update manifest offline:

```bash
vigil --verify-update-manifest Vigil-latest-update-manifest.json Vigil-latest-update-manifest.json.sig
```

## Advisory snapshot imports

Vigil can also extend its protected local advisory cache with operator-supplied public-source snapshots. This is useful when you want advisory context to stay available offline from the last trusted local cache.

Use the CLI importer that matches the source material you have:

```bash
vigil --import-nvd-snapshot nvdcve-page-1.json nvdcve-page-2.json
vigil --import-nvd-change-history nvdcvehistory-page-1.json
vigil --import-euvd euvd-export.json
vigil --import-jvn jvn-export.json jvndbrss.xml
vigil --import-ncsc ncsc-feed.xml ncsc-mirror.json
vigil --import-bsi certbund-feed.xml bsi-advisories.json
```

The NCSC and BSI/CERT-Bund importers accept either RSS snapshots or mirrored JSON, then preserve source links, identifiers, timestamps, and other provenance fields in the same protected advisory cache as the other Phase 16 sources.

## Local software inventory

The standalone `vigil_inventory` helper prints local Windows/Linux software inventory metadata as JSON without touching Vigil's startup path.

```bash
vigil_inventory
```

Each row includes conservative normalized identity hints so later matching can stay explainable:

- `product_key` for the primary normalized product identity
- `product_aliases` for alternate normalized product forms derived from names and executable stems
- `vendor_key` for the primary normalized publisher or vendor identity
- `vendor_aliases` for alternate normalized vendor forms, including suffix-stripped aliases

Current inventory sources:

- Windows uninstall registry
- Linux dpkg status database
- Linux RPM database
- Linux Alpine apk installed database
