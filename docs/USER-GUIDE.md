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

## First-use checklist

If you are new to Vigil, start with a calm observe-first setup instead of enabling every protection at once.

1. Open Activity and Alerts first. Learn what normal traffic looks like on your machine before changing policy.
2. Use Admin Mode only when you need deeper visibility or active response actions. Vigil is still useful without it.
3. Leave auto response, allowlist-only mode, scheduled lockdown, and decoy-triggered auto-isolation off until you trust the scores and your trusted-process list.
4. Prefer reversible actions first. Suspend process, temporary IP blocks, and restore-network workflows are safer than permanent blocking or immediate full isolation.
5. Treat machine isolation as a last resort for suspected active compromise, not as a normal cleanup button.

## Building a sane trusted list

Treat the trusted-process list as a learned baseline, not as a fast way to silence alerts. Trusted entries skip routine penalties and can suppress automatic response, so each one should be familiar, stable, and expected.

1. Start with Vigil's shipped trusted baseline. It covers common system and browser processes that would otherwise generate noise on many machines.
2. Observe first. Watch Activity and Alerts until you know what normal looks like for your browser, chat tools, VPN, terminal, package manager, and other routine software.
3. Prefer trusting from the Inspector. The Inspector lets you review the process name, executable path, publisher, parent, and live connections before you add it.
4. Add only software you recognize and expect to use the network regularly.
5. Revisit your learned additions if the software moves to a new path, changes ownership, or starts triggering new kinds of alerts.

Avoid trusting installers, updaters running from Downloads or Temp, script hosts such as `powershell`, `cmd`, or `mshta`, one-off troubleshooting tools, and anything you do not immediately recognize.

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
- user-defined response rules, including conservative advisory-aware predicates
- scheduled lockdown
- break-glass recovery timeout
- forensic capture options
- honeypot decoy settings
- uninstall confirmation flow

Policy-sensitive settings require Admin Mode when protected policy editing is enabled.
Configured blocklists and response-rule YAML stay operator-managed: Vigil can verify optional `.sha256` sidecars when you provide them, and it also records first-seen and changed hashes in its protected local provenance registry so later edits are visible without treating every intentional update as corruption.

By default, Vigil also requires an extra typed confirmation before turning on disruptive protections such as auto response, allowlist-only mode, scheduled lockdown, or decoy-triggered auto-isolation. That guardrail is there so a non-expert user does not enable a feature that can cut off normal software or network access without pausing to review the consequences.

The Trusted Processes section now includes a short onboarding tutorial. It explains how to keep the shipped baseline, learn from Activity and the Inspector, and add only stable apps you already recognize.

Response rules can also match high-confidence advisory context conservatively, including known-exploited status, mitigation-guidance availability from explicit remediation tags such as `Mitigation`, `Remediation`, `Fix`, `Patch`, `Update`, `Upgrade`, `Workaround`, `Guidance`, and `Solution`, vendor guidance that only counts when the same tagged reference is also marked as vendor-authored material such as `Vendor Advisory`, `Vendor Bulletin`, `Vendor Notice`, `Vendor Mitigation`, or `Vendor Remediation`, missing fixed-version bounds, affected-product text, and obvious public-internet exposure for a globally routable listening socket. See [Response rules](RESPONSE-RULES.md) and `response-rules.example.yaml` for the exact YAML fields and example patterns.
That public-exposure predicate is intentionally strict: only a current `LISTEN` socket bound to an obviously globally routable local IP matches today. Wildcard binds such as `0.0.0.0`, loopback listeners, RFC1918 or CGNAT IPv4 ranges, unique-local IPv6 addresses, and reachability that depends on NAT or reverse proxies still stay unmatched.

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

## Local YARA rule intake

Vigil now uses the reviewed bundled rules plus any verified operator-local rules for bounded runtime executable scanning. When Vigil first sees a readable executable for a newly observed process, it can scan that on-disk executable in the background and surface matches through the normal score reasons as `YARA rule: <name>`.

`vigil --yara-rule-status` remains the operator-facing intake command. The command itself does not run scans. It verifies which local rules under `yara-rules/` are trusted enough to join the runtime ruleset and records their provenance.

The first YARA rule-management UI slice is intentionally read-only: it may display trusted rule metadata and matched rule names, but it must not expose category toggles, rule editing, rule deletion, remote downloads, or auto-enable behavior until those flows have protected policy storage, reload semantics, recovery behavior, and audit coverage. See [YARA rule management UI contract](YARA-RULE-MANAGEMENT-UI.md) for the current UI boundary.

1. Run `vigil --yara-rule-status` if you want Vigil to print the exact `yara-rules/` directory path it expects on your machine.
2. Place each `.yar` or `.yara` file under that directory with a matching `.sha256` sidecar beside it. For example, `sample.yar` should have `sample.yar.sha256`.
3. Re-run the status command:

```bash
vigil --yara-rule-status
```

4. Treat the results conservatively:
- `new` means Vigil accepted the rule and recorded it as a first-seen operator file.
- `verified` means the rule and sidecar still match the last recorded trusted version.
- `changed` means the rule was accepted, but its contents changed since the last recorded trusted version.
- any failure means Vigil did not accept that rule because the sidecar is missing, unreadable, or mismatched.

Warnings on first load or after an intentional rule edit are expected because Vigil records provenance instead of silently treating every local change as corruption.

The next YARA roadmap slice is still narrower than broad live-memory scanning. The safest follow-up remains selected-memory targets such as operator-visible or already-captured process dumps on supported platforms, while preserving the same fail-open behavior as the shipped executable scan path.
