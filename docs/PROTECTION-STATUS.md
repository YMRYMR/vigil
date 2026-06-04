# Vigil Protection Status

`vigil_status` is the first status-reporting foundation for Vigil's production endpoint-protection track.

It prints a conservative JSON report about local Vigil state without attaching to the live GUI or service runtime. Facts that cannot be checked safely from a standalone CLI process are reported as `unknown` rather than guessed.

```bash
vigil_status --json
```

## Current scope

The schema reports:

- app version, target OS, target architecture, and Vigil data directory
- overall state and summary
- `health_summary`, a compact single-panel view of the key Phase 21 protection signals
- subsystem entries for configuration, runtime monitor, blocklist engine, firewall backend, response policy, active-response state, protected storage, YARA rules, advisory cache, and update trust

The first implementation can inspect files and static policy. It intentionally does **not** claim live protection health yet.

## Health summary

`health_summary` repeats selected subsystem states in a stable dashboard-friendly shape:

- `runtime_monitor` — current monitor backend health; remains `unknown` until live runtime health is published
- `blocklist_engine` — standalone preflight for configured blocklist paths and required `.sha256` sidecars
- `advisory_cache` — advisory cache freshness; remains `unknown` until storage-backed cache inspection is available
- `response_rules` — response policy state from protected configuration
- `firewall_isolation` — persisted active-response/isolation state; live reconciliation still requires runtime health
- `native_firewall_engine` — WFP/nftables/iptables backend availability or live-health placeholder

The blocklist preflight is intentionally conservative. It reports `healthy` only when every configured blocklist file can be read, its `<filename>.sha256` sidecar matches the file digest, and at least one active non-comment entry is present. Missing paths, unreadable sidecars, or digest mismatches report `degraded`; no configured blocklists or verified empty lists report `disabled_by_policy`.

## State values

Subsystem states use these lowercase JSON values:

- `healthy` — the standalone check could verify the local condition successfully
- `degraded` — a local inconsistency or missing required file was detected
- `disabled_by_policy` — the feature is off or dry-run by local policy
- `needs_elevation` — future live checks may use this when privilege prevents inspection
- `failed_open` — future live checks may use this when Vigil disabled a protection path to preserve machine availability
- `unknown` — the fact requires live runtime telemetry or deeper integrity verification not available to this standalone command

## Production direction

This is the base contract for the future GUI dashboard, tray health indicator, and `vigil status --json` command. The next slices should move runtime-only checks out of `unknown` by publishing live health from the GUI/service monitor into protected local state.

The status surface must stay honest: it must never report the machine as protected unless the required protection subsystems are actually healthy.
