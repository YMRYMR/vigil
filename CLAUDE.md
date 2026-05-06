# Vigil — Development Context

> Read this first in every coding session. It is a compact project context file, not a substitute for inspecting the exact files you edit.

---

## Identity

| Field | Value |
|---|---|
| Project | **Vigil** — real-time endpoint network threat monitor |
| Language | Rust edition 2021 |
| Primary binary | `vigil` |
| Inventory helper | `vigil_inventory` |
| Active support targets | Windows and Linux |
| License | MIT |

Vigil watches local network and process activity, scores suspicious behavior, shows process/connection context, and offers reversible containment actions. It must be useful security software, not a blocker.

---

## Current direction

**Active phase:** Phase 16 — public vulnerability intelligence, advisory matching, and local software inventory.

**Current support scope:** Windows and Linux only. See `docs/SUPPORTED-PLATFORMS.md`.

**Startup safety rule:** Vigil must fail open at OS startup. A Vigil bug, hang, network failure, advisory-cache failure, package-inventory failure, or service-mode error must not repeatedly prevent the machine from reaching a usable login/session state.

---

## Supported platform priorities

### Windows

- ETW-backed realtime network visibility.
- Task Scheduler boot-time monitor with fail-open guardrails.
- Uninstall-registry software inventory.
- Windows-native reversible active response.
- Clear Admin/elevation UX.

### Linux

- eBPF-backed realtime visibility where available, with polling fallback.
- systemd service mode with fail-open guardrails.
- dpkg, RPM, and Alpine apk software inventory.
- Linux-native reversible active response through capabilities/root-gated controls.
- Clear root/capability UX.

---

## Architecture notes

### Runtime

- `tokio` async runtime.
- Monitor work runs outside the UI thread.
- UI runs on the main thread via `egui` / `eframe`.
- Cross-thread communication uses `tokio::sync::broadcast`, `tokio::sync::mpsc`, or `std::sync::mpsc` as appropriate.

### GUI

- `egui` + `eframe` immediate-mode UI.
- Layout: header, tab strip, body, inspector.
- Main tabs: Activity, Alerts, Settings, Help.

### Monitoring

- Windows realtime path: ETW.
- Linux realtime path: eBPF through aya where available.
- Polling fallback remains important and must stay reliable.
- Monitor events flow into a shared event pipeline consumed by UI, scoring, enrichment, and alerting.

### Active response

All response actions must be explicit, reversible where practical, and auditable.

Supported action families include:

- Kill TCP connection.
- Suspend/resume process.
- Block remote IP.
- Block process by executable path.
- Isolate and restore network.
- Break-glass recovery after isolation.

### Advisory and inventory work

Phase 16 work should remain conservative:

- Public advisory matches are operator decision support, not proof of compromise.
- Inventory and advisory refresh must not make startup risky.
- Prefer offline/local data and the last trusted cache when live refresh fails.
- Surface stale, partial, or failed advisory state clearly.

Current inventory sources:

- Running processes and services.
- Windows uninstall registry.
- Linux dpkg status database.
- Linux RPM database.
- Linux Alpine apk installed database.

---

## Dependency notes

Important dependency constraints and facts:

- `egui` / `eframe` are on the 0.34 family.
- `sysinfo` APIs have changed across versions; inspect the current Cargo.lock and call sites before editing process-refresh code.
- Windows-specific functionality uses the `windows` crate and `winreg` where needed.
- Linux eBPF uses aya.
- Linux tray support uses GTK / AppIndicator pieces where enabled by the current dependency graph.

Do not update dependency versions casually in feature PRs.

---

## Coding rules

- Keep PRs small and focused.
- Do not rewrite large files unless the goal of the PR is explicitly to replace stale documentation.
- Preserve unrelated badges, links, security/compliance wording, release notes, and examples.
- Gate platform-specific implementation with explicit `cfg` blocks.
- Define Windows and Linux behavior for new functionality; if one platform cannot support a feature yet, show that clearly in code and UI.
- Avoid `unwrap()` / `expect()` in hot or startup paths.
- Use `tracing` for non-test diagnostics.
- Add tests for changed pure logic and parsers.
- Never add startup work that can block login or repeatedly re-enter a broken boot path.

---

## UI/theme constants that should not drift casually

The existing dark UI theme, score badge colors, scoring values, and alert threshold default are part of the product feel and operator expectations. Do not change them as incidental cleanup.

---

## Session workflow

1. Read this file.
2. Read `ROADMAP.md`.
3. Inspect only the files you will edit.
4. Make the smallest safe change.
5. Review the diff for unrelated deletions or wording drift before opening/updating a PR.
6. Be explicit about validation limits if tests or OS-specific checks were not run.

---

## Things that must not change accidentally

- Scoring values and their Help/README explanations.
- `ConnInfo` field semantics.
- Startup fail-open behavior.
- Break-glass recovery behavior.
- Protected policy and audit integrity behavior.
- README badges and release/security links.
- Windows/Linux support scope unless the support policy changes first.
