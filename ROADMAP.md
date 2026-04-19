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

**Verified:** ETW fires within milliseconds of a new TCP connection.

---

## Phase 4 — Tray + Notifications + Autostart ✅ COMPLETE

**Goal:** vigil sits in the system tray, shows notifications, survives reboot.

- [x] `src/tray.rs` — tray icon + Win32 event loop
- [x] `src/notifier.rs` — `send_alert(&ConnInfo)` via `notify-rust` (fire-and-forget)
- [x] `src/autostart.rs` — privilege-aware autostart handling
- [x] First-run logic in `main.rs` — enables autostart and sets `first_run_done = true`

---

## Phase 5 — GUI (egui) ✅ COMPLETE

- [x] Activity + Alerts tables
- [x] Inspector panel
- [x] Settings panel
- [x] Help panel
- [x] Tray/UI wiring and persisted state

---

## Phase 6 — Logging + Polish ✅ COMPLETE

- [x] Daily rolling logs
- [x] Audit log stream
- [x] Tray shortcuts and app icon polish
- [x] Versioning and taskbar identity

---

## Phase 7 — Build + Distribution ✅ COMPLETE

- [x] CI / fmt / clippy / test pipeline
- [x] Release automation and installers
- [x] README / LICENSE / issue templates

---

## Phase 8 — UX, Detection & Quality Overhaul ✅ COMPLETE

- [x] Scoring improvements
- [x] Inspector / grid / navigation UX polish
- [x] Help and theme updates

---

## Phase 9 — Enhanced Detection ✅ COMPLETE

- [x] Beaconing detection
- [x] DNS tunneling detection
- [x] Registry persistence watcher
- [x] Pre-login detection
- [x] Cross-platform service mode

---

## Phase 10 — Reputation & Telemetry ✅ COMPLETE

- [x] Local blocklists
- [x] Geolocation / ASN enrichment
- [x] File-drop correlation
- [x] Long-lived connection tracking
- [x] DGA entropy signal
- [x] Reverse DNS cache

---

## Phase 11 — Active Response ✅ FEATURE COMPLETE

Move Vigil from passive observer to intervening defender. All actions must be explicit, reversible, and auditable.

### Per-connection and per-process blocking
- [x] **Block single connection** — Windows implementation via `SetTcpEntry` / delete-TCB
- [x] **Block all connections from a process** — reversible firewall rules scoped to the executable path, with TTL support
- [x] **Active-response UX** — countdowns, unblock actions, privilege-state UI, confirmations
- [x] **Block remote IP / CIDR** system-wide
- [x] **Block remote domain** through reversible hosts-file edits
- [x] **Kill process**
- [x] **Suspend / resume process**

### Machine-wide lockdown
- [x] **Panic button — full network isolation**
- [x] **Allowlist-only mode** — trusted list + operator allowlist + current Microsoft-signed system processes are treated as allowed; non-allowlisted traffic becomes a process-block candidate
- [x] **Quarantine profile** — Windows containment flow now includes:
  - isolate network
  - block executable path when known
  - suspend process when possible
  - disable USB storage
  - pause non-Microsoft scheduled tasks
  - clear-quarantine restores those controls where possible
- [x] **Break-glass recovery** — scheduled watchdog + heartbeat-based automatic recovery from stale isolation lockout
- [ ] **Post-restore network reattachment hardening** — after isolation is removed, reliably restore prior connectivity intent (Wi-Fi and VPN) without UI stalls; track adapter-enabled vs. internet-reachable as separate states and keep operator controls responsive during reassociation

### Rule engine and automation
- [x] **User-defined response rules** — YAML rule file with first-match semantics, dry-run support, and actions for `kill_connection`, `block_remote`, `block_process`, and `quarantine`
- [x] **Threshold escalation** — repeated offences escalate through the built-in auto-response planner
- [x] **Time-boxed blocks** — TTL-backed automatic expiry and reconciliation
- [x] **Scheduled lockdown** — configurable start/end isolation window in Settings

### Containment and forensics
- [x] **PCAP capture on alert** — short `pktmon` window written as `pcapng`
- [x] **Process memory dump on alert** — Windows full-dump capture on sufficiently high-score alerts
- [x] **Freeze autorun entries** — Run / RunOnce baseline capture and rollback
- [x] **Honeypot decoy files** — decoy files in common user locations, synthetic alert on touch, optional auto-isolation

### Operator surface and docs
- [x] Settings UI exposes allowlist-only mode, response rules, honeypot decoys, scheduled lockdown, break-glass recovery, and forensic controls
- [x] Help tab documents the completed Phase 11 feature set
- [x] Example YAML rule file added at `response-rules.example.yaml`

**Important note:** feature-complete here means the planned Phase 11 capability set is implemented in the branch. A fresh full build / test / validation pass is still recommended before calling the branch production-stable.

---

## Phase 12 — Detection Depth 🚧 IN PROGRESS

Goal: deepen confidence on suspicious process behaviour while keeping scoring explainable, operator-auditable, and conservative enough for a workstation defender.

### Implemented in this branch
- [x] **Behavioural baselines** — per-process remote / port / country novelty tracking with persisted baseline state and maturity gating
- [x] **Script-host inspection** — PowerShell / WSH / mshta / regsvr32 / rundll32 / cmd heuristics for encoded, stealthy, or remote-execution style command lines
- [x] **Signed-but-malicious detection** — signed binaries can still receive extra score when strong corroboration signals stack
- [x] **LoLBAS / script proxy expansion** — more signed-binary proxy-execution and script-launch patterns feed the scorer
- [x] **Parent / token anomaly heuristics** — sensitive system ancestry plus script-capable children now raise explicit reasons and ATT&CK-style tags
- [x] **MITRE ATT&CK mapping** — process groups and selected connections carry ATT&CK-style tags into the UI and inspector
- [x] **Operator surface** — Activity / Alerts cards show Phase 12 badges (`SCR`, `BASE`) and the inspector exposes Phase 12 heuristic chips and ATT&CK mappings
- [x] **TLS SNI / JA3 fingerprinting** — ClientHello parsing, pcapng-sidecar extraction, audit trail, and near-live cache reuse back into later matching connection records
- [x] **Visibility / tamper blind-spot heuristics** — ETW downgrade, unresolved live-networking PIDs, and service/system metadata gaps now raise explainable defense-evasion-style signals

### Still remaining before Phase 12 can be called complete
- [ ] **Fresh validation pass** — build, tests, and false-positive review for the new detection-depth signals
- [ ] **Final docs / release notes polish** once the implementation stabilises

**Important note:** this branch now contains a substantial Phase 12 implementation, but it should still be treated as in-progress until the new paths are validated end-to-end.

---

## Phase 13 — Optimization & Efficiency (backlog)

Security remains paramount, but Vigil must stay light enough to protect a workstation without becoming the problem.

- [ ] ETW / polling / enrichment pipeline profiling under normal desktop load
- [ ] Memory and cache budgeting for baselines, TLS metadata, DNS, GeoIP, and reputation data
- [ ] Smarter sampling / throttling for expensive enrichments and forensic capture paths
- [ ] UI rendering efficiency for large activity / alert histories
- [ ] Low-noise defaults that reduce needless CPU wakeups and disk churn
- [ ] Performance test fixtures and regression budgets for CPU, RAM, disk, and startup time

---

## Phase 14 — Hardening & Self-defence (backlog)

- [ ] Protected policy store
- [ ] Policy integrity verification
- [ ] Privilege-gated policy edits
- [ ] Self-protection and tamper evidence
- [ ] Secure update channel

---

## Phase 15 — File Integrity & Anti-Tamper (backlog)

Make sure no file used by Vigil can be silently tampered with without detection, recovery, or operator visibility.

- [ ] Signed or cryptographically verified policy / configuration files
- [ ] Integrity verification for blocklists, rules, caches, and generated state
- [ ] Secure audit-log chaining or append-only protections
- [ ] Forensic artifact provenance and checksum manifests
- [ ] Startup integrity scan with clear operator-visible failure modes
- [ ] Recovery / quarantine path for corrupted or untrusted Vigil-owned files

---

## Phase 16 — Integration & Fleet (backlog)

- [ ] SIEM export
- [ ] Webhook alerts
- [ ] Fleet mode / remote lockdown
- [ ] Shared intel sync and STIX/TAXII

---

## Version Plan

| Version | Phase | Description | Status |
|---|---|---|---|
| 0.1.0 | 1–2 | Types + config + polling monitor | ✅ Done |
| 0.2.0 | 3 | ETW real-time detection | ✅ Done |
| 0.3.0 | 4 | Tray + notifications + autostart | ✅ Done |
| 0.4.0 | 5 | Full GUI | ✅ Done |
| 0.5.0 | 6 | Logging + polish | ✅ Done |
| 1.0.0 | 7 | Build pipeline + open-source release | ✅ Done |
| 1.1.0 | 8 | UX, detection & quality overhaul | ✅ Done |
| 1.2.0 | 9 | Beaconing, DNS, registry, pre-login, service mode | ✅ Done |
| 1.3.0 | 10 | Reputation, geolocation, file-drop correlation, long-lived, DGA | ✅ Done |
| 3.0.0 | 11 | Active response: containment, quarantine, rule engine | ✅ Feature complete |
| 3.x | 12 | Detection depth | 🚧 In progress |
| 4.x | 13 | Optimization & efficiency | 🔲 Backlog |
| 4.x | 14 | Hardening & self-defence | 🔲 Backlog |
| 5.x | 15 | File integrity & anti-tamper | 🔲 Backlog |
| 5.x | 16 | Integration & fleet | 🔲 Backlog |
