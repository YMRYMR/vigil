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
- [x] **Post-restore network reattachment hardening** — after isolation is removed, reliably restore prior connectivity intent (Wi-Fi and VPN) without UI stalls; track adapter-enabled vs. internet-reachable as separate states and keep operator controls responsive during reassociation

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

**Important note:** Phase 11 is now complete and validated with a fresh build / test / lint pass.

---

## Phase 12 — Detection Depth ✅ COMPLETE

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

### Validation
- [x] Fresh validation pass — `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-targets --all-features`, and `cargo build --release` all pass on the current tree
- [x] Final docs / release notes polish

**Important note:** Phase 12 is now complete and validated end-to-end on the current tree.

---

## Phase 13 — Optimization & Efficiency ✅ FEATURE COMPLETE

Security remains paramount, but Vigil must stay light enough to protect a workstation without becoming the problem.

### Implemented in this branch
- [x] **Process-card endpoint aggregation** — identical remote endpoints inside a process card now collapse into one summary row with socket count, local-port rollup, and lifecycle summary, with raw sockets behind a second expand step
- [x] **Broader TCP lifecycle visibility** — keep additional teardown / transient TCP states (`FIN_WAIT*`, `TIME_WAIT`, `LAST_ACK`, `CLOSING`, `DELETE_TCB`) so the UI shows a fuller socket lifecycle instead of mostly `ESTABLISHED`
- [x] **UI rendering cache** — grouped/sorted process cards are cached with a data-version key; recomputation only happens when data, filter, or sort state changes. Process counts for tab labels are cached alongside, eliminating per-frame HashSet iteration
- [x] **Filter matching optimization** — empty-filter fast path moved before string operations; 12 `.to_lowercase()` allocations per row replaced with zero-alloc `.to_ascii_lowercase()`
- [x] **Loopback enrichment skip** — connections to 127.0.0.1 / ::1 / 0.0.0.0 skip the full enrichment pipeline (process collection, geoip, blocklist, revdns, fswatch, baseline, TLS, scoring, tamper) and are tracked with minimal metadata for stale-detection only
- [x] **Memory budgets for enrichment caches** — baseline profiles capped at 512 (LRU eviction), TLS artifact cache capped at 1024 entries, reverse-DNS cache capped at 4096 entries, UI collapsed/expanded state sets capped at 256/128
- [x] **Forensic global rate limiting** — process dumps throttled to one per 30s globally (in addition to per-PID cooldown); PCAP captures throttled to one per 60s globally
- [x] **Pipeline profiling instrumentation** — per-connection microsecond timing for each enrichment step (process collect, geoip, blocklist, revdns, fswatch, baseline, TLS, scoring, tamper); debug-level logging; last 100 entries stored for diagnostics
- [x] **Low-noise defaults** — 5ms time budget on UI event drain prevents frame stalls under burst load
- [x] **eBPF module** — `src/monitor/ebpf.rs` with real `aya`-based TCP tracepoint on Linux (stub on other platforms); `Monitor::start()` attempts eBPF alongside ETW, merging into single receiver. Attaches to `tracepoint:sock:inet_sock_set_state` via `aya::EbpfLoader` for sub-100ms connect/accept/close events; pre-compiled BPF object embedded as `&[u8]` const (8 KB); graceful fallback to `/proc/net/tcp` polling if kernel too old or user lacks `CAP_BPF`/`CAP_SYS_ADMIN`
- [x] **Performance test fixtures** — scoring benchmark (1000 inputs under 50ms), baseline profile cap enforcement test
- [x] **Linux system tray** — full AppIndicator integration: GTK init, themed icon names for GNOME dock, GLib MainContext D-Bus iteration, menu event handling (Open Vigil / Open Logs Folder / Quit), left-click to show window, graceful fallback when no display or running as root
- [x] **Privilege UX** — explain the capability requirement clearly in Settings and Help; offer a one-shot `setcap` helper via pkexec where appropriate

---

## Phase 14 — Hardening & Self-defence ✅ COMPLETE

- [x] Protected policy store — `vigil.json` now carries a local integrity signature and signed backup; legacy installs migrate on first load
- [x] Policy integrity verification — HMAC-backed load-time verification restores from the last known-good backup when tampering is detected
- [x] Privilege-gated policy edits — policy-sensitive settings and trust actions require Admin Mode to persist
- [x] Self-protection and tamper evidence — audit actions are now hash-chained and verified at startup so log tampering is visible
- [x] Secure update channel — release assets now ship with a signed update manifest and signature; the app can verify the manifest offline with the embedded trust anchor
- [x] **Linux active-response parity** — all response actions work cross-platform:
  - Network isolation via `iptables` DROP policies (gated on `CAP_NET_ADMIN` or root)
  - Kill TCP connection via `ss -K` and `/proc/net/tcp` parsing
  - Suspend/resume process via `kill -STOP`/`kill -CONT`
  - Block IP via iptables with comment-based rule management
  - Block program via iptables owner match (UID from `stat()`)
  - Block domain via `/etc/hosts` manipulation + DNS flush
  - Elevated check: `CAP_NET_ADMIN` from `/proc/self/status` `CapEff:` field

---

## Phase 15 — File Integrity & Anti-Tamper ✅ COMPLETE

Make sure no file used by Vigil can be silently tampered with without detection, recovery, or operator visibility.

### Completed slices
- [x] Signed or cryptographically verified policy / configuration files — `vigil.json` carries a local integrity sidecar and signed backup, with legacy installs seeded on first load
- [x] Integrity verification for Vigil-owned generated state — behavioural baselines, active-response state, break-glass recovery state, and quarantine state now use the same integrity sidecar / backup recovery path as the policy store
- [x] Secure audit-log chaining — audit entries are hash-chained and verified at startup so edits or removal become visible
- [x] Forensic artifact provenance and checksum manifests — PCAP captures, TLS sidecars, and process dumps now get `.manifest.json` sidecars with SHA-256, size, alert context, and capture metadata
- [x] Startup integrity scan with clear operator-visible failure modes — startup scans now persist a protected report, surface warnings/failures in the app, and quarantine corrupted forensic artifact sets instead of leaving them beside trusted evidence

### Completed in this branch
- [x] Provenance model for operator-managed blocklists and response-rule YAML files that detects malicious tampering without treating intentional local edits as corruption
- [x] Startup integrity scan with clear operator-visible failure modes
- [x] Recovery / quarantine path for corrupted or untrusted Vigil-owned files beyond the current signed-backup restore paths

---

## Phase 16 — Public Vulnerability Intelligence & Advisory Feeds (OPEN backlog)

Use free public vulnerability and advisory sources to help Vigil keep the local machine secure, while keeping every decision explainable, conservative, and useful offline from the last trusted cache.

### Source ingestion and normalization
- [ ] **NVD ingestion** — scheduled pull + local cache for NVD CVE, CPE, CPE-match, and change-history data with source attribution, rate-limit-aware sync, and local incremental updates
- [ ] **EUVD ingestion** — ingest EUVD records and preserve EU-specific aliases, references, mitigation guidance, exploitation indicators, and coordinator metadata
- [ ] **JVN ingestion** — ingest MyJVN / JVN iPedia records and preserve vendor, product, advisory, and remediation metadata where it complements NVD coverage
- [ ] **Public advisory ingestion for NCSC and BSI** — ingest public RSS, advisory, and malware-analysis content only; do not depend on closed, partner-only, or registration-gated feeds
- [ ] **Normalized vulnerability record model** — shared schema for CVE/advisory/source/affected product/version/severity/exploitation/references/mitigation/provenance so multiple sources can coexist cleanly
- [ ] **Signed local source cache** — store fetched records and source snapshots as tamper-evident local state with expiry, rollback-safe refresh, and operator-visible source health/status

### Endpoint relevance and matching
- [ ] **Local software inventory and version discovery** — broaden process, file, package, service, and installed-software collection so Vigil can reason about what is actually present on the machine, not just what is currently connecting
- [ ] **Product normalization + vendor aliasing** — reconcile executable names, publishers, package names, app bundles, services, and installer metadata into stable vendor/product identities
- [ ] **Version comparison engine** — compare installed versions against advisory ranges conservatively across semver, vendor-specific, and OS package version formats
- [ ] **CPE / product matching pipeline** — map local software identities to CPEs or equivalent source-native product identifiers with confidence scoring and operator-visible explainability
- [ ] **Connection-to-software correlation** — tie a live process or service back to the relevant installed product record so advisory matches can appear in the existing Inspector and Alerts workflows

### Operator value and protection outcomes
- [ ] **Local advisory inspector** — show matched public advisories, CVEs, severity, known-exploitation flags, fixed versions, mitigation links, and source references for the selected process or installed product
- [ ] **Conservative scoring hooks** — optionally raise score only when a live process or exposed service maps with high confidence to a severe or exploited public vulnerability, with clear reasons and low-noise defaults
- [ ] **Mitigation-aware response rules** — let operators build response rules around advisory attributes such as exploited status, vendor guidance, affected product, fixed-version absence, or exposure on the public internet
- [ ] **Public-source-to-blocklist/rule-pack conversion** — derive optional signed local IP, domain, hash, or process rule packs from high-confidence public advisories and NCSC/BSI technical content where indicators are explicitly published
- [ ] **Exposure-first prioritization** — prioritize vulnerabilities that are both relevant to the local machine and actually exposed through a running process, listening service, or browser-facing component
- [ ] **Offline-first and fail-closed behaviour** — keep protection working from the last trusted cache, never weaken existing detection if source refresh fails, and surface stale or partial-source state clearly to the operator

### Docs and policy
- [ ] **Attribution / terms compliance** — document source-specific attribution, caching, redistribution, and update-frequency rules for NVD, EUVD, JVN, NCSC public content, and BSI public content
- [ ] **Operator guidance** — explain what a “matched advisory” means, what confidence limits remain, and why a public CVE match is not by itself proof of compromise

---

## Phase 17 — Protocol Expansion (OPEN backlog)

Extend Vigil from a primarily TCP/UDP-oriented monitor toward broader protocol-aware network visibility, while keeping protocol semantics explicit instead of forcing everything into a TCP-shaped model.

### Planned scope
- [ ] **QUIC visibility** — add QUIC-aware monitoring as the highest-priority protocol expansion, including UDP-based flow visibility, protocol tagging, and conservative detection/scoring hooks where attribution is strong enough
- [ ] **ICMP telemetry** — add ICMP as a separate diagnostics / network-signal stream rather than as fake connection rows, covering operator-useful events such as echo activity and other notable ICMP behaviour
- [ ] **Protocol-aware core model** — generalise the internal event / connection model so protocol, confidence, and protocol-specific semantics are first-class instead of assuming every record behaves like TCP
- [ ] **UI protocol surfacing** — show protocol identity and protocol-specific summaries clearly in the Activity / Alerts views and inspector
- [ ] **Protocol-aware baselining and scoring** — keep QUIC and other future protocols separable from TCP baselines so novelty and risk remain explainable

### Optional scope
- [ ] **SCTP support (optional)** — add SCTP visibility only if a concrete deployment need justifies the extra protocol-specific complexity
- [ ] **DCCP support (optional)** — add DCCP visibility only if a clear real-world use case appears; otherwise keep it out of the default scope

---

## Phase 18 — Cross-platform Detection Parity (OPEN backlog)

Windows and Linux now have first-class detection and active-response support. Broadening to macOS and unifying the monitor architecture unlocks mixed-OS deployments. Mobile is explicitly out of scope.

**macOS — Endpoint Security Framework**
- [ ] **Endpoint Security system extension** — build a signed `EndpointSecurity.framework` subscriber that receives `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_NOTIFY_CONNECT`, and related event types with full process-token and ancestor metadata
- [ ] **Network Extension visibility** — supplement with `NEFilterProvider` / `NEAppProxyProvider` for traffic-level metadata where Endpoint Security alone is insufficient
- [ ] **Code-signing and notarization path** — document the Apple Developer signing, entitlement (`com.apple.developer.endpoint-security.client`), and notarization requirements; gate behind a build feature flag so development builds still work without signing
- [x] **DTrace as a fallback** — current macOS builds now use `dtrace` connect triggers as a degraded-realtime path when available, then resolve real socket metadata through an immediate trusted re-poll
- [x] **Graceful fallback** — if the native macOS backend is unavailable, Vigil now shows an explicit operator notice and falls back to DTrace-assisted polling when possible, or `netstat`-style polling when not

**Shared integration**
- [ ] **Monitor trait unification** — refactor `src/monitor/` so the existing ETW fast path, the eBPF module, and the new ES module all implement a common `EventSource` trait consumed by the same `Monitor` hub, with `tokio::select!` merging whichever sources are active
- [ ] **Cross-platform latency benchmark** — measure p50/p95 detection latency on each platform with the new backends and compare against the polling baseline; target < 200ms on Linux (eBPF) and < 300ms on macOS (Endpoint Security)
- [ ] **Installer and autostart parity** — launchd / systemd service units, signed installers, pkg / deb / rpm / AppImage polish
- [ ] **Cross-platform test fixtures** — CI coverage and detection regression tests on all three OSes

---

## Phase 19 — Cloud Fleet Console & Integrations (PRO backlog)

The single most important phase for turning Vigil into a business. Without a hosted console there is no recurring-revenue surface and no SMB / MSP path. Designed to be buildable and operable by a solo maintainer + AI tooling (managed service, Postgres + Rust/Axum backend, small React/egui-web frontend, no on-call rotation required).

### Hosted fleet console
- [ ] Multi-tenant SaaS backend with agent enrollment via install token
- [ ] Live endpoint status grid, alerts feed, and cross-fleet search
- [ ] Remote trigger: isolate / clear-isolation / kill process / block IP across selected endpoints
- [ ] Role-based access (admin / analyst / read-only) with per-action audit log
- [ ] End-to-end TLS, per-tenant encryption of sensitive fields, signed agent-to-server channel
- [ ] Self-serve signup, Stripe billing, seat-based subscription management

### Outbound integrations
- [ ] Syslog / CEF export
- [ ] Splunk HEC, Elastic, Microsoft Sentinel, Datadog connectors
- [ ] Generic webhook + JSON-out channel
- [ ] PagerDuty / Opsgenie / Slack / Microsoft Teams alerting
- [ ] Jira / ServiceNow ticket creation on high-severity alerts
- [ ] Shared intel sync and STIX / TAXII consumer

---

## Phase 20 — MSP Multi-tenant & White-label (PRO backlog)

Unlocks the highest-conversion channel for a solo-run security product: managed service providers selling Vigil to their SMB clients. Depends on Phase 19.

- [ ] **Tenant hierarchy** — MSP → customer → site → endpoint, with inherited policy and override rules
- [ ] **White-label branding** — per-tenant logo, product name, custom domain, branded alert emails
- [ ] **Bulk deployment tooling** — MSI / pkg / deb with embedded enrollment token, deployment guides for Intune, Kaseya, NinjaOne, ConnectWise Automate
- [ ] **MSP dashboard** — cross-customer alert feed, filterable by tenant, with per-tenant usage and billing exports
- [ ] **Tiered / volume pricing** — per-seat discount curves and monthly invoicing for channel partners

---

## Phase 21 — Managed Threat Intel Feed (PRO backlog)

Turns PRO from a one-time install into a subscription with a clear renewal trigger. Intentionally designed around curation of public and community feeds plus Vigil-specific derived signals, not an in-house research team.

- [ ] **Hosted feed service** — hourly-refreshed managed IP / domain / hash blocklist consumed by PRO agents via authenticated pull
- [ ] **Curated LoLBAS, C2 port, and process-rule updates** — versioned, signed rule packs delivered to agents
- [ ] **Sigma rule import pipeline** — ingest and translate community Sigma rules into Vigil scoring signals
- [ ] **Optional reputation lookup API** — per-request IP / domain / hash reputation endpoint for the fleet console and automation
- [ ] **Transparency and provenance** — every feed entry includes source, first-seen, and confidence so operators can audit blocks

---

## Phase 22 — Compliance Reporting Pack (PRO backlog)

Single biggest lever for selling into regulated SMB verticals (legal, healthcare, financial advisors, MSPs serving them). Pairs naturally with the Phase 15 tamper-evident logging already in the OPEN tier.

- [ ] **Pre-built report templates** — "Network activity evidence for SOC 2 CC7.2", "HIPAA §164.312(b) audit controls", "PCI DSS 10.x logging", "ISO 27001 A.12.4"
- [ ] **Scheduled exports** — automated PDF / CSV delivery by email or to S3-compatible storage on operator-defined cadences
- [ ] **Retention policy controls** — configurable 90-day / 1-year / 7-year log retention per tenant
- [ ] **Exportable hash manifest** — tie reports to the Phase 15 tamper-evident chain so auditors can verify integrity
- [ ] **Evidence bundle export** — one-click packaging of alerts, PCAPs, memory dumps, and audit log for a given incident window

---

## Phase 23 — Identity & User Context (PRO backlog)

Modern detections hinge on who, not just what. Adds identity attribution so alerts can differentiate a connection initiated by a domain admin from one initiated by a kiosk user.

- [ ] **Local-user attribution** — attach the local OS user and session id to every connection record
- [ ] **Active Directory / Entra ID / Okta linkage** — resolve local users to directory identities via per-tenant connector
- [ ] **Privileged-account differentiation** — raise alerts on domain admins and service accounts more aggressively than standard users
- [ ] **Lateral-movement signal** — detect "this endpoint authenticated to N new internal hosts in a short window" as a first-class scoring input
- [ ] **Identity surface in UI and reports** — show user context in inspector, alerts, and compliance reports

---

## Phase 24 — Playbook Builder & SaaS-session Visibility (PRO backlog)

Two differentiators bundled together because each alone is narrow, but together they round out the "modern endpoint" story.

### Low-code response playbooks
- [ ] **GUI rule builder** in the fleet console on top of the existing Phase 11 YAML engine
- [ ] **Pre-built playbooks** — ransomware-like behaviour → isolate + capture PCAP + memory-dump + page; LoLBAS + new country → require approval before block
- [ ] **Dry-run and rollback window** — every action has a reversible TTL and an operator "undo" button before commitment

### Browser / SaaS-session visibility
- [ ] **Tab / SaaS-app attribution** — correlate connections to browser tab identity and known SaaS destinations where possible
- [ ] **OAuth token exfil signal** — detect anomalous cross-origin token flows
- [ ] **Per-SaaS data-volume anomaly** — baseline typical outbound volume per SaaS destination and flag deviations

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
| 3.x | 12 | Detection depth | ✅ Done |
| 4.x | 13 | Optimization & efficiency | ✅ Feature complete |
| 5.x | 14 | Hardening & self-defence | ✅ Done |
| 5.x | 15 | File integrity & anti-tamper (OPEN) | 🚧 In progress |
| 6.x | 16 | Public vulnerability intelligence & advisory feeds (OPEN) | 🔲 Backlog |
| 7.x | 17 | Protocol expansion (OPEN) | 🔲 Backlog |
| 8.x | 18 | Cross-platform detection parity (OPEN) | 🔲 Backlog |
| PRO 1.x | 19 | Cloud fleet console & integrations | 🔲 Backlog |
| PRO 1.x | 20 | MSP multi-tenant & white-label | 🔲 Backlog |
| PRO 1.x | 21 | Managed threat intel feed | 🔲 Backlog |
| PRO 1.x | 22 | Compliance reporting pack | 🔲 Backlog |
| PRO 1.x | 23 | Identity & user context | 🔲 Backlog |
| PRO 1.x | 24 | Playbook builder & SaaS-session visibility | 🔲 Backlog |
