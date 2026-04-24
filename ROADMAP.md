# Vigil — Development Roadmap

Each phase ends with a working, runnable binary. No phase leaves the project broken.

---

## Phase 0 — Scaffolding ✅ COMPLETE

- [x] Name chosen: **Vigil**
- [x] Architecture decided (tokio + egui + ETW)
- [x] CLAUDE.md written
- [x] ROADMAP.md written
- [x] `cargo init vigil` at `C:\dev\vigil`
- [x] `Cargo.toml` with all dependencies
- [x] `.gitignore`
- [x] `src/main.rs` stub
- [x] First `cargo build` succeeded

---

## Phase 1 — Core Types + Config ✅ COMPLETE

- [x] Core event and UI state types
- [x] Persistent config with defaults and trusted-process helpers
- [x] Threat scoring engine with unit coverage
- [x] Config round-trip validated

---

## Phase 2 — Cross-Platform Process + Connection Monitor (Polling) ✅ COMPLETE

- [x] Process metadata collection
- [x] Windows publisher and service enrichment
- [x] TCP/UDP polling monitor
- [x] Broadcast-based monitor hub
- [x] Terminal event stream wiring

---

## Phase 3 — ETW Real-Time Monitor (Windows) ✅ COMPLETE

- [x] Windows ETW fast path for TCP connect/accept events
- [x] Startup polling snapshot
- [x] Hybrid ETW + polling fallback
- [x] Sub-second connection detection on Windows

---

## Phase 4 — Tray + Notifications + Autostart ✅ COMPLETE

- [x] System tray integration
- [x] Desktop notifications
- [x] Privilege-aware autostart
- [x] First-run autostart setup

---

## Phase 5 — GUI (egui) ✅ COMPLETE

- [x] Activity and Alerts tables
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
- [x] Block single connection
- [x] Block all connections from a process
- [x] Active-response UX with confirmations, countdowns, unblock controls, and privilege-state surfacing
- [x] Block remote IP / CIDR system-wide
- [x] Block remote domain through reversible hosts-file edits
- [x] Kill process
- [x] Suspend / resume process

### Machine-wide lockdown
- [x] Panic button — full network isolation
- [x] Allowlist-only mode
- [x] Quarantine profile
- [x] Break-glass recovery
- [x] Post-restore network reattachment hardening

### Rule engine and automation
- [x] YAML response rules with dry-run support
- [x] Threshold escalation
- [x] Time-boxed blocks
- [x] Scheduled lockdown

### Containment and forensics
- [x] PCAP capture on alert
- [x] Process memory dump on alert
- [x] Freeze autorun entries
- [x] Honeypot decoy files

### Operator surface and docs
- [x] Settings UI exposes active-response controls
- [x] Help tab documents the completed Phase 11 feature set
- [x] Example YAML rule file added at `response-rules.example.yaml`

---

## Phase 12 — Detection Depth ✅ COMPLETE

- [x] Behavioural baselines
- [x] Script-host inspection
- [x] Signed-but-malicious detection
- [x] LoLBAS / script proxy expansion
- [x] Parent / token anomaly heuristics
- [x] MITRE ATT&CK mapping
- [x] Operator surface badges and inspector chips
- [x] TLS SNI / JA3 fingerprinting
- [x] Visibility / tamper blind-spot heuristics
- [x] Fresh validation pass completed when the phase landed

---

## Phase 13 — Optimization & Efficiency ✅ FEATURE COMPLETE

- [x] Process-card endpoint aggregation
- [x] Broader TCP lifecycle visibility
- [x] UI rendering cache
- [x] Filter matching optimization
- [x] Loopback enrichment skip
- [x] Memory budgets for enrichment caches
- [x] Forensic global rate limiting
- [x] Pipeline profiling instrumentation
- [x] Low-noise UI event drain defaults
- [x] Linux eBPF module and polling fallback
- [x] Performance test fixtures
- [x] Linux system tray support
- [x] Privilege UX for Linux capabilities

---

## Phase 14 — Hardening & Self-defence ✅ COMPLETE

- [x] Protected policy store — `vigil.json` carries a local integrity signature and signed backup; legacy installs migrate on first load
- [x] Policy integrity verification — HMAC-backed load-time verification restores from the last known-good backup when tampering is detected
- [x] Privilege-gated policy edits — policy-sensitive settings and trust actions require Admin Mode to persist
- [x] Self-protection and tamper evidence — audit actions are hash-chained and verified at startup so log tampering is visible
- [x] Secure update channel — release assets ship with a signed update manifest and signature; the app can verify manifests offline with the embedded trust anchor
- [x] Linux active-response parity — isolation, connection kill, suspend/resume, IP/program/domain blocking, and capability checks work cross-platform

---

## Phase 15 — File Integrity & Anti-Tamper ✅ COMPLETE

Make sure no file used by Vigil can be silently tampered with without detection, recovery, or operator visibility.

### Completed slices
- [x] Signed or cryptographically verified policy / configuration files — `vigil.json` carries a local integrity sidecar and signed backup, with legacy installs seeded on first load
- [x] Integrity verification for Vigil-owned generated state — behavioural baselines, active-response state, break-glass recovery state, and quarantine state use the protected policy-store integrity path where applicable
- [x] Secure audit-log chaining — audit entries are hash-chained and verified at startup so edits or removal become visible
- [x] Forensic artifact provenance and checksum manifests — PCAP captures, TLS sidecars, and process dumps get `.manifest.json` sidecars with SHA-256, size, alert context, and capture metadata
- [x] Startup integrity scan — startup records audited summaries and operator-visible logs for protected policy sidecars, forensic manifests, and configured operator-managed inputs
- [x] Operator-managed file provenance — blocklists and response-rule YAML are tracked with first-seen / changed / missing / unreadable provenance without treating intentional local edits as corruption
- [x] Protected operator provenance registry — the local provenance registry is itself protected by the existing integrity sidecar / backup mechanism
- [x] Recovery / quarantine path for corrupted Vigil-owned files — corrupt forensic manifests and their referenced artifacts move into `quarantine/integrity/...` with an audit trail

### Residual notes
- Operator-managed blocklists and response-rule YAML are intentionally observational only: Vigil records first-seen and changed hashes, but does not quarantine or reject normal local edits.
- Phase 15 is complete once the stacked Phase 15 PRs have landed on `master`.

---

## Phase 16 — Protocol Expansion (OPEN backlog)

Extend Vigil from a primarily TCP/UDP-oriented monitor toward broader protocol-aware network visibility, while keeping protocol semantics explicit instead of forcing everything into a TCP-shaped model.

### Planned scope
- [ ] QUIC visibility — UDP-based flow visibility, protocol tagging, and conservative detection/scoring hooks where attribution is strong enough
- [ ] ICMP telemetry — separate diagnostics / network-signal stream for echo activity and other notable ICMP behaviour
- [ ] Protocol-aware core model — make protocol, confidence, and protocol-specific semantics first-class instead of assuming every record behaves like TCP
- [ ] UI protocol surfacing — show protocol identity and protocol-specific summaries clearly in Activity / Alerts and inspector views
- [ ] Protocol-aware baselining and scoring — keep QUIC and other future protocols separable from TCP baselines so novelty and risk remain explainable

### Optional scope
- [ ] SCTP support only if a concrete deployment need justifies the extra complexity
- [ ] DCCP support only if a clear real-world use case appears

---

## Phase 17 — Cross-platform Detection Parity (OPEN backlog)

Windows and Linux now have first-class detection and active-response support. Broadening to macOS and unifying the monitor architecture unlocks mixed-OS deployments. Mobile is explicitly out of scope.

### macOS — Endpoint Security Framework
- [ ] Endpoint Security system extension — signed `EndpointSecurity.framework` subscriber for exec, connect, and related events with process-token and ancestor metadata
- [ ] Network Extension visibility — supplement with `NEFilterProvider` / `NEAppProxyProvider` where Endpoint Security alone is insufficient
- [ ] Code-signing and notarization path — document Apple Developer signing, Endpoint Security entitlement, notarization, and build-feature gating
- [ ] DTrace fallback — degraded realtime path when Endpoint Security is unavailable
- [ ] Graceful fallback — visible operator notice and polling fallback when ES is unavailable or unapproved

### Shared integration
- [ ] Monitor trait unification — ETW, eBPF, and Endpoint Security implement a common event-source interface consumed by one Monitor hub
- [ ] Cross-platform latency benchmark — measure p50/p95 detection latency on Windows, Linux, and macOS; target <200ms on Linux and <300ms on macOS where supported
- [ ] Installer and autostart parity — launchd / systemd service units, signed installers, pkg / deb / rpm / AppImage polish
- [ ] Cross-platform test fixtures — CI coverage and detection regression tests across supported OSes

---

## Phase 18 — Cloud Fleet Console & Integrations (PRO backlog)

The single most important phase for turning Vigil into a business. Without a hosted console there is no recurring-revenue surface and no SMB / MSP path. This phase intentionally moves after the remaining OPEN technical platform work so the fleet product can build on stronger protocol and cross-platform foundations.

### Hosted fleet console
- [ ] Multi-tenant SaaS backend with agent enrollment via install token
- [ ] Live endpoint status grid, alerts feed, and cross-fleet search
- [ ] Remote trigger: isolate / clear-isolation / kill process / block IP across selected endpoints
- [ ] Role-based access with per-action audit log
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

## Phase 19 — MSP Multi-tenant & White-label (PRO backlog)

Depends on Phase 18.

- [ ] Tenant hierarchy — MSP → customer → site → endpoint, with inherited policy and override rules
- [ ] White-label branding — per-tenant logo, product name, custom domain, branded alert emails
- [ ] Bulk deployment tooling — MSI / pkg / deb with embedded enrollment token and deployment guides for common RMM / MDM tools
- [ ] MSP dashboard — cross-customer alert feed, filterable by tenant, with per-tenant usage and billing exports
- [ ] Tiered / volume pricing — per-seat discount curves and monthly invoicing for channel partners

---

## Phase 20 — Managed Threat Intel Feed (PRO backlog)

- [ ] Hosted feed service — hourly-refreshed managed IP / domain / hash blocklist consumed by PRO agents via authenticated pull
- [ ] Curated LoLBAS, C2 port, and process-rule updates — versioned, signed rule packs delivered to agents
- [ ] Sigma rule import pipeline — ingest and translate community Sigma rules into Vigil scoring signals
- [ ] Optional reputation lookup API — per-request IP / domain / hash reputation endpoint for the fleet console and automation
- [ ] Transparency and provenance — every feed entry includes source, first-seen, and confidence so operators can audit blocks

---

## Phase 21 — Compliance Reporting Pack (PRO backlog)

- [ ] Pre-built report templates — SOC 2, HIPAA, PCI DSS, ISO 27001 evidence mappings
- [ ] Scheduled exports — automated PDF / CSV delivery by email or to S3-compatible storage
- [ ] Retention policy controls — configurable 90-day / 1-year / 7-year log retention per tenant
- [ ] Exportable hash manifest — tie reports to the Phase 15 tamper-evident chain so auditors can verify integrity
- [ ] Evidence bundle export — one-click packaging of alerts, PCAPs, memory dumps, and audit logs for an incident window

---

## Phase 22 — Identity & User Context (PRO backlog)

- [ ] Local-user attribution — attach local OS user and session id to every connection record
- [ ] Active Directory / Entra ID / Okta linkage — resolve local users to directory identities via per-tenant connector
- [ ] Privileged-account differentiation — raise alerts on domain admins and service accounts more aggressively than standard users
- [ ] Lateral-movement signal — detect when an endpoint authenticates to many new internal hosts in a short window
- [ ] Identity surface in UI and reports — show user context in inspector, alerts, and compliance reports

---

## Phase 23 — Playbook Builder & SaaS-session Visibility (PRO backlog)

### Low-code response playbooks
- [ ] GUI rule builder in the fleet console on top of the Phase 11 YAML engine
- [ ] Pre-built playbooks — ransomware-like behaviour → isolate + capture PCAP + memory dump + page; LoLBAS + new country → require approval before block
- [ ] Dry-run and rollback window — every action has a reversible TTL and an operator undo button before commitment

### Browser / SaaS-session visibility
- [ ] Tab / SaaS-app attribution — correlate connections to browser tab identity and known SaaS destinations where possible
- [ ] OAuth token exfil signal — detect anomalous cross-origin token flows
- [ ] Per-SaaS data-volume anomaly — baseline typical outbound volume per SaaS destination and flag deviations

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
| 5.x | 15 | File integrity & anti-tamper | ✅ Complete |
| 6.x | 16 | Protocol expansion | 🔲 Backlog |
| 7.x | 17 | Cross-platform detection parity | 🔲 Backlog |
| PRO 1.x | 18 | Cloud fleet console & integrations | 🔲 Backlog |
| PRO 1.x | 19 | MSP multi-tenant & white-label | 🔲 Backlog |
| PRO 1.x | 20 | Managed threat intel feed | 🔲 Backlog |
| PRO 1.x | 21 | Compliance reporting pack | 🔲 Backlog |
| PRO 1.x | 22 | Identity & user context | 🔲 Backlog |
| PRO 1.x | 23 | Playbook builder & SaaS-session visibility | 🔲 Backlog |
