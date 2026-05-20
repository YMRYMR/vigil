# Vigil — Development Roadmap

Each phase ends with a working, runnable binary. No phase leaves the project broken.

Vigil's active support targets are **Windows and Linux**.

For completed implementation history before Phase 16, use Git history and merged pull requests. This roadmap now tracks active and forward-looking work only.

---

## Phase 16 — Public Vulnerability Intelligence & Advisory Feeds 🚧 FOUNDATIONS IN PLACE

Use free public vulnerability and advisory sources to help Vigil keep the local machine secure, while keeping every decision explainable, conservative, and useful offline from the last trusted cache.

### Source ingestion and normalization

- [x] **Normalized vulnerability record model** — shared schema for CVE/advisory/source/affected product/version/severity/exploitation/references/mitigation/provenance so multiple sources can coexist cleanly.
- [x] **Signed local source cache** — fetched records and source snapshots are stored as tamper-evident local state with expiry, rollback-safe refresh, and operator-visible source health/status.
- [x] **NVD CVE ingestion foundations** — protected local cache for NVD CVE snapshots supports offline import, live API sync, source attribution, rate-limit-aware refresh, and incremental `lastMod*` updates.
- [x] **NVD CVE change-history ingestion** — protected local cache for NVD CVE change-history snapshots supports offline import, live API sync, source attribution, rate-limit-aware refresh, and incremental `changeStartDate` / `changeEndDate` updates.
- [x] **EUVD ingestion foundations** — operator-supplied EUVD JSON snapshots can be normalized into the shared advisory cache while preserving aliases, references, mitigation guidance, exploitation indicators, and provenance.
- [x] **JVN ingestion foundations** — operator-supplied JVN / JVN iPedia JSON snapshots and JVNDBRSS XML items can be normalized into the shared advisory cache while preserving vendor, product, advisory, remediation, and provenance metadata.
- [x] **Public advisory ingestion for NCSC and BSI** — ingest public RSS, advisory, and malware-analysis content only; do not depend on closed, partner-only, or registration-gated feeds.
- [x] **On-demand local software inventory CLI** — standalone Windows/Linux inventory helper emits JSON from Windows uninstall registry and Linux dpkg/RPM/APK package metadata without touching startup.

### Endpoint relevance and matching

- [x] **Local software inventory and version discovery** — fold Windows uninstall registry and Linux package-manager inventory into the main inventory model without adding startup risk.
- [x] **Product normalization + vendor aliasing** — reconcile executable names, publishers, package names, services, and installer metadata into stable vendor/product identities.
- [x] **Version comparison engine** — compare installed versions against advisory ranges conservatively across semver, vendor-specific, and OS package version formats.
- [x] **CPE / product matching pipeline foundations** — map local software identities to CPEs or equivalent source-native product identifiers with confidence scoring and operator-visible explainability in the advisory match pipeline and `--advisory-match-status` CLI.
- [x] **Connection-to-software correlation** — tie a live process or service back to the relevant installed product record so advisory matches can appear in the existing Inspector and Alerts workflows.

### Operator value and protection outcomes

- [x] **Local advisory inspector** — show matched public advisories, CVEs, severity, known-exploitation flags, fixed versions, mitigation links, and source references for the selected process or installed product.
- [x] **Conservative scoring hooks** — optionally raise score only when a live process or exposed service maps with high confidence to a severe or exploited public vulnerability, with clear reasons and low-noise defaults.
- [x] **Mitigation-aware response rules** — three new response rule predicates (`require_advisory_fix_available`, `require_advisory_workaround_available`, `require_advisory_upgrade_available`) plus structured guidance fields (`fix_version`, `workaround_instructions`, `upgrade_instructions`) on `VulnerabilityRecord` populated from NVD reference tags.
- [x] **Public-source-to-blocklist/rule-pack conversion** — `src/advisory_ioc.rs` extracts IPs, domains, and hashes from advisory reference URLs and CVE summaries; `blocklist::add_advisory_iocs()` injects them into the live blocklist engine automatically during each cache save.
- [x] **Exposure-first prioritization** — `exposed` field on `RuntimeAdvisoryCandidate` sorts exposed matches first in advisory scoring; reason strings include `exposed` tag for response rule parsing.
- [x] **Offline-first and fail-open behaviour** — degraded blocklist mode (serves last-known-good cache on integrity failure), stale-data watermarking (reduces advisory score for expired sources), exponential-backoff NVD retry scheduling, and bounded WAL via auto-checkpoint.

### Docs and policy

- [x] **Attribution / terms compliance** — `docs/ADVISORY-SOURCE-COMPLIANCE.md` documents source-specific attribution, caching, redistribution, and update-frequency rules for NVD, EUVD, JVN, NCSC public content, and BSI public content.
- [x] **Operator guidance** — `README.md` and `docs/USER-GUIDE.md` explain what a matched advisory means, what confidence limits remain, and why a public CVE match is not by itself proof of compromise.
- [x] **Supported-platform policy** — `docs/SUPPORTED-PLATFORMS.md` documents Windows/Linux support scope and the startup fail-open rule.

---

## Phase 17 — Protocol Expansion 🚧 FOUNDATIONS IN PLACE

Extend Vigil from a primarily TCP/UDP-oriented monitor toward broader protocol-aware network visibility, while keeping protocol semantics explicit instead of forcing everything into a TCP-shaped model.

### Planned scope

- [x] **QUIC visibility** — UDP/443 connections tagged as QUIC in UI and scoring pipeline. Gets +1 score delta with `QUIC Tunneling` ATT&CK tag. Protocol shown as "QUIC" in inspector panel.
- [x] **ICMP telemetry** — `/proc/net/snmp` ICMP statistics parsed on every Linux poll cycle. Echo flood and high unreachable-rate events logged via tracing. Infrastructure ready for deeper diagnostics integration.
- [x] **Protocol-aware core model** — `TransportProtocol` enum (`Tcp`, `Udp`) added to `RawConn`, `ConnKey`, `ConnInfo`, and `ScoreInput`. Threaded through the entire monitor pipeline and scoring engine. Dedup key includes protocol so same 5-tuple on different transports doesn't collide.
- [x] **UI protocol surfacing** — protocol shown in the inspector panel. Protocol appended to the process-list status badges (`TCP`, `UDP`). UDP ranked alongside LISTEN in status sort order.
- [x] **Protocol-aware baselining and scoring** — UDP traffic gets a +1 score bump with `Protocol Anomaly` ATT&CK tag. Protocol-aware scoring infrastructure ready for future protocol additions.

### Optional scope

- [ ] **SCTP support** — add SCTP visibility only if a concrete deployment need justifies the protocol-specific complexity.
- [ ] **DCCP support** — add DCCP visibility only if a clear real-world use case appears; otherwise keep it out of the default scope.

---

## Phase 18 — Windows/Linux Detection and Response Parity 🚧 FOUNDATIONS IN PLACE

Windows and Linux are the active support targets. This phase is about making those two platforms equally safe, explainable, and useful without expanding the supported OS surface.

### Planned scope

- [x] **Monitor trait unification** — `handle_realtime_event` shared handler eliminates 42-line duplicated code block between ETW and eBPF paths. Event-channel abstraction (`EventRx`) unifies unbounded ETW and bounded eBPF receivers. Ready for full `EventSource` trait extraction.
- [x] **Windows/Linux latency benchmark** — `src/bin/vigil_benchmark.rs` measures p50/p95/p99 latency, distinguishes ETW/eBPF from polling fallback, and emits JSON/HTML reports. Cross-process end-to-end event delivery measurement remains tracked separately in `docs/PHASE-18-PARITY.md`.
- [x] **Windows/Linux installer and service parity guardrails** — `src/bin/vigil_service_check.rs` validates Windows scheduled-task and Linux systemd installation, enabled/running state, privilege expectations, and restart/fail-open checks across the supported platforms.
- [x] **Windows/Linux active-response parity audit** — all 22 active-response functions verified working on both supported platforms. Linux has full parity: iptables/nftables, `ss -K`, `ip link`, `/etc/hosts`, process suspend/resume all work. Only autorun snapshot/revert (Windows registry concept) is Linux-specific unimplemented.
- [x] **Windows/Linux inventory parity** — fold Windows uninstall registry and Linux package-manager inventory into the main inventory model without adding startup risk.
- [x] **Windows/Linux test fixtures** — add detection and response regression tests that cover both supported OS families where practical.

---

## Phase 19 — Native OS Firewall Engine 🚧 IN PROGRESS

Replace the OS firewall with Vigil's own WFP (Windows) / nftables (Linux) engine. All existing Vigil core features (monitoring, scoring, active response, YARA, advisory) are preserved and enhanced by having direct kernel-level firewall control, sub-millisecond rule adds, persistent rule sets, and per-profile/interface filtering. The OS firewall APIs remain available as a safety net until Vigil's engine reaches parity.

### Phase 0 — Foundation (2–3 weeks)

- [ ] **Windows WFP user-mode API wrapper** — dynamic `Fwpuclnt.dll` loading via `LoadLibrary`/`GetProcAddress`. Engine session open, provider/sublayer registration complete. Still needs `FwpmFilterAdd` wired for rule management (currently uses netsh fallback).
- [x] **Linux nftables backend activation** — `nft` added to `command_paths.rs`; full nftables-preferred / iptables-fallback executor bridge wired through `NftablesBackend`.
- [ ] **Persistent rule store** — structured rule database (integrity-protected JSON or SQLite) with globally unique IDs, creation time, TTL, direction, action, layer, profile affinity. Migrate current ad-hoc state tracking into this store.
- [x] **Cross-platform `FirewallBackend` trait** — unified trait with 15 methods, implemented for both WFP and nftables.

### Phase 1 — Core Firewall Engine (4–6 weeks)

- [ ] **Windows WFP rule manager** — `FwpmFilterAdd`/`FwpmFilterDeleteById` wired via `WfpBackend`. `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` filtering. Filter conditions for remote IP, port, protocol, user SID. AE for PID-based filtering.
- [x] **Linux nftables rule manager** — `vigil` nftables table with jump chains. Remote IP blocks via `nft_insert_block_remote`, UID blocks via `nft_insert_block_uid`. Rule lookup by handle via `nft_parse_handle_by_comment`. Setup idempotent.
- [ ] **Dynamic vs. static rule separation** — transient response rules (TTL-based) vs. operator-defined permanent allow/block rules.
- [ ] **Rule ordering and priority** — filter weight / chain priority ensuring Vigil dynamic blocks override OS defaults.

### Phase 2 — Boot-Time Enforcement (2–3 weeks)

- [x] **Startup rule reconciliation** — `reconcile_firewall_rules()` re-applies blocked IP/process/domain rules to the live backend on every startup, ensuring rules survive reboot on Linux. WFP natively persists across reboots.
- [ ] **Linux boot persistence** — nftables config fragment written on shutdown, restored on startup via systemd `nftables.service`.
- [ ] **Boot-time circuit breaker** — extend pre-login guard and break-glass recovery to cover firewall rules; stale Vigil filters cleared on heartbeat expiry.

### Phase 3 — Firewall Management UI (3–4 weeks)

- [x] **Firewall tab in inspector** — shows active rules, isolation state, blocked IPs/processes/domains, suspended processes.
- [ ] **Rule template system** — predefined canned rules for common scenarios.
- [x] **OS firewall profile visibility** — per-profile enabled/disabled, inbound/outbound actions shown in firewall tab.
- [ ] **Permanent allow/block rules** — operator-defined rules that survive restart.
- [x] **CLI firewall commands** — `vigil --firewall status`, `--firewall list`, `--firewall panic` with exit codes.

### Phase 4 — Circuit Breakers, Recovery & Safety (1–2 weeks)

- [ ] **Crash-safe filter lifecycle** — WFP filters persist across process restarts; stale filter cleanup on startup. nftables rules survive process crash; reconcile detects zombie rules.
- [ ] **Graceful uninstall** — `vigil --uninstall` removes all Vigil-owned WFP filters / nftables chains, restores OS firewall defaults.
- [ ] **Panic button hardening** — `vigil --firewall panic` calls `restore_machine()` with brute-force fallback.
- [ ] **Safe-mode watchdog** — break-glass heartbeat mechanism auto-clears Vigil's filters on repeated engine crashes.

### Phase 5 — Feature Parity & Polish (4–6 weeks)

- [ ] **Per-profile rules** — WFP `FWPM_CONDITION_NETWORK_PROFILE_ID` for Domain/Private/Public affinity.
- [ ] **Per-interface rules** — filter by interface index/LUID (WFP) or interface name (nftables).
- [ ] **Logging & audit** — WFP built-in logging per-filter. nftables counter rules with log prefix.
- [ ] **Stealth mode** — drop inbound without RST/ICMP.
- [ ] **Notification balloons** — Windows tray notification on block events, with undo action.
- [ ] **Performance counters** — per-rule match hit count, average evaluation time, last match timestamp.
- [ ] **Rule import/export** — JSON export of all Vigil firewall rules for backup or migration.

### Safety guarantees throughout

- A fresh Vigil install with no rules configured does **nothing** — the OS firewall continues handling traffic.
- An upgrade preserves all active filters across process restarts (WFP kernel persistence) or reapplies them on startup (nftables).
- An uninstall or crash restores the OS firewall to its pre-Vigil state.
- Every rule has an operator-visible owner, creation time, and TTL. No hidden or orphaned state.
- The current break-glass + reconcile + pre-login guard system covers the firewall rule lifecycle.

### Phase 4 — Circuit Breakers, Recovery & Safety (1–2 weeks)

- [ ] **Crash-safe filter lifecycle** — on Vigil startup, `FwpmEngineOpen` binds to a new session. Filters with provider GUID persist; stale filters from old sessions are cleaned up. Linux: nftables rules survive process crash (they're kernel-level); reconcile detects zombie rules.
- [ ] **Graceful uninstall** — `vigil --uninstall` removes all Vigil-owned WFP filters / nftables chains and restores OS firewall to its pre-Vigil state. Preserves operator-defined permanent rules for reinstall.
- [ ] **Panic button** — `Ctrl+Alt+V` or `vigil firewall panic` drops all Vigil firewall rules immediately, restores OS default profiles.
- [ ] **Safe-mode watchdog** — if Vigil's rule engine crashes repeatedly, the existing break-glass heartbeat mechanism auto-clears Vigil's filters and disables boot start.

### Phase 5 — Feature Parity & Polish (4–6 weeks)

- [ ] **Per-profile rules** — WFP `FWPM_CONDITION_NETWORK_PROFILE_ID` for Domain/Private/Public affinity. nftables sets match.
- [ ] **Per-interface rules** — filter by interface index/LUID (WFP) or interface name (nftables).
- [ ] **Logging & audit** — WFP built-in logging per-filter (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`). nftables counter rules with log prefix. Audit trail integration.
- [ ] **Stealth mode** — WFP built-in; nftables drop inbound without RST/ICMP.
- [ ] **Notification balloons** — Windows tray notification on block events, with undo action.
- [ ] **Performance counters** — per-rule match hit count, average evaluation time, last match timestamp.
- [ ] **Rule import/export** — JSON export of all Vigil firewall rules for backup or migration.
- [ ] **Connection security / IPsec foundations** — WFP callout driver scaffolding for future IPsec policy management. Not yet feature-complete.

### Safety guarantees throughout

- A fresh Vigil install with no rules configured does **nothing** — the OS firewall continues handling traffic.
- An upgrade preserves all active filters across process restarts (WFP kernel persistence) or reapplies them on startup (nftables).
- An uninstall or crash restores the OS firewall to its pre-Vigil state.
- Every rule has an operator-visible owner, creation time, and TTL. No hidden or orphaned state.
- The current break-glass + reconcile + pre-login guard system covers the firewall rule lifecycle.

---

## Phase 20 — YARA Signature Integration (OPEN backlog)

Add signature-based malware detection alongside the existing behavioural heuristics. YARA scans new processes and selected memory regions on creation, catches known malware families that behavioural scoring alone misses, and feeds matches into the existing scoring pipeline with clear `YARA rule: <name>` reasons and ATT&CK tags.

- [ ] **Binary embedding of community YARA rules** — bundle a curated ruleset (e.g. Valhalla, YARA Forge) at compile time, updated via signed auto-update (Phase 23).
- [ ] **Process scan on creation** — scan the executable path with YARA when a new process is detected; score bump on match.
- [ ] **Memory region scan** — scan selected process memory (e.g., `--dump` target) for in-memory malware that hides from disk scanning.
- [ ] **YARA rule management UI** — show matched rules in the inspector, allow operators to toggle rule categories, and view rule metadata (author, description, reference).
- [ ] **Custom rule import** — let operators drop their own `.yar` files alongside blocklists, verified by `.sha256` sidecar (same integrity model as response rules).

---

## Phase 21 — Security Posture Dashboard (OPEN backlog)

A single-panel view that answers "is Vigil actually protecting me?" without digging through logs.

- [ ] **Health summary** — real-time monitoring status (ETW/eBPF/polling), blocklist engine state (loaded entries / empty / degraded), advisory cache freshness, response rules loaded, firewall isolation status, native firewall engine health.
- [ ] **Threat dashboard** — current connection score distribution, top blocked targets, recent alerts over time, YARA matches summary, firewall rule hit counts.
- [ ] **Tray indicator integration** — tray icon colour and tooltip reflects current protection status (green = healthy, yellow = degraded, red = stopped / no real-time).
- [ ] **CLI status command** — `vigil status` emits JSON with all health signals for scripting and remote monitoring.

---

## Phase 22 — Jitter-Aware C2 Beaconing Detection (OPEN backlog)

Real command-and-control channels use random intervals (jitter), not fixed-period beacons. The current beacon tracker only catches fixed-interval patterns.

- [ ] **Jitter detection engine** — analyse inter-arrival times for irregular-but-correlated patterns using statistical dispersion (coefficient of variation, entropy of intervals).
- [ ] **Low-and-slow detection** — detect beaconing with very long periods (hours) and high jitter that current fixed-window analysis misses.
- [ ] **Scoring integration** — beaconing-like + jitter → score bump with `C2 Beaconing (jitter)` reason and `T1095 C2 Communication` ATT&CK tag.

---

## Phase 23 — Signed Auto-Update Channel (OPEN backlog)

A lightweight, SaaS-free update mechanism for threat data. Pulls signed JSON manifests from GitHub releases so the OPEN community gets fresh blocklists, YARA rules, and LoLBAS definitions without any cloud dependency.

- [ ] **Signed manifest format** — Ed25519-signed JSON manifest listing the latest rule pack versions and SHA-256 hashes. Verification reuses the existing `security::update` Ed25519 verification code.
- [ ] **Periodic poll** — check for updates every N hours; download and verify new rule packs; apply atomically with rollback on verification failure.
- [ ] **Curated IP/domain blocklist feed** — hourly-refreshed IP/domain blocklist from abuse.ch and Emerging Threats, published as signed releases.
- [ ] **Curated YARA rules feed** — versioned YARA rule packs from Valhalla / YARA Forge community feed.
- [ ] **Curated LoLBAS and C2 port definitions** — versioned updates to the built-in LoLBAS and malware-port heuristics.
- [ ] **Curated firewall rule templates** — versioned updates to canned firewall rule templates (WFP/nftables).
- [ ] **Transparency** — every update logged in the audit trail with manifest hash and rule count.

---

## Phase 24 — File Integrity Monitoring (OPEN backlog)

Track SHA-256 hashes of critical system binaries and configuration files, alert on unexpected changes.

- [ ] **Baseline snapshot** — take hash snapshots of monitored directories on install (system32, `/usr/bin`, common config paths).
- [ ] **Periodic verification** — re-hash on a configurable interval; report changed / new / deleted files.
- [ ] **Alert integration** — unexpected changes feed into the scoring pipeline with `File Integrity` reason and `T1070 Indicator Removal` ATT&CK tag.
- [ ] **Protected state** — baseline hash list stored with the same HMAC integrity protection as other Vigil-owned state files.

---

## Phase 25 — Cloud Fleet Console & Integrations (PRO backlog)

Extends Vigil with a hosted console for multi-endpoint fleet management, alert aggregation, and outbound integrations.

### Hosted fleet console

- [ ] Multi-tenant SaaS backend with agent enrollment via install token.
- [ ] Live endpoint status grid, alerts feed, and cross-fleet search.
- [ ] Remote trigger: isolate / clear-isolation / kill process / block IP / firewall panic across selected endpoints.
- [ ] Role-based access with per-action audit log.
- [ ] End-to-end TLS, per-tenant encryption of sensitive fields, signed agent-to-server channel.
- [ ] Self-serve signup, Stripe billing, seat-based subscription management.

### Outbound integrations

- [ ] Syslog / CEF export.
- [ ] Splunk HEC, Elastic, Microsoft Sentinel, Datadog connectors.
- [ ] Generic webhook + JSON-out channel.
- [ ] PagerDuty / Opsgenie / Slack / Microsoft Teams alerting.
- [ ] Jira / ServiceNow ticket creation on high-severity alerts.
- [ ] Shared intel sync and STIX / TAXII consumer.

---

## Phase 26 — MSP Multi-tenant & White-label (PRO backlog)

Multi-tenant architecture for managed service providers managing multiple customer fleets. Depends on Phase 20 (YARA) and Phase 19 (Firewall Engine).

- [ ] **Tenant hierarchy** — MSP → customer → site → endpoint, with inherited policy and override rules.
- [ ] **White-label branding** — per-tenant logo, product name, custom domain, branded alert emails.
- [ ] **Bulk deployment tooling** — MSI / deb / rpm / AppImage with embedded enrollment token, deployment guides for Intune, Kaseya, NinjaOne, ConnectWise Automate.
- [ ] **MSP dashboard** — cross-customer alert feed, filterable by tenant, with per-tenant usage and billing exports.
- [ ] **Tiered / volume pricing** — per-seat discount curves and monthly invoicing for channel partners.

---

## Phase 27 — Managed Threat Intel Feed (PRO backlog)

Adds a managed intelligence feed for PRO-tier deployments with signed, versioned rule packs.

- [ ] **Hosted feed service** — hourly-refreshed managed IP / domain / hash blocklist consumed by PRO agents via authenticated pull.
- [ ] **Curated LoLBAS, C2 port, and process-rule updates** — versioned, signed rule packs delivered to agents.
- [ ] **Sigma rule import pipeline** — ingest and translate community Sigma rules into Vigil scoring signals.
- [ ] **Optional reputation lookup API** — per-request IP / domain / hash reputation endpoint for the fleet console and automation.
- [ ] **Transparency and provenance** — every feed entry includes source, first-seen, and confidence so operators can audit blocks.

---

## Phase 28 — Compliance Reporting Pack (PRO backlog)

Pairs naturally with the tamper-evident logging already in the OPEN tier.

- [ ] **Pre-built report templates** — network activity evidence, audit controls, logging, and incident-response evidence.
- [ ] **Scheduled exports** — automated PDF / CSV delivery by email or to S3-compatible storage on operator-defined cadences.
- [ ] **Retention policy controls** — configurable 90-day / 1-year / 7-year log retention per tenant.
- [ ] **Exportable hash manifest** — tie reports to the tamper-evident chain so auditors can verify integrity.
- [ ] **Evidence bundle export** — one-click packaging of alerts, PCAPs, memory dumps, and audit log for a given incident window.

---

## Phase 29 — Identity & User Context (PRO backlog)

Modern detections hinge on who, not just what. Adds identity attribution so alerts can differentiate privileged accounts from standard users.

- [ ] **Local-user attribution** — attach the local OS user and session id to every connection record.
- [ ] **Directory linkage** — resolve local users to directory identities via per-tenant connector.
- [ ] **Privileged-account differentiation** — raise alerts on privileged users and service accounts more aggressively than standard users.
- [ ] **Lateral-movement signal** — detect "this endpoint authenticated to N new internal hosts in a short window" as a first-class scoring input.
- [ ] **Identity surface in UI and reports** — show user context in inspector, alerts, and compliance reports.

---

## Phase 30 — Playbook Builder & SaaS-session Visibility (PRO backlog)

Two differentiators bundled together because each alone is narrow, but together they round out the modern endpoint story.

### Low-code response playbooks

- [ ] **GUI rule builder** in the fleet console on top of the existing response-rule engine.
- [ ] **Pre-built playbooks** — ransomware-like behaviour → isolate + capture PCAP + memory-dump + page; LoLBAS + new country → require approval before block.
- [ ] **Dry-run and rollback window** — every action has a reversible TTL and an operator undo button before commitment.

### Browser / SaaS-session visibility

- [ ] **Tab / SaaS-app attribution** — correlate connections to browser tab identity and known SaaS destinations where possible.
- [ ] **OAuth token exfil signal** — detect anomalous cross-origin token flows.
- [ ] **Per-SaaS data-volume anomaly** — baseline typical outbound volume per SaaS destination and flag deviations.

---

## Version Plan

| Version | Phase | Description | Status |
|---|---|---|---|
| 6.x | 16 | Public vulnerability intelligence & advisory feeds | ✅ Complete |
| 7.x | 17 | Protocol expansion | ✅ Complete |
| 8.x | 18 | Windows/Linux detection and response parity | 🚧 Foundations in place |
| 9.x | 19 | Native OS firewall engine | 🚧 Foundations in place |
| 10.x | 20 | YARA signature integration | 🔲 Backlog |
| 11.x | 21 | Security posture dashboard | 🔲 Backlog |
| 12.x | 22 | Jitter-aware C2 beaconing detection | 🔲 Backlog |
| 13.x | 23 | Signed auto-update channel | 🔲 Backlog |
| 14.x | 24 | File integrity monitoring | 🔲 Backlog |
| PRO 1.x | 25 | Cloud fleet console & integrations | 🔲 Backlog |
| PRO 1.x | 26 | MSP multi-tenant & white-label | 🔲 Backlog |
| PRO 1.x | 27 | Managed threat intel feed | 🔲 Backlog |
| PRO 1.x | 28 | Compliance reporting pack | 🔲 Backlog |
| PRO 1.x | 29 | Identity & user context | 🔲 Backlog |
| PRO 1.x | 30 | Playbook builder & SaaS-session visibility | 🔲 Backlog |
