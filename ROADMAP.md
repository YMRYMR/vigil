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

Replace the OS firewall with Vigil's own WFP (Windows) / nftables/XDP (Linux) engine. All existing Vigil core features are preserved and enhanced by having direct kernel-level firewall control. The OS firewall APIs remain available as a safety net until Vigil's engine reaches parity.

### Phase 0 — Foundation

- [x] **Windows WFP user-mode API wrapper** — `Fwpuclnt.dll` via `LoadLibrary`/`GetProcAddress`. `FwpmEngineOpen0`, `FwpmFilterAdd0`, `FwpmFilterDeleteByKey0` loaded dynamically. Provider/sublayer registration. Correct struct layouts matching Windows SDK.
- [x] **Linux nftables backend activation** — `nft` added to `command_paths.rs`; nftables-preferred / iptables-fallback executor bridge wired through `NftablesBackend`.
- [ ] **Persistent rule store** — structured rule database with globally unique IDs, creation time, TTL, direction, action, layer, profile affinity.
- [x] **Cross-platform `FirewallBackend` trait** — unified trait with 16 methods implemented for WFP, nftables, and XDP.

### Phase 1 — Core Firewall Engine

- [x] **Windows WFP rule manager** — `FwpmFilterAdd0`/`FwpmFilterDeleteByKey0`. `FWPM_LAYER_ALE_AUTH_CONNECT_V4` for outbound filtering, `FWPM_CONDITION_IP_REMOTE_ADDRESS` with `FWP_V4_ADDR_AND_MASK`. Program rules use netsh fallback (WFP ALE app-container filtering requires SID setup).
- [x] **Linux nftables rule manager** — `vigil` nftables table with jump chains. Remote IP + UID block rules. Rule lookup by handle via `nft_parse_handle_by_comment`. Idempotent setup.
- [x] **Linux XDP/eBPF kernel firewall** — `xdp_firewall.bpf.c` attached at NIC driver level before iptables. Auto-disable heartbeat (30s timeout) prevents bricking. IPv4-only for now; IPv6 + TC/UDP pass through.
- [x] **Dynamic vs. static rule separation** — `DurationPreset::Permanent` (no TTL) vs OneHour/OneDay (TTL). `reconcile_state`/`reconcile_firewall_rules` respect TTL vs permanent distinction.

### Phase 2 — Boot-Time Enforcement

- [x] **Startup rule reconciliation** — `reconcile_firewall_rules_once()` called at boot before `reconcile()`. Re-applies IP, process (sysinfo PID lookup), domain, and isolation rules. Expired entries deleted only when kernel rule removal succeeds.
- [x] **Linux boot persistence** — nftables config saved to `/etc/nftables/vigil.conf` on reconciliation/state change; restored via `nft -f` on startup before reconciliation.
- [x] **Boot-time circuit breaker** — break-glass recovery already triggers `restore_machine()` which clears firewall rules. XDP auto-disables after 30s heartbeat expiry. WFP filters persist in kernel. Panic button (`--firewall panic`) with brute-force fallback.

### Phase 3 — Firewall Management UI

- [x] **Firewall tab in inspector** — active rules, isolation state, blocked IPs/processes/domains, suspended processes, per-profile status.
- [x] **CLI firewall commands** — `vigil --firewall status|list|panic` with exit codes.
- [ ] **Rule template system** — predefined canned rules for common scenarios.
- [ ] **Permanent allow/block rules** — operator-defined rules that survive restart.

### Phase 4 — Circuit Breakers, Recovery & Safety

- [x] **Panic button** — `vigil --firewall panic` calls `restore_machine()` with brute-force fallback (delete all Vigil rules, set profiles to allow).
- [x] **Graceful uninstall** — `vigil --uninstall-firewall` and `--uninstall-service` call `cleanup_on_uninstall()`: delete isolation rules, restore profiles to allow, log remaining state.
- [x] **Crash-safe filter lifecycle** — WFP filters persist across process restarts (kernel objects); stale filter cleanup via `reconcile_firewall_rules()`. XDP auto-disables on heartbeat expiry. nftables rules survive process crash in kernel.
- [x] **Safe-mode watchdog** — break-glass heartbeat auto-clears Vigil's filters via `restore_machine()`. XDP heartbeat auto-disables after 30s. Pre-login guard disables boot start on repeated failures.

### Phase 5 — Feature Parity & Polish

- [ ] **Per-profile rules** — Domain/Private/Public affinity.
- [ ] **Per-interface rules** — filter by interface index (WFP) or name (nftables).
- [x] **Logging & audit** — structured tracing on every firewall rule add/delete/reapply. `audit::record()` on all operations. Per-uninstall status summary with counts.
- [x] **Stealth mode** — WFP blocks drop silently (no RST). Linux iptables/nftables use DROP (not REJECT). XDP drops at NIC level. No ICMP responses sent by default.
- [x] **Notification balloons** — desktop toast notifications on block_remote, block_process, and isolate_machine. Fire-and-forget via notify-rust fallback on all platforms.
- [x] **Performance counters** — `--firewall status` shows live rule counts (blocked IPs, processes, domains, suspended, autoruns). Backend label + availability displayed.
- [x] **Rule import/export** — `vigil --firewall export` emits full rule list as JSON (blocked IPs, processes, domains, suspended, profiles).

### Safety guarantees

- Fresh install does nothing — OS firewall continues handling traffic.
- Upgrade preserves active filters across process restarts (WFP kernel persistence) or reapplies on startup.
- Uninstall or crash restores OS firewall to pre-Vigil state.
- Every rule has an operator-visible owner, creation time, and TTL.
- Break-glass + reconcile + pre-login guard covers firewall rule lifecycle.
- XDP auto-disables after 30s without heartbeat — cannot brick the machine.

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
