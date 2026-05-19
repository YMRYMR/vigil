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
- [ ] **Windows/Linux latency benchmark** — measure p50/p95 detection latency on Windows ETW and Linux eBPF, compare against polling fallback, and document expected bounds.
- [ ] **Windows/Linux installer and service parity** — keep Windows scheduled-task boot service and Linux systemd service behavior aligned, especially fail-open startup behavior.
- [x] **Windows/Linux active-response parity audit** — completed audit of all 22 active-response functions across Windows, Linux, and macOS. **Linux has full parity**: iptables/nftables, `ss -K`, `ip link`, `/etc/hosts`, process suspend/resume all work. Only autorun snapshot/revert (Windows-only concept) is unimplemented on Linux.
- [x] **Windows/Linux inventory parity** — fold Windows uninstall registry and Linux package-manager inventory into the main inventory model without adding startup risk.
- [ ] **Windows/Linux test fixtures** — add detection and response regression tests that cover both supported OS families where practical.

---

## Phase 19 — Cloud Fleet Console & Integrations (PRO backlog)

The single most important phase for turning Vigil into a business. Without a hosted console there is no recurring-revenue surface and no SMB / MSP path.

### Hosted fleet console

- [ ] Multi-tenant SaaS backend with agent enrollment via install token.
- [ ] Live endpoint status grid, alerts feed, and cross-fleet search.
- [ ] Remote trigger: isolate / clear-isolation / kill process / block IP across selected endpoints.
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

## Phase 20 — MSP Multi-tenant & White-label (PRO backlog)

Unlocks the highest-conversion channel for a solo-run security product: managed service providers selling Vigil to their SMB clients. Depends on Phase 19.

- [ ] **Tenant hierarchy** — MSP → customer → site → endpoint, with inherited policy and override rules.
- [ ] **White-label branding** — per-tenant logo, product name, custom domain, branded alert emails.
- [ ] **Bulk deployment tooling** — MSI / deb / rpm / AppImage with embedded enrollment token, deployment guides for Intune, Kaseya, NinjaOne, ConnectWise Automate.
- [ ] **MSP dashboard** — cross-customer alert feed, filterable by tenant, with per-tenant usage and billing exports.
- [ ] **Tiered / volume pricing** — per-seat discount curves and monthly invoicing for channel partners.

---

## Phase 21 — Managed Threat Intel Feed (PRO backlog)

Turns PRO from a one-time install into a subscription with a clear renewal trigger.

- [ ] **Hosted feed service** — hourly-refreshed managed IP / domain / hash blocklist consumed by PRO agents via authenticated pull.
- [ ] **Curated LoLBAS, C2 port, and process-rule updates** — versioned, signed rule packs delivered to agents.
- [ ] **Sigma rule import pipeline** — ingest and translate community Sigma rules into Vigil scoring signals.
- [ ] **Optional reputation lookup API** — per-request IP / domain / hash reputation endpoint for the fleet console and automation.
- [ ] **Transparency and provenance** — every feed entry includes source, first-seen, and confidence so operators can audit blocks.

---

## Phase 22 — Compliance Reporting Pack (PRO backlog)

Pairs naturally with the tamper-evident logging already in the OPEN tier.

- [ ] **Pre-built report templates** — network activity evidence, audit controls, logging, and incident-response evidence.
- [ ] **Scheduled exports** — automated PDF / CSV delivery by email or to S3-compatible storage on operator-defined cadences.
- [ ] **Retention policy controls** — configurable 90-day / 1-year / 7-year log retention per tenant.
- [ ] **Exportable hash manifest** — tie reports to the tamper-evident chain so auditors can verify integrity.
- [ ] **Evidence bundle export** — one-click packaging of alerts, PCAPs, memory dumps, and audit log for a given incident window.

---

## Phase 23 — Identity & User Context (PRO backlog)

Modern detections hinge on who, not just what. Adds identity attribution so alerts can differentiate privileged accounts from standard users.

- [ ] **Local-user attribution** — attach the local OS user and session id to every connection record.
- [ ] **Directory linkage** — resolve local users to directory identities via per-tenant connector.
- [ ] **Privileged-account differentiation** — raise alerts on privileged users and service accounts more aggressively than standard users.
- [ ] **Lateral-movement signal** — detect "this endpoint authenticated to N new internal hosts in a short window" as a first-class scoring input.
- [ ] **Identity surface in UI and reports** — show user context in inspector, alerts, and compliance reports.

---

## Phase 24 — Playbook Builder & SaaS-session Visibility (PRO backlog)

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
| 8.x | 18 | Windows/Linux detection and response parity | 🔲 Backlog |
| PRO 1.x | 19 | Cloud fleet console & integrations | 🔲 Backlog |
| PRO 1.x | 20 | MSP multi-tenant & white-label | 🔲 Backlog |
| PRO 1.x | 21 | Managed threat intel feed | 🔲 Backlog |
| PRO 1.x | 22 | Compliance reporting pack | 🔲 Backlog |
| PRO 1.x | 23 | Identity & user context | 🔲 Backlog |
| PRO 1.x | 24 | Playbook builder & SaaS-session visibility | 🔲 Backlog |
