# Vigil Production Endpoint Protection Plan

This document turns Vigil's endpoint-protection goal into an implementation and release-readiness contract.

The target is a local Windows/Linux endpoint protection system that is transparent to the operator, safe by default, secure against tampering, reliable across upgrades and crashes, and honest about what it can and cannot protect.

## Product principles

1. **Transparent protection** — every alert, score change, block, quarantine, update, and policy decision must expose the evidence and rule path that caused it.
2. **Safe by default** — fresh installs observe before they disrupt. Destructive or connectivity-breaking actions require explicit policy, clear UI state, and reversible recovery.
3. **Fail open for availability** — Vigil must never repeatedly prevent login, networking, package updates, remote administration, or safe uninstall because one Vigil component failed.
4. **Fail closed for trust inputs** — signed update manifests, bundled rule manifests, protected policy, and Vigil-owned evidence must be rejected on missing, stale, mismatched, or unverifiable integrity metadata.
5. **Least privilege by mode** — user-mode observation must remain useful. Privileged service, firewall, process, forensic, and memory features must be isolated and auditable.
6. **No hidden judgement** — reputation, advisory, YARA, firewall, heuristic, and response-rule decisions must be inspectable locally without requiring a cloud account.
7. **Measured reliability** — production claims require repeatable test evidence, not just implemented features.

## Production readiness levels

### Level 0 — Development build

A build may be useful for local development, but it is not user-trustworthy yet.

Required evidence:

- Compiles on the supported targets touched by the change.
- Unit tests for changed pure logic where practical.
- No knowingly stale or misleading user-facing claims.

### Level 1 — Alpha operator build

A build may be used by technical operators on non-critical machines.

Required evidence:

- CI passes on Windows and Linux.
- Install, launch, observe, quit, and uninstall smoke tests are documented for both supported OS families.
- Disruptive controls are disabled by default or guarded by explicit confirmation.
- Logs and audit trail explain every protection action.
- Known gaps are visible in the user guide and release notes.

### Level 2 — Beta protection build

A build may be recommended for controlled daily-driver testing by informed users.

Required evidence:

- Health/status surface shows whether real-time monitoring, polling fallback, advisory cache, YARA rules, response rules, firewall backend, service mode, and update trust are working.
- Upgrade and rollback tests pass across at least the previous two release lines.
- Crash/restart tests prove break-glass recovery, firewall reconciliation, and policy integrity behavior.
- False-positive review pass against a benign software corpus.
- Malware/suspicious-behavior lab pass against documented offline samples and synthetic attacks.
- Rule and advisory update paths are signed, atomic, rollback-safe, and auditable.

### Level 3 — Production endpoint protection

A build may be marketed as endpoint protection for non-expert users.

Required evidence:

- Reproducible release checklist for Windows installer, Linux package/AppImage, signed manifests, attestations, and uninstall verification.
- Real-time file/process/network coverage matrix for Windows and Linux, including privilege requirements and fallback behavior.
- Independent or adversarial validation report for detection coverage and containment safety.
- Long-running stability soak tests on Windows and Linux.
- Clear privacy statement and local-data inventory.
- Emergency recovery path documented and tested without requiring the GUI.
- User-facing status never says protected unless the required protection subsystems are actually healthy.

## Core workstreams

### 1. Protection health and transparency

Goal: a user can answer "am I protected right now?" without reading logs.

Required deliverables:

- `vigil status --json` for scripting and support.
- GUI security posture dashboard.
- Tray health state with explicit degraded reasons.
- Per-subsystem status for monitoring backend, polling fallback, firewall backend, YARA rules, advisory cache, response rules, update trust, service mode, audit log, and break-glass state.
- Status must distinguish **healthy**, **degraded**, **disabled by policy**, **needs elevation**, **failed open**, and **unknown**.

### 2. Safe response and containment

Goal: containment prevents damage without creating a new outage.

Required deliverables:

- Dry-run/simulation mode for response rules.
- Reversible action ledger with operator-visible owner, reason, scope, TTL, and rollback command.
- Connectivity safety checks before isolation and long-lived firewall changes.
- Firewall panic and break-glass tests in CI-friendly virtualized environments where possible.
- Default policies that observe first and require explicit escalation.

### 3. Detection coverage

Goal: cover the common endpoint threat paths honestly and explainably.

Required deliverables:

- Process and connection behavior scoring coverage matrix.
- YARA executable scanning hardened and surfaced in UI.
- Memory-region scanning with bounded dumps and fail-open safety.
- Jitter-aware beaconing detection.
- File integrity monitoring for critical paths.
- Advisory matching limited to explainable, high-confidence local product matches.
- Every detection reason maps to local evidence and, where appropriate, ATT&CK tags.

### 4. Trust, tamper resistance, and updates

Goal: operators can trust what Vigil is running and what data it consumes.

Required deliverables:

- Signed threat-data update channel with atomic apply and rollback.
- Transparency log for update manifests and rule-pack provenance.
- Protected local policy and evidence integrity checks.
- Tamper events surfaced in status, logs, and UI.
- Release artifacts signed or attested, with documented verification commands.

### 5. Reliability and platform parity

Goal: Windows and Linux behavior is predictable, tested, and honest.

Required deliverables:

- Windows/Linux feature matrix in the user guide.
- VM smoke-test harness for install, service mode, monitoring, response, update, uninstall, and recovery.
- Startup fail-open tests.
- Upgrade/rollback tests.
- Long-run soak tests for UI mode and service mode.
- Performance budgets for CPU, memory, event latency, scan queue backpressure, and disk writes.

### 6. User trust and non-expert safety

Goal: non-expert users can use Vigil without accidentally breaking their machine or misunderstanding alerts.

Required deliverables:

- Plain-language alert explanations.
- Guided first-run observe mode.
- Safe defaults for auto response and allowlist-only mode.
- Warnings before actions that can break networking or kill important processes.
- Help text that names uncertainty instead of overstating confidence.
- Privacy and local-data documentation.

## Near-term implementation order

1. Implement `vigil status --json` and the internal subsystem health model.
2. Build the GUI security posture dashboard on top of the same health model.
3. Add response-rule dry-run mode and action ledger export.
4. Surface YARA executable scan results in the Inspector before expanding memory scanning.
5. Add signed threat-data update polling for rule packs and blocklists.
6. Add VM smoke tests for install, service, firewall panic, recovery, and uninstall.
7. Complete jitter-aware beaconing and file integrity monitoring only after status/recovery surfaces are reliable.

## Release claim policy

Until Level 3 evidence exists, public language should avoid broad claims such as "keeps any machine protected" or "antivirus replacement".

Preferred current wording:

> Vigil is an alpha-stage Windows/Linux endpoint monitoring and response tool with transparent scoring, local-first advisory context, active-response foundations, and YARA foundations.

Preferred future wording after Level 3 evidence:

> Vigil is a local-first Windows/Linux endpoint protection system with transparent detection, signed threat intelligence, safe active response, and auditable recovery.
