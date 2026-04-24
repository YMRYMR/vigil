# Phase 12 — Detection Depth Release Notes

This branch extends Vigil's detection depth while keeping operator output explainable.

Validation on the current tree is complete:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets --all-features`
- `cargo build --release`

## Included in Phase 12

- Behavioural baseline tracking for mature process novelty
- Script-host inspection for PowerShell, cmd, WSH, mshta, regsvr32, rundll32, certutil, msiexec, installutil, and msbuild patterns
- Signed-but-malicious corroboration scoring
- Expanded LoLBAS / proxy-execution coverage
- Parent / token anomaly heuristics with ATT&CK-style tags
- TLS ClientHello enrichment:
  - ClientHello parser
  - SNI extraction
  - JA3 tuple generation
  - pcapng-sidecar extraction from alert captures
  - audit records for extraction success/failure
  - near-live cache reuse for later matching connections
- Visibility / tamper blind-spot heuristics:
  - ETW fast-path downgrade while elevated
  - unresolved live-networking PID after retry
  - service/system ancestry with unreadable executable path
  - core-system metadata gaps

## Operator-facing changes

- Activity / Alerts cards surface SCR, BASE, and TLS indicators
- Inspector shows ATT&CK tags, heuristic reasons, TLS SNI, and TLS JA3 when available
- Help tab documents behavioural baselines, TLS enrichment, and tamper-visibility heuristics

## Validation checklist

Before merging Phase 12, run:

1. `cargo fmt --all --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all`
4. Manual workstation test:
   - normal browser traffic stays low-noise
   - PowerShell encoded command produces clear reasons/tags
   - TLS sidecar extraction works on a captured TLS alert
   - later matching connection reuses cached TLS metadata
   - ETW-off / polling-only fallback still emits connections
5. False-positive review on:
   - browser / chat clients
   - software updaters
   - Microsoft-signed service traffic
   - pre-login service traffic

## Known limits

- TLS metadata is currently derived from alert captures plus near-live cache reuse, not from universal inline packet parsing on every connection.
- Tamper visibility is heuristic and operator-facing; it does not claim a signed kernel driver or guaranteed anti-tamper coverage.
