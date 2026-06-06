# Phase 20 Memory-Region YARA Scan Contract

This document defines the first implemented memory-scanning slice for Phase 20:
scan process-memory dump artifacts with YARA without widening Vigil's trust
boundary or adding ambiguous response behavior.

The repository already has a reviewed executable-scan path in `src/yara_scan.rs`
plus audited process memory dump capture in `src/forensics.rs`. The initial
memory slice now hooks those pieces together by scanning dump artifacts that
Vigil captured for high-confidence alerts.

## Why this contract exists

Memory scanning is materially riskier than on-disk executable scanning:

- process memory can contain secrets, credentials, and unrelated user data
- dump files can be large enough to stall hot paths if scanning is not bounded
- some platforms expose process memory only through privileged or platform-
  specific capture paths
- a failed memory scan must never silently imply a clean result

This contract keeps memory-derived bytes on an explicit, auditable path.

## Implemented runtime slice

The first implemented slice stays intentionally narrow:

- scan only process-memory dump artifacts that Vigil created itself after an
  opt-in high-confidence alert dump capture
- reuse only the existing trusted rule sources: bundled reviewed rules plus
  operator-local rules that already passed `.sha256` verification
- run the scan in a background worker after dump capture so alert delivery and
  normal connection monitoring are not blocked by YARA
- record results under the distinct `process_dump` target kind in
  `yara_scan_result`, separate from executable-path scans
- emit audit records for `matched`, `clean`, `skipped`, and `error` outcomes

This is dump-backed memory inspection, not arbitrary live memory reads across
the whole process table.

## Trust boundary

The memory-scan slice preserves the same trust contract already used by the
executable-scan worker:

- bundled rule files must still pass the generated manifest and hash checks
- operator-local `.yar` and `.yara` files must still require matching
  `.sha256` sidecars before they are compiled
- unverified local rule text must never be executed just because a dump file is
  available
- memory-derived scan results remain distinguishable from executable-file scan
  results through the `process_dump` target kind and payload metadata

## Result handling

The first memory-scan slice is conservative and auditable:

- successful matches are recorded with the dump artifact path, scan time,
  target SHA-256, matched rule identifiers, ATT&CK-like tags when rule-authored,
  and ruleset digest
- failures and skips are logged and audited with the dump path, process context,
  manifest path when available, and error reason
- a memory-scan subsystem failure does not suppress the original alert and does
  not manufacture a synthetic clean verdict
- memory-scan matches are evidence for later triage work; this slice does not
  add new auto-response semantics

## Safety limits

The implemented slice includes explicit bounds:

- process dump scans are skipped above 256 MiB
- each YARA scan uses a 10-second timeout
- scan work runs on a named background thread after dump capture
- failures remain fail-open and auditable

Those caps can be tuned later, but they prevent forensic capture from becoming
an unbounded scan path.

## Non-goals for this memory slice

The following remain later Phase 20 work and should not be inferred from the
current implementation:

- direct arbitrary live-memory reads from unrelated processes
- Linux direct `/proc/<pid>/mem` or `ptrace` acquisition
- Windows live-region enumeration through new memory-reading APIs
- new automatic containment actions triggered solely by memory-scan subsystem
  health or failure
- Inspector rule-management controls and category toggles
- signed remote rule-pack refresh or community pack auto-update logic
- broad claims that every memory match is exploit proof rather than a triage
  signal

## Follow-up work

The next safe follow-up is operator-visible surfacing for YARA results in the
Inspector, still keeping executable and memory-derived results clearly
separated. The UI boundary for that work is documented in
`docs/YARA-INSPECTOR-SURFACING.md`.
