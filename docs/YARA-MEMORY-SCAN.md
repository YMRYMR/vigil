# Phase 20 Memory-Region YARA Scan Contract

This document defines the smallest safe implementation slice for Phase 20's
next unchecked roadmap item: scanning process memory with YARA without widening
Vigil's trust boundary or adding ambiguous response behavior.

It exists to keep the next implementation pass concrete. The repository already
has a reviewed executable-scan path in `src/yara_scan.rs` plus audited process
memory dump capture in `src/forensics.rs`, but it does not yet have a repo-wide
contract for how memory-derived bytes should enter the YARA pipeline.

## Why this contract exists

Memory scanning is materially riskier than on-disk executable scanning:

- process memory can contain secrets, credentials, and unrelated user data
- dump files can be large enough to stall hot paths if scanning is not bounded
- some platforms expose process memory only through privileged or platform-
  specific capture paths
- a failed memory scan must never silently imply a clean result

Without a written contract, it would be too easy to ship an implementation that
blurs those boundaries.

## Smallest safe runtime slice

The next implementation slice should stay intentionally narrow:

- scan only operator-visible process-memory artifacts that Vigil created itself,
  such as reviewed dump targets captured for a high-confidence alert
- reuse only the existing trusted rule sources: bundled reviewed rules plus
  operator-local rules that already passed `.sha256` verification
- keep scanning off the startup-critical and connection-hot paths
- record the result as a distinct target kind from executable-path scans so
  later UI work can preserve provenance and scope

This means the first memory-scan slice is best treated as dump-backed memory
inspection, not arbitrary live memory reads across the whole process table.

## Trust boundary

The memory-scan slice must preserve the same trust contract already used by the
executable-scan worker:

- bundled rule files must still pass the generated manifest and hash checks
- operator-local `.yar` and `.yara` files must still require matching
  `.sha256` sidecars before they are compiled
- unverified local rule text must never be executed just because a dump file is
  available
- memory-derived scan results must remain distinguishable from executable-file
  scan results in any future persistence or UI surface

## Result handling

The first memory-scan slice should stay conservative and auditable:

- successful matches should be recorded with the dump artifact path, scan time,
  matched rule identifiers, and ruleset digest
- failures and skips should be logged clearly enough for maintainers and
  operators to understand why a dump was not scanned
- a memory-scan subsystem failure must not suppress the original alert and must
  not manufacture a synthetic clean verdict
- memory-scan matches may inform later triage or scoring work, but the first
  slice should avoid inventing new auto-response semantics on its own

## Safety limits

To keep the feature reviewable and avoid turning forensic capture into a denial-
-of-service path, the first implementation should include explicit bounds:

- bounded file size for dump-backed scans
- bounded scan timeout
- asynchronous execution so alert delivery is not blocked waiting for YARA
- fail-open behavior when dump capture or scan execution is unavailable

Those caps can be tuned later, but they need to exist from the first shipped
memory-scan slice.

## Non-goals for the first memory slice

The following remain later Phase 20 work and should not be smuggled into the
first memory-scan implementation:

- direct arbitrary live-memory reads from unrelated processes
- new automatic containment actions triggered solely by memory-scan subsystem
  health or failure
- Inspector rule-management controls and category toggles
- signed remote rule-pack refresh or community pack auto-update logic
- broad claims that every memory match is exploit proof rather than a triage
  signal

## Safest next code change

The safest next code change after this contract is:

- hook dump-backed memory scans into the existing trusted YARA pipeline
- persist those results under a distinct memory-scan target kind
- keep the work asynchronous, bounded, and fail-open
- surface the outcome first through audit/provenance paths before adding richer
  UI affordances

That path advances the next roadmap item without inventing product direction or
weakening Vigil's security posture.
