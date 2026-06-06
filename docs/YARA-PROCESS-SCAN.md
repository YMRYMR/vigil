# Phase 20 Process-On-Create YARA Scan Contract

This document defines the smallest safe runtime slice for Phase 20's first
executable-scan milestone: scanning a newly observed process executable with
YARA and feeding the result into Vigil's existing scoring pipeline.

That first slice is now implemented on `master` through `src/yara_scan.rs` and
the `process_conn()` hook in `src/monitor/mod.rs`. The rest of this document
records the contract that implementation follows and the boundaries that still
matter for later Phase 20 work.

It is intentionally narrower than full YARA integration. The goal is to make
one concrete implementation path safe and reviewable before memory scanning,
rule-category controls, or broader UI work land.

## Why this contract exists

The repository already has the foundations needed to trust YARA inputs:

- `src/yara_rules.rs` validates the embedded bundled pack against its generated
  manifest
- `src/yara_rules.rs` verifies operator-local `.yar` and `.yara` files with
  required `.sha256` sidecars and records provenance
- `src/monitor/mod.rs` already has a single enrichment and scoring path for new
  connection events
- `src/types.rs` and `src/ui/inspector.rs` already surface free-form score
  reasons without needing a new UI schema for the first match signal

Before the runtime code landed, what was still missing was a repo-native
contract for where scanning hooks in, what rule sources are trusted enough to
execute, how duplicated connection activity avoids repeated rescans, and which
failures must stay fail-open.

This document now serves as that contract and review boundary for the shipped
executable-scan slice.

## Current code path the first slice uses

The first runtime YARA execution slice attaches to the existing
`process_conn()` path in `src/monitor/mod.rs`.

That path already:

- collects process metadata through `process::collect()`
- builds a single `ScoreInput`
- appends explainable reasons and ATT&CK tags
- emits a `ConnInfo` that the Activity tab, Alerts tab, and Inspector already
  understand

Because Vigil currently observes process activity through connection events, the
initial "process on creation" implementation is interpreted narrowly as:

- scan once when Vigil first sees a previously unseen PID with a readable
  executable path during `process_conn()`
- deliver late-arriving matches as follow-up events rather than blocking the
  hot path

This keeps the first slice aligned with the current architecture instead of
pretending Vigil already has a separate process-creation event pipeline.

## Initial runtime scope

The first shipped runtime YARA slice does only the following:

- scan the on-disk executable file for a newly observed PID
- use the existing bundled rules plus verified operator-local rules
- add match reasons to the normal connection score flow
- avoid changing response-rule semantics, containment behavior, or startup
  requirements

The first shipped runtime YARA slice does not do the following:

- scan process memory
- scan arbitrary files outside the executable tied to the live process
- add category toggles or rule-management controls in the GUI
- claim that every matched rule maps cleanly to an ATT&CK technique
- block, suspend, quarantine, or isolate solely because a YARA scan subsystem
  had an internal failure

## Trusted rule inputs

The initial scan engine executes only trusted rule text:

- bundled rules that pass the existing manifest and hash validation path
- operator-local rules that already passed the existing sidecar and provenance
  intake path

Unverified local rule files must not be compiled or executed.

If operator-local intake reports failures, Vigil should keep those failures
visible through the existing status surfaces and continue with the trusted rule
set that is still valid, rather than silently widening trust.

Bundled and operator-local provenance must remain distinct in any future scan
result reporting so a local custom-rule match never appears to come from the
reviewed bundled pack.

## Match shaping and score behavior

The first slice stays conservative and explainable:

- each matched rule surfaces as a reason string in the existing format
  `YARA rule: <rule_name>`
- rule metadata such as `author`, `description`, `reference`, and `category`
  remain available for later Inspector and UI work, but the first slice does
  not need new UI controls to ship
- score impact stays bounded per event instead of stacking without limit for
  every additional matching rule
- ATT&CK tags are attached only when Vigil can justify them from explicit,
  rule-authored metadata or a separately reviewed mapping source

This preserves explainability and avoids turning a broad rule pack into an
unbounded score amplifier.

## Runtime safety requirements

The initial process-scan implementation preserves Vigil's existing startup and
monitoring safety guarantees.

Required safety rules:

- fail open when scanning cannot run; monitoring and scoring continue without a
  synthetic "clean" result
- treat unreadable, missing, or non-file executable paths as unscannable, not as
  implicit negative matches
- avoid rescanning the same running PID on every new connection event
- keep the scan path off the startup-critical bootstrap flow
- keep Windows and Linux behavior aligned at the contract level, even if the
  underlying file-access details differ by platform

In practice, the implementation caches scan decisions for executable identities
in `src/yara_scan.rs`, avoids repeat work in the live monitor path, and emits a
follow-up event only after the background scan finishes.

## Logging and operator visibility

The first slice keeps visibility simple:

- successful matches appear through existing `reasons` on `ConnInfo`
- subsystem failures or skipped scans should be logged clearly enough for
  maintainers to diagnose them
- the existing `vigil --yara-rule-status` command remains the operator-facing
  source of truth for rule intake health

The first runtime slice does not need a new dedicated status command as long as
scan failures remain visible in logs and do not change core response behavior.

## Explicit non-goals for this slice

The following remain later Phase 20 work and should not be folded into the first
process-scan implementation:

- memory-region scanning
- Inspector category toggles and richer rule-management UI
- signed community-rule refresh and remote pack updates
- automated action policy that triggers directly from raw YARA subsystem health

## Current follow-up boundary

The executable-scan wiring described here now lives in `src/yara_scan.rs` and
`src/monitor/mod.rs::process_conn()`. The dump-backed memory scanning milestone
has also landed and is tracked separately in `docs/YARA-MEMORY-SCAN-CONTRACT.md`.

The next unfinished Phase 20 roadmap item is **YARA rule management UI**. The
safest first UI slice should start from existing trusted data that Vigil already
records: matched rule names in score reasons and parsed rule metadata mirrored by
`vigil --yara-rule-status`. Category toggles, richer provenance browsing, and
policy-affecting controls should remain separate follow-up changes until the UI
contract is explicit enough to review safely.
