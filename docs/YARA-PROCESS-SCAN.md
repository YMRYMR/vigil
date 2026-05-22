# Phase 20 Process-On-Create YARA Scan Contract

This document defines the smallest safe runtime slice for the next unfinished
Phase 20 roadmap item: scanning a newly observed process executable with YARA
and feeding the result into Vigil's existing scoring pipeline.

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

What is still missing is a repo-native contract for where runtime scanning hooks
in, what rule sources are trusted enough to execute, how duplicated connection
activity avoids repeated rescans, and which failures must stay fail-open.

## Current code path the first slice should use

The first runtime YARA execution slice should attach to the existing
`process_conn()` path in `src/monitor/mod.rs`.

That path already:

- collects process metadata through `process::collect()`
- builds a single `ScoreInput`
- appends explainable reasons and ATT&CK tags
- emits a `ConnInfo` that the Activity tab, Alerts tab, and Inspector already
  understand

Because Vigil currently observes process activity through connection events, the
initial "process on creation" implementation should be interpreted narrowly as:

- scan once when Vigil first sees a previously unseen PID with a readable
  executable path during `process_conn()`

This keeps the first slice aligned with the current architecture instead of
pretending Vigil already has a separate process-creation event pipeline.

## Initial runtime scope

The first shipped runtime YARA slice should do only the following:

- scan the on-disk executable file for a newly observed PID
- use the existing bundled rules plus verified operator-local rules
- add match reasons to the normal connection score flow
- avoid changing response-rule semantics, containment behavior, or startup
  requirements

The first shipped runtime YARA slice should not do the following:

- scan process memory
- scan arbitrary files outside the executable tied to the live process
- add category toggles or rule-management controls in the GUI
- claim that every matched rule maps cleanly to an ATT&CK technique
- block, suspend, quarantine, or isolate solely because a YARA scan subsystem
  had an internal failure

## Trusted rule inputs

The initial scan engine should execute only trusted rule text:

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

The first slice should stay conservative and explainable:

- each matched rule should surface as a reason string in the existing format
  `YARA rule: <rule_name>`
- rule metadata such as `author`, `description`, `reference`, and `category`
  should remain available for later Inspector and UI work, but the first slice
  does not need new UI controls to ship
- score impact should be bounded per event, not stacked without limit for every
  additional matching rule
- ATT&CK tags should be attached only when Vigil can justify them from explicit,
  rule-authored metadata or a separately reviewed mapping source

This preserves explainability and avoids turning a broad rule pack into an
unbounded score amplifier.

## Runtime safety requirements

The initial process-scan implementation must preserve Vigil's existing startup
and monitoring safety guarantees.

Required safety rules:

- fail open when scanning cannot run; monitoring and scoring continue without a
  synthetic "clean" result
- treat unreadable, missing, or non-file executable paths as unscannable, not as
  implicit negative matches
- avoid rescanning the same running PID on every new connection event
- keep the scan path off the startup-critical bootstrap flow
- keep Windows and Linux behavior aligned at the contract level, even if the
  underlying file-access details differ by platform

In practice, that means the first implementation should cache scan decisions for
already-seen processes in the live monitor path, then expire that cache when the
PID disappears or the executable identity changes.

## Logging and operator visibility

The first slice should keep visibility simple:

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

## Safest next code change after this document

The next code PR should wire a per-process executable scan into
`src/monitor/mod.rs::process_conn()` using the trusted rule inputs already
validated in `src/yara_rules.rs`, then add focused tests around:

- trusted bundled-rule matches
- verified local-rule matches
- unreadable or missing executable paths
- duplicate connection events for the same PID not causing repeat scans
- bounded score deltas and explainable reason strings
