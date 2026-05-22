# Phase 20 Memory-Region YARA Scan Contract

This document defines the smallest safe next slice for Phase 20's next unchecked item: memory-region scanning.

The repository already ships trusted YARA rule intake and bounded background executable scans. The next step should extend that work without pretending Vigil already has a safe, cross-platform live-memory acquisition engine.

## Why this contract exists

`ROADMAP.md` still lists **Memory region scan** as the next unfinished Phase 20 item.

That item is broad enough to hide multiple risky product decisions:

- whether Vigil reads live process memory directly or scans a captured dump
- which platforms get the first implementation
- how much memory can be read before the feature becomes disruptive
- how scan failures are surfaced without creating false negatives or unsafe containment behavior

This contract narrows that roadmap item into one reviewable implementation path.

## Current foundations the repo already has

Vigil already has these building blocks on `master`:

- trusted bundled and operator-local YARA rule intake in `src/yara_rules.rs`
- bounded background executable scans in `src/yara_scan.rs`
- process-dump artifact capture on high-confidence alerts in `src/forensics.rs`
- protected provenance manifests for captured artifacts
- existing score reasons and ATT&CK-tag surfaces in the monitor and Inspector paths

Those pieces make a dump-backed first memory-scan slice safer than jumping straight to unrestricted live-memory reads.

## Narrow initial scope

The first memory-region scanning slice should do only the following:

- scan a **selected process dump artifact** with the same trusted YARA rules Vigil already executes for executable scans
- treat the dump file as the memory-scanning target instead of opening arbitrary live process memory directly
- preserve fail-open behavior when dump capture or YARA scanning cannot run
- keep result surfacing explainable and bounded

The first memory-region scanning slice should not do the following:

- read arbitrary live process memory on Windows or Linux
- scan every running process opportunistically
- require kernel drivers, `ptrace`, or always-on elevated memory access
- auto-contain a process solely because the memory-scan subsystem failed internally
- claim Windows/Linux parity for memory acquisition before both paths actually exist

## Safest acquisition model for the first slice

For the first implementation, the scan target should be a process dump file that Vigil already captured intentionally.

Why this is the safest first step:

- the artifact is bounded and auditable on disk
- provenance manifests already exist for captured dumps
- scanning a file fits the existing `yara_x` file-scan flow
- the monitor path stays off the critical path because scanning can remain asynchronous
- the repo avoids inventing live-memory privilege semantics in the same change

This means the first slice is better described as:

> YARA scanning of selected process-memory dump artifacts.

That still advances the roadmap item honestly because the bytes being scanned come from process memory, but the implementation path remains reviewable.

## Trusted inputs and trust boundaries

The memory-scan slice must preserve the same trust boundaries already used for executable scans:

- bundled rules must still pass the embedded manifest validation path
- operator-local rules must still pass `.sha256` sidecar verification
- unverified local rules must never be compiled or executed
- dump artifacts should be treated as untrusted scan targets, not as trusted evidence by default

If dump capture fails, scanning must not fabricate a clean result.

## Result shaping and operator visibility

The first slice should surface results conservatively:

- matched rules should appear using the same `YARA rule: <rule_name>` reason format already used for executable scans
- result metadata should clearly distinguish `executable_path` scans from `process_dump` or equivalent memory-dump scans
- a memory-derived match should be inspectable as evidence, not merged silently into unrelated score reasons
- scan failures should be logged clearly enough for maintainers to diagnose them without implying that the target was clean

## Runtime safety requirements

The first memory-scan slice must preserve Vigil's safety rules:

- fail open when dump capture or YARA scanning cannot run
- do not block the main monitor path on dump scanning
- keep the amount of scanned data bounded by the dump artifact that was intentionally captured
- keep the feature opt-in or tied to already opt-in forensic capture behavior for the first slice
- preserve platform honesty: Windows dump-backed scanning may land before Linux memory acquisition does, and the docs/UI must say so plainly

## Explicit non-goals for the first slice

The following remain later work after the first memory-dump scanning milestone:

- live-memory reads from arbitrary PIDs
- Linux direct `/proc/<pid>/mem` or `ptrace` acquisition
- Windows live-region enumeration through new memory-reading APIs
- rule-category toggles or deep per-rule UI management
- automatic quarantine decisions based solely on dump-scan subsystem state

## Safest next code change

The safest next code change after this contract is:

1. add a dump-target result kind alongside the existing executable-scan persistence model
2. scan a captured dump artifact with the existing runtime YARA ruleset
3. persist and surface those matches distinctly from executable-path results
4. keep all failures fail-open and auditable

That gives Phase 20 a concrete memory-scanning milestone without bundling cross-platform live-memory acquisition, new privilege rules, and new UI semantics into one risky change.
