# Phase 20 Selected-Memory YARA Scan Contract

This document records the smallest safe implementation slice for Phase 20's
memory-region scanning roadmap item: scanning selected, operator-visible process
memory dump artifacts with the same trusted YARA ruleset used by the executable
scan path.

The implementation lives in `src/forensics.rs`. It is intentionally narrower
than broad live-memory inspection. Vigil only scans process dump files that were
already captured by the opt-in forensic artifact path, then persists and audits
the YARA verdict without blocking monitoring, startup, or active response.

## Current runtime path

When `process_dump_on_alert` is enabled and an alert crosses
`process_dump_min_score`, `maybe_capture_process_dump()` may capture a process
memory dump. Today that capture path is Windows-only because it uses the Windows
MiniDump flow through `rundll32.exe` and `comsvcs.dll`.

After a dump is captured successfully, Vigil starts a bounded background worker
through `enqueue_process_dump_yara_scan()`. The worker:

- validates that the dump path is a regular file
- rejects dumps larger than `MAX_PROCESS_DUMP_SCAN_BYTES` before scanning
- compiles only bundled rules and verified operator-local YARA rules
- scans the dump file with mmap disabled and a scanner timeout
- records at most `MAX_MEMORY_MATCHED_RULES_RECORDED` matched rules
- persists the result as `target_kind = "process_dump"` in `yara_scan_result`
- records an audit event for clean, matched, skipped, or error outcomes

This keeps selected-memory scanning tied to artifacts the operator can inspect
and keeps broad live process-memory traversal out of scope.

## Trusted rule inputs

Memory dump scanning uses the same trust boundary as executable scanning:

- bundled rules must match the generated bundled-pack manifest and hashes
- local `.yar` / `.yara` files must pass the verified rule intake path
- unverified local rule files are not compiled or executed

If no trusted rules are available, the worker records a skipped audit event and
returns without manufacturing a clean verdict.

## Result handling

Memory dump scan results are evidence-oriented. They do not directly change the
already-emitted connection score, trigger containment, or claim compromise on
their own.

Persisted result payloads include:

- PID, process name, process path, and source alert score
- dump path and optional provenance manifest path
- dump size and filesystem timestamps
- target SHA-256 digest
- ruleset digest
- matched rule identifiers and ATT&CK-like tags when present

This allows later Inspector, report, or dashboard work to surface the evidence
without changing response policy semantics in this slice.

## Safety requirements

The selected-memory scan path preserves Vigil's fail-open contract:

- dump capture remains opt-in and rate-limited
- scanner work runs outside the monitor hot path
- unreadable, missing, oversized, or non-file dump targets are skipped with an
auditable reason
- rule compilation failures do not stop monitoring or active response
- scan failures are logged and audited, not converted into synthetic clean or
malicious verdicts
- Linux currently reports process dump capture as unsupported rather than
pretending to provide equivalent memory scanning

## Explicit non-goals

This slice does not implement:

- arbitrary live process-memory walking
- Linux process dump capture parity
- GUI rule-category controls
- automatic containment based only on memory-scan subsystem health
- signed community-rule refresh or remote rule-pack updates

Those remain separate roadmap work and need their own review boundaries before
shipping.
