# YARA Rule Management UI Contract

This document defines the first safe UI slice for Phase 20 YARA rule management.
It is intentionally narrow: the UI may surface trusted rule metadata that Vigil
already verifies and mirrors into protected local state, but it must not add new
rule-download, rule-editing, or auto-enable behavior until those flows have their
own integrity and rollback design.

## Current data boundary

Vigil already records two trusted YARA rule sources:

- Bundled community rules generated into the binary from the reviewed bundled
  pack manifest.
- Operator-local `.yar` and `.yara` files under the Vigil data directory's
  `yara-rules/` folder, verified by matching `.sha256` sidecars.

The local-rule intake command validates the files, records operator provenance,
parses rule metadata, and mirrors the catalog into the protected SQLite state
catalog. The UI should treat this catalog as read-only display data unless a
future task explicitly adds write support.

## Inspector surface

When a process or captured process-dump scan has matched YARA rules, the
inspector may show a `YARA matches` section with:

- Matched rule name.
- Source label, such as `bundled` or `operator-local`, when available.
- Category, tags, author, description, and reference, when present in trusted
  parsed metadata.
- Target kind, scan verdict, scan time, and match count, when those fields are
  available from persisted scan results.

If a YARA reason is present but metadata is not available, the inspector should
still show the rule name from the scored reason and clearly omit unknown fields.
It must not infer author, category, severity, malware family, or source trust
from the rule name alone.

## Rule catalog surface

A future Settings or dedicated YARA panel may list trusted rule files and parsed
rules from the protected catalog. The first read-only catalog view should show:

- File path relative to the trusted rule root.
- SHA-256 digest and sidecar/provenance status.
- Enabled state from the catalog, currently informational because runtime toggle
  support is not implemented.
- Parsed rule count.
- Per-rule name, namespace, category, author, description, reference, tags, and
  string count.

The UI should cap long lists, wrap long metadata values, and avoid loading raw
rule source text into the main frame. Full rule-source viewing should be a
separate explicit operator action if it is added later.

## Toggle behavior not yet implemented

The roadmap asks for category toggles, but the current safe slice is display
only. Category toggles require a separate implementation that defines:

- Where toggle policy is stored and how it is protected.
- Whether toggles affect bundled rules, operator-local rules, or both.
- How the scan worker reloads compiled rules without weakening fail-closed
  behavior.
- How operators can recover from a bad toggle state.
- How audit records capture rule-management changes.

Until that exists, the UI should not present interactive controls that appear to
enable or disable YARA categories.

## Failure handling

YARA UI surfaces should fail closed and stay explicit:

- Missing local rule directory: show that only bundled/runtime validation may be
  available.
- Missing protected state database: show that the catalog has not been mirrored
  yet and point operators to `vigil --yara-rule-status`.
- Catalog read error: keep the rest of the inspector usable and show the YARA
  metadata as unavailable for this refresh.
- Integrity or provenance failure: rely on the intake command's failed status;
  do not show untrusted rule metadata as if it were verified.

## Out of scope for this slice

The first UI slice does not include remote rule-pack downloads, rule editing,
rule deletion, category toggles, signed refresh, automatic rule updates, or live
memory acquisition. Those remain future Phase 20/23 work and need their own
security review before UI controls are exposed.
