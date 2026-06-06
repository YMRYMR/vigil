# YARA Rule Management UI Contract

This document defines the first safe UI slice for Phase 20 YARA rule management.
It is intentionally narrow: the UI may surface trusted rule metadata that Vigil
already verifies and mirrors into protected local state, but it must not add new
rule-download, rule-editing, or auto-enable behavior until those flows have their
own integrity and rollback design.

## Roadmap decomposition

The Phase 20 roadmap item is intentionally broader than the first safe code
change. Treat the work as these ordered slices:

1. Read-only Inspector display of existing `YARA rule: <name>` score reasons.
2. Read-only trusted catalog display from the protected YARA rule catalog.
3. Category toggle policy, protected persistence, audited operator actions, and
   last-known-good scanner reload behavior.

Only the first slice is concrete enough to implement without new product or
security-policy decisions. The second slice depends on catalog read paths that
keep provenance and source identity explicit. The third slice must remain out of
scope until toggle storage, scanner reload, rollback, and audit behavior are
specified and tested.

## First-slice acceptance criteria

A read-only Inspector implementation of the first slice is complete only when it
meets all of these conditions:

- The Inspector derives the displayed YARA match list only from existing scored
  reasons that exactly use the `YARA rule: <name>` prefix.
- Duplicate rule names are collapsed for readability without changing the
  original score reasons or the selected connection detail.
- The display says no YARA matches are recorded when no matching reason exists;
  it does not say the process is clean, safe, or malware-free.
- The display labels the data as score-derived and metadata-limited until a
  provenance-qualified catalog lookup is available.
- The display does not infer source, author, category, severity, malware family,
  ATT&CK technique, or target kind from the rule name alone.
- The UI adds no rule toggles, enable/disable buttons, import actions, source
  viewers, downloads, or scanner reload controls.
- The existing `Why it scored` section continues to show the original score
  reasons so operator auditability is not reduced.

These criteria intentionally allow a useful first Inspector block without making
new trust claims about bundled or operator-local rule metadata.

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

The UI should reuse trusted scanner outputs. It must not compile rules, trust
unverified local files, or reinterpret scanner failures as clean results.

## Inspector surface

When a process or captured process-dump scan has matched YARA rules, the
inspector may show a `YARA matches` section with:

- Matched rule name.
- Source label, such as `bundled` or `operator-local`, when available.
- Category, tags, author, description, and reference, when present in trusted
  parsed metadata and when the persisted scan result carries enough rule identity
  to disambiguate the catalog entry, such as namespace/source-qualified
  provenance.
- Target kind, scan verdict, scan time, and match count, when those fields are
  available from persisted scan results.
- Rule-authored ATT&CK tags only when they come from trusted YARA scan payloads
  or parsed rule metadata with namespace/source-qualified provenance, not from
  the selected process group's flat `attack_tags` collection.

For the first slice, the only available source is the selected process group's
score reasons. In that mode, the Inspector should show the rule name and clearly
omit metadata that is not backed by provenance-qualified scan or catalog data.

If a YARA reason is present but metadata is not available, the inspector should
still show the rule name from the scored reason and clearly omit unknown fields.
It must not infer author, category, severity, malware family, source trust, or
ATT&CK tags from the rule name alone.

If no YARA matches are available for the selected process group, the inspector
may say no matches are recorded. It must not say the process is clean, safe, or
free of malware.

Executable-file matches and process-dump matches should remain visibly distinct
when the target kind is available. A memory-derived match is evidence for triage,
not proof that every live memory region was scanned.

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

When toggles do land, they should apply to future scans only after a trusted
ruleset rebuild or reload succeeds. A failed rebuild should keep the last
known-good scanner state active and report the failure instead of silently
disabling protection.

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
- Scanner unavailable: show that scanning could not run or compile trusted
  rules, without creating a synthetic clean result.
- Stale result: when a persisted result no longer matches the current executable
  identity or ruleset digest, do not present it as current without that caveat.

Any future action buttons or toggles should stay disabled while their backing
state is unavailable, stale, or ambiguous.

## Privacy and evidence boundaries

YARA UI work may surface sensitive process paths, rule references, and scan
results. It should follow existing Inspector conventions:

- Keep process paths bounded and wrapped.
- Do not expose memory dump contents in the UI.
- Do not turn private operator-local rule text into a public-looking bundled
  source.
- Keep scan target kind, target digest, and ruleset digest available for audit
  paths without overloading the main Inspector view.

## Out of scope for this slice

The first UI slice does not include remote rule-pack downloads, rule editing,
rule deletion, category toggles, signed refresh, automatic rule updates, or live
memory acquisition. Those remain future Phase 20/23 work and need their own
security review before UI controls are exposed.

## Safest next code change

The safest next code change is a read-only Inspector block that extracts
`YARA rule: <name>` entries from the selected process group's existing score
reasons and displays the rule names as YARA matches. It should not attach
ATT&CK tags or other rule metadata unless persisted YARA scan payloads provide
namespace/source-qualified provenance for the matched catalog entry.

That change should not add category toggles yet. Toggle controls should wait
until the scanner has protected enabled-category policy and a last-known-good
ruleset reload path.
