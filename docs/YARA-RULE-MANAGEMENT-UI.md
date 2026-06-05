# Phase 20 YARA Rule Management UI Contract

This document defines the smallest safe UI slice for the remaining Phase 20
roadmap item: showing YARA rule context in the Inspector and, later, letting
operators manage rule categories.

The scanner, local rule intake, bundled pack validation, and process-dump scan
paths already exist. This contract keeps the UI work narrow and auditable so a
future implementation does not accidentally widen trust in rule text, hide
integrity failures, or imply security guarantees that the scanner did not
verify.

## Current trusted data sources

The Inspector may display YARA information only when it comes from one of these
existing protected paths:

- runtime match reasons already attached to a `ConnInfo` as `YARA rule: <name>`
- persisted scan results written by `src/yara_scan.rs` for executable scans
- persisted process-dump scan results written by `src/forensics.rs`
- the mirrored local rule catalog populated by `vigil --yara-rule-status`
- bundled-pack metadata generated at build time and validated by
  `vigil --yara-rule-status`

The UI must not parse arbitrary `.yar` files directly, compile rules, trust a
rule directory listing, or infer that an unverified local rule is active. Rule
text remains untrusted until the existing sidecar and provenance intake accepts
it.

## First Inspector slice

The first code slice should be display-only:

- group existing `YARA rule: <name>` score reasons into a dedicated Inspector
  section named `YARA matches`
- deduplicate rule names per selected process group
- cap the number of visible rule names to protect UI responsiveness
- leave the original score reasons visible in `Why it scored` for backwards
  compatibility and auditability
- show a clear empty state when no YARA match reason is present

This advances the roadmap item without adding rule toggles, changing response
rules, or changing scan behavior.

## Rule metadata display

After the first slice, the Inspector may enrich matched rule names with metadata
from the protected rule catalog:

- source kind: bundled pack or operator-local
- category, when present
- author, description, reference, and tags, when present
- file or pack provenance summary
- enabled state, once category toggles exist

Metadata must stay best-effort. Missing metadata should never suppress a real
match reason, and missing catalog rows should be shown as `metadata unavailable`
rather than being treated as a clean or inactive result.

## Category toggles

Category controls are a later slice. They should follow these rules:

- categories are disabled or enabled by operator choice, not by remote source
  text alone
- default state preserves current scanning behavior for already trusted rules
- changes are stored in protected local state with the same integrity guarantees
  used for other operator-managed policy
- toggles affect future scans only unless the implementation explicitly and
  safely re-evaluates cached results
- every change is recorded in the audit trail with category name, source kind,
  previous state, and new state

A category toggle must not silently disable operator-local rules outside the
chosen category, and it must not mark a failed or unverified rule file as safe.

## Safety and failure handling

YARA UI failure must fail open for monitoring:

- Inspector rendering errors must not stop connection monitoring or active
  response controls
- catalog load failures should show a degraded metadata state, not block the
  process summary
- stale scan results should be labelled as cached when timestamps are available
- scan subsystem failures should not create synthetic `clean` results
- UI copy must avoid claiming that no YARA detection exists unless a trusted scan
  result explicitly supports that statement

## Explicit non-goals for this UI contract

The following remain outside this roadmap slice:

- editing rule text in the GUI
- importing unverified rules from the GUI
- remote rule-pack download or signed auto-update delivery
- automatic containment based only on YARA subsystem health
- live memory acquisition beyond already captured, operator-visible artifacts

## Recommended implementation order

1. Add the display-only Inspector `YARA matches` section from existing score
   reasons.
2. Add protected catalog lookup for matched rule metadata.
3. Add read-only rule source and category summaries.
4. Add protected category toggle state and audit events.
5. Wire category toggle state into future scan compilation or scan selection.

This order keeps each step reviewable and preserves Vigil's existing fail-open
runtime behavior while making YARA findings easier for operators to understand.
