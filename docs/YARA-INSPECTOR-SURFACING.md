# Phase 20 YARA Inspector Surfacing Contract

This document defines the smallest safe UI slice for Phase 20's YARA rule
management work: surface existing YARA scan matches in the Inspector without
adding rule toggles, new scan behavior, or automatic containment semantics.

The current runtime foundations already record two distinct YARA result paths:

- executable-path scans from `src/yara_scan.rs`, surfaced today as score reasons
  in the form `YARA rule: <rule_name>`
- process-dump scans from `src/forensics.rs`, persisted in `yara_scan_result`
  with `target_kind = "process_dump"`

The first Inspector slice should make those existing facts easier for operators
to see and reason about. It should not change what Vigil scans, which rules are
trusted, how scores are computed, or when response actions are allowed.

## Initial UI scope

The first Inspector implementation should do only the following:

- show matched executable-scan rules already attached to the selected process as
  `YARA rule: <rule_name>` reasons
- show process-dump YARA results only when the selected process has a matching,
  persisted `process_dump` scan result in protected local state
- keep executable-file matches and process-dump matches visually distinct
- show matched rule identifiers and ATT&CK-like tags when those tags came from
  reviewed rule metadata
- cap the number of displayed rows so an unusually broad match set cannot make
  the Inspector sluggish

This is match surfacing, not a full rule-management screen.

## Explicit non-goals for this slice

The first Inspector slice must not add:

- category enable/disable controls
- rule editing or local rule import controls
- signed rule-pack update controls
- new scan scheduling or retry behavior
- automatic kill, block, suspend, quarantine, or isolation decisions based only
  on a displayed YARA match
- a claim that a YARA match alone proves compromise

Those remain later Phase 20 or Phase 23 work.

## Provenance and trust boundaries

The UI should preserve the same trust boundaries used by the scan workers:

- bundled rule matches must not be presented as operator-local rules
- operator-local rule matches must not be presented as bundled-pack matches
- executable-file and process-dump targets must remain distinct
- scan errors or skipped targets must never be rendered as clean results
- missing scan data should be described as unavailable or not scanned, not as no
  match

If provenance metadata is incomplete for a row, the UI should omit the uncertain
field rather than guessing.

## Recommended Inspector layout

A minimal, reviewable layout is:

- `YARA matches` section near the existing `Advisories` and `Why it scored`
  sections
- compact chips for counts such as `2 executable matches` or `1 memory match`
- one row per displayed rule with the rule identifier as the primary text
- optional secondary text for source kind, target kind, scanned time, and
  ATT&CK-like tags when available

When there are no known matches, the section can stay quiet or show a muted
message such as `No YARA matches recorded for this process.` The wording should
avoid implying that the process was definitely scanned.

## Data-access rules

The UI should read only already-produced state:

- process-level score reasons already present in the selected `ProcessSelection`
- persisted `yara_scan_result` rows for process-dump artifacts, filtered by the
  selected process context when the stored payload supports that correlation

The UI should not compile rules, hash targets, read process memory, or open
arbitrary executable files. Those operations belong to the existing scan paths.

## Safety and failure handling

Inspector surfacing must remain fail-open:

- a database read failure should leave the Inspector usable and show a muted
  unavailable state for YARA details
- malformed persisted payloads should be skipped with logging rather than
  rendered as trusted facts
- row counts should be bounded before rendering
- display strings should be truncated through the same bounded-display helpers
  used elsewhere in the Inspector

## Suggested first code slice

The safest first code change is to extract `YARA rule: <rule_name>` entries from
`ProcessSelection.reason_summary`, deduplicate them, and render them in a small
`YARA matches` Inspector section. That uses data already flowing through the UI
and does not require a new database query, rule schema, or product decision.

A later slice can add persisted `process_dump` results once the selected-process
correlation key is explicit enough to avoid showing memory-scan evidence for the
wrong process.
