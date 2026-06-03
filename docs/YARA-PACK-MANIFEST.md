# YARA Pack Manifest Format

This document defines the first concrete manifest format for Vigil's future
bundled community YARA packs.

It is intentionally narrower than full Phase 20 implementation. The manifest
exists so future build-time importers, compile-time embedding, and signed-update
artifacts all preserve the same minimum provenance and integrity data.

## Design goals

The manifest format must let Vigil:

- attribute every shipped rule file to a reviewed upstream source
- validate pack contents offline before trusting or exposing them to operators
- keep file paths deterministic and safe for archive extraction or embedding
- surface pack version, license, and source metadata without relying on network
  access
- stay compatible with Phase 23's signed release-manifest model without
  replacing it

## Schema version 1

A pack manifest is UTF-8 JSON with these top-level fields:

- `schema_version` — integer schema identifier. Version `1` is defined here.
- `pack_name` — stable Vigil pack identifier such as `community-core`.
- `pack_version` — pack version chosen by Vigil for this imported snapshot.
- `generated_at` — UTC timestamp showing when Vigil generated the local pack.
- `upstream_name` — reviewed upstream project name.
- `upstream_source_url` — canonical upstream project or export URL.
- `upstream_reference` — upstream tag, release, snapshot date, or pinned commit.
- `license` — reviewed license identifier or clear license reference.
- `files` — array of per-file records included in the pack.

Each `files[]` entry contains:

- `relative_path` — slash-separated path inside the bundled pack.
- `sha256` — lowercase SHA-256 of the shipped rule file bytes.
- `rule_count` — number of YARA rules represented in that file.
- `source_url` — upstream file or export URL for this exact file.
- `source_reference` — upstream tag, release, snapshot date, or pinned commit
  specific to this file.
- `category` — optional operator-visible category or family label.

## Validation rules

Schema version 1 expects the following checks before a pack is trusted:

- every required string field is present and non-empty after trimming
- `schema_version` must equal `1`
- `files` must not be empty
- each `relative_path` must stay relative and normalized: no absolute paths, no
  drive prefixes, no `.` segments, and no `..` traversal
- each `relative_path` must be unique within the manifest
- each `sha256` must be exactly 64 hexadecimal characters
- each `rule_count` must be greater than zero
- `category` may be omitted, but if present it must not be empty

These rules are deliberately conservative because the manifest will eventually
sit on the trust boundary between reviewed upstream rule text and operator
systems.

Validate a candidate manifest offline with:

```bash
vigil --validate-yara-pack-manifest PATH/TO/manifest.json
```

That CLI validates the manifest schema and provenance metadata only. It does not
fetch upstream files, rebuild a pack, or execute YARA scans.

## Relationship to the signed update manifest

This pack manifest does not replace Vigil's signed release manifest.

The Phase 23 signed update manifest answers: "which pack artifact should Vigil
trust and download?"

This YARA pack manifest answers: "what is inside that trusted pack artifact, and
where did each file come from?"

A future signed YARA update should therefore include both:

- the outer signed update manifest naming the pack artifact and its SHA-256
- the inner YARA pack manifest bundled with the pack so Vigil can enumerate and
  explain the pack contents offline

## Example

See `docs/YARA-PACK-MANIFEST.example.json` for a concrete schema-version-1
example.

## Current foundation status

The schema and validator are no longer just a paper design:

- `vigil --validate-yara-pack-manifest` now validates schema-version-1 manifest
  metadata offline
- `build.rs` generates a bundled-pack manifest at compile time from reviewed
  pack metadata under `third_party/yara/inquest-community-core/`
- `vigil --yara-rule-status` validates the embedded bundled-pack manifest and
  bundled file hashes before reporting operator-visible status
- `src/yara_scan.rs` uses the trusted bundled and verified operator-local rules
  for bounded executable scans
- `src/forensics.rs` uses the same trusted rule boundary for bounded
  process-dump YARA scans after opt-in high-confidence dump capture

## Safest next implementation step

The next safe Phase 20 slice is operator-visible surfacing for YARA scan
results. Status and Inspector views should show executable and `process_dump`
results clearly separately, before Vigil adds category toggles, broader live
memory acquisition, or signed remote rule-pack refresh.