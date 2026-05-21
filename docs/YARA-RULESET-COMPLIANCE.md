# Bundled YARA Ruleset Contract

This document defines the minimum source-selection, attribution,
redistribution, update, and operator-visibility rules for future community YARA
packs bundled with Vigil.

The goal is to make Phase 20's first backlog item concrete without guessing at
unsafe product or licensing choices:

- bundle only rules whose license and redistribution terms clearly allow local
  shipping inside Vigil releases or signed Vigil update packs
- preserve enough upstream provenance that operators can tell where every rule
  came from, which version is installed, and when it changed
- keep rule updates offline-verifiable and rollback-safe using Vigil's signed
  manifest model
- avoid silently importing opaque, vendor-restricted, or legally ambiguous rule
  text into an open-source endpoint product
- preserve operator control over which bundled categories are enabled once the
  runtime scanning engine exists

## Source-selection gate

A community ruleset may be considered for bundling only when all of the
following are true:

- the upstream project is publicly accessible without private credentials,
  partner access, or click-through export gates
- the exact license or published terms clearly permit redistribution in Vigil's
  releases or signed update packs
- the upstream project exposes stable versioning such as tagged releases,
  dated snapshots, commit-pinned exports, or another auditable update point
- each shipped rule file can be tied back to an upstream source URL, release,
  tag, or commit
- the ruleset can be mirrored into Vigil's local pack format without adding a
  live network dependency at startup
- Vigil maintainers can review the pack for obviously unsafe content such as
  destructive external-module requirements, undocumented generators, or opaque
  post-processing that would make later audits difficult

If any of those conditions are unclear, Vigil must not bundle the ruleset yet.
A manual operator-import path is safer than shipping material with uncertain
redistribution rights.

## What Vigil must preserve

For every bundled rule file or generated pack, preserve at least:

- upstream project name
- upstream source URL
- upstream version, tag, snapshot date, or pinned commit
- the applicable license identifier or terms reference
- the SHA-256 digest of the shipped rule file or packed artifact
- the time Vigil imported or generated the local pack
- any pack-level category or family label that Vigil surfaces to operators

That provenance must travel with both compile-time embedded packs and future
signed update artifacts.

## Redistribution rules

Vigil should treat community YARA text conservatively:

- do not bundle a ruleset unless the reviewed license or terms clearly allow
  redistribution in an open-source product
- do not remove upstream copyright, license, or attribution notices that the
  upstream project requires downstream redistributors to preserve
- do not imply that an upstream ruleset author endorses Vigil
- do not mix rule text from sources with incompatible or unclear redistribution
  terms into a single shipped pack unless the pack format preserves per-source
  attribution and compliance data
- do not ship closed, registration-gated, evaluation-only, or non-redistributable
  packs through Vigil's default update channel

## Signed update rules

Phase 23 is the intended delivery channel for refreshed bundled rule packs.
When that lands, YARA updates must follow these rules:

- every downloadable pack is listed in a signed manifest with a version,
  SHA-256 digest, and pack identity
- Vigil verifies the manifest signature before trusting any updated rules
- Vigil verifies the pack digest before replacing the local installed pack
- Vigil keeps the previous trusted pack until the replacement pack is fully
  verified
- a failed verification leaves the last known-good pack active and records an
  audit event rather than silently dropping protection
- update metadata should let operators see which pack version is active, when it
  was installed, and whether the source is stale or unavailable

## Build and runtime safety rules

Before a bundled ruleset is shipped or updated, Vigil should validate that:

- the pack can be enumerated and attributed without network access
- rule file sizes and total pack size stay within explicit resource limits
- any category metadata exposed to operators is deterministic and derived from
  reviewed pack contents rather than untrusted runtime text alone
- unsupported or risky YARA modules are either rejected at pack-build time or
  surfaced clearly as unavailable on platforms where they cannot run safely
- a ruleset parse or compile failure does not block Vigil startup; the scanner
  must fail open and fall back to the last trusted pack or to no bundled pack
  with an operator-visible warning

## Operator visibility expectations

Once bundled packs exist, Vigil should expose at least:

- active bundled pack name and version
- upstream source and license information
- install time and verification status
- enabled and disabled rule categories when category toggles land
- clear separation between Vigil-bundled rules and operator-imported local rules

Bundled rules and operator-imported rules must keep separate provenance so a
local custom-rule edit never appears to be a vendor pack update, and a bundled
pack refresh never overwrites operator-managed files.

## Safest next implementation step

This contract makes the next unfinished Phase 20 item more concrete. The next
safe code slice is to add a pack manifest format and build-time importer for one
explicitly approved upstream community ruleset, while preserving the provenance,
redistribution, and signed-update rules above.
