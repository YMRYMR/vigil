# Local storage migration plan (non-backward-compatible)

This document defines the big-push migration from protected JSON cache files to a
single local SQLite-backed state store while preserving Vigil's integrity model.

## Goals

- Faster indexed lookups and joins for advisory matching and software inventory.
- Keep integrity/tamper evidence and rollback-safe recovery semantics.
- Accept a non-backward-compatible cutover (young project, no user migration burden).

## Scope

1. Replace advisory JSON cache persistence in `src/advisory.rs` with DB-backed persistence.
2. Replace advisory change-history JSON cache persistence in `src/advisory_history.rs`.
3. Add DB-backed software inventory persistence and indexed product lookup.
4. Keep security checks by signing/verifying DB checkpoint manifests.

## Proposed storage layout

- Database file: `data_dir()/vigil-state.db`
- Manifest file: `data_dir()/vigil-state.manifest.json` + integrity sidecar/backup
- Secret handling: reuse `security::policy` secret file and sidecar model

### Core tables

- `meta(schema_version, generated_unix, last_integrity_ok_unix, ...)`
- `advisory_source(source_key, source_kind, source_url, fetched_unix, expires_unix, status, last_error, ... )`
- `advisory_record(primary_id, source_key, source_kind, published_unix, updated_unix, severity, exploited, payload_json, ... )`
- `advisory_change_event(change_id, cve_id, source_key, change_unix, event_name, details_json, ... )`
- `software_inventory(product_key, display_name, executable_path, publisher_hint, source, updated_unix)`

### Required indexes

- advisory: `(primary_id)`, `(source_kind, source_key)`, `(updated_unix)`
- change history: `(cve_id, change_unix)`, `(source_key)`
- software inventory: `(product_key)`, `(executable_path)`

## Integrity strategy

1. Quiesce writes and checkpoint DB.
2. Compute deterministic digest over checkpoint artifacts.
3. Save signed manifest via `security::policy::save_struct_with_integrity`.
4. On startup, verify manifest/digest before using DB.
5. If verification fails, restore last known-good DB artifact set and record audit event.

## Performance guardrails

- Use batched inserts/upserts in transactions.
- Keep all DB I/O off the UI/render thread.
- Bound query results for inspector/activity UI surfaces.
- Prefer incremental updates over full table rewrites for periodic sync.

## Rollout plan

### PR 1
- Add storage abstraction and schema bootstrap.
- Keep reads/writes dual-pathed (JSON + DB mirror) for internal validation only.

### PR 2
- Switch advisory and change-history reads to DB.
- Keep JSON writes disabled by default.

### PR 3
- Migrate software inventory to DB + indexes.
- Add query helpers for advisory relevance joins.

### PR 4
- Remove legacy JSON cache code paths.
- Keep only DB + signed manifest integrity checks.

## Definition of done

- No advisory or inventory hot-path reads from legacy JSON cache files.
- Startup fails closed to last trusted DB artifacts on integrity mismatch.
- UI remains responsive under burst updates and large advisory sets.
