# Phase 19 Persistent Rule Store Foundation

The next unfinished Phase 19 roadmap item is the persistent firewall rule store.
The current `vigil-active-response.json` state is enough to reapply temporary
blocks, but it is not yet a first-class rule database with stable record
identity, explicit rule metadata, or a migration contract.

This document defines the minimum schema and safety constraints for the first
implementation slice so later Phase 19 work can extend the store without
breaking recovery, auditability, or operator trust.

---

## Goals

- Give every operator-managed firewall rule a stable record ID.
- Preserve creation time and TTL in a machine-readable form.
- Distinguish transient response rules from future permanent rules.
- Record enough metadata to explain what layer a rule lives on and how it
  should be restored.
- Keep the startup path fail-open: a bad rule-store record must never strand the
  endpoint or block login.

---

## Rule record schema

Each persisted firewall rule record should include at least the following
fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Stable globally unique identifier for the logical Vigil rule record. Do not reuse after deletion. |
| `owner` | string | yes | Human-visible owner label. Use `Vigil` for built-in rules. |
| `kind` | string | yes | Logical category such as `remote_ip_block`, `process_block`, `domain_block`, `isolation`, or a future template/permanent rule kind. |
| `created_at_unix` | integer | yes | First creation time in Unix seconds. This must survive restart and reconciliation. |
| `expires_at_unix` | integer or null | yes | Absolute expiry time for transient rules. `null` means no automatic expiry. |
| `ttl_secs` | integer or null | yes | Original TTL requested at creation time. Preserve even when `expires_at_unix` is later recomputed or a clock shifts. |
| `direction` | string | yes | `inbound`, `outbound`, or `both`. |
| `action` | string | yes | `block` or `allow`. Default scope today is blocking only. |
| `layer` | string | yes | Backend-neutral layer label such as `wfp_ale_connect_v4`, `nft_output`, `xdp_ingress`, or `hosts_file`. |
| `profile_affinity` | array of strings | yes | Explicit OS firewall profile affinity. Use an empty array only when the backend genuinely has no profile concept. |
| `subject` | object | yes | Backend-neutral target payload. Examples: remote IP, executable path, PID hint, domain name, isolation marker. |
| `backend_handles` | array of strings | yes | Concrete backend rule names, filter GUIDs, nft comments, or other delete/reconcile handles. |
| `source` | string | yes | Why the rule exists, such as `manual`, `response_rule`, `quarantine_profile`, or `panic_recovery`. |
| `notes` | string or null | no | Optional operator-facing context. |
|

`backend_handles` must be treated as replaceable implementation details.
`id` is the durable identity; backend handles can change during reconciliation
without changing the logical rule record.

---

## Storage model

The initial implementation can remain inside the protected
`vigil-active-response.json` file if that keeps the change smaller and safer.
A dedicated file is acceptable later, but the first slice should not fork state
across multiple protected stores unless reconciliation clearly requires it.

The protected rule-store section should be append/update friendly and should not
require deleting unrelated state when one record changes.

Recommended top-level shape:

```json
{
  "rule_store": {
    "schema_version": 1,
    "records": [
      {
        "id": "rule_...",
        "owner": "Vigil",
        "kind": "remote_ip_block",
        "created_at_unix": 1716200000,
        "expires_at_unix": 1716203600,
        "ttl_secs": 3600,
        "direction": "outbound",
        "action": "block",
        "layer": "wfp_ale_connect_v4",
        "profile_affinity": ["domain", "private", "public"],
        "subject": { "remote_ip": "203.0.113.10" },
        "backend_handles": ["Vigil Block 203.0.113.10"],
        "source": "manual",
        "notes": null
      }
    ]
  }
}
```

---

## Migration rules

Legacy active-response state must migrate conservatively.

- Missing `id` values must be generated once and then preserved.
- Missing `created_at_unix` values should default to the earliest trustworthy
  timestamp available for that rule. If no trustworthy timestamp exists,
  record the migration time and mark the record as migrated legacy state.
- Existing expiry times must not be widened during migration.
- Migration must be best-effort and reversible: if a record cannot be upgraded,
  Vigil should keep the legacy entry readable and continue using the old
  reconciliation path rather than dropping the rule silently.
- Rule deletion must continue to follow the existing safety rule: only remove a
  persisted record after the live backend delete succeeds.

---

## Safety constraints

Because this is a firewall-control feature, the implementation must preserve
these invariants:

- Loading a corrupt or partially migrated rule store must fail open and fall
  back to the last-known-good protected state.
- Reconciliation must remain add-first when restoring protection after boot.
- A stale record must never cause Vigil to delete unrelated OS firewall rules.
- The store must preserve enough metadata for operator-visible exports and UI.
- Clock drift must not convert a permanent rule into an expiring rule or vice
  versa.
- Future permanent rules must be distinguishable from transient response rules
  without inferring intent from `expires_at_unix == null` alone.

---

## Recommended first implementation slice

The safest first code slice for this item is:

1. Add a protected `rule_store.schema_version` section alongside the current
   active-response state.
2. Populate it for new remote-IP and process-block rules first.
3. Surface the stored IDs, timestamps, TTLs, and backend handles in
   `vigil --firewall export` and the Firewall UI.
4. Keep existing reconciliation behavior intact until the new store has test
   coverage for create, expire, reconcile, and delete paths.

That sequence improves auditability and future compatibility without forcing a
large, risky rewrite of the already-working Phase 19 response paths.
