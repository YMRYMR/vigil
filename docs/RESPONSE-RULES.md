# Vigil Response Rules

Vigil can load an optional operator-managed YAML file of response rules. Rules are checked in order, and the first match wins.

The rule file lives outside the binary and stays under operator control. A matching `<rules-file>.sha256` sidecar is required; Vigil verifies that digest before it accepts the file.

## Existing match fields

These predicates continue to work as before:

- `min_score`
- `process_name_contains`
- `remote_contains`
- `require_unsigned`
- `require_pre_login`
- `require_reputation_hit`
- `require_dga`
- `require_recently_dropped`
- `require_long_lived`

## Advisory-aware predicates

This Phase 16 slice adds conservative advisory-aware predicates that operate on Vigil's existing high-confidence advisory match reason text. They only match when Vigil already attached a high-confidence applicable advisory reason to the connection event.

Supported advisory predicates:

- `require_advisory_match: true`
- `require_known_exploited_advisory: true`
- `advisory_id_contains: "CVE-2026-12345"`
- `advisory_product_contains: "chrome"`
- `min_advisory_severity: high`

Supported `min_advisory_severity` values are `low`, `medium`, `high`, and `critical`.

## Example

```yaml
rules:
  - name: exploited browser advisory
    require_advisory_match: true
    require_known_exploited_advisory: true
    advisory_product_contains: chrome
    min_advisory_severity: critical
    action: block_process
    duration: 24h
```

This example only matches when Vigil already found a high-confidence applicable advisory for a Chrome-family product, marked it as known exploited, and rated it at least critical.

## Current scope limits

This is an intentionally narrow first slice of mitigation-aware response rules.

Today the rule engine can match only these advisory attributes:

- advisory ID text
- affected product text
- known exploited flag
- normalized severity floor

The broader roadmap item still remains open for attributes such as vendor guidance, fixed-version absence, and exposure on the public internet.

## Actions

Rule actions reuse the same active-response primitives as the rest of Vigil:

- `kill_connection`
- `block_remote`
- `block_process`
- `quarantine`

`duration` currently accepts the same values as the existing rule engine:

- `1h` (default)
- `24h`
- `permanent`
