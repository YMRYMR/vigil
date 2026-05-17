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
- `require_advisory_mitigation_guidance: true`
- `require_advisory_vendor_mitigation_guidance: true`
- `require_advisory_public_internet_exposure: true`
- `require_missing_advisory_fix_version: true`
- `advisory_id_contains: "CVE-2026-12345"`
- `advisory_product_contains: "chrome"`
- `min_advisory_severity: high`

Supported `min_advisory_severity` values are `low`, `medium`, `high`, and `critical`.

`require_advisory_mitigation_guidance` is intentionally narrow. Today it matches only when the same high-confidence advisory reason includes `mitigation guidance available`, which Vigil emits only when the matched advisory record already carries non-empty mitigation, remediation, workaround, or guidance text/URLs in the protected advisory cache, or a clearly guidance- or remediation-tagged reference URL such as `Mitigation`, `Patch`, `Update`, `Upgrade`, `Workaround`, or `Guidance`. Vigil now also ignores bare fixed-version tokens like `124.0.6367.99`, so version-only fields do not get mistaken for operator guidance.

`require_advisory_vendor_mitigation_guidance` is intentionally narrower. Today it matches only when the same high-confidence advisory reason also includes `vendor guidance available`, which Vigil emits only when the matched advisory record already has a non-empty guidance- or remediation-tagged reference URL and that same reference is also tagged as vendor-authored material such as `Vendor Advisory`, `Vendor Mitigation`, `Vendor Fix`, `Vendor Patch`, `Vendor Update`, `Vendor Upgrade`, or `Vendor Guidance`. It does not infer authorship from arbitrary domains, free-form mitigation text, or untagged links.

`require_advisory_public_internet_exposure` is intentionally narrow. Today it matches only when the same connection event is a `LISTEN` socket bound to an obviously globally routable local IP address. It does not infer exposure through NAT, wildcard binds, reverse proxies, or reachability beyond what Vigil can observe locally.

`require_missing_advisory_fix_version` is intentionally narrow. Today it matches only when the same high-confidence advisory reason includes `no fixed-version bound`, which Vigil emits only when the matched affected-product range has a lower version boundary but no upper version boundary. It does not guess from unconstrained rows or exact-version-only rows.

## Example

```yaml
rules:
  - name: exploited browser advisory with vendor guidance but no fix bound
    require_advisory_match: true
    require_known_exploited_advisory: true
    require_advisory_mitigation_guidance: true
    require_advisory_vendor_mitigation_guidance: true
    require_missing_advisory_fix_version: true
    advisory_product_contains: chrome
    min_advisory_severity: critical
    action: block_process
    duration: 24h
```

This example only matches when Vigil already found one high-confidence applicable advisory reason for a Chrome-family product, marked it as known exploited, preserved that mitigation guidance is available in the protected advisory cache, confirmed that the matching remediation link is explicitly vendor-tagged, rated it at least critical, and could not find an upper fixed-version bound on the matched advisory range.

## Current scope limits

This is still an intentionally narrow slice of mitigation-aware response rules.

Today the rule engine can match only these advisory attributes:

- advisory ID text
- affected product text
- known exploited flag
- normalized severity floor
- mitigation guidance availability in the protected advisory cache
- explicitly vendor-tagged mitigation guidance references in the protected advisory cache
- obvious public-internet exposure for a current listening socket bound to a globally routable local IP
- missing fixed-version bound on the matched advisory range

The broader roadmap item still remains open for richer guidance attribution beyond explicit vendor-plus-remediation tags and broader exposure inference beyond an obviously globally routable listener.

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
