#!/bin/bash
# Vigil Firewall CLI Smoke Test (no root required)
# Tests that CLI commands run and produce expected output format.
# Does NOT test actual firewall rule creation (needs root for that).
# See tests/firewall_integration_test.sh for full root-required tests.

set -euo pipefail

BINARY="${VIGIL_BINARY:-target/debug/vigil}"
PASS=0
FAIL=0

assert_ok() {
    local label="$1" cmd="$2"
    if output=$(eval "$cmd" 2>&1); then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label — exit code $?"
        echo "  Output: ${output:0:150}"
        FAIL=$((FAIL + 1))
    fi
}

echo "========================================="
echo " Vigil Firewall CLI Smoke Test (no root)"
echo "========================================="

if [ ! -x "$BINARY" ]; then
    echo "Building vigil..."
    cargo build --bin vigil
    BINARY="target/debug/vigil"
fi

assert_ok "--firewall status"               '"$BINARY" --firewall status 2>&1'
assert_ok "--firewall list"                 '"$BINARY" --firewall list 2>&1'
assert_ok "--firewall export"               '"$BINARY" --firewall export 2>&1'
assert_ok "--firewall help"                 '"$BINARY" --firewall help 2>&1'

# Verify export is valid JSON
if output=$("$BINARY" --firewall export 2>&1); then
    if echo "$output" | python3 -m json.tool > /dev/null 2>&1; then
        echo "  PASS: export is valid JSON"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: export is not valid JSON"
        FAIL=$((FAIL + 1))
    fi
fi

echo ""
echo " Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
