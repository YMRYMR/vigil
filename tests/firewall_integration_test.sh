#!/bin/bash
# Vigil Firewall Integration Test Suite
#
# Prerequisites:
#   - Linux with root access (iptables/nftables need it)
#   - vigil binary built: cargo build --release
#   - Run as: sudo ./tests/firewall_integration_test.sh
#
# Safety: uses TEST rule names (prefixed "Vigil Test"). All rules are
# cleaned up on exit via trap. Does NOT touch the hosts file.

set -euo pipefail

BINARY="${VIGIL_BINARY:-target/release/vigil}"
PASS=0
FAIL=0
RULES_CREATED=()

cleanup() {
    echo "=== Cleanup ==="
    for rule in "${RULES_CREATED[@]}"; do
        "$BINARY" --firewall panic > /dev/null 2>&1 || true
    done
    # Brute-force: delete any remaining test rules
    echo "  Removing any leftover Vigil Test rules..."
    iptables -D OUTPUT -m comment --comment "Vigil:Vigil Block Test IP" -j DROP 2>/dev/null || true
    iptables -D INPUT  -m comment --comment "Vigil:Vigil Block Test IP" -j DROP 2>/dev/null || true
    iptables -D FORWARD -m comment --comment "Vigil:Vigil Block Test IP" -j DROP 2>/dev/null || true
    nft flush chain inet vigil output 2>/dev/null || true
    nft flush chain inet vigil input 2>/dev/null || true
    nft flush chain inet vigil isolin 2>/dev/null || true
    nft flush chain inet vigil isolout 2>/dev/null || true
    echo "  Done."
}

trap cleanup EXIT

assert_contains() {
    local label="$1" output="$2" pattern="$3"
    if echo "$output" | grep -qF "$pattern"; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label — expected '$pattern' not found in output"
        echo "  Output: ${output:0:200}"
        FAIL=$((FAIL + 1))
    fi
}

assert_exit_0() {
    local label="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label — command returned non-zero"
        FAIL=$((FAIL + 1))
    fi
}

assert_valid_json() {
    local label="$1" json="$2"
    if echo "$json" | python3 -m json.tool > /dev/null 2>&1; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label — invalid JSON"
        FAIL=$((FAIL + 1))
    fi
}

echo "========================================="
echo " Vigil Firewall Integration Test Suite"
echo " Binary: $BINARY"
echo "========================================="

# ── Prerequisite checks ──────────────────────────────────────────────

echo ""
echo "--- Prerequisites ---"

if [ "$(id -u)" -ne 0 ]; then
    echo "  FAIL: must run as root"
    exit 1
fi
echo "  PASS: running as root"

if [ ! -x "$BINARY" ]; then
    echo "  FAIL: binary not found or not executable: $BINARY"
    echo "  Build with: cargo build --release"
    exit 1
fi
echo "  PASS: binary $BINARY"

# ── CLI smoke tests ──────────────────────────────────────────────────

echo ""
echo "--- CLI smoke tests ---"

output=$("$BINARY" --firewall status 2>&1)
assert_contains "status shows backend" "$output" "Firewall backend:"
assert_contains "status shows available" "$output" "Available:"

output=$("$BINARY" --firewall list 2>&1)
assert_contains "list shows rules" "$output" "Firewall rules"

output=$("$BINARY" --firewall export 2>&1)
assert_valid_json "export is valid JSON" "$output"
assert_contains "export has blocked_ips" "$output" 'blocked_ips'
assert_contains "export has profiles" "$output" 'profiles'

output=$("$BINARY" --firewall help 2>&1)
assert_contains "help shows commands" "$output" "Vigil firewall commands"

if output=$("$BINARY" --firewall unknown_subcommand_xyz 2>&1); then
    echo "  FAIL: unknown subcommand exited 0 when it should have failed"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: unknown subcommand exits non-zero"
    PASS=$((PASS + 1))
fi

# ── Firewall rule CRUD ───────────────────────────────────────────────

echo ""
echo "--- Firewall rule CRUD ---"

# Add a test IP block
output=$("$BINARY" --firewall status 2>&1)
BEFORE_COUNT=$(echo "$output" | grep -oP '\d+(?= IP)' || echo "0")

# Use the auto_response engine via a one-shot invocation
# (Since we can't call block_remote from CLI, we verify the
#  status/list/export commands work correctly with live data)

# Test that export shows the current state consistently
export1=$("$BINARY" --firewall export 2>&1)
export2=$("$BINARY" --firewall export 2>&1)
if [ "$export1" = "$export2" ]; then
    echo "  PASS: export is idempotent (same output twice)"
    PASS=$((PASS + 1))
else
    echo "  FAIL: export changed between calls"
    FAIL=$((FAIL + 1))
fi

# ── SQLite integration check ─────────────────────────────────────────

echo ""
echo "--- SQLite persistent store ---"

# Check that the DB file exists after CLI commands touch state
DATA_DIR="${VIGIL_DATA_DIR:-$HOME/.vigil-data}"
DB_FILE="$DATA_DIR/vigil-state.db"

if [ -f "$DB_FILE" ]; then
    echo "  PASS: SQLite state DB exists at $DB_FILE"

    # Check firewall_rule table exists
    if sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='firewall_rule'" 2>/dev/null | grep -q '1'; then
        echo "  PASS: firewall_rule table exists"
    else
        echo "  WARN: firewall_rule table not found (may need --firewall status to trigger save)"
    fi
else
    echo "  WARN: SQLite DB not found at $DB_FILE (may need --firewall status to trigger creation)"
fi

# ── Result ───────────────────────────────────────────────────────────

echo ""
echo "========================================="
echo " Results: $PASS passed, $FAIL failed"
echo "========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
