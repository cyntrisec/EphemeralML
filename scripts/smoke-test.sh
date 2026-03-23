#!/usr/bin/env bash
# Trust Center Smoke Test
#
# Usage:
#   bash scripts/smoke-test.sh                                          # Test live Cloud Run
#   bash scripts/smoke-test.sh https://trust-center-324130315768.us-central1.run.app
#   bash scripts/smoke-test.sh http://localhost:8080                     # Test local
#
# Exit code 0 = all checks passed, 1 = one or more failed.

set -euo pipefail

BASE_URL="${1:-https://trust-center-324130315768.us-central1.run.app}"
PASSED=0
FAILED=0

# ── Helpers ──────────────────────────────────────────────

pass() { PASSED=$((PASSED + 1)); echo "  [PASS] $1"; }
fail() { FAILED=$((FAILED + 1)); echo "  [FAIL] $1"; }

check_status() {
    local name="$1" url="$2" expected="$3"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
    if [ "$status" = "$expected" ]; then
        pass "$name (HTTP $status)"
    else
        fail "$name — expected $expected, got $status"
    fi
}

check_json_field() {
    local name="$1" url="$2" field="$3" expected="$4"
    local value
    value=$(curl -s --max-time 10 "$url" 2>/dev/null | jq -r "$field" 2>/dev/null || echo "ERROR")
    if [ "$value" = "$expected" ]; then
        pass "$name ($field = $expected)"
    else
        fail "$name — expected $field=$expected, got $value"
    fi
}

# ── Tests ────────────────────────────────────────────────

echo
echo "  Cyntrisec Trust Center Smoke Test"
echo "  Target: $BASE_URL"
echo "  ──────────────────────────────────────"
echo

# 1. Landing page
check_status "Landing page" "$BASE_URL/" "200"

# 2. Health endpoint
check_json_field "Health" "$BASE_URL/health" ".status" "ok"

# 3. AIR v1 sample endpoint
check_json_field "AIR v1 sample format" "$BASE_URL/api/v1/samples/valid" ".format" "air_v1"

# 4. Legacy sample endpoint
check_json_field "Legacy sample format" "$BASE_URL/api/v1/samples/legacy" ".format" "legacy"

# 5. AIR v1 round-trip verification
echo -n "  "
SAMPLE=$(curl -s --max-time 10 "$BASE_URL/api/v1/samples/valid" 2>/dev/null)
B64=$(echo "$SAMPLE" | jq -r '.receipt_base64' 2>/dev/null)
KEY=$(echo "$SAMPLE" | jq -r '.public_key' 2>/dev/null)

if [ -z "$B64" ] || [ "$B64" = "null" ] || [ -z "$KEY" ] || [ "$KEY" = "null" ]; then
    fail "AIR v1 verify — could not fetch sample"
else
    RESULT=$(curl -s --max-time 10 -X POST "$BASE_URL/api/v1/verify" \
        -H "Content-Type: application/json" \
        -d "{\"receipt\": \"$B64\", \"public_key\": \"$KEY\"}" 2>/dev/null)
    VERIFIED=$(echo "$RESULT" | jq -r '.verified' 2>/dev/null)
    FORMAT=$(echo "$RESULT" | jq -r '.format' 2>/dev/null)
    if [ "$VERIFIED" = "true" ] && [ "$FORMAT" = "air_v1" ]; then
        pass "AIR v1 verify — verified=true, format=air_v1"
    else
        fail "AIR v1 verify — verified=$VERIFIED, format=$FORMAT"
    fi
fi

# 6. Tamper detection
echo -n "  "
if [ -z "$B64" ] || [ "$B64" = "null" ]; then
    fail "Tamper detection — no sample to tamper"
else
    MID=$((${#B64} / 2))
    TAMPERED="${B64:0:$MID}TAMPERED${B64:$((MID+8))}"
    RESULT=$(curl -s --max-time 10 -X POST "$BASE_URL/api/v1/verify" \
        -H "Content-Type: application/json" \
        -d "{\"receipt\": \"$TAMPERED\", \"public_key\": \"$KEY\"}" 2>/dev/null)
    VERIFIED=$(echo "$RESULT" | jq -r '.verified' 2>/dev/null)
    if [ "$VERIFIED" = "false" ]; then
        pass "Tamper detection — verified=false"
    else
        fail "Tamper detection — expected false, got $VERIFIED"
    fi
fi

# 7. Legacy round-trip verification
echo -n "  "
LEG_SAMPLE=$(curl -s --max-time 10 "$BASE_URL/api/v1/samples/legacy" 2>/dev/null)
LEG_RECEIPT=$(echo "$LEG_SAMPLE" | jq -c '.receipt' 2>/dev/null)
LEG_KEY=$(echo "$LEG_SAMPLE" | jq -r '.public_key' 2>/dev/null)

if [ -z "$LEG_RECEIPT" ] || [ "$LEG_RECEIPT" = "null" ]; then
    fail "Legacy verify — could not fetch sample"
else
    RESULT=$(curl -s --max-time 10 -X POST "$BASE_URL/api/v1/verify" \
        -H "Content-Type: application/json" \
        -d "{\"receipt\": $LEG_RECEIPT, \"public_key\": \"$LEG_KEY\"}" 2>/dev/null)
    VERIFIED=$(echo "$RESULT" | jq -r '.verified' 2>/dev/null)
    FORMAT=$(echo "$RESULT" | jq -r '.format' 2>/dev/null)
    if [ "$VERIFIED" = "true" ] && [ "$FORMAT" = "legacy" ]; then
        pass "Legacy verify — verified=true, format=legacy"
    else
        fail "Legacy verify — verified=$VERIFIED, format=$FORMAT"
    fi
fi

# ── Summary ──────────────────────────────────────────────

echo
echo "  ──────────────────────────────────────"
TOTAL=$((PASSED + FAILED))
if [ "$FAILED" -eq 0 ]; then
    echo "  ALL $TOTAL CHECKS PASSED"
else
    echo "  $PASSED/$TOTAL passed, $FAILED FAILED"
fi
echo

exit "$FAILED"
