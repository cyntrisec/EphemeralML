#!/usr/bin/env bash
# Verification Center Smoke Test
#
# Usage:
#   bash scripts/smoke-test.sh                                          # Test live Cloud Run
#   bash scripts/smoke-test.sh https://verify.cyntrisec.com
#   bash scripts/smoke-test.sh http://localhost:8080                     # Test local
#
# Exit code 0 = all checks passed, 1 = one or more failed.

set -euo pipefail

BASE_URL="${1:-https://verify.cyntrisec.com}"
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
echo "  Cyntrisec Verification Center Smoke Test"
echo "  Target: $BASE_URL"
echo "  ──────────────────────────────────────"
echo

# 1. Landing page
check_status "Landing page" "$BASE_URL/" "200"
echo -n "  "
LANDING=$(curl -s --max-time 10 "$BASE_URL/" 2>/dev/null || echo "")
if [ -n "$LANDING" ] \
    && [[ "$LANDING" == *"retained for 30 days"* ]] \
    && [[ "$LANDING" == *"they do not contain request bodies"* ]] \
    && [[ "$LANDING" != *"discarded within minutes"* ]]; then
    pass "Privacy copy — metadata fields and 30-day retention disclosed"
else
    fail "Privacy copy — expected body exclusion and 30-day metadata retention disclosure"
fi
echo -n "  "
if [[ "$LANDING" != *"fonts.googleapis.com"* ]] \
    && [[ "$LANDING" != *'src="https://'* ]] \
    && [[ "$LANDING" == *"No app analytics, tracking scripts, or third-party page assets are used"* ]]; then
    pass "Privacy boundary — no automatically loaded third-party page assets"
else
    fail "Privacy boundary — unexpected third-party page asset or disclosure mismatch"
fi
echo -n "  "
HEADERS=$(curl -sS -D - -o /dev/null --max-time 10 "$BASE_URL/" 2>/dev/null || echo "")
if [[ "$HEADERS" == *"object-src 'none'"* ]] \
    && [[ "$HEADERS" == *"base-uri 'none'"* ]] \
    && [[ "$HEADERS" == *"form-action 'self'"* ]] \
    && [[ "$HEADERS" == *"font-src 'self'"* ]] \
    && [[ "$HEADERS" != *"fonts.googleapis.com"* ]]; then
    pass "Security headers — hardened CSP directives present"
else
    fail "Security headers — expected object-src/base-uri/form-action CSP directives"
fi

# 1b. AWS-native PoC evidence page (current 2026-05-03 packet, not stale 2026-04-30)
check_status "AWS evidence page" "$BASE_URL/evidence/aws-native-poc" "200"
echo -n "  "
EVIDENCE=$(curl -s --max-time 10 "$BASE_URL/evidence/aws-native-poc" 2>/dev/null || echo "")
if [ -n "$EVIDENCE" ] \
    && [[ "$EVIDENCE" == *"2026-05-03"* ]] \
    && [[ "$EVIDENCE" == *"aws-native-poc-20260503"* ]] \
    && [[ "$EVIDENCE" != *"aws-native-poc-20260430"* ]]; then
    pass "AWS evidence content — references 2026-05-03 packet, not stale 2026-04-30"
else
    fail "AWS evidence content — expected 2026-05-03 packet references, stale 2026-04-30 must be absent"
fi

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
AIR_RESULT="{}"

if [ -z "$B64" ] || [ "$B64" = "null" ] || [ -z "$KEY" ] || [ "$KEY" = "null" ]; then
    fail "AIR v1 verify — could not fetch sample"
else
    RESULT=$(curl -s --max-time 10 -X POST "$BASE_URL/api/v1/verify" \
        -H "Content-Type: application/json" \
        -d "{\"receipt\": \"$B64\", \"public_key\": \"$KEY\"}" 2>/dev/null)
    AIR_RESULT="$RESULT"
    VERIFIED=$(echo "$RESULT" | jq -r '.verified' 2>/dev/null)
    FORMAT=$(echo "$RESULT" | jq -r '.format' 2>/dev/null)
    if [ "$VERIFIED" = "true" ] && [ "$FORMAT" = "air_v1" ]; then
        pass "AIR v1 verify — verified=true, format=air_v1"
    else
        fail "AIR v1 verify — verified=$VERIFIED, format=$FORMAT"
    fi
fi

# 5b. AIR-local must not be presented as overall confidential-AI provenance.
echo -n "  "
ASSURANCE=$(echo "$AIR_RESULT" | jq -r '.assurance_level' 2>/dev/null)
TEE_PROVENANCE=$(echo "$AIR_RESULT" | jq -r '.tee_provenance_verified' 2>/dev/null)
OVERALL_CONFIDENTIAL_AI=$(echo "$AIR_RESULT" | jq -r '.verdict_matrix.overall_confidential_ai.status' 2>/dev/null)
if [ "$ASSURANCE" = "air_local" ] \
    && [ "$TEE_PROVENANCE" = "false" ] \
    && [ "$OVERALL_CONFIDENTIAL_AI" != "pass" ] \
    && [ "$OVERALL_CONFIDENTIAL_AI" != "null" ]; then
    pass "Assurance UX — AIR-local is distinct from confidential-AI provenance"
else
    fail "Assurance UX — assurance=$ASSURANCE, tee=$TEE_PROVENANCE, overall=$OVERALL_CONFIDENTIAL_AI"
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
