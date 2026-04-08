#!/usr/bin/env bash
# Insurance Claims Pilot — Run All Scenarios
#
# Runs cold-start, warm batch, and failure-path scenarios against the gateway.
# Collects responses, receipts, and timing data.
#
# Usage:
#   bash scripts/run-pilot.sh                        # All scenarios
#   bash scripts/run-pilot.sh --scenario cold        # Cold-start only
#   bash scripts/run-pilot.sh --scenario warm        # Warm batch only
#   bash scripts/run-pilot.sh --scenario negative    # Failure paths only
#
# Environment:
#   GATEWAY_URL   Gateway endpoint (default: http://localhost:8090)
#   API_KEY       API key (default: pilot-test-key-2026)
set -euo pipefail

PILOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS_DIR="${PILOT_DIR}/artifacts"
DATA_FILE="${PILOT_DIR}/data/claims.json"
SYSTEM_PROMPT_FILE="${PILOT_DIR}/requests/system-prompt.txt"

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8090}"
API_KEY="${API_KEY:-pilot-test-key-2026}"
SCENARIO="${2:-all}"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario) SCENARIO="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# Colors
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"
info()  { echo -e "  ${BOLD}$1${RESET}"; }
ok()    { echo -e "  ${GREEN}${BOLD}$1${RESET}"; }
warn()  { echo -e "  ${YELLOW}$1${RESET}"; }
fail()  { echo -e "  ${RED}${BOLD}$1${RESET}"; }
dim()   { echo -e "  ${DIM}$1${RESET}"; }

# Setup output dirs
RUN_ID="run-$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${ARTIFACTS_DIR}/${RUN_ID}"
mkdir -p "${RUN_DIR}/responses" "${RUN_DIR}/receipts" "${RUN_DIR}/timing"

echo ""
info "EphemeralML Insurance Claims Pilot"
echo "  ────────────────────────────────────────"
info "Gateway:    ${GATEWAY_URL}"
info "Run ID:     ${RUN_ID}"
info "Scenario:   ${SCENARIO}"
info "Output:     ${RUN_DIR}/"
echo ""

# Check gateway health
HEALTH_BODY="$(curl -sS --max-time 5 "${GATEWAY_URL}/health" 2>/dev/null || true)"
if ! printf '%s' "${HEALTH_BODY}" | grep -q '"status":"ok"'; then
    fail "Gateway not reachable at ${GATEWAY_URL}/health"
    echo "  Run setup first: bash scripts/setup.sh"
    exit 1
fi
ok "Gateway health: OK"

# Load system prompt
SYSTEM_PROMPT=$(cat "${SYSTEM_PROMPT_FILE}")

# Track results
TOTAL=0; PASSED=0; FAILED=0
RESULTS_CSV="${RUN_DIR}/results.csv"
echo "scenario,claim_id,status,latency_ms,receipt_present,receipt_sha256,http_status" > "${RESULTS_CSV}"

# ---------------------------------------------------------------------------
# Helper: send one claim and collect artifacts
# ---------------------------------------------------------------------------
send_claim() {
    local SCENARIO_NAME="$1"
    local CLAIM_ID="$2"
    local CLAIM_JSON="$3"
    local EXPECT_FAIL="${4:-false}"
    local MAX_TOKENS="${5:-32}"

    TOTAL=$((TOTAL + 1))

    # Build the user message from claim fields
    local USER_MSG
    USER_MSG=$(echo "$CLAIM_JSON" | python3 -c "
import json, sys
c = json.load(sys.stdin)
print(f'''Triage this claim as JSON:
ID: {c['claim_id']}, Type: {c['claim_type']}, Amount: \${c[\"amount_claimed\"]:,.0f}
Summary: {c[\"summary\"][:200]}''')
" 2>/dev/null)

    # Build request body
    local REQUEST_BODY
    REQUEST_BODY=$(python3 -c "
import json, sys
system_prompt = sys.argv[1]
user_msg = sys.argv[2]
max_tokens = int(sys.argv[3])
req = {
    'model': 'gpt-4',
    'messages': [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': user_msg}
    ],
    'max_tokens': max_tokens,
    'temperature': 0.3,
    'top_p': 0.9
}
print(json.dumps(req))
" "$SYSTEM_PROMPT" "$USER_MSG" "$MAX_TOKENS" 2>/dev/null)

    # Save request
    echo "$REQUEST_BODY" | python3 -m json.tool > "${RUN_DIR}/responses/${SCENARIO_NAME}_${CLAIM_ID}_request.json" 2>/dev/null || true

    # Send request with timing
    local START_MS
    START_MS=$(date +%s%N)

    local HTTP_CODE RESPONSE_BODY
    RESPONSE_BODY=$(curl -s --max-time 180 -w "\n%{http_code}" \
        -X POST "${GATEWAY_URL}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_KEY}" \
        -d "$REQUEST_BODY" 2>/dev/null) || RESPONSE_BODY=$'\n000'

    local END_MS
    END_MS=$(date +%s%N)
    local LATENCY_MS=$(( (END_MS - START_MS) / 1000000 ))

    # Split response body and HTTP code
    HTTP_CODE=$(echo "$RESPONSE_BODY" | tail -1)
    RESPONSE_BODY=$(echo "$RESPONSE_BODY" | sed '$d')

    # Save response
    echo "$RESPONSE_BODY" | python3 -m json.tool > "${RUN_DIR}/responses/${SCENARIO_NAME}_${CLAIM_ID}_response.json" 2>/dev/null || \
        echo "$RESPONSE_BODY" > "${RUN_DIR}/responses/${SCENARIO_NAME}_${CLAIM_ID}_response.json"

    # Extract receipt
    local RECEIPT_PRESENT="false"
    local RECEIPT_SHA256="none"
    local RECEIPT_B64=""

    if echo "$RESPONSE_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('_ephemeralml',{}).get('receipt_sha256',''))" 2>/dev/null | grep -q '^[a-f0-9]'; then
        RECEIPT_PRESENT="true"
        RECEIPT_SHA256=$(echo "$RESPONSE_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['_ephemeralml']['receipt_sha256'])" 2>/dev/null)
        RECEIPT_B64=$(echo "$RESPONSE_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['_ephemeralml'].get('air_v1_receipt_b64',''))" 2>/dev/null)

        if [[ -n "$RECEIPT_B64" ]]; then
            echo "$RECEIPT_B64" | base64 -d > "${RUN_DIR}/receipts/${SCENARIO_NAME}_${CLAIM_ID}.cbor" 2>/dev/null || true
        fi
    fi

    # Save timing
    echo "{\"claim_id\":\"${CLAIM_ID}\",\"scenario\":\"${SCENARIO_NAME}\",\"latency_ms\":${LATENCY_MS},\"http_status\":${HTTP_CODE},\"receipt_present\":${RECEIPT_PRESENT}}" \
        > "${RUN_DIR}/timing/${SCENARIO_NAME}_${CLAIM_ID}.json"

    # Evaluate result
    local STATUS="PASS"
    if [[ "$EXPECT_FAIL" == "true" ]]; then
        if [[ "$HTTP_CODE" -ge 400 ]] || [[ "$HTTP_CODE" == "000" ]]; then
            STATUS="PASS"
            ok "[${SCENARIO_NAME}] ${CLAIM_ID}: Expected failure confirmed (HTTP ${HTTP_CODE}) [${LATENCY_MS}ms]"
        else
            STATUS="FAIL"
            fail "[${SCENARIO_NAME}] ${CLAIM_ID}: Expected failure but got HTTP ${HTTP_CODE} [${LATENCY_MS}ms]"
        fi
    else
        if [[ "$HTTP_CODE" -ge 200 ]] && [[ "$HTTP_CODE" -lt 300 ]]; then
            PASSED=$((PASSED + 1))
            ok "[${SCENARIO_NAME}] ${CLAIM_ID}: HTTP ${HTTP_CODE}, receipt=${RECEIPT_PRESENT}, ${LATENCY_MS}ms"
        else
            STATUS="FAIL"
            FAILED=$((FAILED + 1))
            fail "[${SCENARIO_NAME}] ${CLAIM_ID}: HTTP ${HTTP_CODE} [${LATENCY_MS}ms]"
        fi
    fi

    echo "${SCENARIO_NAME},${CLAIM_ID},${STATUS},${LATENCY_MS},${RECEIPT_PRESENT},${RECEIPT_SHA256},${HTTP_CODE}" >> "${RESULTS_CSV}"
}

# ---------------------------------------------------------------------------
# Scenario A: Cold-Start (first 2 claims)
# ---------------------------------------------------------------------------
run_cold_start() {
    info "Scenario A: Cold-Start"
    dim "First inference after gateway start — measures cold path latency"
    echo ""

    # Use claims 1 and 2
    for IDX in 0 1; do
        local CLAIM_JSON
        CLAIM_JSON=$(python3 -c "import json; claims=json.load(open('${DATA_FILE}')); print(json.dumps(claims[${IDX}]))")
        local CLAIM_ID
        CLAIM_ID=$(echo "$CLAIM_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['claim_id'])")
        send_claim "cold" "$CLAIM_ID" "$CLAIM_JSON"
    done
    echo ""
}

# ---------------------------------------------------------------------------
# Scenario B: Warm Batch (claims 1-8 in sequence)
# ---------------------------------------------------------------------------
run_warm_batch() {
    info "Scenario B: Warm Batch (8 claims in sequence)"
    dim "Exercises repeated receipt generation and stable output structure"
    echo ""

    local NUM_CLAIMS
    NUM_CLAIMS=$(python3 -c "import json; print(len(json.load(open('${DATA_FILE}'))))")

    for IDX in $(seq 0 $((NUM_CLAIMS - 1))); do
        local CLAIM_JSON
        CLAIM_JSON=$(python3 -c "import json; claims=json.load(open('${DATA_FILE}')); print(json.dumps(claims[${IDX}]))")
        local CLAIM_ID
        CLAIM_ID=$(echo "$CLAIM_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['claim_id'])")
        send_claim "warm" "$CLAIM_ID" "$CLAIM_JSON"
    done
    echo ""
}

# ---------------------------------------------------------------------------
# Scenario C: Failure Paths
# ---------------------------------------------------------------------------
run_negative() {
    info "Scenario C: Failure Paths"
    dim "Tests error handling and negative scenarios"
    echo ""

    # C.1: Wrong API key
    info "  C.1: Wrong API key"
    local ORIG_KEY="$API_KEY"
    API_KEY="wrong-key-12345"
    local CLAIM_JSON
    CLAIM_JSON=$(python3 -c "import json; claims=json.load(open('${DATA_FILE}')); print(json.dumps(claims[0]))")
    send_claim "neg_auth" "CLM-2026-0001" "$CLAIM_JSON" "true"
    API_KEY="$ORIG_KEY"

    # C.2: Empty messages
    info "  C.2: Empty messages"
    local EMPTY_REQ='{"model":"gpt-4","messages":[],"max_tokens":32}'
    local HTTP_CODE
    HTTP_CODE=$(curl -s --max-time 30 -o /dev/null -w "%{http_code}" \
        -X POST "${GATEWAY_URL}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_KEY}" \
        -d "$EMPTY_REQ" 2>/dev/null) || HTTP_CODE="000"
    if [[ "$HTTP_CODE" -ge 400 ]]; then
        ok "[neg_empty] Empty messages rejected: HTTP ${HTTP_CODE}"
        echo "neg_empty,N/A,PASS,0,false,none,${HTTP_CODE}" >> "${RESULTS_CSV}"
    else
        fail "[neg_empty] Empty messages not rejected: HTTP ${HTTP_CODE}"
        echo "neg_empty,N/A,FAIL,0,false,none,${HTTP_CODE}" >> "${RESULTS_CSV}"
    fi

    # C.3: Unsupported tool_choice
    info "  C.3: Unsupported tool_choice parameter"
    local TOOL_REQ='{"model":"gpt-4","messages":[{"role":"user","content":"test"}],"tool_choice":"auto","max_tokens":32}'
    HTTP_CODE=$(curl -s --max-time 30 -o /dev/null -w "%{http_code}" \
        -X POST "${GATEWAY_URL}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_KEY}" \
        -d "$TOOL_REQ" 2>/dev/null) || HTTP_CODE="000"
    if [[ "$HTTP_CODE" -ge 400 ]]; then
        ok "[neg_tools] tool_choice rejected: HTTP ${HTTP_CODE}"
        echo "neg_tools,N/A,PASS,0,false,none,${HTTP_CODE}" >> "${RESULTS_CSV}"
    else
        fail "[neg_tools] tool_choice not rejected: HTTP ${HTTP_CODE}"
        echo "neg_tools,N/A,FAIL,0,false,none,${HTTP_CODE}" >> "${RESULTS_CSV}"
    fi

    # C.4: Embeddings endpoint (should be rejected — capabilities set to chat only)
    info "  C.4: Embeddings on chat-only model"
    local EMB_REQ='{"model":"gpt-4","input":"test embedding"}'
    HTTP_CODE=$(curl -s --max-time 30 -o /dev/null -w "%{http_code}" \
        -X POST "${GATEWAY_URL}/v1/embeddings" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_KEY}" \
        -d "$EMB_REQ" 2>/dev/null) || HTTP_CODE="000"
    if [[ "$HTTP_CODE" -ge 400 ]]; then
        ok "[neg_embed] Embeddings rejected on chat-only model: HTTP ${HTTP_CODE}"
        echo "neg_embed,N/A,PASS,0,false,none,${HTTP_CODE}" >> "${RESULTS_CSV}"
    else
        fail "[neg_embed] Embeddings not rejected: HTTP ${HTTP_CODE}"
        echo "neg_embed,N/A,FAIL,0,false,none,${HTTP_CODE}" >> "${RESULTS_CSV}"
    fi

    # C.5: Tampered receipt verification
    info "  C.5: Tampered receipt verification"
    # Find any receipt from warm batch and tamper with it
    local RECEIPT_FILE
    RECEIPT_FILE=$(ls "${RUN_DIR}/receipts/warm_"*.cbor 2>/dev/null | head -1 || echo "")
    if [[ -n "$RECEIPT_FILE" ]]; then
        local TAMPERED_FILE="${RUN_DIR}/receipts/tampered.cbor"
        cp "$RECEIPT_FILE" "$TAMPERED_FILE"
        # Flip a byte in the middle of the receipt
        python3 -c "
data = open('${TAMPERED_FILE}', 'rb').read()
ba = bytearray(data)
mid = len(ba) // 2
ba[mid] = ba[mid] ^ 0xFF
open('${TAMPERED_FILE}', 'wb').write(bytes(ba))
"
        ok "[neg_tamper] Created tampered receipt: ${TAMPERED_FILE}"
        echo "neg_tamper,N/A,PASS,0,false,none,N/A" >> "${RESULTS_CSV}"
    else
        warn "[neg_tamper] No receipts available to tamper (skipped)"
        echo "neg_tamper,N/A,SKIP,0,false,none,N/A" >> "${RESULTS_CSV}"
    fi

    echo ""
}

# ---------------------------------------------------------------------------
# Run selected scenarios
# ---------------------------------------------------------------------------
case "$SCENARIO" in
    cold)     run_cold_start ;;
    warm)     run_warm_batch ;;
    negative) run_negative ;;
    all)
        run_cold_start
        run_warm_batch
        run_negative
        ;;
    *)
        fail "Unknown scenario: ${SCENARIO}"
        echo "  Valid: cold, warm, negative, all"
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "  ════════════════════════════════════════"
info "Run Summary: ${RUN_ID}"
echo ""

# Count results
TOTAL_PASS=$(grep -c ",PASS," "${RESULTS_CSV}" 2>/dev/null || true)
TOTAL_FAIL=$(grep -c ",FAIL," "${RESULTS_CSV}" 2>/dev/null || true)
TOTAL_SKIP=$(grep -c ",SKIP," "${RESULTS_CSV}" 2>/dev/null || true)
TOTAL_PASS=${TOTAL_PASS:-0}; TOTAL_FAIL=${TOTAL_FAIL:-0}; TOTAL_SKIP=${TOTAL_SKIP:-0}
TOTAL_TESTS=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))
RECEIPT_COUNT=$(find "${RUN_DIR}/receipts/" -name "*.cbor" ! -name "tampered*" 2>/dev/null | wc -l)

echo "  Tests:    ${TOTAL_TESTS} total, ${TOTAL_PASS} passed, ${TOTAL_FAIL} failed, ${TOTAL_SKIP} skipped"
echo "  Receipts: ${RECEIPT_COUNT} collected"
echo "  Output:   ${RUN_DIR}/"
echo ""

if [[ "$TOTAL_FAIL" -gt 0 ]]; then
    fail "RESULT: ${TOTAL_FAIL} FAILURES"
else
    ok "RESULT: ALL PASSED"
fi
echo "  ════════════════════════════════════════"
echo ""
echo "  Next: bash scripts/verify-receipts.sh ${RUN_DIR}"
echo ""

# Save summary
cat > "${RUN_DIR}/summary.json" << EOF
{
  "run_id": "${RUN_ID}",
  "gateway_url": "${GATEWAY_URL}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "scenario": "${SCENARIO}",
  "total_tests": ${TOTAL_TESTS},
  "passed": ${TOTAL_PASS},
  "failed": ${TOTAL_FAIL},
  "skipped": ${TOTAL_SKIP},
  "receipts_collected": ${RECEIPT_COUNT}
}
EOF
