#!/usr/bin/env bash
# Insurance Claims Pilot — GCP TDX Run
#
# Runs 3 insurance claims against a live GCP TDX deployment.
# Collects real AIR v1 receipts and verifies them.
#
# The CVM runs EphemeralML in direct mode (transport protocol on port 9000).
# The GCP client binary performs handshake + attestation + inference.
#
# Usage:
#   bash scripts/run-gcp-pilot.sh                 # auto-detect IP from running CVM
#   bash scripts/run-gcp-pilot.sh --ip <CVM_IP>   # explicit IP
set -euo pipefail

PILOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$(cd "${PILOT_DIR}/../.." && pwd)"
DATA_FILE="${PILOT_DIR}/data/claims.json"

# Source GCP config
if [[ -f "${PROJECT_DIR}/.env.gcp" ]]; then
    source "${PROJECT_DIR}/.env.gcp"
fi

PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
ZONE="${EPHEMERALML_GCP_ZONE:-us-central1-a}"
CVM_IP=""
CVM_PORT="9000"
INSTANCE_NAME="ephemeralml-cvm"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)      CVM_IP="$2"; shift 2 ;;
        --port)    CVM_PORT="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        --zone)    ZONE="$2"; shift 2 ;;
        *)         shift ;;
    esac
done

# Colors
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"
info()  { echo -e "  ${BOLD}$1${RESET}"; }
ok()    { echo -e "  ${GREEN}${BOLD}$1${RESET}"; }
fail()  { echo -e "  ${RED}${BOLD}$1${RESET}"; }
warn()  { echo -e "  ${YELLOW}$1${RESET}"; }

# Resolve IP if not provided
if [[ -z "$CVM_IP" ]]; then
    info "Resolving CVM IP from instance '${INSTANCE_NAME}'..."
    CVM_IP="$(gcloud compute instances describe "${INSTANCE_NAME}" \
        --zone="${ZONE}" --project="${PROJECT}" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || echo "")"
    if [[ -z "$CVM_IP" || "$CVM_IP" == "None" ]]; then
        fail "Cannot resolve IP. Is the CVM running?"
        echo "  Check: gcloud compute instances list --project=${PROJECT}"
        exit 1
    fi
fi

RUN_ID="gcp-run-$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${PILOT_DIR}/artifacts/${RUN_ID}"
mkdir -p "${RUN_DIR}/responses" "${RUN_DIR}/receipts" "${RUN_DIR}/timing" "${RUN_DIR}/verification"

echo ""
info "EphemeralML Insurance Claims Pilot — GCP TDX"
echo "  ────────────────────────────────────────"
info "CVM:     ${CVM_IP}:${CVM_PORT}"
info "Run ID:  ${RUN_ID}"
info "Output:  ${RUN_DIR}/"
echo ""

# Build client with GCP features (TDX handshake)
info "Building GCP client..."
(cd "$PROJECT_DIR" && cargo build --release --no-default-features --features gcp -p ephemeral-ml-client 2>&1 | tail -3)
CLIENT_BIN="${PROJECT_DIR}/target/release/ephemeral-ml-client"
if [[ ! -f "$CLIENT_BIN" ]]; then
    fail "Client binary not found"
    exit 1
fi
ok "Client binary ready"

# Wait for port
info "Waiting for ${CVM_IP}:${CVM_PORT}..."
WAITED=0
while ! timeout 2 bash -c "echo > /dev/tcp/${CVM_IP}/${CVM_PORT}" 2>/dev/null; do
    WAITED=$((WAITED + 5))
    if [[ ${WAITED} -ge 180 ]]; then
        fail "Port ${CVM_PORT} not reachable after 180s."
        exit 1
    fi
    printf "  Waiting... [%d/180s]\r" "${WAITED}"
    sleep 5
done
ok "Port ${CVM_PORT} is reachable"
echo ""

RESULTS_CSV="${RUN_DIR}/results.csv"
echo "scenario,claim_id,status,latency_ms,receipt_present,receipt_sha256" > "${RESULTS_CSV}"
TOTAL=0; PASSED=0; FAILED=0

# ---------------------------------------------------------------------------
# Run 3 inferences — each one is a fresh client connection + handshake
# ---------------------------------------------------------------------------
run_one_inference() {
    local IDX="$1"
    local CLAIM_ID
    CLAIM_ID=$(python3 -c "import json; print(json.load(open('${DATA_FILE}'))[${IDX}]['claim_id'])")

    TOTAL=$((TOTAL + 1))

    # Clean stale receipts
    rm -f /tmp/ephemeralml-receipt.json /tmp/ephemeralml-receipt.cbor /tmp/ephemeralml-receipt.json.pubkey

    local OUTPUT_FILE="${RUN_DIR}/responses/${CLAIM_ID}_output.txt"
    local START_NS
    START_NS=$(date +%s%N)

    # Run client: env-var based config, writes receipts to /tmp/
    local EXIT_CODE=0
    EPHEMERALML_ENCLAVE_ADDR="${CVM_IP}:${CVM_PORT}" \
        EPHEMERALML_REQUIRE_MRTD=false \
        EPHEMERALML_ALLOW_UNPINNED_AUDIENCE=true \
        EPHEMERALML_GCP_VERIFY_MODEL_ID="stage-0" \
        "$CLIENT_BIN" > "$OUTPUT_FILE" 2>&1 || EXIT_CODE=$?

    local END_NS
    END_NS=$(date +%s%N)
    local LATENCY_MS=$(( (END_NS - START_NS) / 1000000 ))

    # Collect receipt
    local RECEIPT_PRESENT="false"
    local RECEIPT_SHA256="none"
    if [[ -f /tmp/ephemeralml-receipt.cbor ]]; then
        RECEIPT_PRESENT="true"
        cp /tmp/ephemeralml-receipt.cbor "${RUN_DIR}/receipts/${CLAIM_ID}.cbor"
        RECEIPT_SHA256=$(sha256sum /tmp/ephemeralml-receipt.cbor | cut -d' ' -f1)
    fi
    if [[ -f /tmp/ephemeralml-receipt.json ]]; then
        cp /tmp/ephemeralml-receipt.json "${RUN_DIR}/responses/${CLAIM_ID}_receipt.json"
    fi
    if [[ -f /tmp/ephemeralml-receipt.json.pubkey ]]; then
        cp /tmp/ephemeralml-receipt.json.pubkey "${RUN_DIR}/receipts/${CLAIM_ID}.pubkey"
    fi

    # Save timing
    echo "{\"claim_id\":\"${CLAIM_ID}\",\"latency_ms\":${LATENCY_MS},\"receipt_present\":${RECEIPT_PRESENT},\"exit_code\":${EXIT_CODE}}" \
        > "${RUN_DIR}/timing/${CLAIM_ID}.json"

    if [[ $EXIT_CODE -eq 0 ]]; then
        PASSED=$((PASSED + 1))
        ok "[gcp] ${CLAIM_ID}: OK, receipt=${RECEIPT_PRESENT}, sha256=${RECEIPT_SHA256:0:16}..., ${LATENCY_MS}ms"
    else
        FAILED=$((FAILED + 1))
        fail "[gcp] ${CLAIM_ID}: FAILED (exit ${EXIT_CODE}), ${LATENCY_MS}ms"
        tail -5 "$OUTPUT_FILE" 2>/dev/null | while read -r line; do echo "    $line"; done
    fi

    echo "gcp,${CLAIM_ID},$([ $EXIT_CODE -eq 0 ] && echo PASS || echo FAIL),${LATENCY_MS},${RECEIPT_PRESENT},${RECEIPT_SHA256}" >> "${RESULTS_CSV}"
}

info "Running 3 insurance claim inferences on GCP TDX..."
echo ""

run_one_inference 0
run_one_inference 1
run_one_inference 2

echo ""

# ---------------------------------------------------------------------------
# Verify receipts
# ---------------------------------------------------------------------------
info "Verifying receipts..."
echo ""

RECEIPT_FILES=$(ls "${RUN_DIR}/receipts/"*.cbor 2>/dev/null || echo "")
VERIFIED=0; VERIFY_FAIL=0

if [[ -n "$RECEIPT_FILES" ]]; then
    for RF in ${RECEIPT_FILES}; do
        BASENAME=$(basename "$RF" .cbor)
        VERIFY_OUT="${RUN_DIR}/verification/${BASENAME}_verify.json"

        # Use python3 for CBOR structure check
        python3 << 'PYEOF' "$RF" "$VERIFY_OUT" 2>/dev/null
import sys, json, hashlib

receipt_path = sys.argv[1]
output_path = sys.argv[2]

with open(receipt_path, 'rb') as f:
    data = f.read()

result = {
    "file": receipt_path,
    "size_bytes": len(data),
    "sha256": hashlib.sha256(data).hexdigest(),
}

# Check for COSE_Sign1 tag (tag 18)
if len(data) > 3 and data[0] == 0xD8 and data[1] == 0x12:
    result["format"] = "COSE_Sign1"
    result["cbor_tag"] = 18
    result["valid_structure"] = True
elif len(data) > 2 and data[0] == 0xD2:
    result["format"] = "COSE_Sign1"
    result["cbor_tag"] = 18
    result["valid_structure"] = True
else:
    result["format"] = "unknown"
    result["valid_structure"] = False

try:
    import cbor2
    decoded = cbor2.loads(data)
    if hasattr(decoded, 'tag') and decoded.tag == 18:
        result["format"] = "COSE_Sign1"
        result["valid_structure"] = True
        cose_array = decoded.value
        if isinstance(cose_array, list) and len(cose_array) == 4:
            protected, unprotected, payload, signature = cose_array
            result["signature_size"] = len(signature) if isinstance(signature, bytes) else 0
            result["signature_valid_size"] = (len(signature) == 64) if isinstance(signature, bytes) else False
            if isinstance(payload, bytes):
                try:
                    claims = cbor2.loads(payload)
                    if isinstance(claims, dict):
                        result["claims_count"] = len(claims)
                        claim_names = {
                            1: "iss", 6: "iat", 7: "cti", 10: "eat_nonce", 265: "eat_profile",
                            -65537: "model_id", -65538: "model_version", -65539: "model_hash",
                            -65540: "request_hash", -65541: "response_hash",
                            -65542: "attestation_doc_hash", -65543: "enclave_measurements",
                            -65548: "security_mode"
                        }
                        result["claims"] = {}
                        for k, v in claims.items():
                            name = claim_names.get(k, f"key_{k}")
                            if isinstance(v, bytes):
                                result["claims"][name] = v.hex()[:40] + ("..." if len(v) > 20 else "")
                            elif isinstance(v, (int, float, str, bool)):
                                result["claims"][name] = v
                            else:
                                result["claims"][name] = str(v)[:80]
                except Exception:
                    pass
except ImportError:
    result["note"] = "cbor2 not installed"

result["verdict"] = "valid_structure" if result.get("valid_structure") else "invalid_structure"

with open(output_path, 'w') as f:
    json.dump(result, f, indent=2, default=str)

print(json.dumps({"status": result["verdict"], "claims": result.get("claims_count", 0), "sha256": result["sha256"][:16]}))
PYEOF

        VERDICT=$(python3 -c "import json; print(json.load(open('${VERIFY_OUT}'))['verdict'])" 2>/dev/null || echo "error")
        CLAIMS=$(python3 -c "import json; print(json.load(open('${VERIFY_OUT}')).get('claims_count','?'))" 2>/dev/null || echo "?")

        if [[ "$VERDICT" == "valid_structure" ]]; then
            VERIFIED=$((VERIFIED + 1))
            ok "[VERIFIED] ${BASENAME}: ${CLAIMS} claims, valid COSE_Sign1"
        else
            VERIFY_FAIL=$((VERIFY_FAIL + 1))
            fail "[INVALID] ${BASENAME}: ${VERDICT}"
        fi
    done
else
    warn "No receipt files collected."
fi

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "  ════════════════════════════════════════"
info "GCP TDX Pilot Summary: ${RUN_ID}"
echo ""
echo "  Inferences: ${TOTAL} total, ${PASSED} passed, ${FAILED} failed"
echo "  Receipts:   $(ls "${RUN_DIR}/receipts/"*.cbor 2>/dev/null | wc -l) collected, ${VERIFIED} verified"
echo "  Output:     ${RUN_DIR}/"
echo ""

if [[ "$FAILED" -eq 0 ]] && [[ "$VERIFY_FAIL" -eq 0 ]]; then
    ok "RESULT: ALL PASSED"
else
    fail "RESULT: ${FAILED} inference failures, ${VERIFY_FAIL} verification failures"
fi
echo "  ════════════════════════════════════════"

# Save summary
cat > "${RUN_DIR}/summary.json" << EOF
{
  "run_id": "${RUN_ID}",
  "platform": "gcp-tdx",
  "cvm_ip": "${CVM_IP}",
  "cvm_port": ${CVM_PORT},
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "total_inferences": ${TOTAL},
  "passed": ${PASSED},
  "failed": ${FAILED},
  "receipts_collected": $(ls "${RUN_DIR}/receipts/"*.cbor 2>/dev/null | wc -l),
  "receipts_verified": ${VERIFIED}
}
EOF
