#!/usr/bin/env bash
# EphemeralML — Smoke test against a deployed Confidential Space CVM.
#
# Waits for the enclave to be reachable, runs inference, saves receipt, verifies it.
# Always uses --features gcp so the client speaks the same TDX handshake protocol
# as the enclave.
#
# Usage:
#   bash scripts/gcp/verify.sh                              # auto-detect IP; requires GCP_WIP_AUDIENCE
#   bash scripts/gcp/verify.sh --ip 34.72.100.50            # explicit IP
#   bash scripts/gcp/verify.sh --allow-unpinned-audience     # skip audience pin (dev only)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Load shared UI helpers
# shellcheck source=../lib/ui.sh
source "${SCRIPT_DIR}/../lib/ui.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTANCE_NAME="ephemeralml-cvm"
DATA_PORT=9000            # direct mode: client connects to single port (9000)
CONTROL_PORT=9000         # used only for the reachability probe
RECEIPT_PATH="/tmp/ephemeralml-receipt.json"
TIMING_PATH="/tmp/ephemeralml-timing.json"
VERIFY_OUTPUT="$(mktemp /tmp/ephemeralml-verify-output.XXXXXX.txt)"
MAX_WAIT=180              # seconds to wait for port reachability
INFERENCE_TEXT="Verify EphemeralML on Confidential Space"
VERIFY_MODEL_ID="${EPHEMERALML_VERIFY_MODEL_ID:-stage-0}"
VERIFY_RECEIPT_MODEL_ID="${EPHEMERALML_VERIFY_RECEIPT_MODEL_ID:-minilm-l6-v2}"

# Clean up temp files on exit (even on failure).
# Only clean up the script-local temp file; receipt is preserved for E2E callers.
cleanup_temp() {
    rm -f "${VERIFY_OUTPUT}"
}
trap cleanup_temp EXIT

# Defaults — project must come from env or --project flag
PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
ZONE="us-central1-a"
IP=""
GPU=false
ALLOW_UNPINNED_AUDIENCE=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)      IP="$2"; shift 2 ;;
        --zone)    ZONE="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        --model-id) VERIFY_MODEL_ID="$2"; shift 2 ;;
        --receipt-model-id) VERIFY_RECEIPT_MODEL_ID="$2"; shift 2 ;;
        --gpu)     GPU=true; shift ;;
        --allow-unpinned-audience) ALLOW_UNPINNED_AUDIENCE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# GPU mode: match deploy.sh instance name
if $GPU; then
    INSTANCE_NAME="ephemeralml-gpu"
    MAX_WAIT=300
fi

if [[ -z "${PROJECT}" ]]; then
    echo "ERROR: GCP project not set."
    echo "Set EPHEMERALML_GCP_PROJECT or pass --project PROJECT_ID"
    exit 1
fi

ui_header "EphemeralML — Verify Deployment"
ui_blank

# ---------------------------------------------------------------------------
# 1. Resolve instance IP
# ---------------------------------------------------------------------------
if [[ -z "${IP}" ]]; then
    ui_info "[1/4] Resolving instance IP..."
    IP="$(gcloud compute instances describe "${INSTANCE_NAME}" \
        --zone="${ZONE}" --project="${PROJECT}" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)"
    if [[ -z "${IP}" || "${IP}" == "None" ]]; then
        ui_fail "ERROR: Could not resolve IP for '${INSTANCE_NAME}' in zone '${ZONE}'."
        ui_info "Is the instance running? Try: gcloud compute instances list --project=${PROJECT}"
        exit 1
    fi
    ui_kv "Instance IP" "${IP}"
else
    ui_info "[1/4] Using provided IP: ${IP}"
fi
ui_blank

# ---------------------------------------------------------------------------
# 2. Wait for port to be reachable
# ---------------------------------------------------------------------------
ui_info "[2/4] Waiting for ${IP}:${CONTROL_PORT} to be reachable (max ${MAX_WAIT}s)..."
WAITED=0
while ! timeout 2 bash -c "echo >/dev/tcp/${IP}/${CONTROL_PORT}" 2>/dev/null; do
    WAITED=$((WAITED + 5))
    if [[ ${WAITED} -ge ${MAX_WAIT} ]]; then
        ui_fail "ERROR: Port ${CONTROL_PORT} not reachable after ${MAX_WAIT}s."
        ui_bullet "Firewall rule allows TCP ${CONTROL_PORT}: gcloud compute firewall-rules list --project=${PROJECT}"
        ui_bullet "Container is running: gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE} --command='sudo journalctl -u tee-container-runner --no-pager -n 50'"
        exit 1
    fi
    printf "  Waiting... [%d/%ds]\r" "${WAITED}" "${MAX_WAIT}"
    sleep 5
done
ui_ok "Port ${CONTROL_PORT} is reachable."
ui_blank

# ---------------------------------------------------------------------------
# 3. Run inference client
# ---------------------------------------------------------------------------
ui_info "[3/4] Running inference against ${IP}:${DATA_PORT}..."
ui_kv "Text" "\"${INFERENCE_TEXT}\""
ui_kv "Mode" "gcp (TDX attestation + handshake)"
ui_kv "Request model ID" "${VERIFY_MODEL_ID}"
ui_kv "Receipt model ID" "${VERIFY_RECEIPT_MODEL_ID}"
ui_blank

cd "${PROJECT_DIR}"

# Build client with gcp feature — must match the enclave's TDX handshake stack
CLIENT_BUILD_START=$(date +%s%N)
run_step 3 4 "Building GCP client" \
    cargo build --release --no-default-features --features gcp -p ephemeral-ml-client
CLIENT_BUILD_END=$(date +%s%N)

# The GCP-mode client reads EPHEMERALML_ENCLAVE_ADDR for the server address.
# It connects to the data_in port (9001) where the enclave accepts inference traffic.
#
# SECURITY NOTES:
# - EPHEMERALML_REQUIRE_MRTD=false is set because verify.sh is a post-deploy smoke
#   test — the MRTD value is not known until after deployment. Production clients
#   MUST set EPHEMERALML_EXPECTED_MRTD=<96 hex chars> to pin the TDX peer measurement.
# - EPHEMERALML_EXPECTED_AUDIENCE is set from GCP_WIP_AUDIENCE (setup_kms.sh output)
#   so that audience pinning is enforced. If GCP_WIP_AUDIENCE is not set, the script
#   fails unless --allow-unpinned-audience is explicitly passed (development only).
if [[ -n "${GCP_WIP_AUDIENCE:-}" ]]; then
    export EPHEMERALML_EXPECTED_AUDIENCE="${GCP_WIP_AUDIENCE}"
elif $ALLOW_UNPINNED_AUDIENCE; then
    ui_warn "WARNING: --allow-unpinned-audience passed. JWT audience is NOT validated."
    export EPHEMERALML_ALLOW_UNPINNED_AUDIENCE=true
else
    ui_fail "ERROR: GCP_WIP_AUDIENCE not set and audience pinning is required."
    ui_info "Set GCP_WIP_AUDIENCE (from setup_kms.sh output) or pass --allow-unpinned-audience."
    exit 1
fi

INFERENCE_START=$(date +%s%N)
EPHEMERALML_ENCLAVE_ADDR="${IP}:${DATA_PORT}" \
    EPHEMERALML_REQUIRE_MRTD=false \
    EPHEMERALML_GCP_VERIFY_MODEL_ID="${VERIFY_MODEL_ID}" \
    EPHEMERALML_ACCEPT_RECEIPT_MODEL_ID="${VERIFY_RECEIPT_MODEL_ID}" \
    cargo run --release --no-default-features --features gcp \
    -p ephemeral-ml-client --bin ephemeral-ml-client 2>&1 | tee ${VERIFY_OUTPUT}

CLIENT_EXIT=${PIPESTATUS[0]}
INFERENCE_END=$(date +%s%N)

if [[ ${CLIENT_EXIT} -ne 0 ]]; then
    ui_blank
    ui_fail "ERROR: Client exited with code ${CLIENT_EXIT}."
    ui_info "Check the output above for details."
    exit 1
fi
ui_blank
ui_ok "Inference completed successfully."
ui_blank

# ---------------------------------------------------------------------------
# 4. Verify receipt (if saved)
# ---------------------------------------------------------------------------
RECEIPT_VERIFIED=false

ui_info "[4/4] Verifying receipt..."

if [[ -f "${RECEIPT_PATH}" ]]; then
    # Read public key from the .pubkey file the client writes (hex-encoded Ed25519 key).
    PUBKEY_FILE="${RECEIPT_PATH}.pubkey"
    PK_HEX=""
    if [[ -f "${PUBKEY_FILE}" ]]; then
        PK_HEX="$(tr -d '[:space:]' < "${PUBKEY_FILE}")"
    fi

    if [[ -n "${PK_HEX}" ]]; then
        ui_kv "Receipt" "${RECEIPT_PATH}"
        ui_kv "Public key" "${PK_HEX}"
        ui_blank

        VERIFY_START=$(date +%s%N)
        cargo run --release --no-default-features --features gcp \
            --bin ephemeralml-verify -- \
            "${RECEIPT_PATH}" \
            --public-key "${PK_HEX}" \
            --max-age 0 \
            --format text
        VERIFY_EXIT=$?
        VERIFY_END=$(date +%s%N)
        RECEIPT_VERIFIED=true

        # Also verify AIR v1 receipt if present (non-blocking)
        AIR_V1_PATH="/tmp/ephemeralml-receipt.cbor"
        if [[ -f "${AIR_V1_PATH}" ]]; then
            ui_blank
            ui_info "AIR v1 receipt verification..."
            cargo run --release --no-default-features --features gcp \
                --bin ephemeralml-verify -- \
                "${AIR_V1_PATH}" \
                --public-key "${PK_HEX}" \
                --max-age 0 \
                --format text || true
        fi
    else
        ui_warn "WARNING: Receipt file exists but no .pubkey file found at ${PUBKEY_FILE}."
        ui_info "Receipt at: ${RECEIPT_PATH}"
        VERIFY_EXIT=1
    fi
else
    ui_warn "WARNING: No receipt file at ${RECEIPT_PATH}."
    ui_info "The client may not save receipts in this mode."
    VERIFY_EXIT=1
fi
ui_blank

# ---------------------------------------------------------------------------
# Generate timing.json
# ---------------------------------------------------------------------------
# Compute durations in milliseconds (nanosecond timestamps / 1000000).
# Extract execution_time_ms from receipt if available (enclave-measured inference time).
_client_build_ms=$(( (CLIENT_BUILD_END - CLIENT_BUILD_START) / 1000000 ))
_e2e_client_ms=$(( (INFERENCE_END - INFERENCE_START) / 1000000 ))
_verify_ms=0
if [[ -n "${VERIFY_END:-}" && -n "${VERIFY_START:-}" ]]; then
    _verify_ms=$(( (VERIFY_END - VERIFY_START) / 1000000 ))
fi
_port_wait_ms=$(( WAITED * 1000 ))

# Try to extract enclave-reported execution_time_ms from receipt JSON
_exec_time_ms="null"
if [[ -f "${RECEIPT_PATH}" ]]; then
    _exec_time_ms=$(python3 -c "
import json, sys
try:
    r = json.load(open('${RECEIPT_PATH}'))
    print(r.get('execution_time_ms', 'null'))
except Exception:
    print('null')
" 2>/dev/null || echo "null")
fi

cat > "${TIMING_PATH}" << TIMINGEOF
{
  "schema_version": 1,
  "client_build_ms": ${_client_build_ms},
  "port_wait_ms": ${_port_wait_ms},
  "e2e_client_ms": ${_e2e_client_ms},
  "enclave_execution_time_ms": ${_exec_time_ms},
  "receipt_verify_ms": ${_verify_ms},
  "client_exit_code": ${CLIENT_EXIT},
  "receipt_verified": ${RECEIPT_VERIFIED},
  "instance": "${INSTANCE_NAME}",
  "ip": "${IP}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
TIMINGEOF

ui_kv "Timing" "${TIMING_PATH}"

# ---------------------------------------------------------------------------
# Generate artifact manifest
# ---------------------------------------------------------------------------
MANIFEST_PATH="/tmp/ephemeralml-artifact_manifest.json"
{
    echo '{'
    echo '  "schema_version": 1,'
    echo "  \"generated\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo '  "artifacts": ['
    _first=true
    for _f in "${RECEIPT_PATH}" "/tmp/ephemeralml-receipt.cbor" "${RECEIPT_PATH}.pubkey" \
              "/tmp/ephemeralml-attestation.bin" "/tmp/ephemeralml-manifest.json" "${TIMING_PATH}"; do
        [ -f "$_f" ] || continue
        _basename="$(basename "$_f")"
        _hash=$(sha256sum "$_f" | cut -d' ' -f1)
        _size=$(stat --printf='%s' "$_f" 2>/dev/null || stat -f'%z' "$_f" 2>/dev/null)
        if [ "$_first" = true ]; then
            _first=false
        else
            echo ','
        fi
        printf '    {"file": "%s", "sha256": "%s", "bytes": %s}' "$_basename" "$_hash" "$_size"
    done
    echo ''
    echo '  ]'
    echo '}'
} > "${MANIFEST_PATH}"
ui_kv "Manifest" "${MANIFEST_PATH}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [[ ${CLIENT_EXIT} -eq 0 && ${RECEIPT_VERIFIED} == true && ${VERIFY_EXIT} -eq 0 ]]; then
    ui_header "PASS — Inference + receipt verification succeeded"
elif [[ ${CLIENT_EXIT} -eq 0 ]]; then
    ui_header "PARTIAL — Inference succeeded, receipt NOT verified"
else
    ui_header "FAIL — See errors above"
fi
ui_blank
ui_kv "Instance" "${INSTANCE_NAME} (${IP})"
ui_kv "Client" "exit ${CLIENT_EXIT}"
ui_kv "Receipt" "$(if ${RECEIPT_VERIFIED}; then echo "VERIFIED"; else echo "NOT VERIFIED"; fi)"
ui_blank
ui_info "Next: bash scripts/gcp/teardown.sh"

# Exit 0 only when both client and receipt verification passed
if [[ ${CLIENT_EXIT} -eq 0 && ${VERIFY_EXIT} -eq 0 ]]; then
    exit 0
else
    exit 1
fi
