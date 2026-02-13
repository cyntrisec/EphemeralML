#!/usr/bin/env bash
# EphemeralML — Smoke test against a deployed Confidential Space CVM.
#
# Waits for the enclave to be reachable, runs inference, saves receipt, verifies it.
# Always uses --features gcp so the client speaks the same TDX handshake protocol
# as the enclave.
#
# Usage:
#   bash scripts/gcp/verify.sh                         # auto-detect IP from gcloud
#   bash scripts/gcp/verify.sh --ip 34.72.100.50       # explicit IP
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTANCE_NAME="ephemeralml-cvm"
DATA_PORT=9000            # direct mode: client connects to single port (9000)
CONTROL_PORT=9000         # used only for the reachability probe
RECEIPT_PATH="/tmp/ephemeralml-receipt.cbor"
MAX_WAIT=180              # seconds to wait for port reachability
INFERENCE_TEXT="Verify EphemeralML on Confidential Space"

# Defaults — project must come from env or --project flag
PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
ZONE="us-central1-a"
IP=""

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)      IP="$2"; shift 2 ;;
        --zone)    ZONE="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "${PROJECT}" ]]; then
    echo "ERROR: GCP project not set."
    echo "Set EPHEMERALML_GCP_PROJECT or pass --project PROJECT_ID"
    exit 1
fi

echo "============================================"
echo "  EphemeralML — Verify Deployment"
echo "============================================"
echo

# ---------------------------------------------------------------------------
# 1. Resolve instance IP
# ---------------------------------------------------------------------------
if [[ -z "${IP}" ]]; then
    echo "[1/4] Resolving instance IP..."
    IP="$(gcloud compute instances describe "${INSTANCE_NAME}" \
        --zone="${ZONE}" --project="${PROJECT}" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)"
    if [[ -z "${IP}" || "${IP}" == "None" ]]; then
        echo "ERROR: Could not resolve IP for '${INSTANCE_NAME}' in zone '${ZONE}'."
        echo "Is the instance running? Try: gcloud compute instances list --project=${PROJECT}"
        exit 1
    fi
    echo "  Instance IP: ${IP}"
else
    echo "[1/4] Using provided IP: ${IP}"
fi
echo

# ---------------------------------------------------------------------------
# 2. Wait for port to be reachable
# ---------------------------------------------------------------------------
echo "[2/4] Waiting for ${IP}:${CONTROL_PORT} to be reachable (max ${MAX_WAIT}s)..."
WAITED=0
while ! timeout 2 bash -c "echo >/dev/tcp/${IP}/${CONTROL_PORT}" 2>/dev/null; do
    WAITED=$((WAITED + 5))
    if [[ ${WAITED} -ge ${MAX_WAIT} ]]; then
        echo "ERROR: Port ${CONTROL_PORT} not reachable after ${MAX_WAIT}s."
        echo "Check:"
        echo "  - Firewall rule allows TCP ${CONTROL_PORT}: gcloud compute firewall-rules list --project=${PROJECT}"
        echo "  - Container is running: gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE} --command='sudo journalctl -u tee-container-runner --no-pager -n 50'"
        exit 1
    fi
    printf "  Waiting... [%d/%ds]\r" "${WAITED}" "${MAX_WAIT}"
    sleep 5
done
echo "  Port ${CONTROL_PORT} is reachable.                    "
echo

# ---------------------------------------------------------------------------
# 3. Run inference client
# ---------------------------------------------------------------------------
echo "[3/4] Running inference against ${IP}:${DATA_PORT}..."
echo "  Text: \"${INFERENCE_TEXT}\""
echo "  Mode: gcp (TDX attestation + handshake)"
echo

cd "${PROJECT_DIR}"

# Build client with gcp feature — must match the enclave's TDX handshake stack
echo "  Building client..."
cargo build --release --no-default-features --features gcp \
    -p ephemeral-ml-client 2>&1 | tail -3

# The GCP-mode client reads EPHEMERALML_ENCLAVE_ADDR for the server address.
# It connects to the data_in port (9001) where the enclave accepts inference traffic.
EPHEMERALML_ENCLAVE_ADDR="${IP}:${DATA_PORT}" \
    cargo run --release --no-default-features --features gcp \
    -p ephemeral-ml-client --bin ephemeral-ml-client 2>&1 | tee /tmp/ephemeralml-verify-output.txt

CLIENT_EXIT=${PIPESTATUS[0]}

if [[ ${CLIENT_EXIT} -ne 0 ]]; then
    echo
    echo "ERROR: Client exited with code ${CLIENT_EXIT}."
    echo "Check the output above for details."
    exit 1
fi
echo
echo "  Inference completed successfully."
echo

# ---------------------------------------------------------------------------
# 4. Verify receipt (if saved)
# ---------------------------------------------------------------------------
RECEIPT_VERIFIED=false

echo "[4/4] Verifying receipt..."

if [[ -f "${RECEIPT_PATH}" ]]; then
    # Extract public key from client output if available
    PK_HEX="$(grep -oP 'receipt_signing_key: \K[0-9a-f]{64}' /tmp/ephemeralml-verify-output.txt 2>/dev/null || true)"

    if [[ -n "${PK_HEX}" ]]; then
        echo "  Receipt: ${RECEIPT_PATH}"
        echo "  Public key: ${PK_HEX}"
        echo

        cargo run --release --no-default-features --features gcp \
            --bin ephemeralml-verify -- \
            "${RECEIPT_PATH}" \
            --public-key "${PK_HEX}" \
            --max-age 0 \
            --format text
        VERIFY_EXIT=$?
        RECEIPT_VERIFIED=true
    else
        echo "  WARNING: Receipt file exists but could not extract public key from client output."
        echo "  Receipt at: ${RECEIPT_PATH}"
        VERIFY_EXIT=1
    fi
else
    echo "  WARNING: No receipt file at ${RECEIPT_PATH}."
    echo "  The client may not save receipts in this mode."
    VERIFY_EXIT=1
fi
echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "============================================"
if [[ ${CLIENT_EXIT} -eq 0 && ${RECEIPT_VERIFIED} == true && ${VERIFY_EXIT} -eq 0 ]]; then
    echo "  PASS — Inference + receipt verification succeeded."
elif [[ ${CLIENT_EXIT} -eq 0 ]]; then
    echo "  PARTIAL — Inference succeeded, receipt NOT verified."
else
    echo "  FAIL — See errors above."
fi
echo "============================================"
echo
echo "  Instance:   ${INSTANCE_NAME} (${IP})"
echo "  Client:     exit ${CLIENT_EXIT}"
echo "  Receipt:    $(if ${RECEIPT_VERIFIED}; then echo "VERIFIED"; else echo "NOT VERIFIED"; fi)"
echo
echo "  Next: bash scripts/gcp/teardown.sh"

# Exit 0 only when both client and receipt verification passed
if [[ ${CLIENT_EXIT} -eq 0 && ${VERIFY_EXIT} -eq 0 ]]; then
    exit 0
else
    exit 1
fi
