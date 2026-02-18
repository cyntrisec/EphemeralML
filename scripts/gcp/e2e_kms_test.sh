#!/usr/bin/env bash
# Full end-to-end KMS-gated model release test on GCP Confidential Space.
# Chains: setup_kms → encrypt_model → deploy (gcs-kms) → verify → evidence → teardown
#
# Usage:
#   bash scripts/gcp/e2e_kms_test.sh --project PROJECT_ID [--zone ZONE] [--skip-setup]
#
# Outputs: evidence/ directory with receipts, logs, attestation artifacts
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PROJECT=""
ZONE="us-central1-a"
REGION="us-central1"
SKIP_SETUP=false
MODEL_DIR="${PROJECT_DIR}/test_assets/minilm"
EVIDENCE_DIR="${PROJECT_DIR}/evidence"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)    PROJECT="$2"; shift 2 ;;
        --zone)       ZONE="$2"; shift 2 ;;
        --skip-setup) SKIP_SETUP=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

REGION="${ZONE%-*}"

if [[ -z "${PROJECT}" ]]; then
    PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
fi
if [[ -z "${PROJECT}" ]]; then
    echo "ERROR: --project is required (or set EPHEMERALML_GCP_PROJECT)"
    exit 1
fi

export EPHEMERALML_GCP_PROJECT="${PROJECT}"

# Timestamps
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%S")"
mkdir -p "${EVIDENCE_DIR}"

echo "============================================"
echo "  EphemeralML — E2E KMS Test"
echo "============================================"
echo
echo "  Project:    ${PROJECT}"
echo "  Zone:       ${ZONE}"
echo "  Timestamp:  ${TIMESTAMP}"
echo "  Evidence:   ${EVIDENCE_DIR}/"
echo "  Skip setup: ${SKIP_SETUP}"
echo

# ---------------------------------------------------------------------------
# Step 1: KMS + WIP Infrastructure Setup
# ---------------------------------------------------------------------------
if $SKIP_SETUP; then
    echo "[1/7] Skipping KMS setup (--skip-setup)."
    echo "  Using existing env: GCP_KMS_KEY, GCP_WIP_AUDIENCE, GCP_BUCKET"
    if [[ -z "${GCP_KMS_KEY:-}" || -z "${GCP_WIP_AUDIENCE:-}" || -z "${GCP_BUCKET:-}" ]]; then
        echo "ERROR: --skip-setup requires GCP_KMS_KEY, GCP_WIP_AUDIENCE, GCP_BUCKET to be set"
        exit 1
    fi
else
    echo "[1/7] Setting up KMS + WIP infrastructure..."
    export GOOGLE_CLOUD_PROJECT="${PROJECT}"
    bash "${SCRIPT_DIR}/setup_kms.sh" "${PROJECT}" "${REGION}" 2>&1 | tee "${EVIDENCE_DIR}/setup_kms_log.txt"

    # Extract outputs from setup_kms.sh
    KEYRING="ephemeralml"
    KEY="model-dek"
    POOL="ephemeralml-pool"
    PROVIDER="ephemeralml-tdx"
    PROJECT_NUMBER=$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')

    export GCP_KMS_KEY="projects/${PROJECT}/locations/${REGION}/keyRings/${KEYRING}/cryptoKeys/${KEY}"
    export GCP_WIP_AUDIENCE="//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/providers/${PROVIDER}"
    export GCP_BUCKET="ephemeralml-models-${PROJECT}"
fi
echo

# ---------------------------------------------------------------------------
# Step 2: Encrypt model and upload to GCS
# ---------------------------------------------------------------------------
echo "[2/7] Packaging model with manifest and uploading to GCS..."
bash "${SCRIPT_DIR}/package_model.sh" "${MODEL_DIR}" "models/minilm" 2>&1 | tee "${EVIDENCE_DIR}/package_model_log.txt"

# Extract model hash from package_model.sh output.
# Match "SHA-256: <64 hex chars>" to avoid false matches on other lines.
EXPECTED_MODEL_HASH="$(grep -oP 'SHA-256:\s+\K[0-9a-fA-F]{64}' "${EVIDENCE_DIR}/package_model_log.txt" | tail -1)"
if [[ -z "${EXPECTED_MODEL_HASH}" ]]; then
    echo "ERROR: Could not extract model hash from package_model.sh output."
    echo "  Looked for 'SHA-256: <64 hex chars>' in ${EVIDENCE_DIR}/package_model_log.txt"
    echo "  Last 10 lines of log:"
    tail -10 "${EVIDENCE_DIR}/package_model_log.txt" || true
    exit 1
fi

# Extract public key for manifest verification.
# Match "EPHEMERALML_MODEL_SIGNING_PUBKEY <64 hex chars>" pattern.
MODEL_SIGNING_PUBKEY="$(grep -oP 'EPHEMERALML_MODEL_SIGNING_PUBKEY\s+\K[0-9a-fA-F]{64}' "${EVIDENCE_DIR}/package_model_log.txt" | tail -1 || true)"
if [[ -n "${MODEL_SIGNING_PUBKEY}" ]]; then
    echo "  Signing pubkey: ${MODEL_SIGNING_PUBKEY}"
    export EPHEMERALML_MODEL_SIGNING_PUBKEY="${MODEL_SIGNING_PUBKEY}"
fi

echo "  Model hash: ${EXPECTED_MODEL_HASH}"
echo

# ---------------------------------------------------------------------------
# Step 3: Deploy with --model-source gcs-kms
# ---------------------------------------------------------------------------
echo "[3/7] Deploying with KMS-gated model release..."
DEPLOY_ARGS=(
    --project "${PROJECT}"
    --zone "${ZONE}"
    --model-source gcs-kms
    --kms-key "${GCP_KMS_KEY}"
    --wip-audience "${GCP_WIP_AUDIENCE}"
    --bucket "${GCP_BUCKET}"
    --model-prefix "models/minilm"
    --model-hash "${EXPECTED_MODEL_HASH}"
)
if [[ -n "${MODEL_SIGNING_PUBKEY:-}" ]]; then
    DEPLOY_ARGS+=(--model-signing-pubkey "${MODEL_SIGNING_PUBKEY}")
fi
bash "${SCRIPT_DIR}/deploy.sh" "${DEPLOY_ARGS[@]}" \
    2>&1 | tee "${EVIDENCE_DIR}/deploy_log.txt"
echo

# ---------------------------------------------------------------------------
# Step 4: Wait for boot + verify
# ---------------------------------------------------------------------------
echo "[4/7] Verifying deployment (inference + receipt)..."
bash "${SCRIPT_DIR}/verify.sh" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    2>&1 | tee "${EVIDENCE_DIR}/verify_output.txt"
VERIFY_EXIT=${PIPESTATUS[0]}
echo

# Copy receipt if it was saved
if [[ -f /tmp/ephemeralml-receipt.json ]]; then
    cp /tmp/ephemeralml-receipt.json "${EVIDENCE_DIR}/receipt.json"
    echo "  Receipt saved to ${EVIDENCE_DIR}/receipt.json"
fi

# ---------------------------------------------------------------------------
# Step 5: Negative test — wrong model hash
# ---------------------------------------------------------------------------
echo "[5/7] Negative test: deploying with wrong --model-hash..."
WRONG_HASH="0000000000000000000000000000000000000000000000000000000000000000"

# Teardown existing instance first
bash "${SCRIPT_DIR}/teardown.sh" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    2>&1 | tail -5

# Deploy with wrong hash
bash "${SCRIPT_DIR}/deploy.sh" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    --model-source gcs-kms \
    --kms-key "${GCP_KMS_KEY}" \
    --wip-audience "${GCP_WIP_AUDIENCE}" \
    --bucket "${GCP_BUCKET}" \
    --model-prefix "models/minilm" \
    --model-hash "${WRONG_HASH}" \
    --skip-build \
    2>&1 | tee "${EVIDENCE_DIR}/negative_deploy_log.txt"

# Wait a shorter time — container should fail to start or reject the model
echo "  Waiting 90s for container to attempt model load..."
sleep 90

# Try to verify — should fail
if bash "${SCRIPT_DIR}/verify.sh" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    2>&1 | tee "${EVIDENCE_DIR}/negative_test.txt"; then
    echo "  WARNING: Negative test passed (unexpected — container should have rejected wrong hash)"
    NEGATIVE_RESULT="UNEXPECTED_PASS"
else
    echo "  Negative test correctly failed (container rejected wrong model hash)."
    NEGATIVE_RESULT="CORRECTLY_FAILED"
fi
echo

# ---------------------------------------------------------------------------
# Step 6: Collect evidence metadata
# ---------------------------------------------------------------------------
echo "[6/7] Collecting evidence metadata..."

# Get image digest
IMAGE_DIGEST="$(gcloud artifacts docker images list \
    "us-docker.pkg.dev/${PROJECT}/ephemeralml/enclave" \
    --project="${PROJECT}" \
    --format='value(version)' 2>/dev/null | head -1 || echo 'unknown')"

cat > "${EVIDENCE_DIR}/metadata.json" << EOF
{
  "project": "${PROJECT}",
  "zone": "${ZONE}",
  "timestamp": "${TIMESTAMP}",
  "image_digest": "${IMAGE_DIGEST}",
  "model_hash": "${EXPECTED_MODEL_HASH}",
  "kms_key": "${GCP_KMS_KEY}",
  "verify_exit": ${VERIFY_EXIT},
  "negative_test": "${NEGATIVE_RESULT}"
}
EOF
echo "  Metadata saved to ${EVIDENCE_DIR}/metadata.json"
echo

# ---------------------------------------------------------------------------
# Step 7: Teardown
# ---------------------------------------------------------------------------
echo "[7/7] Tearing down..."
bash "${SCRIPT_DIR}/teardown.sh" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    2>&1 | tee "${EVIDENCE_DIR}/teardown_log.txt"
echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "============================================"
echo "  E2E KMS Test Complete"
echo "============================================"
echo
echo "  Evidence directory: ${EVIDENCE_DIR}/"
echo
echo "  Files:"
for f in "${EVIDENCE_DIR}"/*; do
    echo "    $(basename "$f")  ($(du -h "$f" | cut -f1))"
done
echo
if [[ ${VERIFY_EXIT} -eq 0 && "${NEGATIVE_RESULT}" == "CORRECTLY_FAILED" ]]; then
    echo "  RESULT: PASS"
    echo "    - KMS-gated model release: OK"
    echo "    - Inference + receipt verification: OK"
    echo "    - Negative test (wrong hash rejected): OK"
elif [[ ${VERIFY_EXIT} -eq 0 ]]; then
    echo "  RESULT: PARTIAL PASS"
    echo "    - KMS-gated model release: OK"
    echo "    - Inference + receipt verification: OK"
    echo "    - Negative test: ${NEGATIVE_RESULT}"
else
    echo "  RESULT: FAIL"
    echo "    - Verify exit code: ${VERIFY_EXIT}"
    echo "    - Negative test: ${NEGATIVE_RESULT}"
fi
echo
