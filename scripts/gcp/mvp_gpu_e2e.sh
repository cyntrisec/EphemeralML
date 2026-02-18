#!/usr/bin/env bash
# MVP GPU End-to-End golden path for EphemeralML on GCP Confidential Space.
# Chains: KMS setup → package model → deploy (GPU or CPU) → inference + receipt →
#         receipt verify → compliance collect → compliance verify → compliance export →
#         negative tests → teardown
#
# Usage:
#   bash scripts/gcp/mvp_gpu_e2e.sh --project PROJECT_ID [options]
#
# Options:
#   --project PROJECT_ID    GCP project (required, or set EPHEMERALML_GCP_PROJECT)
#   --zone ZONE             GCP zone (default: us-central1-a)
#   --cpu-only              Use c3-standard-4 instead of a3-highgpu-1g
#   --skip-setup            Skip KMS/WIP setup (reuse existing infra)
#   --skip-teardown         Skip VM teardown at end
#   --model-dir DIR         Local model directory (default: test_assets/minilm)
#   --model-format FORMAT   Model format: safetensors or gguf (default: safetensors)
#
# Outputs: evidence/mvp-{TIMESTAMP}/ with receipt, pubkey, logs, compliance bundle
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PROJECT=""
ZONE="us-central1-a"
REGION="us-central1"
CPU_ONLY=false
SKIP_SETUP=false
SKIP_TEARDOWN=false
MODEL_DIR="${PROJECT_DIR}/test_assets/minilm"
MODEL_FORMAT="safetensors"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)       PROJECT="$2"; shift 2 ;;
        --zone)          ZONE="$2"; shift 2 ;;
        --cpu-only)      CPU_ONLY=true; shift ;;
        --skip-setup)    SKIP_SETUP=true; shift ;;
        --skip-teardown) SKIP_TEARDOWN=true; shift ;;
        --model-dir)     MODEL_DIR="$2"; shift 2 ;;
        --model-format)  MODEL_FORMAT="$2"; shift 2 ;;
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

# Timestamps and evidence directory
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%S")"
EVIDENCE_DIR="${PROJECT_DIR}/evidence/mvp-${TIMESTAMP}"
mkdir -p "${EVIDENCE_DIR}"

# Machine type
if $CPU_ONLY; then
    MACHINE_TYPE="c3-standard-4"
    GPU_FLAG=""
else
    MACHINE_TYPE="a3-highgpu-1g"
    GPU_FLAG="--gpu"
fi

STEP_COUNT=10
PASS_COUNT=0
FAIL_COUNT=0

step_pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo "  -> PASS"; }
step_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo "  -> FAIL: $1"; }

echo "============================================"
echo "  EphemeralML — MVP GPU E2E Golden Path"
echo "============================================"
echo
echo "  Project:      ${PROJECT}"
echo "  Zone:         ${ZONE}"
echo "  Machine:      ${MACHINE_TYPE}"
echo "  Model dir:    ${MODEL_DIR}"
echo "  Model format: ${MODEL_FORMAT}"
echo "  Timestamp:    ${TIMESTAMP}"
echo "  Evidence:     ${EVIDENCE_DIR}/"
echo "  Skip setup:   ${SKIP_SETUP}"
echo "  Skip teardown:${SKIP_TEARDOWN}"
echo

# ---------------------------------------------------------------------------
# [1/10] KMS + WIP Infrastructure Setup
# ---------------------------------------------------------------------------
echo "[1/${STEP_COUNT}] KMS + WIP infrastructure setup..."
if $SKIP_SETUP; then
    echo "  Skipping (--skip-setup). Using existing env vars."
    if [[ -z "${GCP_KMS_KEY:-}" || -z "${GCP_WIP_AUDIENCE:-}" || -z "${GCP_BUCKET:-}" ]]; then
        echo "ERROR: --skip-setup requires GCP_KMS_KEY, GCP_WIP_AUDIENCE, GCP_BUCKET to be set"
        exit 1
    fi
    step_pass
else
    if bash "${SCRIPT_DIR}/setup_kms.sh" "${PROJECT}" "${REGION}" \
        2>&1 | tee "${EVIDENCE_DIR}/setup_kms_log.txt"; then

        KEYRING="ephemeralml"
        KEY="model-dek"
        POOL="ephemeralml-pool"
        PROVIDER="ephemeralml-tdx"
        PROJECT_NUMBER=$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')

        export GCP_KMS_KEY="projects/${PROJECT}/locations/${REGION}/keyRings/${KEYRING}/cryptoKeys/${KEY}"
        export GCP_WIP_AUDIENCE="//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/providers/${PROVIDER}"
        export GCP_BUCKET="ephemeralml-models-${PROJECT}"
        step_pass
    else
        step_fail "setup_kms.sh failed"
    fi
fi
echo

# ---------------------------------------------------------------------------
# [2/10] Package Model
# ---------------------------------------------------------------------------
echo "[2/${STEP_COUNT}] Packaging model..."
if bash "${SCRIPT_DIR}/package_model.sh" "${MODEL_DIR}" "models/minilm" \
    2>&1 | tee "${EVIDENCE_DIR}/package_model_log.txt"; then

    EXPECTED_MODEL_HASH="$(grep -oP 'SHA-256:\s+\K[0-9a-fA-F]{64}' \
        "${EVIDENCE_DIR}/package_model_log.txt" | tail -1 || true)"
    MODEL_SIGNING_PUBKEY="$(grep -oP 'EPHEMERALML_MODEL_SIGNING_PUBKEY\s+\K[0-9a-fA-F]{64}' \
        "${EVIDENCE_DIR}/package_model_log.txt" | tail -1 || true)"

    if [[ -z "${EXPECTED_MODEL_HASH}" ]]; then
        step_fail "Could not extract model hash"
    else
        echo "  Model hash: ${EXPECTED_MODEL_HASH}"
        [[ -n "${MODEL_SIGNING_PUBKEY}" ]] && echo "  Signing pubkey: ${MODEL_SIGNING_PUBKEY}"
        [[ -n "${MODEL_SIGNING_PUBKEY}" ]] && export EPHEMERALML_MODEL_SIGNING_PUBKEY="${MODEL_SIGNING_PUBKEY}"
        step_pass
    fi
else
    step_fail "package_model.sh failed"
    EXPECTED_MODEL_HASH=""
fi
echo

# ---------------------------------------------------------------------------
# [3/10] Deploy
# ---------------------------------------------------------------------------
echo "[3/${STEP_COUNT}] Deploying (${MACHINE_TYPE})..."
DEPLOY_ARGS=(
    --project "${PROJECT}"
    --zone "${ZONE}"
    --model-source gcs-kms
    --kms-key "${GCP_KMS_KEY}"
    --wip-audience "${GCP_WIP_AUDIENCE}"
    --bucket "${GCP_BUCKET:-}"
    --model-prefix "models/minilm"
    --model-hash "${EXPECTED_MODEL_HASH}"
)
[[ -n "${GPU_FLAG}" ]] && DEPLOY_ARGS+=("${GPU_FLAG}")
[[ -n "${MODEL_SIGNING_PUBKEY:-}" ]] && DEPLOY_ARGS+=(--model-signing-pubkey "${MODEL_SIGNING_PUBKEY}")

if bash "${SCRIPT_DIR}/deploy.sh" "${DEPLOY_ARGS[@]}" \
    2>&1 | tee "${EVIDENCE_DIR}/deploy_log.txt"; then
    step_pass
else
    step_fail "deploy.sh failed"
fi
echo

# ---------------------------------------------------------------------------
# [4/10] Inference + Receipt
# ---------------------------------------------------------------------------
BOOT_TIMEOUT=300
if ! $CPU_ONLY; then
    BOOT_TIMEOUT=300  # GPU boot can take longer
fi
echo "[4/${STEP_COUNT}] Inference + receipt (timeout: ${BOOT_TIMEOUT}s)..."
if bash "${SCRIPT_DIR}/verify.sh" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    2>&1 | tee "${EVIDENCE_DIR}/verify_output.txt"; then
    VERIFY_EXIT=0
    step_pass
else
    VERIFY_EXIT=$?
    step_fail "verify.sh exit code ${VERIFY_EXIT}"
fi

# Copy receipt and pubkey artifacts
if [[ -f /tmp/ephemeralml-receipt.cbor ]]; then
    cp /tmp/ephemeralml-receipt.cbor "${EVIDENCE_DIR}/receipt.cbor"
fi
if [[ -f /tmp/ephemeralml-receipt.pubkey ]]; then
    cp /tmp/ephemeralml-receipt.pubkey "${EVIDENCE_DIR}/receipt.pubkey"
fi
echo

# ---------------------------------------------------------------------------
# [5/10] Receipt Verification
# ---------------------------------------------------------------------------
echo "[5/${STEP_COUNT}] Receipt verification (ephemeralml-verify)..."
VERIFY_BIN="${PROJECT_DIR}/target/release/ephemeralml-verify"
if [[ ! -x "${VERIFY_BIN}" ]]; then
    # Try building if not present
    VERIFY_BIN="${PROJECT_DIR}/target/debug/ephemeralml-verify"
fi

if [[ -f "${EVIDENCE_DIR}/receipt.cbor" ]] && [[ -x "${VERIFY_BIN}" ]]; then
    VERIFY_ARGS=("${EVIDENCE_DIR}/receipt.cbor")
    [[ -f "${EVIDENCE_DIR}/receipt.pubkey" ]] && VERIFY_ARGS+=(--public-key-file "${EVIDENCE_DIR}/receipt.pubkey")

    if "${VERIFY_BIN}" "${VERIFY_ARGS[@]}" \
        2>&1 | tee "${EVIDENCE_DIR}/receipt_verify_log.txt"; then
        step_pass
    else
        step_fail "ephemeralml-verify failed"
    fi
else
    step_fail "receipt.cbor or ephemeralml-verify not found"
fi
echo

# ---------------------------------------------------------------------------
# [6/10] Compliance Collect
# ---------------------------------------------------------------------------
echo "[6/${STEP_COUNT}] Compliance collect..."
COMPLIANCE_BIN="${PROJECT_DIR}/target/release/ephemeralml-compliance"
if [[ ! -x "${COMPLIANCE_BIN}" ]]; then
    COMPLIANCE_BIN="${PROJECT_DIR}/target/debug/ephemeralml-compliance"
fi

if [[ -x "${COMPLIANCE_BIN}" ]]; then
    if "${COMPLIANCE_BIN}" collect \
        --evidence-dir "${EVIDENCE_DIR}" \
        --output "${EVIDENCE_DIR}/compliance-bundle.json" \
        2>&1 | tee "${EVIDENCE_DIR}/compliance_collect_log.txt"; then
        step_pass
    else
        step_fail "compliance collect failed"
    fi
else
    step_fail "ephemeralml-compliance binary not found"
fi
echo

# ---------------------------------------------------------------------------
# [7/10] Compliance Verify
# ---------------------------------------------------------------------------
echo "[7/${STEP_COUNT}] Compliance verify (--profile baseline)..."
if [[ -x "${COMPLIANCE_BIN}" ]] && [[ -f "${EVIDENCE_DIR}/compliance-bundle.json" ]]; then
    if "${COMPLIANCE_BIN}" verify \
        --bundle "${EVIDENCE_DIR}/compliance-bundle.json" \
        --profile baseline \
        2>&1 | tee "${EVIDENCE_DIR}/compliance_verify_log.txt"; then
        step_pass
    else
        step_fail "compliance verify failed"
    fi
else
    step_fail "compliance binary or bundle not found"
fi
echo

# ---------------------------------------------------------------------------
# [8/10] Compliance Export + Sign
# ---------------------------------------------------------------------------
echo "[8/${STEP_COUNT}] Compliance export..."
if [[ -x "${COMPLIANCE_BIN}" ]] && [[ -f "${EVIDENCE_DIR}/compliance-bundle.json" ]]; then
    if "${COMPLIANCE_BIN}" export \
        --bundle "${EVIDENCE_DIR}/compliance-bundle.json" \
        --output "${EVIDENCE_DIR}/compliance-report" \
        2>&1 | tee "${EVIDENCE_DIR}/compliance_export_log.txt"; then
        step_pass
    else
        step_fail "compliance export failed"
    fi
else
    step_fail "compliance binary or bundle not found"
fi
echo

# ---------------------------------------------------------------------------
# [9/10] Negative Tests
# ---------------------------------------------------------------------------
echo "[9/${STEP_COUNT}] Negative tests..."
NEGATIVE_PASS=0
NEGATIVE_TOTAL=0

# Test 1: Wrong model hash
echo "  [9a] Wrong model hash..."
NEGATIVE_TOTAL=$((NEGATIVE_TOTAL + 1))
bash "${SCRIPT_DIR}/teardown.sh" --project "${PROJECT}" --zone "${ZONE}" 2>&1 | tail -3

WRONG_HASH="0000000000000000000000000000000000000000000000000000000000000000"
bash "${SCRIPT_DIR}/deploy.sh" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    --model-source gcs-kms \
    --kms-key "${GCP_KMS_KEY}" \
    --wip-audience "${GCP_WIP_AUDIENCE}" \
    --bucket "${GCP_BUCKET:-}" \
    --model-prefix "models/minilm" \
    --model-hash "${WRONG_HASH}" \
    --skip-build \
    ${GPU_FLAG} \
    2>&1 | tee "${EVIDENCE_DIR}/negative_wrong_hash_deploy.txt" || true

echo "  Waiting 90s for container boot attempt..."
sleep 90

if bash "${SCRIPT_DIR}/verify.sh" --project "${PROJECT}" --zone "${ZONE}" \
    2>&1 | tee "${EVIDENCE_DIR}/negative_wrong_hash_verify.txt"; then
    echo "  [9a] UNEXPECTED PASS (container should reject wrong hash)"
else
    echo "  [9a] Correctly failed (wrong hash rejected)"
    NEGATIVE_PASS=$((NEGATIVE_PASS + 1))
fi

# Test 2: Wrong KMS key (non-existent)
echo "  [9b] Wrong KMS key..."
NEGATIVE_TOTAL=$((NEGATIVE_TOTAL + 1))
bash "${SCRIPT_DIR}/teardown.sh" --project "${PROJECT}" --zone "${ZONE}" 2>&1 | tail -3

WRONG_KEY="projects/${PROJECT}/locations/${REGION}/keyRings/nonexistent/cryptoKeys/fake"
bash "${SCRIPT_DIR}/deploy.sh" \
    --project "${PROJECT}" \
    --zone "${ZONE}" \
    --model-source gcs-kms \
    --kms-key "${WRONG_KEY}" \
    --wip-audience "${GCP_WIP_AUDIENCE}" \
    --bucket "${GCP_BUCKET:-}" \
    --model-prefix "models/minilm" \
    --model-hash "${EXPECTED_MODEL_HASH}" \
    --skip-build \
    ${GPU_FLAG} \
    2>&1 | tee "${EVIDENCE_DIR}/negative_wrong_key_deploy.txt" || true

echo "  Waiting 90s for container boot attempt..."
sleep 90

if bash "${SCRIPT_DIR}/verify.sh" --project "${PROJECT}" --zone "${ZONE}" \
    2>&1 | tee "${EVIDENCE_DIR}/negative_wrong_key_verify.txt"; then
    echo "  [9b] UNEXPECTED PASS (container should reject wrong key)"
else
    echo "  [9b] Correctly failed (wrong KMS key rejected)"
    NEGATIVE_PASS=$((NEGATIVE_PASS + 1))
fi

if [[ ${NEGATIVE_PASS} -eq ${NEGATIVE_TOTAL} ]]; then
    step_pass
else
    step_fail "${NEGATIVE_PASS}/${NEGATIVE_TOTAL} negative tests passed"
fi
echo

# ---------------------------------------------------------------------------
# [10/10] Teardown
# ---------------------------------------------------------------------------
echo "[10/${STEP_COUNT}] Teardown..."
if $SKIP_TEARDOWN; then
    echo "  Skipping (--skip-teardown)."
    step_pass
else
    if bash "${SCRIPT_DIR}/teardown.sh" \
        --project "${PROJECT}" \
        --zone "${ZONE}" \
        2>&1 | tee "${EVIDENCE_DIR}/teardown_log.txt"; then
        step_pass
    else
        step_fail "teardown.sh failed"
    fi
fi
echo

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------
IMAGE_DIGEST="$(gcloud artifacts docker images list \
    "us-docker.pkg.dev/${PROJECT}/ephemeralml/enclave" \
    --project="${PROJECT}" \
    --format='value(version)' 2>/dev/null | head -1 || echo 'unknown')"

cat > "${EVIDENCE_DIR}/metadata.json" << EOF
{
  "version": "0.2.0",
  "project": "${PROJECT}",
  "zone": "${ZONE}",
  "machine_type": "${MACHINE_TYPE}",
  "model_format": "${MODEL_FORMAT}",
  "timestamp": "${TIMESTAMP}",
  "image_digest": "${IMAGE_DIGEST}",
  "model_hash": "${EXPECTED_MODEL_HASH:-unknown}",
  "kms_key": "${GCP_KMS_KEY:-}",
  "verify_exit": ${VERIFY_EXIT:-1},
  "negative_tests_passed": ${NEGATIVE_PASS},
  "negative_tests_total": ${NEGATIVE_TOTAL},
  "steps_passed": ${PASS_COUNT},
  "steps_total": ${STEP_COUNT}
}
EOF

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "============================================"
echo "  MVP GPU E2E — Results"
echo "============================================"
echo
echo "  Evidence: ${EVIDENCE_DIR}/"
echo
echo "  Files:"
for f in "${EVIDENCE_DIR}"/*; do
    [[ -f "$f" ]] && echo "    $(basename "$f")  ($(du -h "$f" | cut -f1))"
done
echo
echo "  Steps:          ${PASS_COUNT}/${STEP_COUNT} passed"
echo "  Negative tests: ${NEGATIVE_PASS}/${NEGATIVE_TOTAL} correctly failed"
echo

if [[ ${PASS_COUNT} -eq ${STEP_COUNT} ]]; then
    echo "  RESULT: PASS (all ${STEP_COUNT} steps green)"
    exit 0
elif [[ ${PASS_COUNT} -ge $((STEP_COUNT - 2)) ]]; then
    echo "  RESULT: PARTIAL PASS (${FAIL_COUNT} steps failed)"
    exit 0
else
    echo "  RESULT: FAIL (${FAIL_COUNT} steps failed)"
    exit 1
fi
