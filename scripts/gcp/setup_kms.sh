#!/usr/bin/env bash
# setup_kms.sh — Create GCP infrastructure for attestation-bound model release.
#
# Creates:
#   - KMS keyring + symmetric key for model DEK wrapping
#   - Workload Identity Pool + OIDC provider for TDX attestation
#   - IAM binding: WIP principals → cloudkms.cryptoKeyDecrypter
#   - GCS bucket for encrypted models
#
# Usage:
#   bash scripts/gcp/setup_kms.sh [PROJECT_ID] [REGION]
#
# Defaults: PROJECT_ID=$GOOGLE_CLOUD_PROJECT or "ephemeralml", REGION="us-central1"

set -euo pipefail

PROJECT="${1:-${GOOGLE_CLOUD_PROJECT:-ephemeralml}}"
REGION="${2:-us-central1}"

KEYRING="ephemeralml"
KEY="model-dek"
POOL="ephemeralml-pool"
PROVIDER="ephemeralml-tdx"
BUCKET="ephemeralml-models-${PROJECT}"
ISSUER="https://confidentialcomputing.googleapis.com"

echo "=== EphemeralML KMS + WIP Setup ==="
echo "  Project:  ${PROJECT}"
echo "  Region:   ${REGION}"
echo "  Keyring:  ${KEYRING}"
echo "  Key:      ${KEY}"
echo "  Pool:     ${POOL}"
echo "  Provider: ${PROVIDER}"
echo "  Bucket:   ${BUCKET}"
echo ""

# 1. KMS keyring + symmetric key
echo "[1/5] Creating KMS keyring and key..."
gcloud kms keyrings create "${KEYRING}" \
    --project="${PROJECT}" \
    --location="${REGION}" \
    2>/dev/null || echo "  Keyring already exists"

gcloud kms keys create "${KEY}" \
    --project="${PROJECT}" \
    --location="${REGION}" \
    --keyring="${KEYRING}" \
    --purpose=encryption \
    2>/dev/null || echo "  Key already exists"

KMS_KEY_RESOURCE="projects/${PROJECT}/locations/${REGION}/keyRings/${KEYRING}/cryptoKeys/${KEY}"
echo "  KMS key: ${KMS_KEY_RESOURCE}"

# 2. Workload Identity Pool
echo "[2/5] Creating Workload Identity Pool..."
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')

gcloud iam workload-identity-pools create "${POOL}" \
    --project="${PROJECT}" \
    --location="global" \
    --display-name="EphemeralML TDX Attestation Pool" \
    2>/dev/null || echo "  Pool already exists"

# 3. OIDC Provider (Confidential Computing attestation)
echo "[3/5] Creating OIDC provider for TDX attestation..."

# Compute WIP_AUDIENCE first — the provider must accept tokens with this audience.
# CsKmsClient requests Launcher tokens with aud=WIP_AUDIENCE, so --allowed-audiences must match.
WIP_AUDIENCE="//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/providers/${PROVIDER}"

CREATE_OUTPUT=$(gcloud iam workload-identity-pools providers create-oidc "${PROVIDER}" \
    --project="${PROJECT}" \
    --location="global" \
    --workload-identity-pool="${POOL}" \
    --issuer-uri="${ISSUER}" \
    --allowed-audiences="${WIP_AUDIENCE}" \
    --attribute-mapping="google.subject=assertion.sub,attribute.image_digest=assertion.submods.container.image_digest,attribute.gpu_cc_mode=assertion.submods.nvidia_gpu.cc_mode" \
    2>&1) || {
    if echo "${CREATE_OUTPUT}" | grep -qi "already exists"; then
        echo "  Provider already exists — updating allowed-audiences..."
        gcloud iam workload-identity-pools providers update-oidc "${PROVIDER}" \
            --project="${PROJECT}" \
            --location="global" \
            --workload-identity-pool="${POOL}" \
            --allowed-audiences="${WIP_AUDIENCE}" \
            2>&1 || {
            echo "ERROR: Failed to update WIP provider allowed-audiences."
            echo "  Output: ${CREATE_OUTPUT}"
            exit 1
        }
    else
        echo "ERROR: Failed to create WIP OIDC provider."
        echo "  Output: ${CREATE_OUTPUT}"
        exit 1
    fi
}

echo "  WIP audience: ${WIP_AUDIENCE}"
echo "  Attribute mappings:"
echo "    attribute.image_digest  = assertion.submods.container.image_digest"
echo "    attribute.gpu_cc_mode   = assertion.submods.nvidia_gpu.cc_mode"
echo ""
echo "  To gate KMS key release on GPU CC mode (recommended for GPU deployments),"
echo "  add an attribute condition to the IAM binding:"
echo "    attribute.gpu_cc_mode == 'ON'"

# 4. IAM: WIP principals → KMS decrypter
echo "[4/5] Granting KMS decrypt permission to WIP principals..."
gcloud kms keys add-iam-policy-binding "${KEY}" \
    --project="${PROJECT}" \
    --location="${REGION}" \
    --keyring="${KEYRING}" \
    --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/*" \
    --role="roles/cloudkms.cryptoKeyDecrypter" \
    2>/dev/null || echo "  Binding already exists"

# 5. GCS bucket
echo "[5/5] Creating GCS bucket..."
gcloud storage buckets create "gs://${BUCKET}" \
    --project="${PROJECT}" \
    --location="${REGION}" \
    --uniform-bucket-level-access \
    2>/dev/null || echo "  Bucket already exists"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Export these for server invocation:"
echo "  export GCP_KMS_KEY=${KMS_KEY_RESOURCE}"
echo "  export GCP_WIP_AUDIENCE=${WIP_AUDIENCE}"
echo "  export GCP_BUCKET=${BUCKET}"
echo ""
echo "Next: encrypt and upload a model with:"
echo "  bash scripts/gcp/encrypt_model.sh <model_dir> <gcs_prefix>"
