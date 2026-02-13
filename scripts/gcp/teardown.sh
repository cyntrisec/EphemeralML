#!/usr/bin/env bash
# EphemeralML — Delete the Confidential Space CVM.
#
# Does NOT delete the Artifact Registry repo, service account, or firewall rule
# (those are reusable across deployments).
#
# Usage:
#   bash scripts/gcp/teardown.sh
#   bash scripts/gcp/teardown.sh --delete-image   # also delete the container image tag
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTANCE_NAME="ephemeralml-cvm"
REPO_LOCATION="us"
REPO_NAME="ephemeralml"

# Defaults — project must come from env or --project flag
PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
ZONE="us-central1-a"
DELETE_IMAGE=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --delete-image) DELETE_IMAGE=true; shift ;;
        --zone)         ZONE="$2"; shift 2 ;;
        --project)      PROJECT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "${PROJECT}" ]]; then
    echo "ERROR: GCP project not set."
    echo "Set EPHEMERALML_GCP_PROJECT or pass --project PROJECT_ID"
    exit 1
fi

echo "============================================"
echo "  EphemeralML — Teardown"
echo "============================================"
echo

# ---------------------------------------------------------------------------
# 1. Get instance info (for cost summary)
# ---------------------------------------------------------------------------
CREATION_TIME=""
if gcloud compute instances describe "${INSTANCE_NAME}" \
    --zone="${ZONE}" --project="${PROJECT}" &>/dev/null; then

    CREATION_TIME="$(gcloud compute instances describe "${INSTANCE_NAME}" \
        --zone="${ZONE}" --project="${PROJECT}" \
        --format='value(creationTimestamp)' 2>/dev/null || true)"

    echo "[1/2] Deleting instance '${INSTANCE_NAME}' in zone '${ZONE}'..."
    gcloud compute instances delete "${INSTANCE_NAME}" \
        --zone="${ZONE}" --project="${PROJECT}" --quiet
    echo "  Instance deleted."
else
    echo "[1/2] Instance '${INSTANCE_NAME}' not found in zone '${ZONE}'. Nothing to delete."
fi
echo

# ---------------------------------------------------------------------------
# 2. Optionally delete container image
# ---------------------------------------------------------------------------
if $DELETE_IMAGE; then
    echo "[2/2] Deleting container images..."
    # List and delete all tags in the enclave image
    IMAGES="$(gcloud artifacts docker images list \
        "${REPO_LOCATION}-docker.pkg.dev/${PROJECT}/${REPO_NAME}/enclave" \
        --project="${PROJECT}" \
        --format='value(version)' 2>/dev/null || true)"

    if [[ -n "${IMAGES}" ]]; then
        while IFS= read -r digest; do
            echo "  Deleting: enclave@${digest}"
            gcloud artifacts docker images delete \
                "${REPO_LOCATION}-docker.pkg.dev/${PROJECT}/${REPO_NAME}/enclave@${digest}" \
                --project="${PROJECT}" --quiet 2>/dev/null || true
        done <<< "${IMAGES}"
        echo "  Images deleted."
    else
        echo "  No images found in ${REPO_NAME}/enclave."
    fi
else
    echo "[2/2] Skipping image cleanup (use --delete-image to remove)."
fi
echo

# ---------------------------------------------------------------------------
# Cost summary
# ---------------------------------------------------------------------------
echo "============================================"
echo "  Teardown complete."
echo "============================================"
echo
if [[ -n "${CREATION_TIME}" ]]; then
    # Compute approximate runtime
    CREATED_EPOCH="$(date -d "${CREATION_TIME}" +%s 2>/dev/null || echo 0)"
    NOW_EPOCH="$(date +%s)"
    if [[ ${CREATED_EPOCH} -gt 0 ]]; then
        RUNTIME_MIN=$(( (NOW_EPOCH - CREATED_EPOCH) / 60 ))
        echo "  Instance ran for ~${RUNTIME_MIN} minutes."
        # c3-standard-4: ~$0.209/hr (us-central1, on-demand)
        COST="$(echo "scale=2; ${RUNTIME_MIN} * 0.209 / 60" | bc 2>/dev/null || echo '?')"
        echo "  Estimated cost: ~\$${COST} (c3-standard-4 on-demand)"
    fi
fi
echo
echo "  Preserved resources (reusable):"
echo "    - Artifact Registry: ${REPO_LOCATION}-docker.pkg.dev/${PROJECT}/${REPO_NAME}"
echo "    - Service account:   ephemeralml-cvm@${PROJECT}.iam.gserviceaccount.com"
echo "    - Firewall rule:     allow-ephemeralml"
echo
