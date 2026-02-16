#!/usr/bin/env bash
# EphemeralML — Build container, push to Artifact Registry, launch Confidential Space CVM.
#
# Usage:
#   bash scripts/gcp/deploy.sh                     # production image (no SSH)
#   bash scripts/gcp/deploy.sh --debug              # debug image (SSH enabled)
#   bash scripts/gcp/deploy.sh --skip-build         # skip Docker build/push (image already in AR)
#   bash scripts/gcp/deploy.sh --tag v1.0           # custom image tag
#   bash scripts/gcp/deploy.sh --zone us-central1-b # custom zone
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_LOCATION="us"
REPO_NAME="ephemeralml"
INSTANCE_NAME="ephemeralml-cvm"
MACHINE_TYPE="c3-standard-4"
SA_NAME="ephemeralml-cvm"

# Defaults — project must come from env or --project flag
PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
ZONE="us-central1-a"
DEBUG=false
TAG=""
SKIP_BUILD=false

# KMS / model configuration — hydrate from env vars (set by init_gcp.sh / setup_kms.sh)
MODEL_SOURCE="${EPHEMERALML_MODEL_SOURCE:-local}"
KMS_KEY="${EPHEMERALML_GCP_KMS_KEY:-${GCP_KMS_KEY:-}}"
WIP_AUDIENCE="${EPHEMERALML_GCP_WIP_AUDIENCE:-${GCP_WIP_AUDIENCE:-}}"
GCS_BUCKET="${EPHEMERALML_GCS_BUCKET:-${GCP_BUCKET:-ephemeralml-models}}"
GCP_MODEL_PREFIX="${EPHEMERALML_GCP_MODEL_PREFIX:-models/minilm}"
EXPECTED_MODEL_HASH="${EPHEMERALML_EXPECTED_MODEL_HASH:-}"
MODEL_SIGNING_PUBKEY="${EPHEMERALML_MODEL_SIGNING_PUBKEY:-}"

YES=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)        DEBUG=true; shift ;;
        --skip-build)   SKIP_BUILD=true; shift ;;
        --yes|-y)       YES=true; shift ;;
        --tag)          TAG="$2"; shift 2 ;;
        --zone)         ZONE="$2"; shift 2 ;;
        --project)      PROJECT="$2"; shift 2 ;;
        --model-source) MODEL_SOURCE="$2"; shift 2 ;;
        --kms-key)       KMS_KEY="$2"; shift 2 ;;
        --wip-audience)  WIP_AUDIENCE="$2"; shift 2 ;;
        --bucket)       GCS_BUCKET="$2"; shift 2 ;;
        --model-prefix) GCP_MODEL_PREFIX="$2"; shift 2 ;;
        --model-hash)   EXPECTED_MODEL_HASH="$2"; shift 2 ;;
        --model-signing-pubkey) MODEL_SIGNING_PUBKEY="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate metadata-safe values: reject commas and shell metacharacters
# that could inject additional metadata items into the gcloud command.
validate_metadata_value() {
    local name="$1"
    local value="$2"
    if [[ "${value}" == *","* ]]; then
        echo "ERROR: ${name} contains a comma, which would corrupt instance metadata."
        echo "  Value: ${value}"
        exit 1
    fi
    if [[ "${value}" == *"'"* || "${value}" == *'"'* || "${value}" == *'$'* || "${value}" == *'`'* ]]; then
        echo "ERROR: ${name} contains shell metacharacters (quotes, \$, backticks)."
        echo "  Value: ${value}"
        exit 1
    fi
}

# Validate all user-controllable values that end up in instance metadata
for _var_name in PROJECT ZONE MODEL_SOURCE GCS_BUCKET GCP_MODEL_PREFIX KMS_KEY WIP_AUDIENCE EXPECTED_MODEL_HASH MODEL_SIGNING_PUBKEY; do
    _var_val="${!_var_name}"
    if [[ -n "${_var_val}" ]]; then
        validate_metadata_value "${_var_name}" "${_var_val}"
    fi
done

# Validate required flags for gcs-kms mode
if [[ "${MODEL_SOURCE}" == "gcs-kms" ]]; then
    for var in KMS_KEY WIP_AUDIENCE EXPECTED_MODEL_HASH; do
        if [[ -z "${!var}" ]]; then
            flag="$(echo "${var}" | tr '[:upper:]' '[:lower:]' | tr '_' '-')"
            echo "ERROR: --${flag} is required for --model-source=gcs-kms"
            exit 1
        fi
    done
fi

if [[ -z "${PROJECT}" ]]; then
    echo "ERROR: GCP project not set."
    echo "Set EPHEMERALML_GCP_PROJECT or pass --project PROJECT_ID"
    exit 1
fi

# Default tag: git short hash or 'latest'
if [[ -z "${TAG}" ]]; then
    TAG="$(git -C "${PROJECT_DIR}" rev-parse --short HEAD 2>/dev/null || echo 'latest')"
fi

SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
IMAGE_URI="${REPO_LOCATION}-docker.pkg.dev/${PROJECT}/${REPO_NAME}/enclave:${TAG}"

if $DEBUG; then
    CS_IMAGE_FAMILY="confidential-space-debug"
else
    CS_IMAGE_FAMILY="confidential-space"
fi

echo "============================================"
echo "  EphemeralML — Deploy to Confidential Space"
echo "============================================"
echo
echo "  Project:      ${PROJECT}"
echo "  Zone:         ${ZONE}"
echo "  Machine:      ${MACHINE_TYPE}"
echo "  Image:        ${IMAGE_URI}"
echo "  CS family:    ${CS_IMAGE_FAMILY}"
echo "  Debug:        ${DEBUG}"
echo "  Model source: ${MODEL_SOURCE}"
if [[ "${MODEL_SOURCE}" == "gcs-kms" ]]; then
    echo "  KMS key:      ${KMS_KEY}"
    echo "  WIP audience: ${WIP_AUDIENCE}"
    echo "  GCS bucket:   ${GCS_BUCKET}"
    echo "  Model prefix: ${GCP_MODEL_PREFIX}"
fi
echo

if $SKIP_BUILD; then
    echo "[1/6] Skipping model preparation (--skip-build)."
    echo "[2/6] Skipping Docker auth (--skip-build)."
    echo "[3/6] Skipping Docker build (--skip-build)."
    echo "[4/6] Skipping push (--skip-build). Using existing image: ${IMAGE_URI}"
    echo
else
    # ---------------------------------------------------------------------------
    # 1. Resolve model symlink (Docker cannot follow symlinks outside build context)
    # ---------------------------------------------------------------------------
    echo "[1/6] Preparing model files..."
    MODEL_DIR="${PROJECT_DIR}/test_assets/minilm"
    MODEL_WEIGHTS="${MODEL_DIR}/model.safetensors"
    RESTORED_SYMLINK=""

    if [[ -L "${MODEL_WEIGHTS}" ]]; then
        SYMLINK_TARGET="$(readlink -f "${MODEL_WEIGHTS}")"
        if [[ ! -f "${SYMLINK_TARGET}" ]]; then
            echo "ERROR: Model weights symlink target missing: ${SYMLINK_TARGET}"
            echo "Run: bash scripts/download_model.sh"
            exit 1
        fi
        # Save the symlink target so we can restore it after build
        RESTORED_SYMLINK="${SYMLINK_TARGET}"
        echo "  Temporarily resolving symlink for Docker build..."
        echo "  Symlink: model.safetensors -> ${SYMLINK_TARGET}"
        # Copy to a temp file first to avoid TOCTOU between readlink and cp
        # (symlink could be swapped between checks). Atomic rename ensures
        # the final file is always a complete copy.
        TMPFILE="${MODEL_WEIGHTS}.tmp.$$"
        cp "${SYMLINK_TARGET}" "${TMPFILE}"
        rm -f "${MODEL_WEIGHTS}"
        mv "${TMPFILE}" "${MODEL_WEIGHTS}"
        echo "  Copied $(du -h "${MODEL_WEIGHTS}" | cut -f1) model weights into build context."
    elif [[ ! -f "${MODEL_WEIGHTS}" ]]; then
        echo "ERROR: Model weights not found at ${MODEL_WEIGHTS}"
        echo "Run: bash scripts/download_model.sh"
        exit 1
    else
        echo "  Model weights already resolved ($(du -h "${MODEL_WEIGHTS}" | cut -f1))."
    fi
    echo

    # Restore symlink on exit (even if build fails)
    restore_symlink() {
        if [[ -n "${RESTORED_SYMLINK}" && -f "${MODEL_WEIGHTS}" && ! -L "${MODEL_WEIGHTS}" ]]; then
            rm -f "${MODEL_WEIGHTS}"
            ln -s "${RESTORED_SYMLINK}" "${MODEL_WEIGHTS}"
            echo "  Restored model.safetensors symlink."
        fi
    }
    trap restore_symlink EXIT

    # ---------------------------------------------------------------------------
    # 2. Authenticate Docker with Artifact Registry
    # ---------------------------------------------------------------------------
    echo "[2/6] Configuring Docker authentication..."
    gcloud auth configure-docker "${REPO_LOCATION}-docker.pkg.dev" --quiet
    echo "  Docker configured for ${REPO_LOCATION}-docker.pkg.dev"
    echo

    # ---------------------------------------------------------------------------
    # 3. Build container image
    # ---------------------------------------------------------------------------
    echo "[3/6] Building container image..."
    echo "  Tag: ${IMAGE_URI}"
    docker build \
        -f "${PROJECT_DIR}/Dockerfile.gcp" \
        -t "${IMAGE_URI}" \
        "${PROJECT_DIR}"
    echo "  Build complete."
    echo

    # ---------------------------------------------------------------------------
    # 4. Push to Artifact Registry
    # ---------------------------------------------------------------------------
    echo "[4/6] Pushing to Artifact Registry..."
    docker push "${IMAGE_URI}"
    echo "  Push complete."
    echo
fi

# ---------------------------------------------------------------------------
# 5. Launch Confidential Space CVM
# ---------------------------------------------------------------------------
echo "[5/6] Launching Confidential Space CVM..."

# Delete existing instance if present (avoids name conflict)
if gcloud compute instances describe "${INSTANCE_NAME}" \
    --zone="${ZONE}" --project="${PROJECT}" &>/dev/null; then
    echo "  Deleting existing instance '${INSTANCE_NAME}'..."
    gcloud compute instances delete "${INSTANCE_NAME}" \
        --zone="${ZONE}" --project="${PROJECT}" --quiet
fi

# Metadata for Confidential Space Launcher
METADATA="tee-image-reference=${IMAGE_URI}"
METADATA="${METADATA},tee-restart-policy=Never"
METADATA="${METADATA},tee-container-log-redirect=true"
METADATA="${METADATA},tee-env-EPHEMERALML_MODEL_SOURCE=${MODEL_SOURCE}"
METADATA="${METADATA},tee-env-EPHEMERALML_DIRECT=true"
METADATA="${METADATA},tee-env-EPHEMERALML_GCP_PROJECT=${PROJECT}"
METADATA="${METADATA},tee-env-EPHEMERALML_GCP_LOCATION=${ZONE%-*}"
if [[ -n "${KMS_KEY}" ]]; then
    METADATA="${METADATA},tee-env-EPHEMERALML_GCP_KMS_KEY=${KMS_KEY}"
    METADATA="${METADATA},tee-env-EPHEMERALML_GCP_WIP_AUDIENCE=${WIP_AUDIENCE}"
    METADATA="${METADATA},tee-env-EPHEMERALML_GCS_BUCKET=${GCS_BUCKET}"
    METADATA="${METADATA},tee-env-EPHEMERALML_GCP_MODEL_PREFIX=${GCP_MODEL_PREFIX}"
    METADATA="${METADATA},tee-env-EPHEMERALML_EXPECTED_MODEL_HASH=${EXPECTED_MODEL_HASH}"
fi
# Signing pubkey applies to both gcs and gcs-kms model sources
if [[ -n "${MODEL_SIGNING_PUBKEY}" ]]; then
    METADATA="${METADATA},tee-env-EPHEMERALML_MODEL_SIGNING_PUBKEY=${MODEL_SIGNING_PUBKEY}"
fi

gcloud compute instances create "${INSTANCE_NAME}" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --machine-type="${MACHINE_TYPE}" \
    --confidential-compute-type=TDX \
    --min-cpu-platform="Intel Sapphire Rapids" \
    --maintenance-policy=TERMINATE \
    --shielded-secure-boot \
    --image-project=confidential-space-images \
    --image-family="${CS_IMAGE_FAMILY}" \
    --metadata="${METADATA}" \
    --tags=ephemeralml \
    --service-account="${SA_EMAIL}" \
    --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/cloudkms,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write

echo "  Instance '${INSTANCE_NAME}' created."
echo

# ---------------------------------------------------------------------------
# 6. Wait for instance and print connection info
# ---------------------------------------------------------------------------
echo "[6/6] Waiting for instance to become RUNNING..."
for i in $(seq 1 30); do
    STATUS="$(gcloud compute instances describe "${INSTANCE_NAME}" \
        --zone="${ZONE}" --project="${PROJECT}" \
        --format='value(status)' 2>/dev/null || echo 'UNKNOWN')"
    if [[ "${STATUS}" == "RUNNING" ]]; then
        break
    fi
    printf "  Waiting... (%s) [%d/30]\r" "${STATUS}" "$i"
    sleep 5
done
echo

EXTERNAL_IP="$(gcloud compute instances describe "${INSTANCE_NAME}" \
    --zone="${ZONE}" --project="${PROJECT}" \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || echo 'UNKNOWN')"

echo "============================================"
echo "  Deployment complete."
echo "============================================"
echo
echo "  Instance:    ${INSTANCE_NAME}"
echo "  Zone:        ${ZONE}"
echo "  Status:      ${STATUS}"
echo "  External IP: ${EXTERNAL_IP}"
echo "  Ports:       9000 (control), 9001 (data_in), 9002 (data_out)"
echo
if $DEBUG; then
    echo "  SSH:  gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE} --project=${PROJECT}"
    echo "  Logs: gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE} --project=${PROJECT} --command='sudo journalctl -u tee-container-runner -f'"
fi
echo
echo "  Note: The container takes ~30-60s to start after the VM is RUNNING."
echo "        The Launcher pulls the image, verifies it, then starts the workload."
echo
echo "  Next: bash scripts/gcp/verify.sh"
