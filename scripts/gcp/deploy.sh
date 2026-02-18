#!/usr/bin/env bash
# EphemeralML — Build container, push to Artifact Registry, launch Confidential Space CVM.
#
# Usage:
#   bash scripts/gcp/deploy.sh                     # CPU production image (no SSH)
#   bash scripts/gcp/deploy.sh --gpu                # GPU image (a3-highgpu-1g, H100 CC, Spot)
#   bash scripts/gcp/deploy.sh --debug              # debug image (SSH enabled)
#   bash scripts/gcp/deploy.sh --skip-build         # skip Docker build/push (image already in AR)
#   bash scripts/gcp/deploy.sh --tag v1.0           # custom image tag
#   bash scripts/gcp/deploy.sh --zone us-central1-b # custom zone
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Load shared UI helpers
# shellcheck source=../lib/ui.sh
source "${SCRIPT_DIR}/../lib/ui.sh"

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
MODEL_FORMAT="${EPHEMERALML_MODEL_FORMAT:-safetensors}"

YES=false
GPU=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)        DEBUG=true; shift ;;
        --gpu)          GPU=true; shift ;;
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
        --model-format) MODEL_FORMAT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# GPU mode: override machine type, image family, and provisioning model.
# a3-highgpu-1g = 1x H100 80GB + 26 vCPU + 234 GiB RAM (Intel TDX + NVIDIA CC).
# Confidential Space GPU images are Preview (confidential-space-preview-cgpu).
# GPU CC requires Spot or Flex-start provisioning — on-demand is not available.
if $GPU; then
    MACHINE_TYPE="a3-highgpu-1g"
    INSTANCE_NAME="ephemeralml-gpu"
fi

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
for _var_name in PROJECT ZONE MODEL_SOURCE MODEL_FORMAT GCS_BUCKET GCP_MODEL_PREFIX KMS_KEY WIP_AUDIENCE EXPECTED_MODEL_HASH MODEL_SIGNING_PUBKEY; do
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

# Validate model format
if [[ "${MODEL_FORMAT}" != "safetensors" && "${MODEL_FORMAT}" != "gguf" ]]; then
    echo "ERROR: --model-format must be 'safetensors' or 'gguf', got '${MODEL_FORMAT}'"
    exit 1
fi

# Validate required flags for gcs mode (no KMS, but still needs hash + bucket)
if [[ "${MODEL_SOURCE}" == "gcs" ]]; then
    if [[ -z "${EXPECTED_MODEL_HASH}" ]]; then
        echo "ERROR: --model-hash is required for --model-source=gcs"
        exit 1
    fi
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

if $GPU && $DEBUG; then
    CS_IMAGE_FAMILY="confidential-space-debug-preview-cgpu"
elif $GPU; then
    CS_IMAGE_FAMILY="confidential-space-preview-cgpu"
elif $DEBUG; then
    CS_IMAGE_FAMILY="confidential-space-debug"
else
    CS_IMAGE_FAMILY="confidential-space"
fi

ui_header "EphemeralML — Deploy to Confidential Space"
ui_blank
ui_kv "Project" "${PROJECT}"
ui_kv "Zone" "${ZONE}"
ui_kv "Machine" "${MACHINE_TYPE}"
ui_kv "Image" "${IMAGE_URI}"
ui_kv "CS family" "${CS_IMAGE_FAMILY}"
ui_kv "Debug" "${DEBUG}"
ui_kv "GPU" "${GPU}"
ui_kv "Model src" "${MODEL_SOURCE}"
ui_kv "Format" "${MODEL_FORMAT}"
if [[ "${MODEL_SOURCE}" == "gcs" || "${MODEL_SOURCE}" == "gcs-kms" ]]; then
    ui_kv "GCS bucket" "${GCS_BUCKET}"
    ui_kv "Model prefix" "${GCP_MODEL_PREFIX}"
    ui_kv "Model hash" "${EXPECTED_MODEL_HASH}"
fi
if [[ "${MODEL_SOURCE}" == "gcs-kms" ]]; then
    ui_kv "KMS key" "${KMS_KEY}"
    ui_kv "WIP audience" "${WIP_AUDIENCE}"
fi
ui_blank

if $SKIP_BUILD; then
    ui_info "[1/6] Skipping model preparation (--skip-build)."
    ui_info "[2/6] Skipping Docker auth (--skip-build)."
    ui_info "[3/6] Skipping Docker build (--skip-build)."
    ui_info "[4/6] Skipping push (--skip-build). Using existing image: ${IMAGE_URI}"
    ui_blank
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
    run_step 2 6 "Configuring Docker authentication" \
        gcloud auth configure-docker "${REPO_LOCATION}-docker.pkg.dev" --quiet
    ui_blank

    # ---------------------------------------------------------------------------
    # 3. Build container image
    # ---------------------------------------------------------------------------
    if $GPU; then
        DOCKERFILE="${PROJECT_DIR}/Dockerfile.gpu"
    else
        DOCKERFILE="${PROJECT_DIR}/Dockerfile.gcp"
    fi
    run_step 3 6 "Building container image (${DOCKERFILE##*/})" \
        docker build -f "${DOCKERFILE}" -t "${IMAGE_URI}" "${PROJECT_DIR}"
    ui_blank

    # ---------------------------------------------------------------------------
    # 4. Push to Artifact Registry
    # ---------------------------------------------------------------------------
    run_step 4 6 "Pushing to Artifact Registry" \
        docker push "${IMAGE_URI}"
    ui_blank
fi

# ---------------------------------------------------------------------------
# 5. Launch Confidential Space CVM
# ---------------------------------------------------------------------------
ui_info "[5/6] Launching Confidential Space CVM..."

# Delete existing instance if present (avoids name conflict)
if gcloud compute instances describe "${INSTANCE_NAME}" \
    --zone="${ZONE}" --project="${PROJECT}" &>/dev/null; then
    ui_info "Deleting existing instance '${INSTANCE_NAME}'..."
    gcloud compute instances delete "${INSTANCE_NAME}" \
        --zone="${ZONE}" --project="${PROJECT}" --quiet
fi

# Metadata for Confidential Space Launcher
METADATA="tee-image-reference=${IMAGE_URI}"
METADATA="${METADATA},tee-restart-policy=Never"
METADATA="${METADATA},tee-container-log-redirect=true"
# GPU: Confidential Space installs CC-capable NVIDIA drivers at boot
if $GPU; then
    METADATA="${METADATA},tee-install-gpu-driver=true"
fi
METADATA="${METADATA},tee-env-EPHEMERALML_MODEL_SOURCE=${MODEL_SOURCE}"
METADATA="${METADATA},tee-env-EPHEMERALML_DIRECT=true"
METADATA="${METADATA},tee-env-EPHEMERALML_MODEL_FORMAT=${MODEL_FORMAT}"
METADATA="${METADATA},tee-env-EPHEMERALML_LOG_FORMAT=json"
METADATA="${METADATA},tee-env-EPHEMERALML_GCP_PROJECT=${PROJECT}"
METADATA="${METADATA},tee-env-EPHEMERALML_GCP_LOCATION=${ZONE%-*}"
# Inject GCS env vars for gcs and gcs-kms model sources
if [[ "${MODEL_SOURCE}" == "gcs" || "${MODEL_SOURCE}" == "gcs-kms" ]]; then
    METADATA="${METADATA},tee-env-EPHEMERALML_GCS_BUCKET=${GCS_BUCKET}"
    METADATA="${METADATA},tee-env-EPHEMERALML_GCP_MODEL_PREFIX=${GCP_MODEL_PREFIX}"
    METADATA="${METADATA},tee-env-EPHEMERALML_EXPECTED_MODEL_HASH=${EXPECTED_MODEL_HASH}"
fi
# KMS-specific env vars only for gcs-kms
if [[ "${MODEL_SOURCE}" == "gcs-kms" ]]; then
    METADATA="${METADATA},tee-env-EPHEMERALML_GCP_KMS_KEY=${KMS_KEY}"
    METADATA="${METADATA},tee-env-EPHEMERALML_GCP_WIP_AUDIENCE=${WIP_AUDIENCE}"
fi
# Signing pubkey applies to both gcs and gcs-kms model sources
if [[ -n "${MODEL_SIGNING_PUBKEY}" ]]; then
    METADATA="${METADATA},tee-env-EPHEMERALML_MODEL_SIGNING_PUBKEY=${MODEL_SIGNING_PUBKEY}"
fi

# Build gcloud create command — GPU requires --provisioning-model=SPOT and
# larger boot disk (GPU drivers are ~10 GB), and omits --min-cpu-platform
# (a3-highgpu-1g already implies Sapphire Rapids).
GCLOUD_ARGS=(
    --project="${PROJECT}"
    --zone="${ZONE}"
    --machine-type="${MACHINE_TYPE}"
    --confidential-compute-type=TDX
    --maintenance-policy=TERMINATE
    --shielded-secure-boot
    --image-project=confidential-space-images
    --image-family="${CS_IMAGE_FAMILY}"
    --metadata="${METADATA}"
    --tags=ephemeralml
    --service-account="${SA_EMAIL}"
    --scopes=cloud-platform
)

if $GPU; then
    # GPU CC requires Spot or Flex-start provisioning (on-demand not available).
    GCLOUD_ARGS+=(--provisioning-model=SPOT)
    GCLOUD_ARGS+=(--boot-disk-size=30GB)
else
    GCLOUD_ARGS+=(--min-cpu-platform="Intel Sapphire Rapids")
fi

gcloud compute instances create "${INSTANCE_NAME}" "${GCLOUD_ARGS[@]}"

ui_info "Instance '${INSTANCE_NAME}' created."
ui_blank

# ---------------------------------------------------------------------------
# 6. Wait for instance and print connection info
# ---------------------------------------------------------------------------
ui_info "[6/6] Waiting for instance to become RUNNING..."
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

ui_header "Deployment complete"
ui_blank
ui_kv "Instance" "${INSTANCE_NAME}"
ui_kv "Zone" "${ZONE}"
ui_kv "Status" "${STATUS}"
ui_kv "External IP" "${EXTERNAL_IP}"
ui_kv "Ports" "9000 (control), 9001 (data_in), 9002 (data_out)"
ui_blank
if $DEBUG; then
    ui_info "SSH:  gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE} --project=${PROJECT}"
    ui_info "Logs: gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE} --project=${PROJECT} --command='sudo journalctl -u tee-container-runner -f'"
fi
ui_blank
if $GPU; then
    ui_info "Note: GPU instances take ~2-5 minutes to start (driver install + CC boot)."
    ui_warn "WARNING: GPU Confidential Space is Preview. Spot VMs may be preempted."
else
    ui_info "Note: The container takes ~30-60s to start after the VM is RUNNING."
fi
ui_blank
ui_info "Next: bash scripts/gcp/verify.sh"
