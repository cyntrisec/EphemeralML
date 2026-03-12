#!/usr/bin/env bash
# EphemeralML — local OpenAI-compatible gateway against a real GCP backend.
#
# Starts the gateway locally with --features gcp, points it at a deployed
# Confidential Space backend, then runs the Python OpenAI SDK client and saves
# evidence under evidence/openai-gateway-e2e-<timestamp>/.
#
# Usage:
#   bash scripts/gcp/openai_gateway_e2e.sh --project PROJECT_ID
#   bash scripts/gcp/openai_gateway_e2e.sh --project PROJECT_ID --gpu
#   bash scripts/gcp/openai_gateway_e2e.sh --project PROJECT_ID --ip 34.x.x.x
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PY_CLIENT="${SCRIPT_DIR}/openai_gateway_client.py"

# shellcheck source=../lib/ui.sh
source "${SCRIPT_DIR}/../lib/ui.sh"

PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
ZONE="${EPHEMERALML_GCP_ZONE:-us-central1-a}"
INSTANCE_NAME="ephemeralml-cvm"
IP=""
GATEWAY_PORT="${EPHEMERALML_GATEWAY_PORT:-8090}"
API_KEY="${EPHEMERALML_API_KEY:-test-key}"
DEFAULT_MODEL="${EPHEMERALML_DEFAULT_MODEL:-stage-0}"
MODEL_CAPABILITIES="${EPHEMERALML_MODEL_CAPABILITIES:-embeddings}"
ALLOW_UNPINNED_AUDIENCE=false
SKIP_BUILD=false
USE_DOCKER=false
DOCKER_IMAGE="${EPHEMERALML_GATEWAY_DOCKER_IMAGE:-ephemeralml-gateway-gcp-e2e}"
TARGET_DIR="${EPHEMERALML_GATEWAY_TARGET_DIR:-${PROJECT_DIR}/.target_openai_gateway}"
TMP_WORK_DIR="${EPHEMERALML_GATEWAY_TMPDIR:-${PROJECT_DIR}/.tmp_openai_gateway}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) PROJECT="$2"; shift 2 ;;
        --zone) ZONE="$2"; shift 2 ;;
        --ip) IP="$2"; shift 2 ;;
        --gpu) INSTANCE_NAME="ephemeralml-gpu"; shift ;;
        --gateway-port) GATEWAY_PORT="$2"; shift 2 ;;
        --api-key) API_KEY="$2"; shift 2 ;;
        --default-model) DEFAULT_MODEL="$2"; shift 2 ;;
        --model-capabilities) MODEL_CAPABILITIES="$2"; shift 2 ;;
        --allow-unpinned-audience) ALLOW_UNPINNED_AUDIENCE=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --docker) USE_DOCKER=true; shift ;;
        --docker-image) DOCKER_IMAGE="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -f "${PROJECT_DIR}/.env.gcp" ]]; then
    # shellcheck disable=SC1091
    source "${PROJECT_DIR}/.env.gcp"
fi

PROJECT="${PROJECT:-${EPHEMERALML_GCP_PROJECT:-}}"
ZONE="${ZONE:-${EPHEMERALML_GCP_ZONE:-us-central1-a}}"

if [[ -z "${PROJECT}" ]]; then
    ui_fail "ERROR: GCP project not set."
    ui_info "Pass --project PROJECT_ID or set EPHEMERALML_GCP_PROJECT."
    exit 1
fi

if [[ -z "${IP}" ]]; then
    ui_info "Resolving backend IP from ${INSTANCE_NAME}..."
    IP="$(gcloud compute instances describe "${INSTANCE_NAME}" \
        --zone="${ZONE}" \
        --project="${PROJECT}" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || true)"
    if [[ -z "${IP}" || "${IP}" == "None" ]]; then
        ui_fail "ERROR: could not resolve external IP for ${INSTANCE_NAME}."
        ui_info "Deploy the backend first with scripts/gcp/deploy.sh or pass --ip."
        exit 1
    fi
fi

if [[ -z "${GCP_WIP_AUDIENCE:-}" ]]; then
    ui_fail "ERROR: GCP_WIP_AUDIENCE is not set."
    ui_info "Set it in .env.gcp or export it before running this script."
    exit 1
fi

TIMESTAMP="$(date -u +%Y%m%d_%H%M%SZ)"
EVIDENCE_DIR="${PROJECT_DIR}/evidence/openai-gateway-e2e-${TIMESTAMP}"
mkdir -p "${EVIDENCE_DIR}"
GATEWAY_LOG="${EVIDENCE_DIR}/gateway.log"

cleanup() {
    if [[ -n "${DOCKER_CONTAINER_NAME:-}" ]]; then
        docker rm -f "${DOCKER_CONTAINER_NAME}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${GATEWAY_PID:-}" ]]; then
        kill "${GATEWAY_PID}" >/dev/null 2>&1 || true
        wait "${GATEWAY_PID}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

ui_header "EphemeralML — OpenAI Gateway E2E (GCP backend)"
ui_kv "Project" "${PROJECT}"
ui_kv "Zone" "${ZONE}"
ui_kv "Backend IP" "${IP}"
ui_kv "Gateway port" "${GATEWAY_PORT}"
ui_kv "Default model" "${DEFAULT_MODEL}"
ui_kv "Capabilities" "${MODEL_CAPABILITIES}"
ui_kv "Runtime" "$($USE_DOCKER && echo docker || echo cargo)"
ui_kv "Docker image" "${DOCKER_IMAGE}"
ui_kv "Cargo target" "${TARGET_DIR}"
ui_kv "Cargo tmp" "${TMP_WORK_DIR}"
ui_kv "Evidence dir" "${EVIDENCE_DIR}"
ui_blank

if ! python3 -c "import openai, httpx" >/dev/null 2>&1; then
    ui_fail "ERROR: python packages 'openai' and 'httpx' are required."
    ui_info "Install them first, then rerun this script."
    exit 1
fi

mkdir -p "${TARGET_DIR}" "${TMP_WORK_DIR}"

if ! $SKIP_BUILD; then
    if $USE_DOCKER; then
        ui_info "Building gateway Docker image with GCP feature..."
        (
            cd "${PROJECT_DIR}" && \
            docker build \
              --build-arg GATEWAY_FEATURES=gcp \
              -f gateway-api/Dockerfile \
              -t "${DOCKER_IMAGE}" .
        ) >"${EVIDENCE_DIR}/gateway_build.log" 2>&1
    else
        ui_info "Building gateway with GCP feature..."
        (cd "${PROJECT_DIR}" && \
            TMPDIR="${TMP_WORK_DIR}" RUSTC_WRAPPER= CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TARGET_DIR}" \
            cargo build --release --no-default-features --features gcp -p ephemeralml-gateway) \
            >"${EVIDENCE_DIR}/gateway_build.log" 2>&1
    fi
fi

ui_info "Starting local gateway..."
if $USE_DOCKER; then
    DOCKER_CONTAINER_NAME="ephemeralml-gateway-e2e-${TIMESTAMP}"
    (
        cd "${PROJECT_DIR}"
        docker run --rm \
          --name "${DOCKER_CONTAINER_NAME}" \
          -p "127.0.0.1:${GATEWAY_PORT}:${GATEWAY_PORT}" \
          -e EPHEMERALML_BACKEND_ADDR="${IP}:9000" \
          -e EPHEMERALML_DEFAULT_MODEL="${DEFAULT_MODEL}" \
          -e EPHEMERALML_API_KEY="${API_KEY}" \
          -e EPHEMERALML_GATEWAY_PORT="${GATEWAY_PORT}" \
          -e EPHEMERALML_INCLUDE_METADATA_JSON=true \
          -e EPHEMERALML_MODEL_CAPABILITIES="${MODEL_CAPABILITIES}" \
          -e EPHEMERALML_EXPECTED_AUDIENCE="${GCP_WIP_AUDIENCE}" \
          -e EPHEMERALML_REQUIRE_MRTD=false \
          -e EPHEMERALML_ALLOW_UNPINNED_AUDIENCE="$($ALLOW_UNPINNED_AUDIENCE && echo true || echo false)" \
          -e RUST_LOG=ephemeralml_gateway=info \
          "${DOCKER_IMAGE}" \
          --backend-addr "${IP}:9000" \
          --port "${GATEWAY_PORT}" \
          --default-model "${DEFAULT_MODEL}"
    ) >"${GATEWAY_LOG}" 2>&1 &
    GATEWAY_PID=$!
else
    (
        cd "${PROJECT_DIR}"
        EPHEMERALML_BACKEND_ADDR="${IP}:9000" \
        EPHEMERALML_DEFAULT_MODEL="${DEFAULT_MODEL}" \
        EPHEMERALML_API_KEY="${API_KEY}" \
        EPHEMERALML_GATEWAY_PORT="${GATEWAY_PORT}" \
        EPHEMERALML_INCLUDE_METADATA_JSON=true \
        EPHEMERALML_MODEL_CAPABILITIES="${MODEL_CAPABILITIES}" \
        EPHEMERALML_EXPECTED_AUDIENCE="${GCP_WIP_AUDIENCE}" \
        EPHEMERALML_REQUIRE_MRTD=false \
        EPHEMERALML_ALLOW_UNPINNED_AUDIENCE=$($ALLOW_UNPINNED_AUDIENCE && echo true || echo false) \
        RUST_LOG=ephemeralml_gateway=info \
        TMPDIR="${TMP_WORK_DIR}" RUSTC_WRAPPER= CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TARGET_DIR}" \
        cargo run --release --no-default-features --features gcp -p ephemeralml-gateway -- \
          --backend-addr "${IP}:9000" \
          --port "${GATEWAY_PORT}" \
          --default-model "${DEFAULT_MODEL}"
    ) >"${GATEWAY_LOG}" 2>&1 &
    GATEWAY_PID=$!
fi

ui_info "Waiting for local gateway health..."
READY_URL="http://127.0.0.1:${GATEWAY_PORT}/readyz"
HEALTH_URL="http://127.0.0.1:${GATEWAY_PORT}/health"
for _ in $(seq 1 60); do
    if curl -sf "${HEALTH_URL}" >/dev/null 2>&1; then
        if curl -sf "${READY_URL}" >/dev/null 2>&1; then
            ui_ok "Gateway is ready."
            break
        fi
    fi
    sleep 2
done

if ! curl -sf "${READY_URL}" >/dev/null 2>&1; then
    ui_fail "ERROR: gateway did not become ready."
    ui_info "See log: ${GATEWAY_LOG}"
    tail -n 60 "${GATEWAY_LOG}" || true
    exit 1
fi

ui_info "Running OpenAI SDK client..."
EPHEMERALML_GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}" \
EPHEMERALML_API_KEY="${API_KEY}" \
EPHEMERALML_E2E_OUTPUT_DIR="${EVIDENCE_DIR}" \
python3 "${PY_CLIENT}" | tee "${EVIDENCE_DIR}/client_stdout.txt"

ui_blank
ui_ok "End-to-end OpenAI gateway test completed."
ui_kv "Evidence dir" "${EVIDENCE_DIR}"
ui_kv "Gateway log" "${GATEWAY_LOG}"
