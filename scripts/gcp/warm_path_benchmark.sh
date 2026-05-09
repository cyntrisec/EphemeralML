#!/usr/bin/env bash
# EphemeralML — GCP Confidential Space warm-path benchmark.
#
# Requires a deployed backend started with:
#   bash scripts/gcp/deploy.sh --benchmark ...
#
# Produces raw and redacted JSONL request/summary records under:
#   evidence/benchmarks/gcp-cs-tdx-warm-path-<timestamp>/{raw,redacted}/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../lib/ui.sh
source "${SCRIPT_DIR}/../lib/ui.sh"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
gcp_source_env_file "${PROJECT_DIR}"
gcp_export_env_aliases

PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
ZONE="${EPHEMERALML_GCP_ZONE:-us-central1-a}"
INSTANCE_NAME="ephemeralml-cvm"
IP=""
MODEL_ID="${EPHEMERALML_VERIFY_MODEL_ID:-stage-0}"
RECEIPT_MODEL_ID="${EPHEMERALML_VERIFY_RECEIPT_MODEL_ID:-minilm-l6-v2}"
CONCURRENCY="1,4,16"
PROMPT_SIZES="short,medium,long"
WARMUP=10
MEASURED=120
ALLOW_UNPINNED_AUDIENCE=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) PROJECT="$2"; shift 2 ;;
        --zone) ZONE="$2"; shift 2 ;;
        --ip) IP="$2"; shift 2 ;;
        --gpu) INSTANCE_NAME="ephemeralml-gpu"; shift ;;
        --model-id) MODEL_ID="$2"; shift 2 ;;
        --receipt-model-id) RECEIPT_MODEL_ID="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --prompt-sizes) PROMPT_SIZES="$2"; shift 2 ;;
        --warmup) WARMUP="$2"; shift 2 ;;
        --measured) MEASURED="$2"; shift 2 ;;
        --allow-unpinned-audience) ALLOW_UNPINNED_AUDIENCE=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

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
        exit 1
    fi
fi

if [[ -n "${GCP_WIP_AUDIENCE:-}" ]]; then
    export EPHEMERALML_EXPECTED_AUDIENCE="${GCP_WIP_AUDIENCE}"
elif $ALLOW_UNPINNED_AUDIENCE; then
    ui_warn "WARNING: --allow-unpinned-audience passed. JWT audience is NOT validated."
    export EPHEMERALML_ALLOW_UNPINNED_AUDIENCE=true
else
    ui_fail "ERROR: GCP_WIP_AUDIENCE not set and audience pinning is required."
    ui_info "Pass --allow-unpinned-audience only for development evidence."
    exit 1
fi

if [[ "${EPHEMERALML_ALLOW_UNPINNED_AUDIENCE:-}" == "true" ]]; then
    export EPHEMERALML_INSECURE_ALLOW_UNPINNED=I_UNDERSTAND
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="${PROJECT_DIR}/evidence/benchmarks/gcp-cs-tdx-warm-path-${TIMESTAMP}"
RAW_DIR="${EVIDENCE_DIR}/raw"
REDACTED_DIR="${EVIDENCE_DIR}/redacted"
RAW_JSONL_PATH="${RAW_DIR}/warm-path-records.jsonl"
REDACTED_JSONL_PATH="${REDACTED_DIR}/warm-path-records.jsonl"
mkdir -p "${RAW_DIR}" "${REDACTED_DIR}"

ui_header "EphemeralML — GCP CS TDX Warm-Path Benchmark"
ui_kv "Project" "${PROJECT}"
ui_kv "Zone" "${ZONE}"
ui_kv "Backend" "${IP}:9000"
ui_kv "Model ID" "${MODEL_ID}"
ui_kv "Receipt model ID" "${RECEIPT_MODEL_ID}"
ui_kv "Concurrency" "${CONCURRENCY}"
ui_kv "Prompt sizes" "${PROMPT_SIZES}"
ui_kv "Warmup/session" "${WARMUP}"
ui_kv "Measured/point" "${MEASURED}"
ui_kv "Evidence dir" "${EVIDENCE_DIR}"
ui_kv "Raw dir" "${RAW_DIR}"
ui_kv "Redacted dir" "${REDACTED_DIR}"
ui_blank

ui_info "Waiting for ${IP}:9000..."
for _ in $(seq 1 60); do
    if timeout 2 bash -c "echo >/dev/tcp/${IP}/9000" 2>/dev/null; then
        ui_ok "Backend port reachable."
        break
    fi
    sleep 2
done
if ! timeout 2 bash -c "echo >/dev/tcp/${IP}/9000" 2>/dev/null; then
    ui_fail "ERROR: ${IP}:9000 not reachable."
    exit 1
fi

if ! $SKIP_BUILD; then
    ui_info "Building GCP warm-path benchmark client..."
    (
        cd "${PROJECT_DIR}"
        cargo build --release --no-default-features --features gcp \
            -p ephemeral-ml-client --bin benchmark_gcp_warm_path
    ) >"${RAW_DIR}/build.log" 2>&1
fi

ui_info "Running benchmark matrix..."
(
    cd "${PROJECT_DIR}"
    EPHEMERALML_BENCHMARK_MODE=development \
    EPHEMERALML_REQUIRE_MRTD=false \
    EPHEMERALML_ACCEPT_RECEIPT_MODEL_ID="${RECEIPT_MODEL_ID}" \
    cargo run --release --no-default-features --features gcp \
        -p ephemeral-ml-client --bin benchmark_gcp_warm_path -- \
        --backend-addr "${IP}:9000" \
        --model-id "${MODEL_ID}" \
        --receipt-model-id "${RECEIPT_MODEL_ID}" \
        --concurrency "${CONCURRENCY}" \
        --prompt-sizes "${PROMPT_SIZES}" \
        --warmup "${WARMUP}" \
        --measured "${MEASURED}" \
        --output "${RAW_JSONL_PATH}"
) 2>&1 | tee "${RAW_DIR}/run.log"

(
    cd "${RAW_DIR}"
    HASH_INPUTS=(warm-path-records.jsonl run.log)
    if [[ -f build.log ]]; then
        HASH_INPUTS+=(build.log)
    fi
    sha256sum "${HASH_INPUTS[@]}" > SHA256SUMS
)

redact_artifact_file() {
    local src="$1"
    local dst="$2"
    local wip_audience="${GCP_WIP_AUDIENCE:-}"
    REDACT_PROJECT="${PROJECT}" \
    REDACT_IP="${IP}" \
    REDACT_WIP_AUDIENCE="${wip_audience}" \
    perl -0pe '
        BEGIN {
            $project = $ENV{"REDACT_PROJECT"} // "";
            $ip = $ENV{"REDACT_IP"} // "";
            $wip = $ENV{"REDACT_WIP_AUDIENCE"} // "";
        }
        s/\Q$project\E/gcp-project-redacted/g if length($project);
        s/\Q$ip\E/redacted-backend-ip/g if length($ip);
        s{\Q$wip\E}{//iam.googleapis.com/projects/gcp-project-number-redacted/locations/global/workloadIdentityPools/redacted-pool/providers/redacted-provider}g if length($wip);
    ' "${src}" > "${dst}"
}

redact_artifact_file "${RAW_JSONL_PATH}" "${REDACTED_JSONL_PATH}"
redact_artifact_file "${RAW_DIR}/run.log" "${REDACTED_DIR}/run.log"
if [[ -f "${RAW_DIR}/build.log" ]]; then
    redact_artifact_file "${RAW_DIR}/build.log" "${REDACTED_DIR}/build.log"
fi

(
    cd "${REDACTED_DIR}"
    HASH_INPUTS=(warm-path-records.jsonl run.log)
    if [[ -f build.log ]]; then
        HASH_INPUTS+=(build.log)
    fi
    sha256sum "${HASH_INPUTS[@]}" > SHA256SUMS
)

ui_blank
ui_ok "Warm-path benchmark completed."
ui_kv "Raw JSONL" "${RAW_JSONL_PATH}"
ui_kv "Raw SHA256SUMS" "${RAW_DIR}/SHA256SUMS"
ui_kv "Redacted JSONL" "${REDACTED_JSONL_PATH}"
ui_kv "Redacted SHA256SUMS" "${REDACTED_DIR}/SHA256SUMS"
