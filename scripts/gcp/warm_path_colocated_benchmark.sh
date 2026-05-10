#!/usr/bin/env bash
# EphemeralML — GCP Confidential Space warm-path benchmark from same-zone VM.
#
# Requires a deployed backend started with:
#   bash scripts/gcp/deploy.sh --benchmark ...
#
# This runner creates a temporary client VM in the same zone/VPC as the backend,
# copies the prebuilt benchmark binary to it, runs the benchmark against the
# backend private IP, copies the JSONL back, redacts operator metadata, and
# deletes the client VM by default.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/ui.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"
gcp_source_env_file "${PROJECT_DIR}"
gcp_export_env_aliases

PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
ZONE="${EPHEMERALML_GCP_ZONE:-us-central1-a}"
BACKEND_INSTANCE="ephemeralml-cvm"
BACKEND_PRIVATE_IP=""
MODEL_ID="${EPHEMERALML_VERIFY_MODEL_ID:-stage-0}"
RECEIPT_MODEL_ID="${EPHEMERALML_VERIFY_RECEIPT_MODEL_ID:-minilm-l6-v2}"
CONCURRENCY="1"
PROMPT_SIZES="short,medium,long"
WARMUP=10
MEASURED=120
ALLOW_UNPINNED_AUDIENCE=false
ALLOW_DIRTY=false
SKIP_BUILD=false
KEEP_CLIENT=false
CLIENT_NAME="ephemeralml-bench-client"
CLIENT_MACHINE="e2-standard-2"
CLIENT_IMAGE_FAMILY="debian-12"
CLIENT_IMAGE_PROJECT="debian-cloud"
CLIENT_BOOT_DISK_SIZE="20GB"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) PROJECT="$2"; shift 2 ;;
        --zone) ZONE="$2"; shift 2 ;;
        --backend-instance) BACKEND_INSTANCE="$2"; shift 2 ;;
        --backend-private-ip) BACKEND_PRIVATE_IP="$2"; shift 2 ;;
        --client-name) CLIENT_NAME="$2"; shift 2 ;;
        --client-machine) CLIENT_MACHINE="$2"; shift 2 ;;
        --model-id) MODEL_ID="$2"; shift 2 ;;
        --receipt-model-id) RECEIPT_MODEL_ID="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --prompt-sizes) PROMPT_SIZES="$2"; shift 2 ;;
        --warmup) WARMUP="$2"; shift 2 ;;
        --measured) MEASURED="$2"; shift 2 ;;
        --allow-unpinned-audience) ALLOW_UNPINNED_AUDIENCE=true; shift ;;
        --allow-dirty) ALLOW_DIRTY=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --keep-client) KEEP_CLIENT=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "${PROJECT}" ]]; then
    ui_fail "ERROR: GCP project not set."
    ui_info "Pass --project PROJECT_ID or set EPHEMERALML_GCP_PROJECT."
    exit 1
fi

if [[ ! "${CLIENT_NAME}" =~ ^ephemeralml-bench-client[-a-z0-9]*$ ]]; then
    ui_fail "ERROR: refusing unsafe client VM name: ${CLIENT_NAME}"
    ui_info "Client VM name must start with 'ephemeralml-bench-client'."
    exit 1
fi

if [[ -z "${BACKEND_PRIVATE_IP}" ]]; then
    ui_info "Resolving backend private IP from ${BACKEND_INSTANCE}..."
    BACKEND_PRIVATE_IP="$(gcloud compute instances describe "${BACKEND_INSTANCE}" \
        --zone="${ZONE}" \
        --project="${PROJECT}" \
        --format='value(networkInterfaces[0].networkIP)' 2>/dev/null || true)"
    if [[ -z "${BACKEND_PRIVATE_IP}" || "${BACKEND_PRIVATE_IP}" == "None" ]]; then
        ui_fail "ERROR: could not resolve private IP for ${BACKEND_INSTANCE}."
        exit 1
    fi
fi

BACKEND_MACHINE="$(gcloud compute instances describe "${BACKEND_INSTANCE}" \
    --zone="${ZONE}" \
    --project="${PROJECT}" \
    --format='value(machineType.basename())' 2>/dev/null || true)"
BACKEND_MACHINE="${BACKEND_MACHINE:-unknown}"

PROJECT_NUMBER="$(gcloud projects describe "${PROJECT}" \
    --format='value(projectNumber)' 2>/dev/null || true)"

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

GIT_SHA="$(git -C "${PROJECT_DIR}" rev-parse --short HEAD)"
if [[ -n "$(git -C "${PROJECT_DIR}" status --porcelain)" ]] && ! $ALLOW_DIRTY; then
    ui_fail "ERROR: working tree is dirty; benchmark git_sha would not identify the exact binary."
    ui_info "Commit changes first, or pass --allow-dirty for local-only exploratory runs."
    exit 1
fi
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="${PROJECT_DIR}/evidence/benchmarks/gcp-cs-tdx-warm-path-colocated-${TIMESTAMP}"
RAW_DIR="${EVIDENCE_DIR}/raw"
REDACTED_DIR="${EVIDENCE_DIR}/redacted"
RAW_JSONL_PATH="${RAW_DIR}/warm-path-records.jsonl"
REDACTED_JSONL_PATH="${REDACTED_DIR}/warm-path-records.jsonl"
mkdir -p "${RAW_DIR}" "${REDACTED_DIR}"

ui_header "EphemeralML — GCP CS TDX Warm-Path Benchmark (Same-Zone Client)"
ui_kv "Project" "${PROJECT}"
ui_kv "Zone" "${ZONE}"
ui_kv "Backend instance" "${BACKEND_INSTANCE}"
ui_kv "Backend private" "${BACKEND_PRIVATE_IP}:9000"
ui_kv "Backend machine" "${BACKEND_MACHINE}"
ui_kv "Client VM" "${CLIENT_NAME}"
ui_kv "Client machine" "${CLIENT_MACHINE}"
ui_kv "Git SHA" "${GIT_SHA}"
ui_kv "Model ID" "${MODEL_ID}"
ui_kv "Receipt model ID" "${RECEIPT_MODEL_ID}"
ui_kv "Concurrency" "${CONCURRENCY}"
ui_kv "Prompt sizes" "${PROMPT_SIZES}"
ui_kv "Warmup/session" "${WARMUP}"
ui_kv "Measured/point" "${MEASURED}"
ui_kv "Evidence dir" "${EVIDENCE_DIR}"
ui_blank

if ! $SKIP_BUILD; then
    ui_info "Building benchmark client..."
    (
        cd "${PROJECT_DIR}"
        cargo build --release --no-default-features --features gcp \
            -p ephemeral-ml-client --bin benchmark_gcp_warm_path
    ) >"${RAW_DIR}/build.log" 2>&1
fi

BENCH_BIN="${PROJECT_DIR}/target/release/benchmark_gcp_warm_path"
if [[ ! -x "${BENCH_BIN}" ]]; then
    ui_fail "ERROR: benchmark binary not found: ${BENCH_BIN}"
    exit 1
fi

if gcloud compute instances describe "${CLIENT_NAME}" \
    --zone="${ZONE}" \
    --project="${PROJECT}" >/dev/null 2>&1; then
    ui_fail "ERROR: client VM already exists: ${CLIENT_NAME}"
    ui_info "Delete it first, or pass --client-name ephemeralml-bench-client-<suffix>."
    exit 1
fi

CLIENT_CREATED=false
cleanup_client() {
    if $CLIENT_CREATED && ! $KEEP_CLIENT; then
        ui_info "Deleting temporary client VM ${CLIENT_NAME}..."
        gcloud compute instances delete "${CLIENT_NAME}" \
            --zone="${ZONE}" \
            --project="${PROJECT}" \
            --quiet >/dev/null 2>&1 || true
    fi
}
trap cleanup_client EXIT

ui_info "Creating same-zone client VM..."
gcloud compute instances create "${CLIENT_NAME}" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --machine-type="${CLIENT_MACHINE}" \
    --image-family="${CLIENT_IMAGE_FAMILY}" \
    --image-project="${CLIENT_IMAGE_PROJECT}" \
    --boot-disk-size="${CLIENT_BOOT_DISK_SIZE}" \
    --tags=ephemeralml-bench-client \
    --scopes=cloud-platform >"${RAW_DIR}/client-create.log" 2>&1
CLIENT_CREATED=true

CLIENT_PRIVATE_IP="$(gcloud compute instances describe "${CLIENT_NAME}" \
    --zone="${ZONE}" \
    --project="${PROJECT}" \
    --format='value(networkInterfaces[0].networkIP)' 2>/dev/null || true)"
CLIENT_PUBLIC_IP="$(gcloud compute instances describe "${CLIENT_NAME}" \
    --zone="${ZONE}" \
    --project="${PROJECT}" \
    --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || true)"

ui_info "Waiting for client SSH..."
for _ in $(seq 1 60); do
    if gcloud compute ssh "${CLIENT_NAME}" \
        --project="${PROJECT}" \
        --zone="${ZONE}" \
        --quiet \
        --command='echo ready' >/dev/null 2>&1; then
        ui_ok "Client SSH ready."
        break
    fi
    sleep 5
done
if ! gcloud compute ssh "${CLIENT_NAME}" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --quiet \
    --command='echo ready' >/dev/null 2>&1; then
    ui_fail "ERROR: client SSH not ready."
    exit 1
fi

ui_info "Copying benchmark binary to client VM..."
gcloud compute scp "${BENCH_BIN}" "${CLIENT_NAME}:/tmp/benchmark_gcp_warm_path" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --quiet >"${RAW_DIR}/client-scp.log" 2>&1

REMOTE_SCRIPT="${RAW_DIR}/remote-run.sh"
cat >"${REMOTE_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
mkdir -p /tmp/ephemeralml-bench-run
chmod +x /tmp/benchmark_gcp_warm_path
for _ in \$(seq 1 90); do
    if timeout 2 bash -c "echo >/dev/tcp/${BACKEND_PRIVATE_IP}/9000" 2>/dev/null; then
        echo "backend_private_port_ready"
        break
    fi
    sleep 2
done
if ! timeout 2 bash -c "echo >/dev/tcp/${BACKEND_PRIVATE_IP}/9000" 2>/dev/null; then
    echo "backend_private_port_not_reachable" >&2
    exit 1
fi
EPHEMERALML_BENCHMARK_MODE=development \\
EPHEMERALML_BENCHMARK_GIT_SHA=${GIT_SHA} \\
EPHEMERALML_REQUIRE_MRTD=false \\
EPHEMERALML_EXPECTED_AUDIENCE="${EPHEMERALML_EXPECTED_AUDIENCE:-}" \\
EPHEMERALML_ALLOW_UNPINNED_AUDIENCE="${EPHEMERALML_ALLOW_UNPINNED_AUDIENCE:-}" \\
EPHEMERALML_INSECURE_ALLOW_UNPINNED="${EPHEMERALML_INSECURE_ALLOW_UNPINNED:-}" \\
EPHEMERALML_ACCEPT_RECEIPT_MODEL_ID="${RECEIPT_MODEL_ID}" \\
/tmp/benchmark_gcp_warm_path \\
    --backend-addr "${BACKEND_PRIVATE_IP}:9000" \\
    --model-id "${MODEL_ID}" \\
    --receipt-model-id "${RECEIPT_MODEL_ID}" \\
    --concurrency "${CONCURRENCY}" \\
    --prompt-sizes "${PROMPT_SIZES}" \\
    --warmup "${WARMUP}" \\
    --measured "${MEASURED}" \\
    --output /tmp/ephemeralml-bench-run/warm-path-records.jsonl
sha256sum /tmp/ephemeralml-bench-run/warm-path-records.jsonl > /tmp/ephemeralml-bench-run/SHA256SUMS
EOF
chmod +x "${REMOTE_SCRIPT}"

gcloud compute scp "${REMOTE_SCRIPT}" "${CLIENT_NAME}:/tmp/ephemeralml-bench-run.sh" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --quiet >"${RAW_DIR}/remote-script-scp.log" 2>&1

ui_info "Running same-zone benchmark..."
gcloud compute ssh "${CLIENT_NAME}" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --quiet \
    --command='bash /tmp/ephemeralml-bench-run.sh' 2>&1 | tee "${RAW_DIR}/run.log"

ui_info "Copying benchmark artifacts back..."
gcloud compute scp "${CLIENT_NAME}:/tmp/ephemeralml-bench-run/warm-path-records.jsonl" "${RAW_JSONL_PATH}" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --quiet >"${RAW_DIR}/copy-jsonl.log" 2>&1
gcloud compute scp "${CLIENT_NAME}:/tmp/ephemeralml-bench-run/SHA256SUMS" "${RAW_DIR}/SHA256SUMS.remote" \
    --project="${PROJECT}" \
    --zone="${ZONE}" \
    --quiet >"${RAW_DIR}/copy-sha.log" 2>&1

if ! grep -q "${GIT_SHA}" "${RAW_JSONL_PATH}"; then
    ui_fail "ERROR: benchmark JSONL does not contain expected git SHA ${GIT_SHA}."
    exit 1
fi
if grep -q '"git_sha":"unknown"' "${RAW_JSONL_PATH}"; then
    ui_fail "ERROR: benchmark JSONL contains git_sha=unknown."
    exit 1
fi

cat >"${RAW_DIR}/CONTEXT.md" <<EOF
# GCP Same-Zone Warm-Path Benchmark Context

Date: ${TIMESTAMP}
Project: ${PROJECT}
Project number: ${PROJECT_NUMBER}
Zone: ${ZONE}
Git SHA: ${GIT_SHA}
Backend instance: ${BACKEND_INSTANCE}
Backend private IP: ${BACKEND_PRIVATE_IP}
Backend machine: ${BACKEND_MACHINE}
Client VM: ${CLIENT_NAME}
Client private IP: ${CLIENT_PRIVATE_IP}
Client public IP: ${CLIENT_PUBLIC_IP}
Client machine: ${CLIENT_MACHINE}
Benchmark mode: development
MRTD pinning: disabled for performance measurement
Concurrency: ${CONCURRENCY}
Prompt sizes: ${PROMPT_SIZES}
Warmup/session: ${WARMUP}
Measured/point: ${MEASURED}
EOF

(
    cd "${RAW_DIR}"
    HASH_INPUTS=(warm-path-records.jsonl run.log CONTEXT.md)
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
    REDACT_PROJECT_NUMBER="${PROJECT_NUMBER}" \
    REDACT_BACKEND_PRIVATE_IP="${BACKEND_PRIVATE_IP}" \
    REDACT_CLIENT_PRIVATE_IP="${CLIENT_PRIVATE_IP}" \
    REDACT_CLIENT_PUBLIC_IP="${CLIENT_PUBLIC_IP}" \
    REDACT_CLIENT_NAME="${CLIENT_NAME}" \
    REDACT_WIP_AUDIENCE="${wip_audience}" \
    perl -0pe '
        BEGIN {
            $project = $ENV{"REDACT_PROJECT"} // "";
            $project_number = $ENV{"REDACT_PROJECT_NUMBER"} // "";
            $backend_private_ip = $ENV{"REDACT_BACKEND_PRIVATE_IP"} // "";
            $client_private_ip = $ENV{"REDACT_CLIENT_PRIVATE_IP"} // "";
            $client_public_ip = $ENV{"REDACT_CLIENT_PUBLIC_IP"} // "";
            $client_name = $ENV{"REDACT_CLIENT_NAME"} // "";
            $wip = $ENV{"REDACT_WIP_AUDIENCE"} // "";
        }
        s/\Q$project\E/gcp-project-redacted/g if length($project);
        s/\Q$project_number\E/gcp-project-number-redacted/g if length($project_number);
        s/\Q$backend_private_ip\E/gcp-same-zone-private/g if length($backend_private_ip);
        s/\Q$client_private_ip\E/gcp-client-private-redacted/g if length($client_private_ip);
        s/\Q$client_public_ip\E/gcp-client-public-redacted/g if length($client_public_ip);
        s/\Q$client_name\E/ephemeralml-bench-client-redacted/g if length($client_name);
        s{\Q$wip\E}{//iam.googleapis.com/projects/gcp-project-number-redacted/locations/global/workloadIdentityPools/redacted-pool/providers/redacted-provider}g if length($wip);
    ' "${src}" > "${dst}"
}

redact_artifact_file "${RAW_JSONL_PATH}" "${REDACTED_JSONL_PATH}"
redact_artifact_file "${RAW_DIR}/run.log" "${REDACTED_DIR}/run.log"
redact_artifact_file "${RAW_DIR}/CONTEXT.md" "${REDACTED_DIR}/CONTEXT.md"
if [[ -f "${RAW_DIR}/build.log" ]]; then
    redact_artifact_file "${RAW_DIR}/build.log" "${REDACTED_DIR}/build.log"
fi

PRIVACY_TOKENS=("${PROJECT}" "${PROJECT_NUMBER}" "${BACKEND_PRIVATE_IP}" "${CLIENT_PRIVATE_IP}" "${CLIENT_PUBLIC_IP}")
for token in "${PRIVACY_TOKENS[@]}"; do
    if [[ -n "${token}" ]] && grep -R -F -q -- "${token}" "${REDACTED_DIR}"; then
        ui_fail "ERROR: redacted artifacts still contain operator metadata token: ${token}"
        exit 1
    fi
done

python3 "${SCRIPT_DIR}/summarize_warm_path_benchmark.py" \
    --artifact-dir "${REDACTED_DIR}" \
    --title "GCP Confidential Space Warm-Path Benchmark, Same-Zone Client"

(
    cd "${REDACTED_DIR}"
    HASH_INPUTS=(SUMMARY.md FACT_CHECK.md warm-path-records.jsonl run.log CONTEXT.md)
    if [[ -f build.log ]]; then
        HASH_INPUTS+=(build.log)
    fi
    sha256sum "${HASH_INPUTS[@]}" > SHA256SUMS
)

ui_blank
ui_ok "Same-zone warm-path benchmark completed."
ui_kv "Raw JSONL" "${RAW_JSONL_PATH}"
ui_kv "Raw SHA256SUMS" "${RAW_DIR}/SHA256SUMS"
ui_kv "Redacted JSONL" "${REDACTED_JSONL_PATH}"
ui_kv "Redacted SHA256SUMS" "${REDACTED_DIR}/SHA256SUMS"
if ! $KEEP_CLIENT; then
    ui_kv "Client cleanup" "scheduled via EXIT trap"
else
    ui_warn "Client cleanup skipped due to --keep-client: ${CLIENT_NAME}"
fi
