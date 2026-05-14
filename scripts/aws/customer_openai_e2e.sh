#!/usr/bin/env bash
# Customer-style OpenAI-compatible E2E smoke for the AWS BYOC worker path.
#
# This script assumes the customer-side cyntrisec-proxy is already running
# from the CloudFormation stack output's ProxyCommand. It sends a batch of
# OpenAI-compatible embedding requests, fetches every emitted evidence bundle,
# verifies bundle integrity offline, and runs cyntrisec-verify against each AIR
# receipt + attestation pair.
set -euo pipefail

GATEWAY_URL="${CYNTRISEC_GATEWAY_URL:-http://127.0.0.1:4000}"
MODEL="${CYNTRISEC_E2E_MODEL:-stage-0}"
EXPECTED_MODEL="${CYNTRISEC_EXPECTED_RECEIPT_MODEL:-${MODEL}}"
OUT_DIR="${CYNTRISEC_E2E_OUT_DIR:-/tmp/cyntrisec-customer-openai-e2e-$(date -u +%Y%m%d_%H%M%SZ)}"
API_KEY="${OPENAI_API_KEY:-${CYNTRISEC_API_KEY:-}}"
PROMPTS_FILE=""
STRICT_BUNDLES=true
INCLUDE_CHAT=false
REQUIRE_CHAT=false
MAX_AGE="${CYNTRISEC_VERIFY_MAX_AGE:-0}"
REQUEST_TIMEOUT_SECS="${CYNTRISEC_E2E_REQUEST_TIMEOUT_SECS:-60}"
AWS_REGION_NAME="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
S3_PRESIGN_SSM_INSTANCE_ID="${CYNTRISEC_E2E_S3_PRESIGN_SSM_INSTANCE_ID:-}"
ALLOW_RECEIPT_HEADER_MISMATCH="${CYNTRISEC_E2E_ALLOW_RECEIPT_HEADER_MISMATCH:-false}"

TOTAL_REQUESTS=0
VERIFIED_BUNDLES=0

usage() {
    cat <<'USAGE'
Usage:
  bash scripts/aws/customer_openai_e2e.sh [options]

Options:
  --url URL                 Gateway base URL (default: http://127.0.0.1:4000)
  --model MODEL             OpenAI model name to request (default: stage-0)
  --expected-model MODEL    Model ID expected inside AIR receipt (default: --model)
  --out-dir DIR             Evidence output directory (default: /tmp/cyntrisec-customer-openai-e2e-*)
  --prompts-file PATH       Newline-delimited prompts to use instead of defaults
  --allow-missing-bundles   Do not fail if bundle headers are absent
  --include-chat            Also try /v1/chat/completions; unsupported chat is OK
  --require-chat            Require /v1/chat/completions to return 200
  --s3-presign-ssm-instance-id ID
                            Fetch s3:// bundles via a pre-signed URL generated
                            by the stack instance role over SSM
  --allow-receipt-header-mismatch
                            Diagnostic mode only: continue if x-cyntrisec-receipt-sha256
                            does not match bundle/air.cbor
  --help                    Show this help

Environment:
  CYNTRISEC_GATEWAY_URL
  CYNTRISEC_E2E_MODEL
  CYNTRISEC_EXPECTED_RECEIPT_MODEL
  CYNTRISEC_E2E_OUT_DIR
  CYNTRISEC_E2E_REQUEST_TIMEOUT_SECS
  CYNTRISEC_E2E_S3_PRESIGN_SSM_INSTANCE_ID
  CYNTRISEC_E2E_ALLOW_RECEIPT_HEADER_MISMATCH
  CYNTRISEC_VERIFY_MAX_AGE
  OPENAI_API_KEY or CYNTRISEC_API_KEY

Prerequisites:
  curl, jq, tar, sha256sum, and either cyntrisec-verify in PATH or cargo.
  aws CLI is required when bundle URLs are s3://...
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) GATEWAY_URL="$2"; shift 2 ;;
        --model) MODEL="$2"; shift 2 ;;
        --expected-model) EXPECTED_MODEL="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --prompts-file) PROMPTS_FILE="$2"; shift 2 ;;
        --allow-missing-bundles) STRICT_BUNDLES=false; shift ;;
        --include-chat) INCLUDE_CHAT=true; shift ;;
        --require-chat) INCLUDE_CHAT=true; REQUIRE_CHAT=true; shift ;;
        --s3-presign-ssm-instance-id) S3_PRESIGN_SSM_INSTANCE_ID="$2"; shift 2 ;;
        --allow-receipt-header-mismatch) ALLOW_RECEIPT_HEADER_MISMATCH=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: missing required command: $1" >&2
        exit 2
    fi
}

need curl
need jq
need tar
need sha256sum

mkdir -p "${OUT_DIR}"

log() {
    printf '[customer-e2e] %s\n' "$*"
}

fail() {
    printf '[customer-e2e] ERROR: %s\n' "$*" >&2
    exit 1
}

json_escape_file() {
    local input="$1"
    jq -R -s 'split("\n") | map(select(length > 0))' "$input"
}

header_value() {
    local header_name="$1"
    local headers_file="$2"
    awk -v key="$(printf '%s' "$header_name" | tr '[:upper:]' '[:lower:]')" '
        BEGIN { found = 0 }
        {
            line = $0
            sub(/\r$/, "", line)
            lower = tolower(line)
            if (index(lower, key ":") == 1 && found == 0) {
                sub(/^[^:]*:[[:space:]]*/, "", line)
                print line
                found = 1
            }
        }
    ' "$headers_file"
}

verify_cmd() {
    if [[ -n "${CYNTRISEC_VERIFY_BIN:-}" ]]; then
        "${CYNTRISEC_VERIFY_BIN}" "$@"
    elif command -v cyntrisec-verify >/dev/null 2>&1; then
        cyntrisec-verify "$@"
    else
        CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/ephemeralml-target}" \
            cargo run -q -p ephemeral-ml-client --bin cyntrisec-verify -- "$@"
    fi
}

presign_s3_with_ssm() {
    local url="$1"
    local command_id status presigned

    [[ "$url" =~ ^s3://[A-Za-z0-9._/=:-]+$ ]] || fail "refusing to presign unexpected S3 URL: $url"
    command_id="$(aws ssm send-command \
        --region "$AWS_REGION_NAME" \
        --instance-ids "$S3_PRESIGN_SSM_INSTANCE_ID" \
        --document-name AWS-RunShellScript \
        --comment "cyntrisec customer e2e presign bundle" \
        --parameters "commands=aws s3 presign ${url} --expires-in 600" \
        --query 'Command.CommandId' \
        --output text)"

    for _ in $(seq 1 45); do
        status="$(aws ssm get-command-invocation \
            --region "$AWS_REGION_NAME" \
            --command-id "$command_id" \
            --instance-id "$S3_PRESIGN_SSM_INSTANCE_ID" \
            --query 'Status' \
            --output text 2>/dev/null || true)"
        case "$status" in
            Success)
                presigned="$(aws ssm get-command-invocation \
                    --region "$AWS_REGION_NAME" \
                    --command-id "$command_id" \
                    --instance-id "$S3_PRESIGN_SSM_INSTANCE_ID" \
                    --query 'StandardOutputContent' \
                    --output text | awk 'NF { print; exit }')"
                [[ -n "$presigned" ]] || fail "SSM presign command returned no URL for $url"
                printf '%s\n' "$presigned"
                return 0
                ;;
            Failed|Cancelled|TimedOut|Cancelling)
                aws ssm get-command-invocation \
                    --region "$AWS_REGION_NAME" \
                    --command-id "$command_id" \
                    --instance-id "$S3_PRESIGN_SSM_INSTANCE_ID" >&2 || true
                fail "SSM presign command ${command_id} ended with status ${status}"
                ;;
        esac
        sleep 1
    done

    fail "timed out waiting for SSM presign command ${command_id}"
}

fetch_bundle() {
    local url="$1"
    local dest="$2"

    case "$url" in
        s3://*)
            need aws
            if [[ -n "$S3_PRESIGN_SSM_INSTANCE_ID" ]]; then
                local presigned_url
                presigned_url="$(presign_s3_with_ssm "$url")"
                curl -fsSL --max-time "$REQUEST_TIMEOUT_SECS" -o "$dest" "$presigned_url"
            else
                aws s3 cp "$url" "$dest" >/dev/null
            fi
            ;;
        http://*|https://*)
            curl -fsSL --max-time "$REQUEST_TIMEOUT_SECS" -o "$dest" "$url"
            ;;
        *)
            fail "unsupported bundle URL scheme: $url"
            ;;
    esac
}

verify_bundle() {
    local case_dir="$1"
    local headers="$2"
    local bundle_url bundle_sha receipt_sha archive actual_sha unpack_dir verify_log

    bundle_url="$(header_value x-cyntrisec-bundle-url "$headers")"
    bundle_sha="$(header_value x-cyntrisec-bundle-sha256 "$headers")"
    receipt_sha="$(header_value x-cyntrisec-receipt-sha256 "$headers")"

    if [[ -z "$bundle_url" || -z "$bundle_sha" ]]; then
        if [[ "$STRICT_BUNDLES" == true ]]; then
            fail "missing x-cyntrisec-bundle-url or x-cyntrisec-bundle-sha256 in ${headers}"
        fi
        log "bundle headers absent for ${case_dir}; continuing because --allow-missing-bundles was set"
        return 0
    fi

    if ! [[ "$bundle_sha" =~ ^[0-9a-f]{64}$ ]]; then
        fail "bundle SHA is not lowercase 64-char hex: $bundle_sha"
    fi

    archive="${case_dir}/bundle.tar.gz"
    unpack_dir="${case_dir}/bundle"
    mkdir -p "$unpack_dir"

    log "fetch bundle: ${bundle_url}"
    fetch_bundle "$bundle_url" "$archive"

    actual_sha="$(sha256sum "$archive" | awk '{print $1}')"
    if [[ "$actual_sha" != "$bundle_sha" ]]; then
        fail "bundle hash mismatch for ${case_dir}: header=${bundle_sha} actual=${actual_sha}"
    fi

    tar -xzf "$archive" -C "$unpack_dir"

    local required=(
        "air.cbor"
        "attestation.cbor"
        "cyntrisec-policy.json"
        "model-manifest.json"
        "runtime-passport.json"
        "verification-report.json"
        "vendor-evidence/aws-nitro-attestation.cbor"
        "SHA256SUMS"
    )
    local path
    for path in "${required[@]}"; do
        [[ -f "${unpack_dir}/${path}" ]] || fail "bundle missing ${path} in ${case_dir}"
    done

    (cd "$unpack_dir" && sha256sum -c SHA256SUMS) >"${case_dir}/sha256sums.verify.txt"

    if [[ -n "$receipt_sha" ]]; then
        local actual_receipt_sha
        actual_receipt_sha="$(sha256sum "${unpack_dir}/air.cbor" | awk '{print $1}')"
        if [[ "$actual_receipt_sha" != "$receipt_sha" ]]; then
            if [[ "$ALLOW_RECEIPT_HEADER_MISMATCH" == true ]]; then
                log "WARNING: AIR receipt hash mismatch for ${case_dir}: header=${receipt_sha} actual=${actual_receipt_sha}"
            else
                fail "AIR receipt hash mismatch for ${case_dir}: header=${receipt_sha} actual=${actual_receipt_sha}"
            fi
        fi
    fi

    verify_log="${case_dir}/cyntrisec-verify.txt"
    verify_cmd "${unpack_dir}/air.cbor" \
        --attestation "${unpack_dir}/attestation.cbor" \
        --expected-model "$EXPECTED_MODEL" \
        --expected-security-mode production \
        --max-age "$MAX_AGE" \
        >"$verify_log" 2>&1 || {
            cat "$verify_log" >&2
            fail "offline receipt verification failed for ${case_dir}"
        }

    VERIFIED_BUNDLES=$((VERIFIED_BUNDLES + 1))
}

curl_json() {
    local method="$1"
    local path="$2"
    local payload="$3"
    local headers="$4"
    local body="$5"
    local status
    local args=(
        -sS
        --max-time "$REQUEST_TIMEOUT_SECS"
        -D "$headers"
        -o "$body"
        -w '%{http_code}'
        -H 'content-type: application/json'
    )

    if [[ -n "$API_KEY" ]]; then
        args+=(-H "authorization: Bearer ${API_KEY}")
    fi

    if [[ "$method" == "GET" ]]; then
        if ! status="$(curl "${args[@]}" "${GATEWAY_URL}${path}")"; then
            status="${status:-000}"
        fi
    else
        if ! status="$(curl "${args[@]}" -X "$method" "${GATEWAY_URL}${path}" --data-binary @"$payload")"; then
            status="${status:-000}"
        fi
    fi
    printf '%s' "$status"
}

assert_embedding_response() {
    local body="$1"
    local expected_count="$2"
    jq -e --argjson n "$expected_count" '
        .object == "list"
        and (.data | length) == $n
        and (.data | all(.object == "embedding" and (.embedding | type == "array") and (.embedding | length > 0)))
        and (.usage.total_tokens | type == "number")
    ' "$body" >/dev/null
}

run_embedding_case() {
    local name="$1"
    local expected_count="$2"
    local payload="$3"
    local case_dir="${OUT_DIR}/${name}"
    local headers="${case_dir}/headers.txt"
    local body="${case_dir}/response.json"
    local status

    mkdir -p "$case_dir"
    cp "$payload" "${case_dir}/request.json"

    TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))
    log "POST /v1/embeddings ${name}"
    status="$(curl_json POST /v1/embeddings "$payload" "$headers" "$body")"
    printf '%s\n' "$status" >"${case_dir}/http_status.txt"

    [[ "$status" == "200" ]] || {
        cat "$body" >&2 || true
        fail "${name} returned HTTP ${status}"
    }
    assert_embedding_response "$body" "$expected_count" || {
        cat "$body" >&2
        fail "${name} returned invalid OpenAI embeddings response shape"
    }
    verify_bundle "$case_dir" "$headers"
}

run_chat_case() {
    local case_dir="${OUT_DIR}/chat_optional"
    local payload="${case_dir}/request.json"
    local headers="${case_dir}/headers.txt"
    local body="${case_dir}/response.json"
    local status

    mkdir -p "$case_dir"
    jq -n --arg model "$MODEL" '{
        model: $model,
        messages: [
            {role: "system", content: "You are a concise security analyst."},
            {role: "user", content: "In one sentence, explain what an attested inference receipt proves."}
        ],
        temperature: 0.0,
        max_tokens: 64
    }' >"$payload"

    TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))
    log "POST /v1/chat/completions chat_optional"
    status="$(curl_json POST /v1/chat/completions "$payload" "$headers" "$body")"
    printf '%s\n' "$status" >"${case_dir}/http_status.txt"

    if [[ "$status" == "200" ]]; then
        jq -e '.choices[0].message.content | type == "string"' "$body" >/dev/null || {
            cat "$body" >&2
            fail "chat response shape invalid"
        }
        verify_bundle "$case_dir" "$headers"
        return 0
    fi

    if [[ "$REQUIRE_CHAT" == true ]]; then
        cat "$body" >&2 || true
        fail "chat was required but returned HTTP ${status}"
    fi

    log "chat returned HTTP ${status}; accepted because Cluster A v1.1 is embeddings-first"
}

write_default_prompts() {
    local file="$1"
    cat >"$file" <<'PROMPTS'
Summarize this audit requirement: prove each AI inference was run inside the expected confidential worker.
Classify this support ticket: customer asks whether the cloud operator can read their prompt.
Extract entities from this sentence: Cyntrisec stores evidence bundles in the customer's S3 bucket.
Convert to a retrieval query: HIPAA attorney wants proof that model input was processed inside a Nitro Enclave.
Write a short risk label for: missing attestation document in an inference receipt bundle.
Explain in plain English: what does a SHA-256 hash bind in an audit receipt?
Find the main theme: customer-owned AWS account, KMS key release, and offline receipt verification.
Generate a concise title for: per-inference proof for confidential AI workloads.
PROMPTS
}

main() {
    log "gateway: ${GATEWAY_URL}"
    log "model: ${MODEL}"
    log "expected receipt model: ${EXPECTED_MODEL}"
    log "output: ${OUT_DIR}"

    local health_headers="${OUT_DIR}/health.headers.txt"
    local health_body="${OUT_DIR}/health.json"
    local health_status
    health_status="$(curl_json GET /health /dev/null "$health_headers" "$health_body")"
    [[ "$health_status" == "200" ]] || fail "health check returned HTTP ${health_status}"

    local models_headers="${OUT_DIR}/models.headers.txt"
    local models_body="${OUT_DIR}/models.json"
    local models_status
    models_status="$(curl_json GET /v1/models /dev/null "$models_headers" "$models_body")"
    [[ "$models_status" == "200" ]] || fail "/v1/models returned HTTP ${models_status}"
    jq -e '.object == "list" and (.data | length > 0)' "$models_body" >/dev/null \
        || fail "/v1/models response shape invalid"

    local prompts="${OUT_DIR}/prompts.txt"
    if [[ -n "$PROMPTS_FILE" ]]; then
        cp "$PROMPTS_FILE" "$prompts"
    else
        write_default_prompts "$prompts"
    fi

    local prompt_count
    prompt_count="$(grep -cv '^[[:space:]]*$' "$prompts")"
    [[ "$prompt_count" -gt 0 ]] || fail "no prompts to test"

    local i=0
    local line
    while IFS= read -r line; do
        [[ -n "${line//[[:space:]]/}" ]] || continue
        i=$((i + 1))
        local payload="${OUT_DIR}/embedding_${i}.request.json"
        jq -n --arg model "$MODEL" --arg input "$line" '{
            model: $model,
            input: $input,
            encoding_format: "float"
        }' >"$payload"
        run_embedding_case "$(printf 'embedding_%02d' "$i")" 1 "$payload"
    done <"$prompts"

    local batch_payload="${OUT_DIR}/embedding_batch.request.json"
    local batch_count
    batch_count="$(head -n 4 "$prompts" | grep -cv '^[[:space:]]*$')"
    jq -n \
        --arg model "$MODEL" \
        --argjson input "$(head -n 4 "$prompts" | json_escape_file /dev/stdin)" \
        '{model: $model, input: $input, encoding_format: "float"}' \
        >"$batch_payload"
    run_embedding_case "embedding_batch" "$batch_count" "$batch_payload"

    if [[ "$INCLUDE_CHAT" == true ]]; then
        run_chat_case
    fi

    jq -n \
        --arg gateway_url "$GATEWAY_URL" \
        --arg model "$MODEL" \
        --arg expected_model "$EXPECTED_MODEL" \
        --arg out_dir "$OUT_DIR" \
        --argjson total_requests "$TOTAL_REQUESTS" \
        --argjson verified_bundles "$VERIFIED_BUNDLES" \
        '{
            gateway_url: $gateway_url,
            model: $model,
            expected_receipt_model: $expected_model,
            output_dir: $out_dir,
            total_requests: $total_requests,
            verified_bundles: $verified_bundles,
            status: "pass"
        }' >"${OUT_DIR}/summary.json"

    log "PASS: ${TOTAL_REQUESTS} OpenAI-format requests, ${VERIFIED_BUNDLES} offline bundle verifications"
    log "evidence saved under ${OUT_DIR}"
}

main "$@"
