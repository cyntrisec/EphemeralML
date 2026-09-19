#!/usr/bin/env bash
# Exercise every AIR v1 golden vector against a running Verification Center.
# Valid vectors must verify; invalid vectors must return a structured HTTP 200
# verdict with the expected failed check and failure code.

set -euo pipefail

BASE_URL="${1:-https://verify.cyntrisec.com}"
BASE_URL="${BASE_URL%/}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VECTOR_DIR="${TRUST_CENTER_VECTOR_DIR:-$REPO_DIR/spec/v1/vectors}"
CURL_CONFIG_ARGS=()
if [[ -n "${TRUST_CENTER_CURL_CONFIG:-}" ]]; then
    if [[ ! -r "$TRUST_CENTER_CURL_CONFIG" ]]; then
        echo "ERROR: curl config is not readable: $TRUST_CENTER_CURL_CONFIG" >&2
        exit 2
    fi
    CURL_CONFIG_ARGS=(--config "$TRUST_CENTER_CURL_CONFIG")
fi

for command_name in base64 curl jq xxd; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $command_name" >&2
        exit 2
    fi
done

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

passed=0
failed=0

post_vector() {
    local vector_file="$1"
    local response_file="$2"
    local receipt_hex receipt_b64 public_key payload value

    receipt_hex="$(jq -r '.receipt_hex' "$vector_file")"
    receipt_b64="$(printf '%s' "$receipt_hex" | xxd -r -p | base64 | tr -d '\n')"
    public_key="$(jq -r '.public_key_hex // .wrong_public_key_hex' "$vector_file")"
    payload="$(jq -n --arg receipt "$receipt_b64" --arg public_key "$public_key" \
        '{receipt: $receipt, public_key: $public_key}')"

    if jq -e '.verify_policy.expected_model_hash_hex' "$vector_file" >/dev/null 2>&1; then
        value="$(jq -r '.verify_policy.expected_model_hash_hex' "$vector_file")"
        payload="$(jq --arg value "$value" '.expected_model_hash_hex = $value' <<<"$payload")"
    fi
    if jq -e '.verify_policy.expected_nonce_hex' "$vector_file" >/dev/null 2>&1; then
        value="$(jq -r '.verify_policy.expected_nonce_hex' "$vector_file")"
        payload="$(jq --arg value "$value" '.expected_nonce_hex = $value' <<<"$payload")"
    fi
    if jq -e '.verify_policy.expected_platform' "$vector_file" >/dev/null 2>&1; then
        value="$(jq -r '.verify_policy.expected_platform' "$vector_file")"
        payload="$(jq --arg value "$value" '.measurement_type = $value' <<<"$payload")"
    fi
    if jq -e '.verify_policy.max_age_secs' "$vector_file" >/dev/null 2>&1; then
        value="$(jq -r '.verify_policy.max_age_secs' "$vector_file")"
        payload="$(jq --argjson value "$value" '.max_age_secs = $value' <<<"$payload")"
    fi

    local http_status
    if ! http_status="$(curl "${CURL_CONFIG_ARGS[@]}" -sS --max-time 20 -o "$response_file" -w '%{http_code}' \
        -X POST "$BASE_URL/api/v1/verify" \
        -H 'Content-Type: application/json' \
        --data-binary "$payload")"; then
        http_status="000"
    fi
    printf '%s' "$http_status"
}

echo "Cyntrisec Verification Center AIR v1 conformance"
echo "Target: $BASE_URL"

for vector_file in "$VECTOR_DIR"/valid/*.json; do
    name="$(basename "$vector_file")"
    response_file="$work_dir/$name.response"
    http_status="$(post_vector "$vector_file" "$response_file")"
    verified="$(jq -r 'if has("verified") then (.verified | tostring) else "missing" end' \
        "$response_file" 2>/dev/null || printf 'invalid-json')"

    if [[ "$http_status" == "200" && "$verified" == "true" ]]; then
        echo "  [PASS] valid/$name"
        passed=$((passed + 1))
    else
        echo "  [FAIL] valid/$name — HTTP $http_status, verified=$verified"
        failed=$((failed + 1))
    fi
done

for vector_file in "$VECTOR_DIR"/invalid/*.json; do
    name="$(basename "$vector_file")"
    response_file="$work_dir/$name.response"
    http_status="$(post_vector "$vector_file" "$response_file")"
    expected_check="$(jq -r '.expected_failure.check' "$vector_file")"
    expected_code="$(jq -r '.expected_failure.code' "$vector_file")"
    # Golden vectors use the AIR specification's broad "COSE" check name.
    # The HTTP API exposes the implementation's more precise layer-1 ID.
    expected_api_check="$expected_check"
    if [[ "$expected_check" == "COSE" ]]; then
        expected_api_check="COSE_DECODE"
    fi
    verified="$(jq -r 'if has("verified") then (.verified | tostring) else "missing" end' \
        "$response_file" 2>/dev/null || printf 'invalid-json')"
    check_count="$(jq --arg expected "$expected_api_check" \
        '[.checks[]? | select(.id == $expected and .status == "fail")] | length' \
        "$response_file" 2>/dev/null || printf '0')"
    code_count="$(jq --arg expected "$expected_code" \
        '[.errors[]? | select(contains($expected))] | length' \
        "$response_file" 2>/dev/null || printf '0')"

    if [[ "$http_status" == "200" && "$verified" == "false" \
        && "$check_count" -gt 0 && "$code_count" -gt 0 ]]; then
        echo "  [PASS] invalid/$name — $expected_code"
        passed=$((passed + 1))
    else
        echo "  [FAIL] invalid/$name — HTTP $http_status, verified=$verified, expected=$expected_api_check/$expected_code"
        failed=$((failed + 1))
    fi
done

echo "Summary: $passed passed, $failed failed"
if [[ "$failed" -ne 0 ]]; then
    exit 1
fi
