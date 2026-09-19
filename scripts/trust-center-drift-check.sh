#!/usr/bin/env bash
# Ensure the live container was built from the latest commit that can affect it.

set -euo pipefail

BASE_URL="${1:-https://verify.cyntrisec.com}"
BASE_URL="${BASE_URL%/}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURL_CONFIG_ARGS=()
if [[ -n "${TRUST_CENTER_CURL_CONFIG:-}" ]]; then
    if [[ ! -r "$TRUST_CENTER_CURL_CONFIG" ]]; then
        echo "ERROR: curl config is not readable: $TRUST_CENTER_CURL_CONFIG" >&2
        exit 2
    fi
    CURL_CONFIG_ARGS=(--config "$TRUST_CENTER_CURL_CONFIG")
fi

expected_sha="${EXPECTED_BUILD_SHA:-}"
if [[ -z "$expected_sha" ]]; then
    expected_sha="$(
        git -C "$REPO_DIR" log -1 --format=%H -- \
            Cargo.toml Cargo.lock Dockerfile.verifier \
            common client verifier-api
    )"
fi

if [[ -z "$expected_sha" ]]; then
    echo "ERROR: could not resolve expected verifier source commit" >&2
    exit 2
fi

health="$(curl "${CURL_CONFIG_ARGS[@]}" -fsS --max-time 20 "$BASE_URL/health")"
actual_sha="$(jq -r '.build_sha // "unknown"' <<<"$health")"
cloud_revision="$(jq -r '.cloud_revision // "unknown"' <<<"$health")"

if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "FAIL: deployed build $actual_sha does not match expected source commit $expected_sha" >&2
    echo "Cloud revision: $cloud_revision" >&2
    exit 1
fi

echo "PASS: deployed build matches $expected_sha ($cloud_revision)"
