#!/usr/bin/env bash
# Ensure no verifier runtime input changed after the deployed build commit.

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

health="$(curl "${CURL_CONFIG_ARGS[@]}" -fsS --max-time 20 "$BASE_URL/health")"
actual_sha="$(jq -r '.build_sha // "unknown"' <<<"$health")"
cloud_revision="$(jq -r '.cloud_revision // "unknown"' <<<"$health")"
expected_sha="${EXPECTED_BUILD_SHA:-}"

if [[ -n "$expected_sha" ]]; then
    if [[ "$actual_sha" != "$expected_sha" ]]; then
        echo "FAIL: deployed build $actual_sha does not match expected commit $expected_sha" >&2
        echo "Cloud revision: $cloud_revision" >&2
        exit 1
    fi
    echo "PASS: deployed build matches $expected_sha ($cloud_revision)"
    exit 0
fi

if [[ ! "$actual_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "FAIL: health endpoint returned an invalid build SHA: $actual_sha" >&2
    echo "Cloud revision: $cloud_revision" >&2
    exit 1
fi

if ! git -C "$REPO_DIR" cat-file -e "${actual_sha}^{commit}" 2>/dev/null; then
    echo "FAIL: deployed build commit $actual_sha is not present in this repository" >&2
    echo "Cloud revision: $cloud_revision" >&2
    exit 1
fi

if ! git -C "$REPO_DIR" merge-base --is-ancestor "$actual_sha" HEAD; then
    echo "FAIL: deployed build $actual_sha is not an ancestor of $(git -C "$REPO_DIR" rev-parse HEAD)" >&2
    echo "Cloud revision: $cloud_revision" >&2
    exit 1
fi

if git -C "$REPO_DIR" diff --quiet "$actual_sha..HEAD" -- \
    .dockerignore Cargo.toml Cargo.lock Dockerfile.verifier \
    cloudbuild-verifier.yaml common client verifier-api; then
    echo "PASS: deployed build $actual_sha has no verifier runtime drift ($cloud_revision)"
    exit 0
fi

latest_runtime_change="$(
    git -C "$REPO_DIR" log -1 --format=%H "$actual_sha..HEAD" -- \
        .dockerignore Cargo.toml Cargo.lock Dockerfile.verifier \
        cloudbuild-verifier.yaml common client verifier-api
)"
echo "FAIL: verifier runtime inputs changed after deployed build $actual_sha" >&2
echo "Latest runtime change: ${latest_runtime_change:-unknown}" >&2
echo "Cloud revision: $cloud_revision" >&2
exit 1
