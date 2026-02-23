#!/usr/bin/env bash
# Test that deploy.sh metadata rendering includes WIP audience for all model sources.
#
# This is a regression test for the fix where EPHEMERALML_GCP_WIP_AUDIENCE was
# only passed to CVM metadata for --model-source=gcs-kms. Transport attestation
# (Launcher JWT) needs WIP audience regardless of model source.
#
# Usage: bash scripts/test_deploy_metadata.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0

check() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    if [[ "$actual" == *"$expected"* ]]; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name"
        echo "    Expected to contain: $expected"
        echo "    Got: $actual"
        FAIL=$((FAIL + 1))
    fi
}

check_absent() {
    local test_name="$1"
    local absent="$2"
    local actual="$3"
    if [[ "$actual" != *"$absent"* ]]; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name"
        echo "    Expected NOT to contain: $absent"
        echo "    Got: $actual"
        FAIL=$((FAIL + 1))
    fi
}

# Simulate deploy.sh metadata assembly logic (extracted from deploy.sh lines 270-301)
build_metadata() {
    local MODEL_SOURCE="$1"
    local WIP_AUDIENCE="${2:-}"
    local KMS_KEY="${3:-}"
    local GCS_BUCKET="${4:-ephemeralml-models}"
    local GCP_MODEL_PREFIX="${5:-models/minilm}"
    local EXPECTED_MODEL_HASH="${6:-abc123}"
    local MODEL_FORMAT="${7:-safetensors}"
    local PROJECT="test-project"
    local ZONE="us-central1-a"

    local METADATA="tee-image-reference=test-image"
    METADATA="${METADATA},tee-restart-policy=Never"
    METADATA="${METADATA},tee-container-log-redirect=true"
    METADATA="${METADATA},tee-env-EPHEMERALML_MODEL_SOURCE=${MODEL_SOURCE}"
    METADATA="${METADATA},tee-env-EPHEMERALML_DIRECT=true"
    METADATA="${METADATA},tee-env-EPHEMERALML_MODEL_FORMAT=${MODEL_FORMAT}"
    METADATA="${METADATA},tee-env-EPHEMERALML_LOG_FORMAT=json"
    METADATA="${METADATA},tee-env-EPHEMERALML_GCP_PROJECT=${PROJECT}"
    METADATA="${METADATA},tee-env-EPHEMERALML_GCP_LOCATION=${ZONE%-*}"

    if [[ "${MODEL_SOURCE}" == "gcs" || "${MODEL_SOURCE}" == "gcs-kms" ]]; then
        METADATA="${METADATA},tee-env-EPHEMERALML_GCS_BUCKET=${GCS_BUCKET}"
        METADATA="${METADATA},tee-env-EPHEMERALML_GCP_MODEL_PREFIX=${GCP_MODEL_PREFIX}"
        METADATA="${METADATA},tee-env-EPHEMERALML_EXPECTED_MODEL_HASH=${EXPECTED_MODEL_HASH}"
    fi
    if [[ "${MODEL_SOURCE}" == "gcs-kms" ]]; then
        METADATA="${METADATA},tee-env-EPHEMERALML_GCP_KMS_KEY=${KMS_KEY}"
    fi
    # This is the fix: WIP audience passed whenever available, not just gcs-kms
    if [[ -n "${WIP_AUDIENCE}" ]]; then
        METADATA="${METADATA},tee-env-EPHEMERALML_GCP_WIP_AUDIENCE=${WIP_AUDIENCE}"
    fi

    echo "$METADATA"
}

echo "=== Deploy Metadata Regression Tests ==="
echo ""

# Test 1: local mode with WIP audience
META=$(build_metadata "local" "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov")
check "local + WIP: audience present" "tee-env-EPHEMERALML_GCP_WIP_AUDIENCE=//iam.googleapis.com" "$META"
check_absent "local: no GCS bucket" "tee-env-EPHEMERALML_GCS_BUCKET" "$META"
check_absent "local: no KMS key" "tee-env-EPHEMERALML_GCP_KMS_KEY" "$META"

# Test 2: gcs mode with WIP audience
META=$(build_metadata "gcs" "//iam.googleapis.com/wip" "" "my-bucket" "models/v1" "deadbeef")
check "gcs + WIP: audience present" "tee-env-EPHEMERALML_GCP_WIP_AUDIENCE=//iam.googleapis.com/wip" "$META"
check "gcs: bucket present" "tee-env-EPHEMERALML_GCS_BUCKET=my-bucket" "$META"
check "gcs: model hash present" "tee-env-EPHEMERALML_EXPECTED_MODEL_HASH=deadbeef" "$META"
check_absent "gcs: no KMS key" "tee-env-EPHEMERALML_GCP_KMS_KEY" "$META"

# Test 3: gcs-kms mode with WIP audience
META=$(build_metadata "gcs-kms" "//iam.googleapis.com/wip" "projects/p/locations/l/keyRings/k/cryptoKeys/c")
check "gcs-kms + WIP: audience present" "tee-env-EPHEMERALML_GCP_WIP_AUDIENCE=//iam.googleapis.com/wip" "$META"
check "gcs-kms: KMS key present" "tee-env-EPHEMERALML_GCP_KMS_KEY=projects/p" "$META"
check "gcs-kms: bucket present" "tee-env-EPHEMERALML_GCS_BUCKET" "$META"

# Test 4: no WIP audience provided
META=$(build_metadata "local" "")
check_absent "local, no WIP: audience absent" "tee-env-EPHEMERALML_GCP_WIP_AUDIENCE" "$META"

# Test 5: model source appears correctly
META=$(build_metadata "local" "wip")
check "model source local" "tee-env-EPHEMERALML_MODEL_SOURCE=local" "$META"
META=$(build_metadata "gcs-kms" "wip" "key")
check "model source gcs-kms" "tee-env-EPHEMERALML_MODEL_SOURCE=gcs-kms" "$META"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
