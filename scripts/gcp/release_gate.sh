#!/usr/bin/env bash
# EphemeralML GCP Release Gate
#
# Validates the codebase is ready for a GCP production release.
# Runs format checks, linting, tests, and preflight verification.
#
# Usage:
#   bash scripts/gcp/release_gate.sh             # full gate
#   bash scripts/gcp/release_gate.sh --quick      # skip slow tests (fmt + clippy + unit)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

QUICK=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick) QUICK=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

PASS=0
FAIL=0
TOTAL=0

run_step() {
    local name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "────────────────────────────────────────"
    echo "  [${TOTAL}] ${name}"
    echo "────────────────────────────────────────"
    if "$@"; then
        PASS=$((PASS + 1))
        echo "  ✓ PASS: ${name}"
    else
        FAIL=$((FAIL + 1))
        echo "  ✗ FAIL: ${name}"
    fi
}

echo "============================================"
echo "  EphemeralML GCP Release Gate"
echo "============================================"
if $QUICK; then
    echo "  Mode: --quick (skipping slow tests)"
fi
echo ""

cd "${PROJECT_DIR}"

# 1. Format check
run_step "cargo fmt --check" cargo fmt --check

# 2. Clippy (workspace)
run_step "clippy (workspace)" cargo clippy --workspace -- -D warnings

# 3. Clippy (GCP enclave)
run_step "clippy (GCP enclave)" cargo clippy --no-default-features --features gcp -p ephemeral-ml-enclave -- -D warnings

# 4. Clippy (GCP client)
run_step "clippy (GCP client)" cargo clippy --no-default-features --features gcp -p ephemeral-ml-client -- -D warnings

# 5. Unit tests (workspace)
run_step "cargo test (workspace)" cargo test --workspace

if ! $QUICK; then
    # 6. GCP-specific tests
    run_step "cargo test (GCP enclave)" cargo test --no-default-features --features gcp -p ephemeral-ml-enclave

    # 7. GCS-KMS integration test
    run_step "GCS-KMS integration" cargo test --no-default-features --features gcp -p ephemeral-ml-enclave --test gcs_kms_integration

    # 8. Doctor preflight
    run_step "doctor.sh" bash scripts/doctor.sh

    # 9. CLI --help contains expected env vars
    run_step "CLI env vars" bash -c '
        cargo run --no-default-features --features gcp -p ephemeral-ml-enclave -- --help 2>&1 | grep -q EPHEMERALML_MODEL_SOURCE &&
        cargo run --no-default-features --features gcp -p ephemeral-ml-enclave -- --help 2>&1 | grep -q EPHEMERALML_GCP_WIP_AUDIENCE &&
        cargo run --no-default-features --features gcp -p ephemeral-ml-enclave -- --help 2>&1 | grep -q EPHEMERALML_GCP_KMS_KEY
    '
fi

# Summary
echo ""
echo "============================================"
echo "  Release Gate Summary"
echo "============================================"
echo ""
echo "  Total: ${TOTAL}"
echo "  Pass:  ${PASS}"
echo "  Fail:  ${FAIL}"
echo ""

if [[ ${FAIL} -gt 0 ]]; then
    echo "  RELEASE GATE: FAILED"
    exit 1
else
    echo "  RELEASE GATE: PASSED"
    exit 0
fi
