#!/usr/bin/env bash
# smoke_test_nitro.sh — Orchestrate production attestation smoke test on a Nitro instance.
#
# This script automates the full workflow:
#   1. Build the enclave binary (production mode)
#   2. Build the smoke test binary
#   3. Build the Docker image and EIF
#   4. Start the enclave
#   5. Run the smoke test
#   6. Capture and display results
#   7. Terminate the enclave
#
# Prerequisites:
#   - Run ON the Nitro-enabled EC2 instance (m6i.xlarge+)
#   - Docker and nitro-cli installed and running
#   - Rust toolchain installed
#   - Repo cloned and available at $REPO_DIR
#
# Usage:
#   ./scripts/smoke_test_nitro.sh [--cid CID] [--port PORT] [--skip-build] [--debug]
#
# Environment variables:
#   REPO_DIR    — Path to repo root (default: script's parent directory)
#   ENCLAVE_CID — Enclave CID (default: 16)
#   ENCLAVE_PORT — VSock port (default: 5000)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(dirname "$SCRIPT_DIR")}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
ENCLAVE_PORT="${ENCLAVE_PORT:-5000}"
SKIP_BUILD=false
DEBUG_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cid)
            ENCLAVE_CID="$2"
            shift 2
            ;;
        --port)
            ENCLAVE_PORT="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--cid CID] [--port PORT] [--skip-build] [--debug]"
            echo ""
            echo "Options:"
            echo "  --cid CID      Enclave CID (default: 16)"
            echo "  --port PORT    VSock port (default: 5000)"
            echo "  --skip-build   Skip cargo and docker builds (use existing artifacts)"
            echo "  --debug        Run enclave in debug mode (enables console, zeros PCR values)"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

echo "=== EphemeralML Production Attestation Smoke Test ==="
echo "Repository: $REPO_DIR"
echo "Enclave CID: $ENCLAVE_CID"
echo "Enclave Port: $ENCLAVE_PORT"
echo "Debug mode: $DEBUG_MODE"
echo ""

cd "$REPO_DIR"

# Step 1: Build production enclave binary
if [ "$SKIP_BUILD" = false ]; then
    echo "[Step 1/7] Building production enclave binary..."
    cargo build --release --features production --no-default-features -p ephemeral-ml-enclave
    echo "           Done."
    echo ""

    # Step 2: Build smoke test binary
    echo "[Step 2/7] Building smoke test binary..."
    cargo build --release --bin smoke_test_nitro --features production --no-default-features -p ephemeral-ml-host
    echo "           Done."
    echo ""

    # Step 3: Build Docker image and EIF
    echo "[Step 3/7] Building Docker image..."
    docker build -f enclave/Dockerfile.enclave -t ephemeral-ml-enclave:latest .
    echo "           Done."
    echo ""

    echo "[Step 4/7] Building EIF (this may take a while)..."
    nitro-cli build-enclave \
        --docker-uri ephemeral-ml-enclave:latest \
        --output-file /tmp/ephemeral-ml-enclave.eif | tee /tmp/eif_build_output.json
    echo ""
    echo "           EIF built. PCR values from build:"
    cat /tmp/eif_build_output.json
    echo ""
else
    echo "[Steps 1-4] Skipped (--skip-build)"
    echo ""
fi

# Step 5: Terminate any existing enclave
echo "[Step 5/7] Terminating any existing enclaves..."
nitro-cli terminate-enclave --all 2>/dev/null || true
sleep 1
echo "           Done."
echo ""

# Step 6: Start enclave
echo "[Step 6/7] Starting enclave..."
ENCLAVE_RUN_ARGS=(
    --eif-path /tmp/ephemeral-ml-enclave.eif
    --memory 4096
    --cpu-count 2
    --enclave-cid "$ENCLAVE_CID"
)
if [ "$DEBUG_MODE" = true ]; then
    ENCLAVE_RUN_ARGS+=(--debug-mode)
    echo "           NOTE: Debug mode enabled — PCR values will be all zeros."
else
    echo "           NOTE: Non-debug mode — real PCR values from NSM attestation."
fi
ENCLAVE_OUTPUT=$(nitro-cli run-enclave "${ENCLAVE_RUN_ARGS[@]}" 2>&1) || {
    echo "ERROR: Failed to start enclave"
    echo "$ENCLAVE_OUTPUT"
    exit 1
}
echo "$ENCLAVE_OUTPUT"

ENCLAVE_ID=$(echo "$ENCLAVE_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['EnclaveID'])" 2>/dev/null || echo "")
if [ -z "$ENCLAVE_ID" ]; then
    echo "WARNING: Could not extract EnclaveID from output"
    ENCLAVE_ID=$(nitro-cli describe-enclaves | python3 -c "import sys,json; enclaves=json.load(sys.stdin); print(enclaves[0]['EnclaveID'] if enclaves else '')" 2>/dev/null || echo "")
fi

echo "           Enclave started (ID: ${ENCLAVE_ID:-unknown})"
echo ""

# Give the enclave a moment to boot and start listening
echo "           Waiting 10 seconds for enclave to initialize..."
sleep 10

# Start capturing console output in background (only works in debug mode)
if [ "$DEBUG_MODE" = true ] && [ -n "$ENCLAVE_ID" ]; then
    nitro-cli console --enclave-id "$ENCLAVE_ID" > /tmp/enclave_console.log 2>&1 &
    CONSOLE_PID=$!
    echo "           Console capture started (PID: $CONSOLE_PID)"
else
    echo "           Console not available (non-debug mode). Use --debug to enable."
fi
echo ""

# Step 7: Run smoke test
echo "[Step 7/7] Running smoke test..."
echo "=========================================="
echo ""

SMOKE_TEST_EXIT=0
"$REPO_DIR/target/release/smoke_test_nitro" --cid "$ENCLAVE_CID" --port "$ENCLAVE_PORT" || SMOKE_TEST_EXIT=$?

echo ""
echo "=========================================="

# Cleanup
echo ""
echo "[Cleanup] Terminating enclave..."
nitro-cli terminate-enclave --all 2>/dev/null || true

if [ -n "${CONSOLE_PID:-}" ]; then
    kill "$CONSOLE_PID" 2>/dev/null || true
fi

# Show console output if test failed (only available in debug mode)
if [ $SMOKE_TEST_EXIT -ne 0 ]; then
    echo ""
    if [ "$DEBUG_MODE" = true ]; then
        echo "[Debug] Enclave console output (last 50 lines):"
        echo "---"
        tail -50 /tmp/enclave_console.log 2>/dev/null || echo "(no console output captured)"
        echo "---"
    else
        echo "[Info] Console output not available in non-debug mode."
        echo "       Rerun with --debug to see enclave console output on failure."
    fi
fi

exit $SMOKE_TEST_EXIT
