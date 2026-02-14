#!/usr/bin/env bash
# run_pipeline_demo.sh — Launch a 2-stage pipeline demo with receipt chaining.
#
# Starts two stage workers (both running MiniLM) and an orchestrator,
# produces a pipeline proof bundle with chained receipts.
#
# Usage:
#   bash scripts/run_pipeline_demo.sh
#
# Prerequisites:
#   - Model assets in test_assets/minilm/ (run scripts/download_model.sh first)
#   - Built with: cargo build --release --features mock

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

MODEL_DIR="test_assets/minilm"
MANIFEST="manifests/minilm-2stage.json"
OUTPUT="pipeline-proof-bundle.json"

# Check prerequisites
if [ ! -f "${MODEL_DIR}/model.safetensors" ]; then
    echo "ERROR: Model not found at ${MODEL_DIR}/model.safetensors"
    echo "Run: bash scripts/download_model.sh"
    exit 1
fi

if [ ! -f "${MANIFEST}" ]; then
    echo "ERROR: Manifest not found at ${MANIFEST}"
    exit 1
fi

echo "EphemeralML 2-Stage Pipeline Demo"
echo "================================="
echo ""

# Build
echo "[1/5] Building (mock features)..."
cargo build --release --features mock 2>&1 | tail -1

ENCLAVE_BIN="target/release/ephemeral-ml-enclave"
ORCH_BIN="target/release/ephemeralml-orchestrator"
VERIFY_BIN="target/release/ephemeralml"

if [ ! -f "${ENCLAVE_BIN}" ]; then
    echo "ERROR: ${ENCLAVE_BIN} not found"
    exit 1
fi

# Stage 0: control=10000, data_in=10001, data_out→11001 (stage 1's data_in)
echo "[2/5] Launching stage 0 (layers 0-5)..."
"${ENCLAVE_BIN}" \
    --model-dir "${MODEL_DIR}" \
    --model-id "stage-0" \
    --control-addr 127.0.0.1:10000 \
    --data-in-addr 127.0.0.1:10001 \
    --data-out-target 127.0.0.1:11001 \
    &
STAGE0_PID=$!
echo "  PID: ${STAGE0_PID}"

# Stage 1: control=11000, data_in=11001, data_out→orchestrator (will connect)
echo "[3/5] Launching stage 1 (layers 6-11)..."
"${ENCLAVE_BIN}" \
    --model-dir "${MODEL_DIR}" \
    --model-id "stage-1" \
    --control-addr 127.0.0.1:11000 \
    --data-in-addr 127.0.0.1:11001 \
    --data-out-target 127.0.0.1:12000 \
    &
STAGE1_PID=$!
echo "  PID: ${STAGE1_PID}"

# Wait for stages to bind
sleep 2

# Orchestrator
echo "[4/5] Running orchestrator..."
"${ORCH_BIN}" \
    --manifest "${MANIFEST}" \
    --text "The patient presents with acute respiratory distress and bilateral infiltrates." \
    --output "${OUTPUT}" \
    || true

echo ""

# Verify pipeline
if [ -f "${OUTPUT}" ]; then
    echo "[5/5] Verifying pipeline proof bundle..."
    "${VERIFY_BIN}" verify-pipeline "${OUTPUT}" --max-age 0 || true
else
    echo "[5/5] No proof bundle generated (orchestrator may have failed)"
fi

# Cleanup
echo ""
echo "Cleaning up..."
kill "${STAGE0_PID}" 2>/dev/null || true
kill "${STAGE1_PID}" 2>/dev/null || true
wait "${STAGE0_PID}" 2>/dev/null || true
wait "${STAGE1_PID}" 2>/dev/null || true

echo "Done."
