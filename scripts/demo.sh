#!/usr/bin/env bash
# EphemeralML End-to-End Demo
# Loads MiniLM-L6-v2 in enclave, sends text, gets 384-dim embeddings + signed receipt
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODEL_DIR="$PROJECT_DIR/test_assets/minilm"

echo "============================================"
echo "  EphemeralML - Confidential AI Demo"
echo "============================================"
echo

# Step 1: Ensure model weights
echo "[1/5] Checking model weights..."
bash "$SCRIPT_DIR/download_model.sh"
echo

# Step 2: Build (mock mode — for production use --no-default-features --features production)
echo "[2/5] Building enclave and host (release)..."
cd "$PROJECT_DIR"
cargo build --release --features mock -p ephemeral-ml-enclave -p ephemeral-ml-host 2>&1 | tail -5
echo "Build complete."
echo

# Step 3: Start enclave in background
echo "[3/5] Starting enclave stage worker..."
cargo run --release --features mock --bin ephemeral-ml-enclave -- \
    --model-dir "$MODEL_DIR" --model-id stage-0 &
ENCLAVE_PID=$!

# Cleanup on exit
cleanup() {
    if kill -0 "$ENCLAVE_PID" 2>/dev/null; then
        kill "$ENCLAVE_PID" 2>/dev/null || true
        wait "$ENCLAVE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Step 4: Wait for enclave to load model and bind ports
echo "[4/5] Waiting for enclave to start..."
sleep 4
echo

# Step 5: Run host (connects, infers, prints receipt)
echo "[5/5] Running host inference..."
echo
cargo run --release --features mock --bin ephemeral-ml-host
HOST_EXIT=$?

echo
if [ $HOST_EXIT -eq 0 ]; then
    echo "============================================"
    echo "  Demo completed successfully!"
    echo "============================================"
else
    echo "Demo failed with exit code $HOST_EXIT"
    exit $HOST_EXIT
fi
