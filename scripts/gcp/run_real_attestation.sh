#!/usr/bin/env bash
# run_real_attestation.sh — Run EphemeralML with real TDX hardware attestation.
#
# Captures a full run without --synthetic on a GCP c3-standard-4 TDX VM.
# Produces timestamped output proving real hardware attestation binding.
#
# Prerequisites:
#   - Running on GCP Confidential VM (c3-standard-4, TDX)
#   - sudo access (configfs-tsm requires root)
#   - Model weights in test_assets/minilm/
#   - Built with: cargo build --release --features mock,gcp
#
# Usage:
#   sudo bash scripts/gcp/run_real_attestation.sh
#
# To launch the VM:
#   gcloud compute instances create ephml-tdx \
#     --zone=us-central1-a --machine-type=c3-standard-4 \
#     --confidential-compute-type=TDX --min-cpu-platform="Intel Sapphire Rapids" \
#     --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
#     --maintenance-policy=TERMINATE
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_DIR/attestation-evidence"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="$OUTPUT_DIR/real-attestation-$TIMESTAMP.log"

mkdir -p "$OUTPUT_DIR"

# ── Check prerequisites ────────────────────────────────────

echo "EphemeralML Real Hardware Attestation" | tee "$OUTPUT_FILE"
echo "=====================================" | tee -a "$OUTPUT_FILE"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Check TDX hardware
echo "[1/6] Checking TDX hardware..." | tee -a "$OUTPUT_FILE"
if [ -d /sys/kernel/config/tsm/report ]; then
    echo "  configfs-tsm: PRESENT" | tee -a "$OUTPUT_FILE"
else
    echo "  configfs-tsm: MISSING — not a TDX VM" | tee -a "$OUTPUT_FILE"
    echo "  Falling back to smoke test with --synthetic" | tee -a "$OUTPUT_FILE"
    SYNTHETIC_FLAG="--synthetic"
fi

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "  WARNING: Not running as root. configfs-tsm may fail." | tee -a "$OUTPUT_FILE"
    echo "  Hint: sudo bash $0" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"

# ── Check model ────────────────────────────────────────────

echo "[2/6] Checking model weights..." | tee -a "$OUTPUT_FILE"
MODEL_DIR="$PROJECT_DIR/test_assets/minilm"
if [ -f "$MODEL_DIR/model.safetensors" ]; then
    echo "  Model: $MODEL_DIR/model.safetensors" | tee -a "$OUTPUT_FILE"
    ls -lh "$MODEL_DIR/model.safetensors" | tee -a "$OUTPUT_FILE"
else
    echo "  Downloading model..." | tee -a "$OUTPUT_FILE"
    bash "$PROJECT_DIR/scripts/download_model.sh" 2>&1 | tee -a "$OUTPUT_FILE"
fi
echo "" | tee -a "$OUTPUT_FILE"

# ── Build ──────────────────────────────────────────────────

echo "[3/6] Building (mock+gcp features, release)..." | tee -a "$OUTPUT_FILE"
cd "$PROJECT_DIR"
cargo build --release --features mock,gcp 2>&1 | tail -5 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# ── TDX Smoke Test ─────────────────────────────────────────

echo "[4/6] Running TDX attestation smoke test..." | tee -a "$OUTPUT_FILE"
ENCLAVE_BIN="$PROJECT_DIR/target/release/ephemeral-ml-enclave"

"$ENCLAVE_BIN" --smoke-tdx ${SYNTHETIC_FLAG:-} 2>&1 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# ── Direct Mode Server ─────────────────────────────────────

echo "[5/6] Starting server with real attestation (direct mode)..." | tee -a "$OUTPUT_FILE"

"$ENCLAVE_BIN" \
    --model-dir "$MODEL_DIR" \
    --model-id stage-0 \
    --gcp \
    --model-source local \
    --direct \
    ${SYNTHETIC_FLAG:-} \
    > "$OUTPUT_DIR/server-$TIMESTAMP.log" 2>&1 &
SERVER_PID=$!
echo "  Server PID: $SERVER_PID" | tee -a "$OUTPUT_FILE"

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for server to start
echo "  Waiting for server..." | tee -a "$OUTPUT_FILE"
ATTEMPTS=0
while ! bash -c "echo > /dev/tcp/127.0.0.1/9000" 2>/dev/null; do
    sleep 1
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ $ATTEMPTS -ge 30 ]; then
        echo "  ERROR: Server failed to start" | tee -a "$OUTPUT_FILE"
        echo "  Server log:" | tee -a "$OUTPUT_FILE"
        tail -20 "$OUTPUT_DIR/server-$TIMESTAMP.log" | tee -a "$OUTPUT_FILE"
        exit 1
    fi
done
echo "  Server ready." | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# ── Inference + Receipt ────────────────────────────────────

echo "[6/6] Running inference with receipt capture..." | tee -a "$OUTPUT_FILE"
CLI_BIN="$PROJECT_DIR/target/release/ephemeralml"
RECEIPT="$OUTPUT_DIR/receipt-$TIMESTAMP.json"

"$CLI_BIN" infer \
    --addr 127.0.0.1:9000 \
    --text "Patient presents with acute respiratory distress and bilateral infiltrates." \
    --receipt "$RECEIPT" \
    2>&1 | tee -a "$OUTPUT_FILE"

echo "" | tee -a "$OUTPUT_FILE"

# ── Verify Receipt ─────────────────────────────────────────

PUBKEY="$RECEIPT.pubkey"
if [ -f "$PUBKEY" ]; then
    echo "Verifying receipt..." | tee -a "$OUTPUT_FILE"
    "$CLI_BIN" verify "$RECEIPT" \
        --public-key-file "$PUBKEY" \
        --max-age 0 \
        2>&1 | tee -a "$OUTPUT_FILE" || true
fi

echo "" | tee -a "$OUTPUT_FILE"

# ── Extract attestation hash ──────────────────────────────

echo "Attestation Evidence:" | tee -a "$OUTPUT_FILE"
echo "---------------------" | tee -a "$OUTPUT_FILE"

if command -v python3 &>/dev/null && [ -f "$RECEIPT" ]; then
    python3 -c "
import json
r = json.load(open('$RECEIPT'))
att = r.get('attestation_doc_hash', [])
att_hex = ''.join(f'{b:02x}' for b in att) if isinstance(att, list) else str(att)
print(f'  attestation_doc_hash: {att_hex}')
zero = all(b == 0 for b in att) if isinstance(att, list) else att == '0' * 64
print(f'  hardware_bound:       {\"YES\" if not zero else \"NO (zero — mock or synthetic)\"}')
print(f'  model_id:             {r.get(\"model_id\")}')
print(f'  model_version:        {r.get(\"model_version\")}')
print(f'  sequence_number:      {r.get(\"sequence_number\")}')
print(f'  platform:             {r.get(\"enclave_measurements\", {}).get(\"measurement_type\")}')
" 2>&1 | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "Server log: $OUTPUT_DIR/server-$TIMESTAMP.log" | tee -a "$OUTPUT_FILE"
echo "Receipt:    $RECEIPT" | tee -a "$OUTPUT_FILE"
echo "Full log:   $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"
echo "Done." | tee -a "$OUTPUT_FILE"
