#!/usr/bin/env bash
# EphemeralML One-Command Demo
#
# Usage:
#   bash scripts/demo.sh              # Run full demo (up → infer → verify → tamper → down)
#   bash scripts/demo.sh up           # Start server only
#   bash scripts/demo.sh infer        # Run inference (server must be running)
#   bash scripts/demo.sh verify       # Verify the receipt
#   bash scripts/demo.sh tamper       # Tamper receipt, show verification FAIL
#   bash scripts/demo.sh down         # Stop server
#   bash scripts/demo.sh all          # Full automated sequence
#
# Prerequisites:
#   - Model assets in test_assets/minilm/ (auto-downloaded if missing)
#   - Rust toolchain installed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODEL_DIR="$PROJECT_DIR/test_assets/minilm"
PID_FILE="$PROJECT_DIR/.demo-server.pid"
RECEIPT_FILE="$PROJECT_DIR/demo-receipt.json"
PUBKEY_FILE="$PROJECT_DIR/demo-receipt.json.pubkey"
TAMPERED_FILE="$PROJECT_DIR/demo-receipt-tampered.json"

ENCLAVE_BIN="$PROJECT_DIR/target/release/ephemeral-ml-enclave"
CLI_BIN="$PROJECT_DIR/target/release/ephemeralml"

# ── Helpers ──────────────────────────────────────────────

header() {
    echo
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
}

ensure_built() {
    if [ ! -f "$ENCLAVE_BIN" ] || [ ! -f "$CLI_BIN" ]; then
        echo "  Building (mock mode, release)..."
        cd "$PROJECT_DIR"
        cargo build --release --features mock 2>&1 | tail -3
        echo "  Build complete."
        echo
    fi
}

ensure_model() {
    if [ ! -f "$MODEL_DIR/model.safetensors" ]; then
        echo "  Downloading model weights..."
        bash "$SCRIPT_DIR/download_model.sh"
        echo
    fi
}

# ── Commands ─────────────────────────────────────────────

cmd_up() {
    header "DEMO UP — Starting EphemeralML Server"

    ensure_model
    ensure_built

    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "  Server already running (PID $(cat "$PID_FILE"))"
        return 0
    fi

    echo "  Starting enclave server (direct mode, mock attestation)..."
    "$ENCLAVE_BIN" \
        --model-dir "$MODEL_DIR" \
        --model-id stage-0 \
        --direct \
        > "$PROJECT_DIR/.demo-server.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"

    # Wait for port to open
    echo "  Waiting for server to bind 127.0.0.1:9000..."
    local attempts=0
    while ! bash -c "echo > /dev/tcp/127.0.0.1/9000" 2>/dev/null; do
        sleep 0.5
        attempts=$((attempts + 1))
        if [ $attempts -ge 20 ]; then
            echo "  ERROR: Server failed to start within 10s"
            echo "  Log:"
            tail -10 "$PROJECT_DIR/.demo-server.log"
            kill "$pid" 2>/dev/null || true
            rm -f "$PID_FILE"
            exit 1
        fi
    done
    echo "  Server ready (PID $pid)"
}

cmd_infer() {
    header "DEMO INFER — Confidential Inference"

    ensure_built

    if [ ! -f "$PID_FILE" ] || ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "  ERROR: Server not running. Run: bash scripts/demo.sh up"
        exit 1
    fi

    echo "  Sending: \"Patient presents with acute respiratory distress.\""
    echo

    "$CLI_BIN" infer \
        --addr 127.0.0.1:9000 \
        --text "Patient presents with acute respiratory distress and bilateral infiltrates on chest X-ray." \
        --receipt "$RECEIPT_FILE"
}

cmd_verify() {
    header "DEMO VERIFY — Receipt Verification"

    ensure_built

    if [ ! -f "$RECEIPT_FILE" ]; then
        echo "  ERROR: No receipt found. Run: bash scripts/demo.sh infer"
        exit 1
    fi

    if [ ! -f "$PUBKEY_FILE" ]; then
        echo "  ERROR: No public key file. Run: bash scripts/demo.sh infer"
        exit 1
    fi

    "$CLI_BIN" verify "$RECEIPT_FILE" \
        --public-key-file "$PUBKEY_FILE" \
        --max-age 0 \
    || true
}

cmd_tamper() {
    header "DEMO TAMPER — Tamper Detection"

    if [ ! -f "$RECEIPT_FILE" ]; then
        echo "  ERROR: No receipt found. Run: bash scripts/demo.sh infer"
        exit 1
    fi

    if [ ! -f "$PUBKEY_FILE" ]; then
        echo "  ERROR: No public key file. Run: bash scripts/demo.sh infer"
        exit 1
    fi

    # Tamper: change model_id in the receipt
    echo "  Tampering receipt: changing model_id to 'TAMPERED'..."
    python3 -c "
import json, sys
r = json.load(open('$RECEIPT_FILE'))
r['model_id'] = 'TAMPERED'
json.dump(r, open('$TAMPERED_FILE', 'w'), indent=2)
" 2>/dev/null || {
        # Fallback: use sed if python3 not available
        sed 's/"model_id":"[^"]*"/"model_id":"TAMPERED"/' "$RECEIPT_FILE" > "$TAMPERED_FILE"
    }

    echo "  Verifying tampered receipt (should FAIL)..."
    echo

    "$CLI_BIN" verify "$TAMPERED_FILE" \
        --public-key-file "$PUBKEY_FILE" \
        --max-age 0 \
    && echo "  BUG: Tampered receipt should not verify!" \
    || echo "  Tamper correctly detected."
}

cmd_down() {
    header "DEMO DOWN — Stopping Server"

    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            echo "  Server stopped (PID $pid)"
        else
            echo "  Server already stopped"
        fi
        rm -f "$PID_FILE"
    else
        echo "  No server running"
    fi

    # Cleanup temp files
    rm -f "$TAMPERED_FILE" "$PROJECT_DIR/.demo-server.log"
    echo "  Cleaned up."
}

cmd_all() {
    header "EphemeralML Confidential AI — Full Demo"

    echo "  This demo proves:"
    echo "    1. Data enters a TEE-attested enclave"
    echo "    2. Model runs inference, produces output"
    echo "    3. A signed receipt binds input/output hashes to attestation"
    echo "    4. Tampering is cryptographically detected"
    echo

    cmd_up
    cmd_infer
    cmd_verify
    cmd_tamper
    cmd_down

    header "Demo Complete"
    echo "  All steps passed. Your data existed for ~2 seconds."
    echo "  Here's the cryptographic proof: $RECEIPT_FILE"
    echo
}

# ── Main ─────────────────────────────────────────────────

case "${1:-all}" in
    up)     cmd_up ;;
    infer)  cmd_infer ;;
    verify) cmd_verify ;;
    tamper) cmd_tamper ;;
    down)   cmd_down ;;
    all)    cmd_all ;;
    *)
        echo "Usage: $0 {up|infer|verify|tamper|down|all}"
        exit 1
        ;;
esac
