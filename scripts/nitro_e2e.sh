#!/usr/bin/env bash
# nitro_e2e.sh — End-to-end Nitro Enclave inference with PCR-pinned attestation.
#
# This script runs the full EphemeralML production pipeline on a Nitro-enabled EC2 instance:
#   1. Build production enclave + host binaries
#   2. Build Docker image and EIF (with model bundled)
#   3. Extract PCR measurements for pinning
#   4. Launch enclave
#   5. Run host orchestrator with PCR pinning
#   6. Collect evidence (logs, receipt, timing)
#   7. Cleanup
#
# Prerequisites:
#   - Run ON a Nitro-enabled EC2 instance (m6i.xlarge+)
#   - Docker, nitro-cli installed and running
#   - Rust toolchain installed
#   - ec2-user in docker and ne groups
#
# Usage:
#   ./scripts/nitro_e2e.sh [--skip-build] [--debug] [--text "your input text"]
#
# Evidence is collected in /tmp/nitro-e2e-evidence/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(dirname "$SCRIPT_DIR")}"
EVIDENCE_DIR="/tmp/nitro-e2e-evidence"
EIF_PATH="/tmp/ephemeral-ml-enclave.eif"

# Defaults
ENCLAVE_CID=16
ENCLAVE_MEMORY=4096
ENCLAVE_CPUS=2
SKIP_BUILD=false
DEBUG_MODE=false
INPUT_TEXT="Confidential AI inference with cryptographic proof"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build) SKIP_BUILD=true; shift ;;
        --debug) DEBUG_MODE=true; shift ;;
        --text) INPUT_TEXT="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--skip-build] [--debug] [--text \"input text\"]"
            echo ""
            echo "Options:"
            echo "  --skip-build   Skip cargo and docker builds"
            echo "  --debug        Run enclave in debug mode (enables console, zeros PCRs)"
            echo "  --text TEXT    Input text for inference (default: standard test phrase)"
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# --- Helpers ---
ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*"; }
fail() { echo "[$(ts)] FATAL: $*" >&2; exit 1; }

# --- Setup evidence directory ---
rm -rf "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR"
log "Evidence directory: $EVIDENCE_DIR"

cd "$REPO_DIR"
log "Repository: $REPO_DIR"
log "Debug mode: $DEBUG_MODE"
log "Input text: \"$INPUT_TEXT\""
echo ""

# ============================================================
# PHASE 1: BUILD
# ============================================================
if [ "$SKIP_BUILD" = false ]; then
    log "=== PHASE 1: BUILD ==="

    log "[1/4] Building production enclave binary..."
    BUILD_START=$(date +%s)
    cargo build --release --no-default-features --features production \
        -p ephemeral-ml-enclave 2>&1 | tail -5
    BUILD_END=$(date +%s)
    log "       Enclave binary built in $((BUILD_END - BUILD_START))s"

    log "[2/4] Building production host binary..."
    BUILD_START=$(date +%s)
    cargo build --release --no-default-features --features production \
        -p ephemeral-ml-host 2>&1 | tail -5
    BUILD_END=$(date +%s)
    log "       Host binary built in $((BUILD_END - BUILD_START))s"

    log "[3/4] Building Docker image..."
    # target/ is in .dockerignore, so stage the binary outside it
    mkdir -p docker-stage
    cp target/release/ephemeral-ml-enclave docker-stage/
    docker build -f enclave/Dockerfile.enclave -t ephemeral-ml-enclave:latest . 2>&1 | tail -3
    log "       Docker image built."

    log "[4/4] Building EIF (this takes ~30-60s)..."
    nitro-cli build-enclave \
        --docker-uri ephemeral-ml-enclave:latest \
        --output-file "$EIF_PATH" > "$EVIDENCE_DIR/eif_build_output.json" 2>&1
    log "       EIF built."
    echo ""
else
    log "=== PHASE 1: BUILD (skipped) ==="
    if [ ! -f "$EIF_PATH" ]; then
        fail "EIF not found at $EIF_PATH. Cannot skip build without existing EIF."
    fi
    echo ""
fi

# ============================================================
# PHASE 2: EXTRACT PCR MEASUREMENTS
# ============================================================
log "=== PHASE 2: PCR EXTRACTION ==="

# Extract PCRs from the EIF build output
if [ ! -f "$EVIDENCE_DIR/eif_build_output.json" ]; then
    # If build was skipped, try to rebuild just the EIF measurements
    log "No EIF build output found — re-reading measurements..."
    nitro-cli describe-eif --eif-path "$EIF_PATH" > "$EVIDENCE_DIR/eif_build_output.json" 2>&1 || true
fi

# Parse PCRs — nitro-cli may print status lines before the JSON payload.
extract_pcr() {
    local pcr_name="$1"
    python3 - "$EVIDENCE_DIR/eif_build_output.json" "$pcr_name" <<'PY' 2>/dev/null
import json
import sys

path, pcr_name = sys.argv[1], sys.argv[2]
try:
    raw = open(path, "r", encoding="utf-8", errors="replace").read()
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        print("")
        raise SystemExit(0)
    data = json.loads(raw[start:end + 1])
    if "Measurements" in data:
        print(data["Measurements"].get(pcr_name, ""))
    else:
        print(data.get(pcr_name, ""))
except Exception:
    print("")
PY
}

PCR0=$(extract_pcr "PCR0")
PCR1=$(extract_pcr "PCR1")
PCR2=$(extract_pcr "PCR2")

# Debug mode zeros out PCRs — that's expected, but we still pin them
if [ "$DEBUG_MODE" = true ]; then
    log "WARNING: Debug mode — PCR values from the EIF build are real,"
    log "         but the enclave will report all-zero PCRs at runtime."
    log "         PCR pinning will use all-zero values for debug mode."
    PCR0=$(printf '%096d' 0)
    PCR1=$(printf '%096d' 0)
    PCR2=$(printf '%096d' 0)
fi

# Fail-closed: refuse to proceed without PCRs
if [ -z "$PCR0" ] || [ -z "$PCR1" ] || [ -z "$PCR2" ]; then
    log "EIF build output:"
    cat "$EVIDENCE_DIR/eif_build_output.json" 2>/dev/null || true
    fail "Could not extract PCR0/1/2 from EIF build output. Refusing to run unpinned."
fi

# Validate PCR format (96 hex chars = 48 bytes)
for pcr_name in PCR0 PCR1 PCR2; do
    pcr_val="${!pcr_name}"
    if ! echo "$pcr_val" | grep -qE '^[0-9a-fA-F]{96}$'; then
        fail "$pcr_name has invalid format: '$pcr_val' (expected 96 hex chars)"
    fi
done

log "PCR0 (image):  ${PCR0:0:32}..."
log "PCR1 (kernel): ${PCR1:0:32}..."
log "PCR2 (app):    ${PCR2:0:32}..."

# Save PCRs for evidence
cat > "$EVIDENCE_DIR/pcr_measurements.json" << PCREOF
{
  "PCR0": "$PCR0",
  "PCR1": "$PCR1",
  "PCR2": "$PCR2",
  "debug_mode": $DEBUG_MODE,
  "eif_path": "$EIF_PATH",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
PCREOF

export EPHEMERALML_EXPECTED_PCR0="$PCR0"
export EPHEMERALML_EXPECTED_PCR1="$PCR1"
export EPHEMERALML_EXPECTED_PCR2="$PCR2"

log "PCR pinning ENABLED (all 3 PCRs exported as env vars)"
echo ""

# ============================================================
# PHASE 3: LAUNCH ENCLAVE
# ============================================================
log "=== PHASE 3: LAUNCH ENCLAVE ==="

# Terminate any existing enclaves
log "Terminating any existing enclaves..."
nitro-cli terminate-enclave --all 2>/dev/null || true
sleep 2

# Build run command
ENCLAVE_RUN_ARGS=(
    --eif-path "$EIF_PATH"
    --memory "$ENCLAVE_MEMORY"
    --cpu-count "$ENCLAVE_CPUS"
    --enclave-cid "$ENCLAVE_CID"
)
if [ "$DEBUG_MODE" = true ]; then
    ENCLAVE_RUN_ARGS+=(--debug-mode)
    log "NOTE: Debug mode — enclave console available, PCRs will be all zeros at runtime."
fi

log "Launching enclave (CID=$ENCLAVE_CID, memory=${ENCLAVE_MEMORY}MB, cpus=$ENCLAVE_CPUS)..."
ENCLAVE_OUTPUT=$(nitro-cli run-enclave "${ENCLAVE_RUN_ARGS[@]}" 2>&1) || {
    echo "$ENCLAVE_OUTPUT"
    fail "Failed to launch enclave"
}
echo "$ENCLAVE_OUTPUT" | tee "$EVIDENCE_DIR/enclave_launch.json"

ENCLAVE_ID=$(echo "$ENCLAVE_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['EnclaveID'])" 2>/dev/null || echo "")
if [ -z "$ENCLAVE_ID" ]; then
    ENCLAVE_ID=$(nitro-cli describe-enclaves | python3 -c "import sys,json; e=json.load(sys.stdin); print(e[0]['EnclaveID'] if e else '')" 2>/dev/null || echo "")
fi
log "Enclave launched: ID=$ENCLAVE_ID"

# Start console capture in background (debug mode only)
if [ "$DEBUG_MODE" = true ] && [ -n "$ENCLAVE_ID" ]; then
    nitro-cli console --enclave-id "$ENCLAVE_ID" > "$EVIDENCE_DIR/enclave_console.log" 2>&1 &
    CONSOLE_PID=$!
    log "Console capture started (PID: $CONSOLE_PID)"
fi

# Wait for enclave to boot and start VSock listeners
log "Waiting 15 seconds for enclave to initialize..."
sleep 15

# Verify enclave is running
ENCLAVE_STATE=$(nitro-cli describe-enclaves | python3 -c "import sys,json; e=json.load(sys.stdin); print(e[0]['State'] if e else 'NONE')" 2>/dev/null || echo "UNKNOWN")
if [ "$ENCLAVE_STATE" != "RUNNING" ]; then
    log "Enclave state: $ENCLAVE_STATE"
    if [ "$DEBUG_MODE" = true ] && [ -f "$EVIDENCE_DIR/enclave_console.log" ]; then
        log "Last 30 lines of enclave console:"
        tail -30 "$EVIDENCE_DIR/enclave_console.log" || true
    fi
    fail "Enclave is not in RUNNING state (got: $ENCLAVE_STATE)"
fi
log "Enclave confirmed RUNNING"

# Save describe-enclaves output
nitro-cli describe-enclaves > "$EVIDENCE_DIR/enclave_describe.json" 2>/dev/null
echo ""

# ============================================================
# PHASE 4: RUN HOST ORCHESTRATOR (E2E INFERENCE)
# ============================================================
log "=== PHASE 4: E2E INFERENCE ==="

log "Running host orchestrator with PCR pinning..."
log "  Enclave CID: $ENCLAVE_CID"
log "  Control port: 5000, Data-in port: 5001, Data-out port: 5002"
log "  Input: \"$INPUT_TEXT\""
log ""

INFER_START=$(date +%s%N)

# Run host orchestrator — capture both stdout and stderr
set +e
"$REPO_DIR/target/release/ephemeral-ml-host" \
    --enclave-cid "$ENCLAVE_CID" \
    --control-port 5000 \
    --data-in-port 5001 \
    --data-out-port 5002 \
    --text "$INPUT_TEXT" \
    --receipt-output "$EVIDENCE_DIR/receipt.json" \
    --receipt-output-raw "$EVIDENCE_DIR/receipt.raw" \
    --receipt-output-air-v1 "$EVIDENCE_DIR/receipt.cbor" \
    2>&1 | tee "$EVIDENCE_DIR/host_output.log"
HOST_EXIT=${PIPESTATUS[0]}
set -e

INFER_END=$(date +%s%N)
INFER_MS=$(( (INFER_END - INFER_START) / 1000000 ))

log "Host orchestrator exited with code: $HOST_EXIT"
log "Total E2E time: ${INFER_MS}ms"

# Extract enclave-reported execution_time_ms from receipt if available
EXEC_TIME_MS="null"
if [ -f "$EVIDENCE_DIR/receipt.json" ]; then
    EXEC_TIME_MS=$(python3 -c "
import json, sys
try:
    r = json.load(open('$EVIDENCE_DIR/receipt.json'))
    print(r.get('execution_time_ms', 'null'))
except Exception:
    print('null')
" 2>/dev/null || echo "null")
fi

# Save timing
cat > "$EVIDENCE_DIR/timing.json" << TIMEOF
{
  "schema_version": 1,
  "e2e_client_ms": $INFER_MS,
  "enclave_execution_time_ms": $EXEC_TIME_MS,
  "client_exit_code": $HOST_EXIT,
  "input_text": "$(echo "$INPUT_TEXT" | sed 's/"/\\"/g')",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
TIMEOF

echo ""

# ============================================================
# PHASE 5: COLLECT EVIDENCE & CLEANUP
# ============================================================
log "=== PHASE 5: EVIDENCE COLLECTION ==="

# Save enclave state after inference
nitro-cli describe-enclaves > "$EVIDENCE_DIR/enclave_describe_post.json" 2>/dev/null || true

# Stop console capture
if [ -n "${CONSOLE_PID:-}" ]; then
    kill "$CONSOLE_PID" 2>/dev/null || true
fi

# Terminate enclave
log "Terminating enclave..."
nitro-cli terminate-enclave --all 2>/dev/null || true

# Generate artifact manifest (SHA-256 of all evidence files)
log "Generating artifact manifest..."
MANIFEST="$EVIDENCE_DIR/artifact_manifest.json"
{
    echo '{'
    echo '  "schema_version": 1,'
    echo "  \"generated\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo '  "artifacts": ['
    FIRST=true
    for f in "$EVIDENCE_DIR"/*; do
        [ -f "$f" ] || continue
        BASENAME="$(basename "$f")"
        # Skip the manifest itself
        [ "$BASENAME" = "artifact_manifest.json" ] && continue
        HASH=$(sha256sum "$f" | cut -d' ' -f1)
        SIZE=$(stat --printf='%s' "$f" 2>/dev/null || stat -f'%z' "$f" 2>/dev/null)
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo ','
        fi
        printf '    {"file": "%s", "sha256": "%s", "bytes": %s}' "$BASENAME" "$HASH" "$SIZE"
    done
    echo ''
    echo '  ]'
    echo '}'
} > "$MANIFEST"
log "Artifact manifest: $MANIFEST"

# Summary
echo ""
log "============================================================"
log "  E2E EVIDENCE SUMMARY"
log "============================================================"
echo ""
log "  Evidence directory: $EVIDENCE_DIR"
echo ""
log "  Files collected:"
ls -la "$EVIDENCE_DIR/"
echo ""

if [ $HOST_EXIT -eq 0 ]; then
    log "  STATUS: SUCCESS"
    log "  The host orchestrator completed inference with PCR-pinned attestation."
else
    log "  STATUS: FAILED (exit code $HOST_EXIT)"
    if [ "$DEBUG_MODE" = true ] && [ -f "$EVIDENCE_DIR/enclave_console.log" ]; then
        log ""
        log "  Enclave console (last 50 lines):"
        tail -50 "$EVIDENCE_DIR/enclave_console.log" || true
    fi
fi

log "============================================================"
exit $HOST_EXIT
