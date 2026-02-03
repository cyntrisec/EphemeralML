#!/usr/bin/env bash
# run_benchmark.sh — Orchestrate full EphemeralML benchmark suite
#
# Runs on the EC2 host (parent instance with Nitro Enclaves enabled).
# Produces ALL benchmark artifacts in one output directory:
#
#   baseline_results.json        - bare-metal inference baseline
#   enclave_results.json         - enclave inference (captured from nitro-cli console)
#   crypto_results.json          - crypto primitive benchmarks (HPKE, Ed25519, receipts)
#   e2e_results.json             - E2E encrypted request (crypto-only, no inference)
#   cose_results.json            - COSE attestation verification
#   concurrent_results.json      - concurrency scaling (inference only)
#   input_scaling_results.json   - latency vs token count
#   true_e2e_results.json        - true E2E (crypto + real inference)
#   enclave_concurrency_results.json - concurrent E2E sessions
#   benchmark_report.md          - markdown comparison report
#   *_stderr.log                 - stderr from each benchmark
#
# Prerequisites:
#   - EC2 instance: m6i.xlarge+ with Nitro Enclaves enabled
#   - Terraform applied: infra/hello-enclave/ (creates KMS key, IAM role, S3 policy)
#   - S3 bucket "ephemeral-ml-models-demo" exists with model artifacts uploaded:
#       ./scripts/prepare_benchmark_model.sh --upload
#   - KMS alias "alias/ephemeral-ml-test" exists (created by Terraform)
#   - Instance profile attached with S3 + KMS permissions
#   - Docker and nitro-cli installed
#   - Rust toolchain installed
#
# Usage:
#   ./scripts/run_benchmark.sh [--skip-baseline] [--skip-build] [--output-dir DIR]

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/benchmark_results}"
SKIP_BASELINE=false
SKIP_BUILD=false
ENCLAVE_MEMORY_MB=4096
ENCLAVE_CPUS=2
INSTANCE_TYPE=$(curl -s http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
GIT_COMMIT=$(cd "$PROJECT_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-baseline) SKIP_BASELINE=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

log() { echo "[bench $(date -u +%H:%M:%S)] $*"; }

mkdir -p "$OUTPUT_DIR"

export GIT_COMMIT INSTANCE_TYPE

# ── Step 1: Run bare-metal baseline ──
if ! $SKIP_BASELINE; then
    log "Step 1: Running bare-metal baseline benchmark"

    # Ensure model artifacts exist
    if [[ ! -f "$PROJECT_ROOT/test_artifacts/config.json" ]]; then
        log "  Model artifacts not found, running prepare_benchmark_model.sh..."
        "$SCRIPT_DIR/prepare_benchmark_model.sh"
    fi

    # Build baseline binary
    if ! $SKIP_BUILD; then
        log "  Building benchmark_baseline binary..."
        (cd "$PROJECT_ROOT" && cargo build --release --bin benchmark_baseline 2>&1 | tail -5)
    fi

    log "  Running baseline..."
    "$PROJECT_ROOT/target/release/benchmark_baseline" \
        --model-dir "$PROJECT_ROOT/test_artifacts" \
        --instance-type "$INSTANCE_TYPE" \
        > "$OUTPUT_DIR/baseline_results.json" 2>"$OUTPUT_DIR/baseline_stderr.log"

    log "  Baseline results saved to $OUTPUT_DIR/baseline_results.json"
else
    log "Step 1: Skipping baseline (--skip-baseline)"
fi

# ── Step 2: Build enclave Docker image ──
if ! $SKIP_BUILD; then
    log "Step 2: Building enclave Docker image with MODE=benchmark"
    sudo docker build \
        -f "$PROJECT_ROOT/enclaves/vsock-pingpong/Dockerfile" \
        --build-arg MODE=benchmark \
        --build-arg GIT_COMMIT="$GIT_COMMIT" \
        --build-arg INSTANCE_TYPE="$INSTANCE_TYPE" \
        -t vsock-pingpong-benchmark:latest \
        "$PROJECT_ROOT" 2>&1 | tail -10
    log "  Docker image built"
else
    log "Step 2: Skipping build (--skip-build)"
fi

# ── Step 3: Build EIF ──
if ! $SKIP_BUILD; then
    log "Step 3: Building EIF (Enclave Image Format)"
    sudo nitro-cli build-enclave \
        --docker-uri vsock-pingpong-benchmark:latest \
        --output-file "$OUTPUT_DIR/benchmark.eif" \
        2>&1 | tee "$OUTPUT_DIR/eif_build.log" | tail -5
    log "  EIF built"
else
    log "Step 3: Skipping EIF build (--skip-build)"
fi

# ── Step 4: Start kms_proxy_host ──
log "Step 4: Starting kms_proxy_host"

# Kill any existing proxy
pkill -f kms_proxy_host 2>/dev/null || true
sleep 1

if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release --bin kms_proxy_host --features production 2>&1 | tail -5)
fi

"$PROJECT_ROOT/target/release/kms_proxy_host" \
    > "$OUTPUT_DIR/kms_proxy.log" 2>&1 &
KMS_PROXY_PID=$!
log "  kms_proxy_host started (PID=$KMS_PROXY_PID)"
sleep 2

# ── Step 5: Run enclave and capture console output ──
log "Step 5: Running enclave benchmark"

# Terminate any existing enclaves
sudo nitro-cli describe-enclaves | grep -q EnclaveID && \
    sudo nitro-cli terminate-enclave --all 2>/dev/null || true

sudo nitro-cli run-enclave \
    --eif-path "$OUTPUT_DIR/benchmark.eif" \
    --memory "$ENCLAVE_MEMORY_MB" \
    --cpu-count "$ENCLAVE_CPUS" \
    --enclave-cid 16 \
    2>&1 | tee "$OUTPUT_DIR/enclave_run.log"

ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | grep -oP '"EnclaveID"\s*:\s*"\K[^"]+' | head -1)
log "  Enclave started: $ENCLAVE_ID"

# Capture console output (benchmark results come via stderr → console)
log "  Waiting for benchmark results (timeout: 300s)..."
timeout 300 sudo nitro-cli console --enclave-id "$ENCLAVE_ID" \
    > "$OUTPUT_DIR/enclave_console.log" 2>&1 &
CONSOLE_PID=$!

# Wait for benchmark to complete (look for the JSON marker)
DEADLINE=$((SECONDS + 300))
while [[ $SECONDS -lt $DEADLINE ]]; do
    if grep -q "BENCHMARK_RESULTS_JSON_END" "$OUTPUT_DIR/enclave_console.log" 2>/dev/null; then
        log "  Benchmark results captured"
        break
    fi
    sleep 5
done

# Extract JSON from console log
if grep -q "BENCHMARK_RESULTS_JSON_BEGIN" "$OUTPUT_DIR/enclave_console.log"; then
    sed -n '/BENCHMARK_RESULTS_JSON_BEGIN/,/BENCHMARK_RESULTS_JSON_END/p' \
        "$OUTPUT_DIR/enclave_console.log" | \
        grep -v "BENCHMARK_RESULTS_JSON" \
        > "$OUTPUT_DIR/enclave_results.json"
    log "  Enclave results saved to $OUTPUT_DIR/enclave_results.json"
else
    log "  WARNING: Benchmark results not found in console output"
    log "  Check $OUTPUT_DIR/enclave_console.log for details"
fi

# Cleanup
kill "$CONSOLE_PID" 2>/dev/null || true
sudo nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" 2>/dev/null || true
kill "$KMS_PROXY_PID" 2>/dev/null || true

# ── Step 6a: Existing bare-metal benchmarks (crypto, e2e, cose, concurrent) ──
log "Step 6a: Running bare-metal benchmark suite (crypto, e2e, cose, concurrent)"

# Crypto primitives
if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release --bin benchmark_crypto 2>&1 | tail -3)
fi
"$PROJECT_ROOT/target/release/benchmark_crypto" \
    --instance-type "$INSTANCE_TYPE" \
    > "$OUTPUT_DIR/crypto_results.json" 2>"$OUTPUT_DIR/crypto_stderr.log"
log "  crypto_results.json saved"

# E2E encrypted request (crypto-only, no inference)
if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release --bin benchmark_e2e 2>&1 | tail -3)
fi
"$PROJECT_ROOT/target/release/benchmark_e2e" \
    --instance-type "$INSTANCE_TYPE" \
    > "$OUTPUT_DIR/e2e_results.json" 2>"$OUTPUT_DIR/e2e_stderr.log"
log "  e2e_results.json saved"

# COSE attestation verification
if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release --bin benchmark_cose 2>&1 | tail -3)
fi
"$PROJECT_ROOT/target/release/benchmark_cose" \
    --instance-type "$INSTANCE_TYPE" \
    > "$OUTPUT_DIR/cose_results.json" 2>"$OUTPUT_DIR/cose_stderr.log"
log "  cose_results.json saved"

# Concurrency scaling (inference only, no crypto)
if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release --bin benchmark_concurrent 2>&1 | tail -3)
fi
"$PROJECT_ROOT/target/release/benchmark_concurrent" \
    --model-dir "$PROJECT_ROOT/test_artifacts" \
    --instance-type "$INSTANCE_TYPE" \
    > "$OUTPUT_DIR/concurrent_results.json" 2>"$OUTPUT_DIR/concurrent_stderr.log"
log "  concurrent_results.json saved"

# ── Step 6b: Input scaling benchmark (bare metal, no enclave needed) ──
log "Step 6b: Running input scaling benchmark"
if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release --bin benchmark_input_scaling 2>&1 | tail -5)
fi
"$PROJECT_ROOT/target/release/benchmark_input_scaling" \
    --model-dir "$PROJECT_ROOT/test_artifacts" \
    --instance-type "$INSTANCE_TYPE" \
    > "$OUTPUT_DIR/input_scaling_results.json" 2>"$OUTPUT_DIR/input_scaling_stderr.log"
log "  Input scaling results saved to $OUTPUT_DIR/input_scaling_results.json"

# ── Step 6c: True E2E benchmark (mock mode, no enclave needed) ──
log "Step 6c: Running true E2E benchmark"
if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release -p ephemeral-ml-client --features benchmark --bin benchmark_true_e2e 2>&1 | tail -5)
fi
"$PROJECT_ROOT/target/release/benchmark_true_e2e" \
    --model-dir "$PROJECT_ROOT/test_artifacts" \
    --instance-type "$INSTANCE_TYPE" \
    > "$OUTPUT_DIR/true_e2e_results.json" 2>"$OUTPUT_DIR/true_e2e_stderr.log"
log "  True E2E results saved to $OUTPUT_DIR/true_e2e_results.json"

# ── Step 6d: Enclave concurrency benchmark (mock mode, no enclave needed) ──
log "Step 6d: Running enclave concurrency benchmark"
if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release -p ephemeral-ml-client --features benchmark --bin benchmark_enclave_concurrency 2>&1 | tail -5)
fi
"$PROJECT_ROOT/target/release/benchmark_enclave_concurrency" \
    --model-dir "$PROJECT_ROOT/test_artifacts" \
    --instance-type "$INSTANCE_TYPE" \
    > "$OUTPUT_DIR/enclave_concurrency_results.json" 2>"$OUTPUT_DIR/enclave_concurrency_stderr.log"
log "  Enclave concurrency results saved to $OUTPUT_DIR/enclave_concurrency_results.json"

# ── Step 7: Generate comparison report ──
log "Step 7: Generating benchmark report"
if [[ -f "$OUTPUT_DIR/baseline_results.json" && -f "$OUTPUT_DIR/enclave_results.json" ]]; then
    # Quality determinism (baseline vs enclave) using full embedding + SHA-256 when available.
    # This lets the report state "bit-identical" only when proven.
    if [[ -x "$SCRIPT_DIR/analyze_quality_determinism.py" ]]; then
        python3 "$SCRIPT_DIR/analyze_quality_determinism.py" \
            --baseline-files "$OUTPUT_DIR/baseline_results.json" \
            --enclave-files "$OUTPUT_DIR/enclave_results.json" \
            --output "$OUTPUT_DIR/quality_determinism.json" \
            2>"$OUTPUT_DIR/quality_determinism_stderr.log" || true
    fi

    REPORT_ARGS=(
        --baseline "$OUTPUT_DIR/baseline_results.json"
        --enclave "$OUTPUT_DIR/enclave_results.json"
        --output "$OUTPUT_DIR/benchmark_report.md"
    )
    [[ -f "$OUTPUT_DIR/crypto_results.json" ]] && REPORT_ARGS+=(--crypto "$OUTPUT_DIR/crypto_results.json")
    [[ -f "$OUTPUT_DIR/input_scaling_results.json" ]] && REPORT_ARGS+=(--input-scaling "$OUTPUT_DIR/input_scaling_results.json")
    [[ -f "$OUTPUT_DIR/true_e2e_results.json" ]] && REPORT_ARGS+=(--true-e2e "$OUTPUT_DIR/true_e2e_results.json")
    [[ -f "$OUTPUT_DIR/enclave_concurrency_results.json" ]] && REPORT_ARGS+=(--enclave-concurrency "$OUTPUT_DIR/enclave_concurrency_results.json")
    [[ -f "$OUTPUT_DIR/quality_determinism.json" ]] && REPORT_ARGS+=(--quality-determinism "$OUTPUT_DIR/quality_determinism.json")
    python3 "$SCRIPT_DIR/benchmark_report.py" "${REPORT_ARGS[@]}"
    log "  Report saved to $OUTPUT_DIR/benchmark_report.md"
    echo ""
    cat "$OUTPUT_DIR/benchmark_report.md"

    # Generate LaTeX table snippets directly from JSON to avoid copy/paste drift.
    PAPER_ARGS=(
        --baseline "$OUTPUT_DIR/baseline_results.json"
        --enclave "$OUTPUT_DIR/enclave_results.json"
    )
    [[ -f "$OUTPUT_DIR/input_scaling_results.json" ]] && PAPER_ARGS+=(--input-scaling "$OUTPUT_DIR/input_scaling_results.json")
    python3 "$SCRIPT_DIR/generate_paper_tables.py" "${PAPER_ARGS[@]}" \
        > "$OUTPUT_DIR/paper_tables_generated.tex" 2>"$OUTPUT_DIR/paper_tables_stderr.log" || true
else
    log "  Cannot generate report: missing baseline or enclave results"
fi

log "Benchmark suite complete. Results in $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR/"
