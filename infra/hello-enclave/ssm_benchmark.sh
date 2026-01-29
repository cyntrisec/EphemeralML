#!/usr/bin/env bash
# ssm_benchmark.sh — Remote benchmark trigger via AWS SSM
#
# Similar to ssm_diag10.sh but focused on running the full benchmark suite.
# Clones the repo, installs Rust, builds everything, runs benchmarks, collects results.
#
# Usage (from local machine):
#   aws ssm send-command \
#     --instance-ids i-XXXX \
#     --document-name "AWS-RunShellScript" \
#     --parameters 'commands=["bash -lc \"curl -sL https://raw.githubusercontent.com/.../ssm_benchmark.sh | bash\""]' \
#     --timeout-seconds 900

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

HARD_TIMEOUT_SECS=900
OUT_BASE="/tmp/ephemeral-ml-benchmark-$(date -u +%Y%m%d-%H%M%S)"
REPO_URL="${REPO_URL:-https://github.com/EphemeralML/EphemeralML.git}"
REPO_BRANCH="${REPO_BRANCH:-master}"

log() { echo "[ssm-bench $(date -u +%H:%M:%S)] $*"; }

on_err() {
    local rc=$?
    log "ERROR rc=$rc line=$LINENO cmd=$BASH_COMMAND"
    collect_logs || true
    exit $rc
}
trap on_err ERR

mkdir -p "$OUT_BASE"
exec > >(tee -a "$OUT_BASE/ssm_benchmark.full.log") 2>&1

collect_logs() {
    log "collect_logs"
    {
        echo "--- whoami/id ---"; whoami; id
        echo "--- df -h ---"; df -h || true
        echo "--- free -h ---"; free -h || true
        echo "--- nitro-cli describe ---"; sudo nitro-cli describe-enclaves || true
        echo "--- dmesg tail ---"; sudo dmesg -T | tail -n 100 || true
    } >> "$OUT_BASE/diagnostics.log" 2>&1 || true

    # Pack results
    local tarball="/tmp/benchmark-results-$(date -u +%Y%m%d-%H%M%S).tgz"
    tar czf "$tarball" -C "$(dirname "$OUT_BASE")" "$(basename "$OUT_BASE")" 2>/dev/null || true
    log "Results packed: $tarball ($(du -h "$tarball" 2>/dev/null | cut -f1))"
}

main() {
    log "=== EphemeralML Benchmark Suite (SSM) ==="
    log "OUT_BASE=$OUT_BASE"

    # ── Prerequisites ──
    log "Installing prerequisites..."

    # Rust toolchain
    if ! command -v rustc &>/dev/null; then
        log "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>&1 | tail -3
        source "$HOME/.cargo/env"
    fi
    log "Rust: $(rustc --version)"

    # Python3 + cryptography (for model prep)
    if ! python3 -c "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305" 2>/dev/null; then
        log "Installing python3-cryptography..."
        sudo pip3 install cryptography 2>&1 | tail -3 || \
        sudo yum install -y python3-pip && sudo pip3 install cryptography 2>&1 | tail -3 || true
    fi

    # Nitro CLI
    if ! command -v nitro-cli &>/dev/null; then
        log "ERROR: nitro-cli not found. This must run on a Nitro Enclaves-enabled instance."
        exit 1
    fi
    log "nitro-cli: $(nitro-cli --version 2>&1 || echo 'unknown')"

    # ── Clone repo ──
    WORK_DIR="/tmp/ephemeral-ml-bench-src"
    if [[ -d "$WORK_DIR" ]]; then
        log "Updating existing clone..."
        (cd "$WORK_DIR" && git fetch origin && git checkout "$REPO_BRANCH" && git pull) 2>&1 | tail -5
    else
        log "Cloning repo..."
        git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$WORK_DIR" 2>&1 | tail -3
    fi
    cd "$WORK_DIR"
    GIT_COMMIT=$(git rev-parse --short HEAD)
    log "Commit: $GIT_COMMIT"

    # ── Prepare model artifacts ──
    log "Preparing benchmark model artifacts..."
    bash scripts/prepare_benchmark_model.sh 2>&1 | tail -10

    # ── Build binaries ──
    log "Building baseline binary..."
    cargo build --release --bin benchmark_baseline 2>&1 | tail -5

    log "Building kms_proxy_host..."
    cargo build --release --bin kms_proxy_host --features production 2>&1 | tail -5

    log "Building vsock-pingpong enclave (benchmark mode)..."
    (cd enclaves/vsock-pingpong && \
        sudo docker build \
            --build-arg MODE=benchmark \
            --build-arg GIT_COMMIT="$GIT_COMMIT" \
            -t vsock-pingpong-benchmark:latest \
            . 2>&1 | tail -10)

    log "Building EIF..."
    sudo nitro-cli build-enclave \
        --docker-uri vsock-pingpong-benchmark:latest \
        --output-file "$OUT_BASE/benchmark.eif" \
        2>&1 | tee "$OUT_BASE/eif_build.log" | tail -5

    # ── Run benchmark suite ──
    log "Running benchmark suite..."
    export OUTPUT_DIR="$OUT_BASE"
    bash scripts/run_benchmark.sh \
        --skip-build \
        --output-dir "$OUT_BASE" \
        2>&1 | tee "$OUT_BASE/run_benchmark.log"

    # ── Collect and pack results ──
    log "Results:"
    ls -lh "$OUT_BASE/"*.json "$OUT_BASE/"*.md 2>/dev/null || true

    if [[ -f "$OUT_BASE/benchmark_report.md" ]]; then
        log "=== BENCHMARK REPORT ==="
        cat "$OUT_BASE/benchmark_report.md"
        log "=== END REPORT ==="
    fi

    collect_logs
    log "=== Benchmark suite complete ==="
}

# Run with hard timeout
if (( HARD_TIMEOUT_SECS > 0 )); then
    timeout "$HARD_TIMEOUT_SECS" bash -c "$(declare -f); main" || {
        log "HARD TIMEOUT after ${HARD_TIMEOUT_SECS}s"
        collect_logs
        exit 124
    }
else
    main
fi
