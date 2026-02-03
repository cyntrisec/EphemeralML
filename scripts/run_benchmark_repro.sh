#!/usr/bin/env bash
# run_benchmark_repro.sh — Run the full benchmark suite N times for reproducibility analysis.
#
# Each run gets a timestamped subdirectory. After all runs complete,
# run analyze_repro.py to compute variance statistics.
#
# Usage:
#   ./scripts/run_benchmark_repro.sh [--runs N] [--output-dir DIR] [--skip-build]
#
# Example:
#   ./scripts/run_benchmark_repro.sh --runs 3
#   python3 scripts/analyze_repro.py --run-dirs benchmark_results/repro_*/run_*

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NUM_RUNS=3
OUTPUT_BASE="${OUTPUT_BASE:-$PROJECT_ROOT/benchmark_results}"
SKIP_BUILD=false
EIF_PATH="${EIF_PATH:-}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) NUM_RUNS="$2"; shift 2 ;;
        --output-dir) OUTPUT_BASE="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

REPRO_DIR="$OUTPUT_BASE/repro_$(date -u +%Y%m%d_%H%M%S)"
mkdir -p "$REPRO_DIR"

log() { echo "[repro $(date -u +%H:%M:%S)] $*"; }

log "Starting reproducibility suite: $NUM_RUNS runs"
log "Output directory: $REPRO_DIR"

if $SKIP_BUILD; then
    if [[ -z "$EIF_PATH" ]]; then
        EIF_PATH="$OUTPUT_BASE/benchmark.eif"
    fi
    if [[ ! -f "$EIF_PATH" ]]; then
        echo "ERROR: --skip-build requires an existing EIF. Set EIF_PATH or place benchmark.eif at $EIF_PATH" >&2
        exit 1
    fi
    cp -f "$EIF_PATH" "$REPRO_DIR/benchmark.eif"
    log "Using existing EIF: $EIF_PATH"
fi

for i in $(seq -w 1 "$NUM_RUNS"); do
    RUN_DIR="$REPRO_DIR/run_$i"
    mkdir -p "$RUN_DIR"
    log "=== Run $i/$NUM_RUNS ==="

    if [[ "$i" == "01" && "$SKIP_BUILD" == "false" ]]; then
        # First run builds everything and produces the reference EIF.
        "$SCRIPT_DIR/run_benchmark.sh" \
            --output-dir "$RUN_DIR"
        if [[ -f "$RUN_DIR/benchmark.eif" ]]; then
            cp -f "$RUN_DIR/benchmark.eif" "$REPRO_DIR/benchmark.eif"
            log "  Saved reference EIF to $REPRO_DIR/benchmark.eif"
        else
            log "  WARNING: benchmark.eif not found in first run output"
        fi
    else
        # Subsequent runs reuse the EIF to avoid rebuild noise/time.
        if [[ -f "$REPRO_DIR/benchmark.eif" ]]; then
            cp -f "$REPRO_DIR/benchmark.eif" "$RUN_DIR/benchmark.eif"
        fi
        "$SCRIPT_DIR/run_benchmark.sh" \
            --skip-build \
            --output-dir "$RUN_DIR"
    fi

    log "  Run $i complete"

    # Small pause between runs to avoid thermal throttling effects
    sleep 2
done

log "All $NUM_RUNS runs complete"
log "Run: python3 scripts/analyze_repro.py --run-dirs $REPRO_DIR/run_*"
log "Results in $REPRO_DIR/"
ls -la "$REPRO_DIR/"
