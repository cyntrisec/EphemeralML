#!/usr/bin/env bash
# run_benchmark_repro.sh — Run the maintained benchmark suite N times for reproducibility analysis.
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
    log "Reusing existing modern benchmark build artifacts where available"
fi

for i in $(seq -w 1 "$NUM_RUNS"); do
    RUN_DIR="$REPRO_DIR/run_$i"
    mkdir -p "$RUN_DIR"
    log "=== Run $i/$NUM_RUNS ==="

    if [[ "$i" == "01" && "$SKIP_BUILD" == "false" ]]; then
        # First run builds current-architecture benchmark artifacts.
        "$SCRIPT_DIR/run_benchmark_modern.sh" \
            --output-dir "$RUN_DIR"
    else
        # Subsequent runs reuse build artifacts where the modern path supports it.
        "$SCRIPT_DIR/run_benchmark_modern.sh" \
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
