#!/usr/bin/env bash
# final_release_gate.sh — Single-command release gate for benchmark evidence.
#
# Chains:
#   1. run_final_kms_validation.sh (N runs with --require-kms)
#   2. check_kms_integrity.sh (audit all produced run dirs)
#   3. Print SUMMARY.md and manifest
#
# Exits non-zero on any failure. Passes all arguments through to
# run_final_kms_validation.sh (defaults: --runs 3, --require-kms, minilm-l6).
#
# Usage:
#   ./scripts/final_release_gate.sh
#   ./scripts/final_release_gate.sh --runs 5 --model-id bert-base
#   ./scripts/final_release_gate.sh --output-dir benchmark_results_final/my_run

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

OUTPUT_DIR=""
PASSTHROUGH_ARGS=()

# Parse args to capture --output-dir for later steps; pass everything through.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; PASSTHROUGH_ARGS+=("$1" "$2"); shift 2 ;;
        *) PASSTHROUGH_ARGS+=("$1"); shift ;;
    esac
done

# Default output dir if not specified.
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="benchmark_results_final/kms_validation_$(date -u +%Y%m%d_%H%M%S)"
    PASSTHROUGH_ARGS+=(--output-dir "$OUTPUT_DIR")
fi

# Release gate requires --require-kms; reject --allow-kms-bypass.
for arg in "${PASSTHROUGH_ARGS[@]}"; do
    if [[ "$arg" == "--allow-kms-bypass" ]]; then
        echo "ERROR: --allow-kms-bypass is not permitted in the release gate." >&2
        exit 1
    fi
done
# Add --require-kms if not already present.
HAS_KMS_FLAG=false
for arg in "${PASSTHROUGH_ARGS[@]}"; do
    [[ "$arg" == "--require-kms" ]] && HAS_KMS_FLAG=true
done
if ! $HAS_KMS_FLAG; then
    PASSTHROUGH_ARGS+=(--require-kms)
fi

log() { echo "[release-gate $(date -u +%H:%M:%S)] $*"; }

log "=== Step 1/3: Run benchmarks with KMS enforcement ==="
"$SCRIPT_DIR/run_final_kms_validation.sh" "${PASSTHROUGH_ARGS[@]}"

log "=== Step 2/3: Audit KMS integrity of produced artifacts ==="
RUN_DIRS=("$OUTPUT_DIR"/run_*)
if [[ ${#RUN_DIRS[@]} -eq 0 ]] || [[ ! -d "${RUN_DIRS[0]}" ]]; then
    log "ERROR: No run directories found in $OUTPUT_DIR"
    exit 1
fi
"$SCRIPT_DIR/check_kms_integrity.sh" "${RUN_DIRS[@]}"

log "=== Step 3/3: Summary ==="
echo ""
if [[ -f "$OUTPUT_DIR/SUMMARY.md" ]]; then
    cat "$OUTPUT_DIR/SUMMARY.md"
else
    log "WARNING: SUMMARY.md not found"
fi

echo ""
if [[ -f "$OUTPUT_DIR/final_validation_manifest.json" ]]; then
    log "Manifest:"
    cat "$OUTPUT_DIR/final_validation_manifest.json"
else
    log "WARNING: final_validation_manifest.json not found"
fi

echo ""
log "Release gate PASSED. Artifacts at: $OUTPUT_DIR"
if [[ -f "$OUTPUT_DIR.tar.gz" ]]; then
    log "Archive: $OUTPUT_DIR.tar.gz"
fi
