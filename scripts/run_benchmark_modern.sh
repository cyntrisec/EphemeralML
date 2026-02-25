#!/usr/bin/env bash
# run_benchmark_modern.sh — Benchmark fallback for current EphemeralML architecture.
#
# This script exists because the legacy benchmark pipeline (vsock-pingpong + many benchmark_*.rs
# binaries) no longer exists on the current branch. It preserves the baseline/enclave JSON schema
# expected by benchmark_report.py by:
#   - running benchmark_baseline (bare metal, 100 iters)
#   - running benchmark_cose (client-side COSE verification)
#   - collecting Nitro enclave execution_time_ms samples from repeated nitro_e2e.sh runs
#     (receipt field, not wall-clock cold-start)
#
# Output is a reduced-but-compatible benchmark bundle with enclave inference statistics, COSE
# stats, and a generated markdown report.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/benchmark_results}"
SKIP_BASELINE=false
SKIP_BUILD=false
CLEAN_BUILD=false
MODEL_ID="minilm-l6"
REQUIRE_KMS=true
NITRO_RUNS=10
NITRO_WARMUP=2
INPUT_TEXT="Confidential AI inference with cryptographic proof"

# IMDSv2 requires a token; fall back to IMDSv1, then "unknown"
IMDS_TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
if [ -n "$IMDS_TOKEN" ]; then
    INSTANCE_TYPE=$(curl -sf -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
else
    INSTANCE_TYPE=$(curl -sf http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
fi
[ -z "$INSTANCE_TYPE" ] && INSTANCE_TYPE="unknown"
GIT_COMMIT="${GIT_COMMIT:-$(cd "$PROJECT_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-baseline) SKIP_BASELINE=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --clean) CLEAN_BUILD=true; shift ;;
        --model-id) MODEL_ID="$2"; shift 2 ;;
        --require-kms) REQUIRE_KMS=true; shift ;;
        --allow-kms-bypass) REQUIRE_KMS=false; shift ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --nitro-runs) NITRO_RUNS="$2"; shift 2 ;;
        --nitro-warmup) NITRO_WARMUP="$2"; shift 2 ;;
        --text) INPUT_TEXT="$2"; shift 2 ;;
        --help|-h)
            cat <<'EOF'
Usage: ./scripts/run_benchmark_modern.sh [options]

Options:
  --model-id MODEL          Model ID for benchmark_baseline (default: minilm-l6)
  --clean                   cargo clean before builds
  --skip-baseline           Skip bare-metal baseline benchmark
  --skip-build              Reuse binaries / nitro_e2e build artifacts where possible
  --require-kms             Accepted for compatibility (not used by nitro_e2e local-model flow)
  --allow-kms-bypass        Accepted for compatibility (not used by nitro_e2e local-model flow)
  --output-dir DIR          Output directory (default: benchmark_results)
  --nitro-runs N            Measured Nitro E2E runs to aggregate (default: 10)
  --nitro-warmup N          Warmup Nitro E2E runs excluded from stats (default: 2)
  --text TEXT               Input text passed to nitro_e2e.sh
EOF
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

log() { echo "[bench-modern $(date -u +%H:%M:%S)] $*"; }

mkdir -p "$OUTPUT_DIR"
RUN_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export GIT_COMMIT INSTANCE_TYPE

cat >"$OUTPUT_DIR/run_metadata.json" <<EOF
{
  "timestamp": "${RUN_TS}",
  "git_commit": "${GIT_COMMIT}",
  "instance_type": "${INSTANCE_TYPE}",
  "model_id": "${MODEL_ID}",
  "require_kms_compat_flag": ${REQUIRE_KMS},
  "mode": "modern_fallback",
  "nitro_runs": ${NITRO_RUNS},
  "nitro_warmup": ${NITRO_WARMUP},
  "notes": [
    "Legacy vsock-pingpong benchmark pipeline is absent on this branch.",
    "Enclave benchmark statistics are aggregated from repeated scripts/nitro_e2e.sh runs using receipt.execution_time_ms."
  ]
}
EOF

if $CLEAN_BUILD; then
    log "Step 0: cargo clean"
    (cd "$PROJECT_ROOT" && cargo clean 2>&1 | tail -3)
fi

if ! $SKIP_BASELINE; then
    log "Step 1: Running bare-metal baseline benchmark"
    if [[ ! -f "$PROJECT_ROOT/test_artifacts/$MODEL_ID/config.json" && ! -f "$PROJECT_ROOT/test_artifacts/config.json" ]]; then
        log "  Model artifacts missing; running prepare_benchmark_model.sh..."
        "$SCRIPT_DIR/prepare_benchmark_model.sh" --model-id "$MODEL_ID"
    fi
    if ! $SKIP_BUILD; then
        log "  Building benchmark_baseline..."
        (cd "$PROJECT_ROOT" && cargo build --release --bin benchmark_baseline 2>&1 | tail -5)
    fi
    log "  Running benchmark_baseline (RAYON_NUM_THREADS=2)..."
    RAYON_NUM_THREADS=2 "$PROJECT_ROOT/target/release/benchmark_baseline" \
        --model-id "$MODEL_ID" \
        --model-dir "$PROJECT_ROOT/test_artifacts" \
        --instance-type "$INSTANCE_TYPE" \
        > "$OUTPUT_DIR/baseline_results.json" 2>"$OUTPUT_DIR/baseline_stderr.log"
    log "  baseline_results.json saved"
else
    log "Step 1: Skipping baseline (--skip-baseline)"
fi

log "Step 2: Running COSE attestation verification benchmark"
if ! $SKIP_BUILD; then
    (cd "$PROJECT_ROOT" && cargo build --release --bin benchmark_cose 2>&1 | tail -5)
fi
"$PROJECT_ROOT/target/release/benchmark_cose" \
    --instance-type "$INSTANCE_TYPE" \
    > "$OUTPUT_DIR/cose_results.json" 2>"$OUTPUT_DIR/cose_stderr.log"
log "  cose_results.json saved"

log "Step 3: Aggregating Nitro enclave execution-time samples via nitro_e2e.sh"
if ! command -v nitro-cli >/dev/null 2>&1; then
    log "ERROR: nitro-cli not found. This script must run on a Nitro-enabled EC2 host."
    exit 1
fi

NITRO_RUN_ROOT="$OUTPUT_DIR/nitro_e2e_runs"
mkdir -p "$NITRO_RUN_ROOT"
SAMPLES_JSONL="$OUTPUT_DIR/nitro_enclave_samples.jsonl"
: > "$SAMPLES_JSONL"

TOTAL_RUNS=$((NITRO_WARMUP + NITRO_RUNS))
for i in $(seq 1 "$TOTAL_RUNS"); do
    if [[ "$i" -le "$NITRO_WARMUP" ]]; then
        warmup=true
        phase_label="warmup"
    else
        warmup=false
        phase_label="measured"
    fi

    log "  Nitro run $i/$TOTAL_RUNS ($phase_label)"
    NITRO_ARGS=(--text "$INPUT_TEXT")
    if $SKIP_BUILD || [[ "$i" -gt 1 ]]; then
        NITRO_ARGS=(--skip-build "${NITRO_ARGS[@]}")
    fi

    "$SCRIPT_DIR/nitro_e2e.sh" "${NITRO_ARGS[@]}" > "$OUTPUT_DIR/nitro_run_${i}.stdout.log" 2>&1 || {
        log "ERROR: nitro_e2e.sh failed on run $i (see $OUTPUT_DIR/nitro_run_${i}.stdout.log)"
        tail -n 60 "$OUTPUT_DIR/nitro_run_${i}.stdout.log" >&2 || true
        exit 1
    }

    RUN_DIR="$NITRO_RUN_ROOT/run_$(printf '%03d' "$i")"
    rm -rf "$RUN_DIR"
    mkdir -p "$RUN_DIR"
    cp -a /tmp/nitro-e2e-evidence/. "$RUN_DIR/"

    python3 - "$RUN_DIR" "$i" "$warmup" >> "$SAMPLES_JSONL" <<'PY'
import json, pathlib, sys
run_dir = pathlib.Path(sys.argv[1])
run_idx = int(sys.argv[2])
warmup = sys.argv[3].lower() == "true"
timing = json.load(open(run_dir / "timing.json"))
receipt = json.load(open(run_dir / "receipt.json"))
sample = {
    "run": run_idx,
    "warmup": warmup,
    "e2e_client_ms": timing.get("e2e_client_ms"),
    "enclave_execution_time_ms": receipt.get("execution_time_ms", timing.get("enclave_execution_time_ms")),
    "memory_peak_mb": receipt.get("memory_peak_mb"),
    "timestamp": timing.get("timestamp"),
    "receipt_id": receipt.get("receipt_id"),
}
print(json.dumps(sample))
PY
done

log "  Aggregating enclave samples into enclave_results.json"
python3 - "$SAMPLES_JSONL" "$OUTPUT_DIR" "$MODEL_ID" "$INSTANCE_TYPE" "$GIT_COMMIT" "$PROJECT_ROOT" <<'PY'
import json, math, pathlib, statistics, sys

samples_path = pathlib.Path(sys.argv[1])
out_dir = pathlib.Path(sys.argv[2])
model_id = sys.argv[3]
instance_type = sys.argv[4]
git_commit = sys.argv[5]
project_root = pathlib.Path(sys.argv[6])

samples = [json.loads(line) for line in samples_path.read_text().splitlines() if line.strip()]
measured = [s for s in samples if not s.get("warmup")]
if not measured:
    raise SystemExit("No measured samples found")

def pct_nearest(values, p):
    if not values:
        return 0.0
    vals = sorted(values)
    idx = round((p / 100.0) * (len(vals) - 1))
    return float(vals[idx])

def round2(v):
    return round(float(v) + 1e-12, 2)

exec_vals = [float(s["enclave_execution_time_ms"]) for s in measured if s.get("enclave_execution_time_ms") is not None]
e2e_vals = [float(s["e2e_client_ms"]) for s in measured if s.get("e2e_client_ms") is not None]
mem_vals = [float(s["memory_peak_mb"]) for s in measured if s.get("memory_peak_mb") is not None]
mem_nonzero_vals = [v for v in mem_vals if v > 0]

if not exec_vals:
    raise SystemExit("Missing enclave_execution_time_ms samples")

baseline_path = out_dir / "baseline_results.json"
baseline = json.load(open(baseline_path)) if baseline_path.exists() else {}
baseline_mem = (baseline.get("memory") or {})
baseline_quality = (baseline.get("quality") or {})

model_label = baseline.get("model", model_id)
model_params = baseline.get("model_params", 0)
model_size_mb = baseline_mem.get("model_size_mb", 0.0)

exec_mean = sum(exec_vals) / len(exec_vals)
tp = (1000.0 / exec_mean) if exec_mean > 0 else 0.0

quality = {}
if "reference_text" in baseline_quality:
    # Preserve only metadata; the Nitro host log does not currently emit the full embedding vector.
    quality = {
        "reference_text": baseline_quality.get("reference_text"),
        "embedding_dim": baseline_quality.get("embedding_dim"),
        "notes": "Modern Nitro benchmark fallback does not capture full embedding vectors; quality comparison omitted."
    }

results = {
    "benchmark_mode": "nitro_e2e_receipt_execution_time",
    "notes": {
        "samples_source": "Repeated scripts/nitro_e2e.sh runs; execution_time_ms read from receipt.json",
        "latency_metric": "receipt.execution_time_ms (enclave-side execution only)",
        "e2e_client_latency_metric": "timing.json.e2e_client_ms (host orchestrator wall-clock)",
        "stage_timings": "Unavailable in current architecture benchmark path; set to 0/N/A",
        "quality_capture": quality.get("notes") if quality else "No quality metadata captured"
    },
    "environment": "enclave",
    "model": model_label,
    "model_id": model_id,
    "model_params": model_params,
    "hardware": instance_type,
    "timestamp": measured[-1].get("timestamp", "unknown"),
    "commit": git_commit,
    "stages": {
        "attestation_ms": 0.0,
        "kms_key_release_ms": 0.0,
        "model_fetch_ms": 0.0,
        "model_decrypt_ms": 0.0,
        "model_load_ms": 0.0,
        "tokenizer_setup_ms": 0.0,
        "cold_start_total_ms": 0.0,
    },
    "inference": {
        "input_texts": [baseline_quality.get("reference_text", "Confidential AI inference with cryptographic proof")],
        "num_iterations": len(exec_vals),
        "latency_ms": {
            "mean": round2(exec_mean),
            "p50": round2(pct_nearest(exec_vals, 50.0)),
            "p95": round2(pct_nearest(exec_vals, 95.0)),
            "p99": round2(pct_nearest(exec_vals, 99.0)),
            "min": round2(min(exec_vals)),
            "max": round2(max(exec_vals)),
        },
        "throughput_inferences_per_sec": round2(tp),
        "e2e_client_latency_ms": {
            "mean": round2(sum(e2e_vals) / len(e2e_vals)) if e2e_vals else 0.0,
            "p50": round2(pct_nearest(e2e_vals, 50.0)) if e2e_vals else 0.0,
            "p95": round2(pct_nearest(e2e_vals, 95.0)) if e2e_vals else 0.0,
            "p99": round2(pct_nearest(e2e_vals, 99.0)) if e2e_vals else 0.0,
            "min": round2(min(e2e_vals)) if e2e_vals else 0.0,
            "max": round2(max(e2e_vals)) if e2e_vals else 0.0,
        },
    },
    "memory": {
        "peak_rss_mb": round2(max(mem_vals)) if mem_vals else 0.0,
        "peak_rss_available": bool(mem_nonzero_vals),
        "peak_rss_source": "receipt.memory_peak_mb",
        "peak_vmsize_mb": 0.0,
        "model_size_mb": round2(model_size_mb),
    },
    "vsock": {
        "rtt_64b_ms": 0.0,
        "rtt_1kb_ms": 0.0,
        "rtt_64kb_ms": 0.0,
        "rtt_1mb_ms": 0.0,
        "upload_throughput_mb_per_sec": 0.0,
    },
    "quality": quality,
    "raw_samples": {
        "warmup_runs": sum(1 for s in samples if s.get("warmup")),
        "measured_runs": len(exec_vals),
        "samples_file": "nitro_enclave_samples.jsonl",
    },
}

out_dir.joinpath("enclave_results.json").write_text(json.dumps(results, indent=2) + "\n")
PY
log "  enclave_results.json saved"

log "Step 4: Generating report"
if [[ -f "$OUTPUT_DIR/baseline_results.json" && -f "$OUTPUT_DIR/enclave_results.json" ]]; then
    REPORT_ARGS=(
        --baseline "$OUTPUT_DIR/baseline_results.json"
        --enclave "$OUTPUT_DIR/enclave_results.json"
        --output "$OUTPUT_DIR/benchmark_report.md"
    )
    [[ -f "$OUTPUT_DIR/cose_results.json" ]] && REPORT_ARGS+=(--cose "$OUTPUT_DIR/cose_results.json")
    python3 "$SCRIPT_DIR/benchmark_report.py" "${REPORT_ARGS[@]}"
    {
        echo ""
        echo "## Modern Fallback Notes"
        echo ""
        echo "- Legacy Nitro benchmark pipeline components are missing on this branch."
        echo "- Enclave latency stats use receipt \`execution_time_ms\` aggregated from repeated \`scripts/nitro_e2e.sh\` runs."
        echo "- Cold-start stage breakdown and VSock RTT are unavailable in this fallback mode and appear as N/A."
        echo "- COSE verification microbenchmark is available separately in \`cose_results.json\`."
        echo ""
    } >> "$OUTPUT_DIR/benchmark_report.md"

    PAPER_ARGS=(
        --baseline "$OUTPUT_DIR/baseline_results.json"
        --enclave "$OUTPUT_DIR/enclave_results.json"
    )
    [[ -f "$OUTPUT_DIR/cose_results.json" ]] && PAPER_ARGS+=(--cose "$OUTPUT_DIR/cose_results.json")
    python3 "$SCRIPT_DIR/generate_paper_tables.py" "${PAPER_ARGS[@]}" \
        > "$OUTPUT_DIR/paper_tables_generated.tex" 2>"$OUTPUT_DIR/paper_tables_stderr.log" || true
    log "  benchmark_report.md and paper_tables_generated.tex saved"
else
    log "  Cannot generate report: missing baseline_results.json or enclave_results.json"
fi

log "Step 5: Validating JSON metadata"
VALIDATION_OK=true
for json_file in "$OUTPUT_DIR"/baseline_results.json "$OUTPUT_DIR"/enclave_results.json "$OUTPUT_DIR"/cose_results.json; do
    [[ -f "$json_file" ]] || continue
    fname="$(basename "$json_file")"
    file_commit=$(python3 -c "import json; print(json.load(open('$json_file')).get('commit','MISSING'))" 2>/dev/null || echo "PARSE_ERROR")
    if [[ "$file_commit" == "unknown" && "$GIT_COMMIT" == "unknown" ]]; then
        :
    elif [[ "$file_commit" == "unknown" || "$file_commit" == "MISSING" || "$file_commit" == "PARSE_ERROR" ]]; then
        log "  WARNING: $fname has commit='$file_commit' (expected '$GIT_COMMIT')"
        VALIDATION_OK=false
    elif [[ "$file_commit" != "$GIT_COMMIT" ]]; then
        log "  WARNING: $fname has commit='$file_commit', expected '$GIT_COMMIT'"
        VALIDATION_OK=false
    fi
    file_hw=$(python3 -c "import json; print(json.load(open('$json_file')).get('hardware','MISSING'))" 2>/dev/null || echo "PARSE_ERROR")
    if [[ "$file_hw" == "unknown" || "$file_hw" == "MISSING" || "$file_hw" == "PARSE_ERROR" ]]; then
        log "  WARNING: $fname has hardware='$file_hw' (expected '$INSTANCE_TYPE')"
        VALIDATION_OK=false
    elif [[ "$file_hw" != "$INSTANCE_TYPE" ]]; then
        log "  WARNING: $fname has hardware='$file_hw', expected '$INSTANCE_TYPE'"
        VALIDATION_OK=false
    fi
done

if [[ "$VALIDATION_OK" != true ]]; then
    log "Validation completed with warnings (see above)"
else
    log "Validation passed"
fi

log "Benchmark artifacts written to $OUTPUT_DIR"
ls -1 "$OUTPUT_DIR" | sed 's/^/  - /'
