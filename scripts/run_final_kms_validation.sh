#!/usr/bin/env bash
# run_final_kms_validation.sh — End-to-end final benchmark validation on Nitro.
#
# This script automates the post-fix integrity flow:
#   1) Run benchmark N times from one commit with KMS enforcement.
#   2) Verify per-run security/commit/hardware integrity.
#   3) Regenerate reproducibility + quality + combined report/tables.
#   4) Produce a tar.gz archive of the full result bundle.
#
# Usage:
#   ./scripts/run_final_kms_validation.sh [--runs N] [--model-id MODEL] [--output-dir DIR]
#                                        [--require-kms|--allow-kms-bypass]
#                                        [--no-clean-first] [--rebuild-each-run]
#                                        [--no-archive]

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

NUM_RUNS=3
MODEL_ID="minilm-l6"
OUTPUT_ROOT="${PROJECT_ROOT}/benchmark_results_final/kms_validation_$(date -u +%Y%m%d_%H%M%S)"
REQUIRE_KMS=true
CLEAN_FIRST=true
REBUILD_EACH_RUN=false
CREATE_ARCHIVE=true

usage() {
    cat <<EOF
Usage:
  ./scripts/run_final_kms_validation.sh [options]

Options:
  --runs N              Number of benchmark runs (default: 3)
  --model-id MODEL      Model ID passed to run_benchmark.sh (default: minilm-l6)
  --output-dir DIR      Root output directory (default: benchmark_results_final/kms_validation_<timestamp>)
  --require-kms         Enforce fail-closed KMS path (default)
  --allow-kms-bypass    Allow fallback DEK path (not for final artifact runs)
  --no-clean-first      Do not run --clean on first run
  --rebuild-each-run    Rebuild on every run (default: only first run builds, later runs use --skip-build)
  --no-archive          Skip tar.gz archive creation
  --help                Show this message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) NUM_RUNS="$2"; shift 2 ;;
        --model-id) MODEL_ID="$2"; shift 2 ;;
        --output-dir) OUTPUT_ROOT="$2"; shift 2 ;;
        --require-kms) REQUIRE_KMS=true; shift ;;
        --allow-kms-bypass) REQUIRE_KMS=false; shift ;;
        --no-clean-first) CLEAN_FIRST=false; shift ;;
        --rebuild-each-run) REBUILD_EACH_RUN=true; shift ;;
        --no-archive) CREATE_ARCHIVE=false; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

if ! [[ "$NUM_RUNS" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: --runs must be a positive integer (got: $NUM_RUNS)" >&2
    exit 1
fi

log() { echo "[final-kms $(date -u +%H:%M:%S)] $*"; }

mkdir -p "$OUTPUT_ROOT"

HEAD_COMMIT=$(cd "$PROJECT_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# IMDSv2 token (fallback to IMDSv1, then unknown)
IMDS_TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
if [ -n "$IMDS_TOKEN" ]; then
    INSTANCE_TYPE=$(curl -sf -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
else
    INSTANCE_TYPE=$(curl -sf http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
fi
[ -z "$INSTANCE_TYPE" ] && INSTANCE_TYPE="unknown"

log "Starting final validation suite"
log "Output root: $OUTPUT_ROOT"
log "Commit: $HEAD_COMMIT"
log "Instance type: $INSTANCE_TYPE"
log "Model: $MODEL_ID"
log "Runs: $NUM_RUNS"
if $REQUIRE_KMS; then
    log "KMS policy: fail-closed enforced"
else
    log "KMS policy: bypass allowed (NOT recommended for final artifact runs)"
fi

declare -a RUN_DIRS
declare -a BASELINE_FILES
declare -a ENCLAVE_FILES

for run_idx in $(seq 1 "$NUM_RUNS"); do
    run_label=$(printf "%02d" "$run_idx")
    RUN_DIR="$OUTPUT_ROOT/run_$run_label"
    mkdir -p "$RUN_DIR"

    log "=== Run $run_label/$NUM_RUNS ==="

    RUN_ARGS=(
        --model-id "$MODEL_ID"
        --output-dir "$RUN_DIR"
    )
    if $REQUIRE_KMS; then
        RUN_ARGS+=(--require-kms)
    else
        RUN_ARGS+=(--allow-kms-bypass)
    fi
    if [[ "$run_idx" -eq 1 ]]; then
        if $CLEAN_FIRST; then
            RUN_ARGS+=(--clean)
        fi
    else
        if ! $REBUILD_EACH_RUN; then
            RUN_ARGS+=(--skip-build)
        fi
    fi

    "$SCRIPT_DIR/run_benchmark.sh" "${RUN_ARGS[@]}"

    for required in baseline_results.json enclave_results.json run_metadata.json; do
        if [[ ! -f "$RUN_DIR/$required" ]]; then
            log "ERROR: Missing required artifact: $RUN_DIR/$required"
            exit 1
        fi
    done

    python3 - "$RUN_DIR" "$HEAD_COMMIT" "$INSTANCE_TYPE" "$REQUIRE_KMS" <<'PY'
import json
import pathlib
import sys

run_dir = pathlib.Path(sys.argv[1])
head_commit = sys.argv[2]
instance_type = sys.argv[3]
require_kms = sys.argv[4].lower() == "true"

errors = []

def load(name: str):
    path = run_dir / name
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        errors.append(f"{name}: failed to parse JSON ({exc})")
        return {}

baseline = load("baseline_results.json")
enclave = load("enclave_results.json")
meta = load("run_metadata.json")

for name, data in [("baseline_results.json", baseline), ("enclave_results.json", enclave)]:
    commit = data.get("commit")
    if commit != head_commit:
        errors.append(f"{name}: commit={commit!r}, expected {head_commit!r}")
    if instance_type != "unknown":
        hw = data.get("hardware")
        if hw != instance_type:
            errors.append(f"{name}: hardware={hw!r}, expected {instance_type!r}")

meta_commit = meta.get("git_commit")
if meta_commit != head_commit:
    errors.append(f"run_metadata.json: git_commit={meta_commit!r}, expected {head_commit!r}")

meta_require_kms = bool(meta.get("require_kms"))
if meta_require_kms != require_kms:
    errors.append(
        f"run_metadata.json: require_kms={meta_require_kms!r}, expected {require_kms!r}"
    )

security = enclave.get("security", {})
kms_exercised = security.get("kms_exercised")
kms_bypassed = security.get("kms_bypassed")
if require_kms:
    if kms_exercised is not True or kms_bypassed is not False:
        errors.append(
            "enclave_results.json: require-kms violated "
            f"(kms_exercised={kms_exercised!r}, kms_bypassed={kms_bypassed!r})"
        )
else:
    if kms_exercised is False and kms_bypassed is not True:
        errors.append(
            "enclave_results.json: expected kms_bypassed=true when kms_exercised=false"
        )

if errors:
    for line in errors:
        print(f"[verify] ERROR: {line}", file=sys.stderr)
    sys.exit(1)

print(
    "[verify] PASS: "
    f"{run_dir.name} "
    f"(kms_exercised={kms_exercised}, kms_bypassed={kms_bypassed}, commit={head_commit})"
)
PY

    RUN_DIRS+=("$RUN_DIR")
    BASELINE_FILES+=("$RUN_DIR/baseline_results.json")
    ENCLAVE_FILES+=("$RUN_DIR/enclave_results.json")
done

log "Generating cross-run reproducibility summary"
python3 "$SCRIPT_DIR/analyze_repro.py" \
    --run-dirs "${RUN_DIRS[@]}" \
    --output "$OUTPUT_ROOT/reproducibility_summary.json"

log "Generating cross-run quality determinism summary"
QUALITY_OUT="$OUTPUT_ROOT/quality_determinism_${NUM_RUNS}runs.json"
python3 "$SCRIPT_DIR/analyze_quality_determinism.py" \
    --baseline-files "${BASELINE_FILES[@]}" \
    --enclave-files "${ENCLAVE_FILES[@]}" \
    --output "$QUALITY_OUT"

REP_RUN="${RUN_DIRS[$((${#RUN_DIRS[@]} - 1))]}"

log "Generating combined benchmark report from representative run: $(basename "$REP_RUN")"
REPORT_ARGS=(
    --baseline "$REP_RUN/baseline_results.json"
    --enclave "$REP_RUN/enclave_results.json"
    --quality-determinism "$QUALITY_OUT"
    --output "$OUTPUT_ROOT/benchmark_report_combined.md"
)
[[ -f "$REP_RUN/crypto_results.json" ]] && REPORT_ARGS+=(--crypto "$REP_RUN/crypto_results.json")
[[ -f "$REP_RUN/input_scaling_results.json" ]] && REPORT_ARGS+=(--input-scaling "$REP_RUN/input_scaling_results.json")
[[ -f "$REP_RUN/true_e2e_results.json" ]] && REPORT_ARGS+=(--true-e2e "$REP_RUN/true_e2e_results.json")
[[ -f "$REP_RUN/enclave_concurrency_results.json" ]] && REPORT_ARGS+=(--enclave-concurrency "$REP_RUN/enclave_concurrency_results.json")
python3 "$SCRIPT_DIR/benchmark_report.py" "${REPORT_ARGS[@]}"

log "Generating combined LaTeX tables from representative run: $(basename "$REP_RUN")"
TABLE_ARGS=(
    --baseline "$REP_RUN/baseline_results.json"
    --enclave "$REP_RUN/enclave_results.json"
)
[[ -f "$REP_RUN/crypto_results.json" ]] && TABLE_ARGS+=(--crypto "$REP_RUN/crypto_results.json")
[[ -f "$REP_RUN/cose_results.json" ]] && TABLE_ARGS+=(--cose "$REP_RUN/cose_results.json")
[[ -f "$REP_RUN/e2e_results.json" ]] && TABLE_ARGS+=(--e2e "$REP_RUN/e2e_results.json")
[[ -f "$REP_RUN/concurrent_results.json" ]] && TABLE_ARGS+=(--concurrent "$REP_RUN/concurrent_results.json")
[[ -f "$REP_RUN/input_scaling_results.json" ]] && TABLE_ARGS+=(--input-scaling "$REP_RUN/input_scaling_results.json")
[[ -f "$REP_RUN/true_e2e_results.json" ]] && TABLE_ARGS+=(--true-e2e "$REP_RUN/true_e2e_results.json")
[[ -f "$REP_RUN/enclave_concurrency_results.json" ]] && TABLE_ARGS+=(--enclave-concurrency "$REP_RUN/enclave_concurrency_results.json")
python3 "$SCRIPT_DIR/generate_paper_tables.py" "${TABLE_ARGS[@]}" > "$OUTPUT_ROOT/paper_tables_combined.tex"

log "Writing summary manifest"
python3 - "$OUTPUT_ROOT" "$MODEL_ID" "$HEAD_COMMIT" "$INSTANCE_TYPE" "$NUM_RUNS" "$REQUIRE_KMS" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

output_root = pathlib.Path(sys.argv[1])
model_id = sys.argv[2]
head_commit = sys.argv[3]
instance_type = sys.argv[4]
num_runs = int(sys.argv[5])
require_kms = sys.argv[6].lower() == "true"

runs = []
for run_dir in sorted(output_root.glob("run_*")):
    enclave_path = run_dir / "enclave_results.json"
    baseline_path = run_dir / "baseline_results.json"
    run_meta_path = run_dir / "run_metadata.json"
    if not (enclave_path.exists() and baseline_path.exists() and run_meta_path.exists()):
        continue
    with enclave_path.open("r", encoding="utf-8") as f:
        enclave = json.load(f)
    with baseline_path.open("r", encoding="utf-8") as f:
        baseline = json.load(f)
    with run_meta_path.open("r", encoding="utf-8") as f:
        run_meta = json.load(f)

    b_mean = baseline.get("inference", {}).get("latency_ms", {}).get("mean", 0.0)
    e_mean = enclave.get("inference", {}).get("latency_ms", {}).get("mean", 0.0)
    overhead = ((e_mean - b_mean) / b_mean * 100.0) if b_mean else None
    sec = enclave.get("security", {})
    runs.append(
        {
            "run_dir": run_dir.name,
            "git_commit": run_meta.get("git_commit"),
            "instance_type": run_meta.get("instance_type"),
            "kms_exercised": sec.get("kms_exercised"),
            "kms_bypassed": sec.get("kms_bypassed"),
            "baseline_mean_ms": b_mean,
            "enclave_mean_ms": e_mean,
            "overhead_pct": overhead,
        }
    )

manifest = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "model_id": model_id,
    "expected_commit": head_commit,
    "expected_instance_type": instance_type,
    "require_kms": require_kms,
    "num_runs_expected": num_runs,
    "num_runs_found": len(runs),
    "runs": runs,
    "outputs": {
        "reproducibility_summary": "reproducibility_summary.json",
        "quality_determinism": f"quality_determinism_{num_runs}runs.json",
        "combined_report": "benchmark_report_combined.md",
        "paper_tables": "paper_tables_combined.tex",
    },
}

with (output_root / "final_validation_manifest.json").open("w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

lines = [
    "# Final KMS Validation Summary",
    "",
    f"- Timestamp (UTC): {manifest['timestamp_utc']}",
    f"- Model: {model_id}",
    f"- Expected commit: {head_commit}",
    f"- Instance type: {instance_type}",
    f"- Runs requested: {num_runs}",
    f"- Runs found: {len(runs)}",
    f"- Require KMS: {str(require_kms).lower()}",
    "",
    "## Per-run checks",
    "",
    "| Run | Commit | KMS Exercised | KMS Bypassed | Baseline Mean (ms) | Enclave Mean (ms) | Overhead |",
    "|-----|--------|--------------|--------------|--------------------|-------------------|----------|",
]

for run in runs:
    overhead = run["overhead_pct"]
    overhead_str = f"{overhead:+.2f}%" if overhead is not None else "N/A"
    lines.append(
        f"| {run['run_dir']} | {run['git_commit']} | {run['kms_exercised']} | {run['kms_bypassed']} | "
        f"{run['baseline_mean_ms']:.2f} | {run['enclave_mean_ms']:.2f} | {overhead_str} |"
    )

lines.extend(
    [
        "",
        "## Generated outputs",
        "",
        "- `reproducibility_summary.json`",
        f"- `quality_determinism_{num_runs}runs.json`",
        "- `benchmark_report_combined.md`",
        "- `paper_tables_combined.tex`",
        "- `final_validation_manifest.json`",
    ]
)

with (output_root / "SUMMARY.md").open("w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
PY

if $CREATE_ARCHIVE; then
    ARCHIVE_PATH="${OUTPUT_ROOT}.tar.gz"
    log "Creating archive: $ARCHIVE_PATH"
    tar -C "$(dirname "$OUTPUT_ROOT")" -czf "$ARCHIVE_PATH" "$(basename "$OUTPUT_ROOT")"
fi

log "Final validation complete."
log "Artifacts: $OUTPUT_ROOT"
if $CREATE_ARCHIVE; then
    log "Archive: ${OUTPUT_ROOT}.tar.gz"
fi
