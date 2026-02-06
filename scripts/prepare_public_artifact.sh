#!/usr/bin/env bash
# prepare_public_artifact.sh
# Create a reader-facing benchmark artifact bundle (no AWS access required to consume).
#
# Outputs:
#   - <archive>.tar.gz
#   - <archive>.sha256
#   - <archive>.manifest.txt
#
# Example:
#   ./scripts/prepare_public_artifact.sh \
#     --input-dir benchmark_results_final/kms_validation_20260205_234917 \
#     --name kms_validation_20260205_234917.tar.gz

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: prepare_public_artifact.sh --input-dir DIR [options]

Required:
  --input-dir DIR        Directory containing final benchmark evidence

Optional:
  --output-dir DIR       Output directory (default: artifacts/public)
  --name FILE            Archive file name (default: <input-dir-name>.tar.gz)
  --keep-logs            Keep *.log files in packaged artifact
  --allow-sensitive      Do not fail on potential sensitive-pattern matches
  -h, --help             Show this help

The script scans text files for common sensitive markers:
  - arn:aws
  - EC2 instance IDs (i-...)
  - likely AWS access keys (AKIA..., ASIA...)
  - "account" near 12-digit IDs
  - IPv4 addresses
EOF
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $1" >&2
        exit 1
    fi
}

INPUT_DIR=""
OUTPUT_DIR="artifacts/public"
ARCHIVE_NAME=""
ALLOW_SENSITIVE=false
KEEP_LOGS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input-dir)
            INPUT_DIR="${2:-}"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        --name)
            ARCHIVE_NAME="${2:-}"
            shift 2
            ;;
        --allow-sensitive)
            ALLOW_SENSITIVE=true
            shift
            ;;
        --keep-logs)
            KEEP_LOGS=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$INPUT_DIR" ]]; then
    echo "ERROR: --input-dir is required" >&2
    usage
    exit 1
fi

require_cmd tar
require_cmd sha256sum
require_cmd rg

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "ERROR: input directory does not exist: $INPUT_DIR" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

INPUT_BASENAME="$(basename "$INPUT_DIR")"
if [[ -z "$ARCHIVE_NAME" ]]; then
    ARCHIVE_NAME="${INPUT_BASENAME}.tar.gz"
fi

ARCHIVE_PATH="$OUTPUT_DIR/$ARCHIVE_NAME"
SHA_PATH="${ARCHIVE_PATH}.sha256"
MANIFEST_PATH="${ARCHIVE_PATH}.manifest.txt"
SCAN_PATH="${ARCHIVE_PATH}.sensitive_scan.txt"

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

STAGE_DIR="$TMP_DIR/$INPUT_BASENAME"
cp -a "$INPUT_DIR" "$STAGE_DIR"

# Remove obvious local noise if present.
find "$STAGE_DIR" -type f \( -name '.DS_Store' -o -name '*.tmp' -o -name '*.swp' \) -delete || true

# Public artifact default: omit logs (often contain infrastructure identifiers).
if ! $KEEP_LOGS; then
    find "$STAGE_DIR" -type f -name '*.log' -delete || true
fi

echo "Scanning for potential sensitive data..."
: > "$SCAN_PATH"

scan_pattern() {
    local label="$1"
    local pattern="$2"
    if rg -n --pcre2 "$pattern" "$STAGE_DIR" > "$TMP_DIR/match.txt" 2>/dev/null; then
        {
            echo "=== $label ==="
            cat "$TMP_DIR/match.txt"
            echo
        } >> "$SCAN_PATH"
        return 0
    fi
    return 1
}

FOUND=false
scan_pattern "AWS ARN" 'arn:aws[a-zA-Z-]*:' && FOUND=true || true
scan_pattern "EC2 Instance ID" '\bi-[0-9a-f]{8,17}\b' && FOUND=true || true
scan_pattern "AWS Access Key ID" '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b' && FOUND=true || true
scan_pattern "Account-ID Context" '(?i)\b(account|acct)[^0-9\n]{0,24}\b[0-9]{12}\b' && FOUND=true || true
scan_pattern "IPv4 Address" '\b(?:\d{1,3}\.){3}\d{1,3}\b' && FOUND=true || true

if $FOUND; then
    echo "WARNING: potential sensitive markers found. See: $SCAN_PATH"
    if ! $ALLOW_SENSITIVE; then
        echo "ERROR: refusing to package while sensitive markers are present."
        echo "If acceptable for this artifact, rerun with --allow-sensitive."
        exit 1
    fi
else
    rm -f "$SCAN_PATH"
fi

echo "Creating archive: $ARCHIVE_PATH"
tar -C "$TMP_DIR" -czf "$ARCHIVE_PATH" "$INPUT_BASENAME"

sha256sum "$ARCHIVE_PATH" > "$SHA_PATH"
ARCHIVE_SHA="$(cut -d' ' -f1 "$SHA_PATH")"
FILE_COUNT="$(find "$STAGE_DIR" -type f | wc -l | tr -d ' ')"
BYTES="$(stat -c '%s' "$ARCHIVE_PATH")"
UTC_NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "$MANIFEST_PATH" <<EOF
artifact_name: $ARCHIVE_NAME
artifact_sha256: $ARCHIVE_SHA
created_utc: $UTC_NOW
source_dir: $INPUT_DIR
packaged_root: $INPUT_BASENAME
file_count: $FILE_COUNT
archive_bytes: $BYTES
logs_included: $KEEP_LOGS
verify:
  - sha256sum -c $(basename "$SHA_PATH")
EOF

echo
echo "Public artifact bundle ready:"
echo "  Archive:  $ARCHIVE_PATH"
echo "  SHA256:   $SHA_PATH"
echo "  Manifest: $MANIFEST_PATH"
if [[ -f "$SCAN_PATH" ]]; then
    echo "  Scan:     $SCAN_PATH"
fi
