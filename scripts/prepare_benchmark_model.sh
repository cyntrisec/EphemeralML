#!/usr/bin/env bash
# prepare_benchmark_model.sh — Download embedding models, encrypt weights, upload to S3
#
# Supports multiple models for benchmarking:
#   - minilm-l6  (MiniLM-L6-v2, 22.7M params, 384 dim)
#   - minilm-l12 (MiniLM-L12-v2, 33.4M params, 384 dim)
#   - bert-base  (BERT-base-uncased, 110M params, 768 dim)
#
# Uses the same DEK/nonce for all models (benchmark artifacts only).
# Requires: curl, python3, aws cli
#
# Usage:
#   ./scripts/prepare_benchmark_model.sh [--model-id MODEL] [--upload] [--bucket BUCKET]
#
# Examples:
#   ./scripts/prepare_benchmark_model.sh --model-id minilm-l6
#   ./scripts/prepare_benchmark_model.sh --model-id bert-base --upload

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
S3_BUCKET="${S3_BUCKET:-ephemeral-ml-models-demo}"
UPLOAD=false
MODEL_ID="minilm-l6"

# Model registry: model_id -> HuggingFace repo
declare -A MODEL_REPOS=(
    ["minilm-l6"]="sentence-transformers/all-MiniLM-L6-v2"
    ["minilm-l12"]="sentence-transformers/all-MiniLM-L12-v2"
    ["bert-base"]="google-bert/bert-base-uncased"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --model-id) MODEL_ID="$2"; shift 2 ;;
        --upload) UPLOAD=true; shift ;;
        --bucket) S3_BUCKET="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--model-id MODEL] [--upload] [--bucket BUCKET]"
            echo ""
            echo "Models:"
            echo "  minilm-l6   MiniLM-L6-v2 (22.7M params, 384 dim) [default]"
            echo "  minilm-l12  MiniLM-L12-v2 (33.4M params, 384 dim)"
            echo "  bert-base   BERT-base-uncased (110M params, 768 dim)"
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# Validate model ID
if [[ -z "${MODEL_REPOS[$MODEL_ID]:-}" ]]; then
    echo "Error: Unknown model '$MODEL_ID'. Valid options: ${!MODEL_REPOS[*]}"
    exit 1
fi

HF_REPO="${MODEL_REPOS[$MODEL_ID]}"
BASE_URL="https://huggingface.co/$HF_REPO/resolve/main"
ARTIFACT_DIR="$PROJECT_ROOT/test_artifacts/$MODEL_ID"

log() { echo "[prepare-bench $(date -u +%H:%M:%S)] $*"; }

mkdir -p "$ARTIFACT_DIR"

# Step 1: Download model files from HuggingFace
log "Downloading $MODEL_ID ($HF_REPO)..."

for file in config.json tokenizer.json model.safetensors; do
    dest="$ARTIFACT_DIR/$file"
    if [[ -f "$dest" ]]; then
        log "  $file already exists, skipping download"
    else
        log "  Downloading $file..."
        if ! curl -L -f -o "$dest" "$BASE_URL/$file" 2>/dev/null; then
            # Some models use tokenizer_config.json instead, or have different structure
            if [[ "$file" == "tokenizer.json" ]]; then
                log "  tokenizer.json not found, trying to download tokenizer files..."
                # For BERT-base, we need vocab.txt and tokenizer_config.json
                curl -L -f -o "$ARTIFACT_DIR/vocab.txt" "$BASE_URL/vocab.txt" 2>/dev/null || true
                curl -L -f -o "$ARTIFACT_DIR/tokenizer_config.json" "$BASE_URL/tokenizer_config.json" 2>/dev/null || true
            else
                log "  ERROR: Failed to download $file"
                exit 1
            fi
        fi
    fi
done

log "Model files downloaded to $ARTIFACT_DIR:"
ls -lh "$ARTIFACT_DIR"

# Step 2: Encrypt weights with ChaCha20-Poly1305
log "Encrypting model weights..."
ARTIFACT_DIR="$ARTIFACT_DIR" MODEL_ID="$MODEL_ID" python3 - <<'PYEOF'
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ARTIFACT_DIR = os.environ["ARTIFACT_DIR"]
MODEL_ID = os.environ["MODEL_ID"]

# Fixed DEK/nonce for benchmark reproducibility (not for production!)
DEK = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
NONCE = bytes.fromhex("000102030405060708090a0b")

weights_path = os.path.join(ARTIFACT_DIR, "model.safetensors")
with open(weights_path, "rb") as f:
    plaintext = f.read()

plaintext_hash = hashlib.sha256(plaintext).hexdigest()
print(f"  Plaintext size: {len(plaintext):,} bytes ({len(plaintext)/1024/1024:.1f} MB)")
print(f"  Plaintext SHA-256: {plaintext_hash}")

cipher = ChaCha20Poly1305(DEK)
encrypted = NONCE + cipher.encrypt(NONCE, plaintext, None)

enc_path = os.path.join(ARTIFACT_DIR, f"{MODEL_ID}-weights.enc")
with open(enc_path, "wb") as f:
    f.write(encrypted)

encrypted_hash = hashlib.sha256(encrypted).hexdigest()
print(f"  Encrypted size: {len(encrypted):,} bytes ({len(encrypted)/1024/1024:.1f} MB)")
print(f"  Encrypted SHA-256: {encrypted_hash}")
print(f"  Written to: {enc_path}")
PYEOF

log "Encryption complete"

# Step 3: Upload to S3 (optional)
if $UPLOAD; then
    log "Uploading to s3://$S3_BUCKET/"

    aws s3 cp "$ARTIFACT_DIR/config.json" \
        "s3://$S3_BUCKET/$MODEL_ID-config" \
        --content-type "application/json"

    # Handle tokenizer (either tokenizer.json or vocab.txt + tokenizer_config.json)
    if [[ -f "$ARTIFACT_DIR/tokenizer.json" ]]; then
        aws s3 cp "$ARTIFACT_DIR/tokenizer.json" \
            "s3://$S3_BUCKET/$MODEL_ID-tokenizer" \
            --content-type "application/json"
    elif [[ -f "$ARTIFACT_DIR/vocab.txt" ]]; then
        # For BERT-style tokenizers, upload vocab.txt as the tokenizer
        aws s3 cp "$ARTIFACT_DIR/vocab.txt" \
            "s3://$S3_BUCKET/$MODEL_ID-tokenizer" \
            --content-type "text/plain"
        if [[ -f "$ARTIFACT_DIR/tokenizer_config.json" ]]; then
            aws s3 cp "$ARTIFACT_DIR/tokenizer_config.json" \
                "s3://$S3_BUCKET/$MODEL_ID-tokenizer-config" \
                --content-type "application/json"
        fi
    fi

    aws s3 cp "$ARTIFACT_DIR/$MODEL_ID-weights.enc" \
        "s3://$S3_BUCKET/$MODEL_ID-weights" \
        --content-type "application/octet-stream"

    log "Upload complete. Listing bucket contents:"
    aws s3 ls "s3://$S3_BUCKET/" | grep "$MODEL_ID" || true
else
    log "Skipping S3 upload (use --upload to enable)"
fi

log "Artifacts ready in $ARTIFACT_DIR:"
ls -lh "$ARTIFACT_DIR"

# Also create a symlink for backwards compatibility with existing benchmarks
# that expect test_artifacts/mini-lm-v2-weights.enc
if [[ "$MODEL_ID" == "minilm-l6" ]]; then
    OLD_COMPAT_DIR="$PROJECT_ROOT/test_artifacts"
    mkdir -p "$OLD_COMPAT_DIR"
    for f in config.json tokenizer.json; do
        if [[ -f "$ARTIFACT_DIR/$f" ]] && [[ ! -f "$OLD_COMPAT_DIR/$f" ]]; then
            cp "$ARTIFACT_DIR/$f" "$OLD_COMPAT_DIR/$f"
        fi
    done
    if [[ -f "$ARTIFACT_DIR/$MODEL_ID-weights.enc" ]] && [[ ! -f "$OLD_COMPAT_DIR/mini-lm-v2-weights.enc" ]]; then
        cp "$ARTIFACT_DIR/$MODEL_ID-weights.enc" "$OLD_COMPAT_DIR/mini-lm-v2-weights.enc"
    fi
    log "Created backwards-compatible files in $OLD_COMPAT_DIR"
fi

log "Done"
