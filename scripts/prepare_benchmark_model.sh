#!/usr/bin/env bash
# prepare_benchmark_model.sh — Download MiniLM-L6-v2, encrypt weights, upload to S3
#
# Uses the same DEK/nonce as prepare_minilm.py for consistency.
# Requires: curl, python3, aws cli
#
# Usage:
#   ./scripts/prepare_benchmark_model.sh [--upload] [--bucket BUCKET]

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="$PROJECT_ROOT/test_artifacts"
MODEL_ID="mini-lm-v2"
S3_BUCKET="${S3_BUCKET:-ephemeral-ml-models-demo}"
BASE_URL="https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main"
UPLOAD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --upload) UPLOAD=true; shift ;;
        --bucket) S3_BUCKET="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

log() { echo "[prepare-bench $(date -u +%H:%M:%S)] $*"; }

mkdir -p "$ARTIFACT_DIR"

# Step 1: Download model files from HuggingFace
log "Downloading MiniLM-L6-v2 model artifacts..."

for file in config.json tokenizer.json model.safetensors; do
    dest="$ARTIFACT_DIR/$file"
    if [[ -f "$dest" ]]; then
        log "  $file already exists, skipping download"
    else
        log "  Downloading $file..."
        curl -L -o "$dest" "$BASE_URL/$file"
    fi
done

log "Model files downloaded:"
ls -lh "$ARTIFACT_DIR"/{config.json,tokenizer.json,model.safetensors}

# Step 2: Encrypt weights with ChaCha20-Poly1305
log "Encrypting model weights..."
python3 - <<'PYEOF'
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "test_artifacts")
MODEL_ID = "mini-lm-v2"

DEK = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
NONCE = bytes.fromhex("000102030405060708090a0b")

weights_path = os.path.join(ARTIFACT_DIR, "model.safetensors")
with open(weights_path, "rb") as f:
    plaintext = f.read()

plaintext_hash = hashlib.sha256(plaintext).hexdigest()
print(f"  Plaintext size: {len(plaintext)} bytes")
print(f"  Plaintext SHA-256: {plaintext_hash}")

cipher = ChaCha20Poly1305(DEK)
encrypted = NONCE + cipher.encrypt(NONCE, plaintext, None)

enc_path = os.path.join(ARTIFACT_DIR, f"{MODEL_ID}-weights.enc")
with open(enc_path, "wb") as f:
    f.write(encrypted)

encrypted_hash = hashlib.sha256(encrypted).hexdigest()
print(f"  Encrypted size: {len(encrypted)} bytes")
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

    aws s3 cp "$ARTIFACT_DIR/tokenizer.json" \
        "s3://$S3_BUCKET/$MODEL_ID-tokenizer" \
        --content-type "application/json"

    aws s3 cp "$ARTIFACT_DIR/$MODEL_ID-weights.enc" \
        "s3://$S3_BUCKET/$MODEL_ID-weights" \
        --content-type "application/octet-stream"

    log "Upload complete. Listing bucket contents:"
    aws s3 ls "s3://$S3_BUCKET/" | grep "$MODEL_ID"
else
    log "Skipping S3 upload (use --upload to enable)"
fi

log "Artifacts ready in $ARTIFACT_DIR:"
ls -lh "$ARTIFACT_DIR"/{config.json,tokenizer.json,model.safetensors,"$MODEL_ID-weights.enc"}

log "Done"
